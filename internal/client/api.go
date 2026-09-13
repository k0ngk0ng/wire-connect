package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/k0ngk0ng/wire-connect/internal/config"
	"github.com/k0ngk0ng/wire-connect/internal/control"
	"github.com/k0ngk0ng/wire-connect/internal/endpoint"
	"github.com/k0ngk0ng/wire-connect/internal/secure"
)

type Client struct {
	Server     string
	Credential config.Credential
	HTTP       *http.Client
}

func New(server string, cred config.Credential) (*Client, error) {
	u, err := endpoint.Parse(server)
	if err != nil {
		return nil, err
	}
	h, err := endpoint.HTTPClient(cred.CertificateSHA256)
	if err != nil {
		return nil, err
	}
	return &Client{Server: u.String(), Credential: cred, HTTP: h}, nil
}

type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string { return fmt.Sprintf("server returned %d: %s", e.Status, e.Message) }

func (c *Client) request(ctx context.Context, method, path string, body, out any) error {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	var data []byte
	var err error
	if body != nil {
		data, err = json.Marshal(body)
		if err != nil {
			return err
		}
	}
	r, err := http.NewRequestWithContext(ctx, method, c.Server+path, bytes.NewReader(data))
	if err != nil {
		return err
	}
	r.Header.Set("Content-Type", "application/json")
	if c.Credential.Token != "" {
		r.Header.Set("Authorization", "Bearer "+c.Credential.Token)
	}
	resp, err := c.HTTP.Do(r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 65537))
	if err != nil {
		return err
	}
	if len(b) > 65536 {
		return errors.New("server response exceeds size limit")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &APIError{resp.StatusCode, string(b)}
	}
	if out != nil && len(b) > 0 {
		return json.Unmarshal(b, out)
	}
	return nil
}

func (c *Client) Login(ctx context.Context, token, name string) (config.Credential, error) {
	var out control.LoginResponse
	err := c.request(ctx, "POST", "/v1/login", control.LoginRequest{Token: token, Name: name}, &out)
	if err != nil {
		return config.Credential{}, err
	}
	if out.Token == "" || out.DeviceID == "" {
		return config.Credential{}, errors.New("server returned an empty credential")
	}
	return config.Credential{Token: out.Token, DeviceID: out.DeviceID, CertificateSHA256: c.Credential.CertificateSHA256}, nil
}

func (c *Client) Health(ctx context.Context) error {
	return c.request(ctx, "GET", "/healthz", nil, nil)
}

type socketResult struct {
	message control.Message
	err     error
}
type socket struct {
	conn     *websocket.Conn
	incoming chan socketResult
	cancel   context.CancelFunc
}

func (c *Client) socket(ctx context.Context, path string) (*socket, error) {
	dialCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	w, _, err := websocket.Dial(dialCtx, endpoint.WebSocketURL(c.Server, path), &websocket.DialOptions{HTTPClient: c.HTTP, HTTPHeader: http.Header{"Authorization": []string{"Bearer " + c.Credential.Token}}, CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return nil, err
	}
	w.SetReadLimit(32 << 10)
	readCtx, stop := context.WithCancel(ctx)
	s := &socket{conn: w, incoming: make(chan socketResult, 32), cancel: stop}
	go func() {
		defer close(s.incoming)
		for {
			var m control.Message
			err := wsjson.Read(readCtx, w, &m)
			select {
			case s.incoming <- socketResult{m, err}:
			case <-readCtx.Done():
				return
			default:
				w.CloseNow()
				return
			}
			if err != nil {
				return
			}
		}
	}()
	return s, nil
}

func (s *socket) close() { s.cancel(); s.conn.CloseNow() }
func (s *socket) next(ctx context.Context) (control.Message, error) {
	select {
	case r, ok := <-s.incoming:
		if !ok {
			return control.Message{}, errors.New("signaling connection closed")
		}
		return r.message, r.err
	case <-ctx.Done():
		return control.Message{}, ctx.Err()
	}
}
func (s *socket) write(ctx context.Context, kind string, b []byte) error {
	payload, err := json.Marshal(b)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return wsjson.Write(ctx, s.conn, control.Message{Kind: kind, Payload: payload})
}

func (s *socket) read(ctx context.Context, kind string) ([]byte, error) {
	for {
		m, err := s.next(ctx)
		if err != nil {
			return nil, err
		}
		if m.Kind == "peer" {
			var p struct {
				Connected bool `json:"connected"`
			}
			if err := json.Unmarshal(m.Payload, &p); err != nil {
				return nil, err
			}
			if !p.Connected {
				return nil, errors.New("peer disconnected")
			}
			continue
		}
		if m.Kind != kind {
			return nil, fmt.Errorf("unexpected signaling phase %q", m.Kind)
		}
		var b []byte
		if err := json.Unmarshal(m.Payload, &b); err != nil {
			return nil, err
		}
		return b, nil
	}
}

func (s *socket) waitPeer(ctx context.Context) error {
	m, err := s.next(ctx)
	if err != nil {
		return err
	}
	if m.Kind != "peer" {
		return errors.New("server did not announce peer readiness")
	}
	var p struct {
		Connected bool `json:"connected"`
	}
	if err := json.Unmarshal(m.Payload, &p); err != nil {
		return err
	}
	if !p.Connected {
		return errors.New("peer is not connected")
	}
	return nil
}

type pakeExchange struct{ *socket }

func (x pakeExchange) Send(ctx context.Context, b []byte) error    { return x.write(ctx, "pake", b) }
func (x pakeExchange) Receive(ctx context.Context) ([]byte, error) { return x.read(ctx, "pake") }

type channel struct {
	socket *socket
	secure *secure.Session
}

func newChannel(ctx context.Context, s *socket, secret []byte, host bool, binding string) (*channel, error) {
	session, err := secure.NewSession(secret, host, binding)
	if err != nil {
		return nil, err
	}
	hello, err := session.Hello()
	if err != nil {
		return nil, err
	}
	if err := s.write(ctx, "sealed", hello); err != nil {
		return nil, err
	}
	other, err := s.read(ctx, "sealed")
	if err != nil {
		return nil, err
	}
	if err := session.AcceptHello(other); err != nil {
		return nil, err
	}
	return &channel{s, session}, nil
}

func (c *channel) send(ctx context.Context, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	sealed, err := c.secure.Seal(b)
	if err != nil {
		return err
	}
	return c.socket.write(ctx, "sealed", sealed)
}
func (c *channel) recv(ctx context.Context, v any) error {
	b, err := c.socket.read(ctx, "sealed")
	if err != nil {
		return err
	}
	plain, err := c.secure.Open(b)
	if err != nil {
		return err
	}
	return json.Unmarshal(plain, v)
}
