// Package endpoint centralizes server URL and TLS policy for HTTP and relay traffic.
package endpoint

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

func Parse(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if len(raw) > 2048 {
		return nil, errors.New("server URL exceeds size limit")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("server must be a hostname or an HTTPS origin without credentials, path or query")
	}
	if u.Scheme != "https" {
		ip, e := netip.ParseAddr(u.Hostname())
		if u.Scheme != "http" || e != nil || !ip.IsLoopback() {
			return nil, errors.New("HTTPS is required (HTTP is allowed only on loopback for local tests)")
		}
	}
	u.Host = strings.ToLower(u.Host)
	if (u.Scheme == "https" && u.Port() == "443") || (u.Scheme == "http" && u.Port() == "80") {
		host := u.Hostname()
		u.Host = host
		if strings.Contains(host, ":") {
			u.Host = strings.TrimSuffix(net.JoinHostPort(host, ""), ":")
		}
	}
	u.Path = ""
	u.RawPath = ""
	return u, nil
}

func HTTPClient(pin string) (*http.Client, error) {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if pin != "" {
		want, err := hex.DecodeString(strings.ReplaceAll(pin, ":", ""))
		if err != nil || len(want) != sha256.Size {
			return nil, errors.New("certificate fingerprint must be SHA-256 hex")
		}
		// A pinned certificate is an explicit alternate trust anchor for IP-only
		// deployments. The callback checks its exact bytes and validity period;
		// no code path accepts an unverified certificate without a supplied pin.
		tr.TLSClientConfig.InsecureSkipVerify = true
		tr.TLSClientConfig.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("server sent no certificate")
			}
			cert := cs.PeerCertificates[0]
			got := sha256.Sum256(cert.Raw)
			if subtle.ConstantTimeCompare(got[:], want) != 1 {
				return errors.New("server certificate fingerprint mismatch")
			}
			now := time.Now()
			if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
				return errors.New("pinned server certificate is outside its validity period")
			}
			return nil
		}
	}
	return &http.Client{Transport: tr, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return fmt.Errorf("refusing server redirect to %s", req.URL.Host)
	}}, nil
}

func WebSocketURL(server, path string) string {
	u, _ := url.Parse(server + path)
	if u.Scheme == "https" {
		u.Scheme = "wss"
	} else {
		u.Scheme = "ws"
	}
	return u.String()
}
