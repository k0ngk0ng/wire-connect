// Command wire-connect-testutil contains small helpers used by the disposable
// Linux NAT integration test. It is deliberately kept outside the release
// build: the release script builds only cmd/wirectl-connect.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const httpBody = "wire-connect-nat-http-ok\n"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: wire-connect-testutil <cert|http|udp|udp-client> [options]")
	}
	switch args[0] {
	case "cert":
		return makeCert(args[1:])
	case "http":
		return serveHTTP(args[1:])
	case "udp":
		return serveUDP(args[1:])
	case "udp-client":
		return udpClient(args[1:])
	case "help", "--help", "-h":
		fmt.Println("usage: wire-connect-testutil <cert|http|udp|udp-client> [options]")
		return nil
	default:
		return fmt.Errorf("unknown testutil command %q", args[0])
	}
}

func makeCert(args []string) error {
	f := flag.NewFlagSet("cert", flag.ContinueOnError)
	f.SetOutput(os.Stderr)
	ipText := f.String("ip", "", "IPv4 address to include in the certificate")
	certPath := f.String("cert", "", "certificate PEM output path")
	keyPath := f.String("key", "", "private key PEM output path")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 || *ipText == "" || *certPath == "" || *keyPath == "" {
		return errors.New("usage: wire-connect-testutil cert --ip IP --cert CERT.pem --key KEY.pem")
	}
	ip, err := netip.ParseAddr(*ipText)
	if err != nil || !ip.Is4() {
		return fmt.Errorf("certificate IP must be an IPv4 address: %q", *ipText)
	}
	if err := ensureOutputPath(*certPath); err != nil {
		return err
	}
	if err := ensureOutputPath(*keyPath); err != nil {
		return err
	}

	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate certificate key: %w", err)
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return fmt.Errorf("generate certificate serial: %w", err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "wire-connect disposable NAT test"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{ip.AsSlice()},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &private.PublicKey, private)
	if err != nil {
		return fmt.Errorf("create certificate: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(private)
	if err != nil {
		return fmt.Errorf("marshal certificate key: %w", err)
	}
	if err := writePrivate(*keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})); err != nil {
		return err
	}
	if err := writePrivate(*certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})); err != nil {
		return err
	}
	fingerprint := sha256.Sum256(der)
	fmt.Printf("%x\n", fingerprint[:])
	return nil
}

func ensureOutputPath(path string) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("output path is empty")
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("output path is not a regular file: %s", path)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect output path %s: %w", path, err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	return nil
}

func writePrivate(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	if err := f.Chmod(0600); err != nil {
		_ = f.Close()
		return fmt.Errorf("protect %s: %w", path, err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close %s: %w", path, err)
	}
	return nil
}

func serveHTTP(args []string) error {
	f := flag.NewFlagSet("http", flag.ContinueOnError)
	f.SetOutput(os.Stderr)
	addr := f.String("addr", "", "listen address")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 || *addr == "" {
		return errors.New("usage: wire-connect-testutil http --addr IP:PORT")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, httpBody)
	})
	server := &http.Server{Addr: *addr, Handler: mux, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second}
	return serveUntilSignal(func() error { return server.ListenAndServe() }, server.Shutdown)
}

func serveUDP(args []string) error {
	f := flag.NewFlagSet("udp", flag.ContinueOnError)
	f.SetOutput(os.Stderr)
	addr := f.String("addr", "", "listen address")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 || *addr == "" {
		return errors.New("usage: wire-connect-testutil udp --addr IP:PORT")
	}
	conn, err := net.ListenPacket("udp", *addr)
	if err != nil {
		return fmt.Errorf("listen UDP: %w", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()
	buf := make([]byte, 64<<10)
	for {
		n, peer, err := conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("read UDP: %w", err)
		}
		if _, err := conn.WriteTo(buf[:n], peer); err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("write UDP: %w", err)
		}
	}
}

func udpClient(args []string) error {
	f := flag.NewFlagSet("udp-client", flag.ContinueOnError)
	f.SetOutput(os.Stderr)
	addr := f.String("addr", "", "destination address")
	payload := f.String("payload", "wire-connect-nat-udp", "payload to send")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 || *addr == "" {
		return errors.New("usage: wire-connect-testutil udp-client --addr IP:PORT [--payload TEXT]")
	}
	conn, err := net.DialTimeout("udp", *addr, 3*time.Second)
	if err != nil {
		return fmt.Errorf("dial UDP: %w", err)
	}
	defer conn.Close()
	if deadline := time.Now().Add(3 * time.Second); conn.SetDeadline(deadline) != nil {
		return errors.New("set UDP deadline")
	}
	want := []byte(*payload)
	if _, err := conn.Write(want); err != nil {
		return fmt.Errorf("write UDP: %w", err)
	}
	got := make([]byte, 64<<10)
	n, err := conn.Read(got)
	if err != nil {
		return fmt.Errorf("read UDP echo: %w", err)
	}
	if string(got[:n]) != string(want) {
		return fmt.Errorf("UDP echo mismatch: got %d bytes, want %d", n, len(want))
	}
	fmt.Println("udp echo ok")
	return nil
}

func serveUntilSignal(serve func() error, shutdown func(context.Context) error) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	done := make(chan error, 1)
	go func() { done <- serve() }()
	select {
	case err := <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		err := <-done
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}
