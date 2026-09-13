package endpoint

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestURLPolicy(t *testing.T) {
	for _, s := range []string{"vpn.example.com", "https://vpn.example.com:443/", "http://127.0.0.1:1234", "http://[::1]:1234"} {
		if _, err := Parse(s); err != nil {
			t.Errorf("%s: %v", s, err)
		}
	}
	for _, s := range []string{"http://example.com", "https://user:password@example.com", "https://example.com/foo", "https://example.com/?token=x", "https://example.com/#x", "file:///tmp/a", "https://"} {
		if _, err := Parse(s); err == nil {
			t.Errorf("accepted %s", s)
		}
	}
}

func TestPinnedTLS(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer s.Close()
	h := sha256.Sum256(s.Certificate().Raw)
	c, err := HTTPClient(hex.EncodeToString(h[:]))
	if err != nil {
		t.Fatal(err)
	}
	r, err := c.Get(s.URL)
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	wrong, err := HTTPClient(hex.EncodeToString(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	if r, err := wrong.Get(s.URL); err == nil {
		r.Body.Close()
		t.Fatal("accepted wrong certificate")
	}
	normal, _ := HTTPClient("")
	if r, err := normal.Get(s.URL); err == nil {
		r.Body.Close()
		t.Fatal("accepted untrusted certificate")
	}
}
