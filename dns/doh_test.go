package dns

import (
	"context"
	"encoding/base64"
	"errors"
	stdhttp "net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/common/utils"

	"github.com/metacubex/http"
	D "github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func newTestDoH(t *testing.T, handler stdhttp.HandlerFunc) (*dnsOverHTTPS, *http.Client) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL + "/dns-query")
	if err != nil {
		t.Fatal(err)
	}
	return &dnsOverHTTPS{url: u, addr: u.Redacted()}, &http.Client{}
}

func TestDoHResponseSizeLimit(t *testing.T) {
	doh, client := newTestDoH(t, func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(make([]byte, maxDoHResponseSize+1))
	})

	_, err := doh.exchangeHTTPS(context.Background(), client, new(D.Msg).SetQuestion("example.com.", D.TypeA))
	var limitErr *utils.SizeLimitError
	if !errors.As(err, &limitErr) || limitErr.Limit != maxDoHResponseSize {
		t.Fatalf("want SizeLimitError(%d), got %v", maxDoHResponseSize, err)
	}
}

func TestDoHUnpackErrorOmitsBody(t *testing.T) {
	const secret = "<html>not a dns message</html>"
	doh, client := newTestDoH(t, func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		_, _ = w.Write([]byte(secret))
	})

	_, err := doh.exchangeHTTPS(context.Background(), client, new(D.Msg).SetQuestion("example.com.", D.TypeA))
	if err == nil {
		t.Fatal("want unpack error")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error leaks the response body: %v", err)
	}
	if !strings.Contains(err.Error(), "bytes") {
		t.Fatalf("error should report the body length: %v", err)
	}
}

func TestDoHStatusCheckedBeforeBody(t *testing.T) {
	doh, client := newTestDoH(t, func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		w.WriteHeader(stdhttp.StatusBadGateway)
		_, _ = w.Write(make([]byte, 4*maxDoHResponseSize))
	})

	_, err := doh.exchangeHTTPS(context.Background(), client, new(D.Msg).SetQuestion("example.com.", D.TypeA))
	if err == nil || !strings.Contains(err.Error(), "expected status") {
		t.Fatalf("want status error, got %v", err)
	}
}

func TestDoHValidResponse(t *testing.T) {
	doh, client := newTestDoH(t, func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		raw, err := base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
		if err != nil {
			stdhttp.Error(w, err.Error(), stdhttp.StatusBadRequest)
			return
		}
		req := new(D.Msg)
		if err := req.Unpack(raw); err != nil {
			stdhttp.Error(w, err.Error(), stdhttp.StatusBadRequest)
			return
		}
		resp := new(D.Msg).SetReply(req)
		buf, _ := resp.Pack()
		_, _ = w.Write(buf)
	})

	req := new(D.Msg).SetQuestion("example.com.", D.TypeA)
	resp, err := doh.exchangeHTTPS(context.Background(), client, req)
	if err != nil {
		t.Fatalf("valid response: %v", err)
	}
	if resp.Id != req.Id {
		t.Fatalf("id mismatch: %d != %d", resp.Id, req.Id)
	}
}

func TestDoHAddressRedactsUserinfo(t *testing.T) {
	client := newDoHClient("https://user:s3cret@dns.example.com:443/dns-query", nil, false, map[string]string{}, nil, "")
	doh := client.(*dnsOverHTTPS)
	defer doh.Close()

	assert.NotContains(t, doh.Address(), "s3cret")
	assert.Equal(t, "https://user:xxxxx@dns.example.com:443/dns-query", doh.Address())

	// the request itself still carries the credentials
	password, ok := doh.url.User.Password()
	assert.True(t, ok)
	assert.Equal(t, "s3cret", password)
}

func TestDoHAddressWithoutUserinfo(t *testing.T) {
	client := newDoHClient("https://dns.example.com/dns-query", nil, false, map[string]string{}, nil, "")
	doh := client.(*dnsOverHTTPS)
	defer doh.Close()

	assert.Equal(t, "https://dns.example.com/dns-query", doh.Address())
}
