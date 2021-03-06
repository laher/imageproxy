package imageproxy

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"image"
	"image/png"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestAllowed(t *testing.T) {
	whitelist := []string{"a.test", "*.b.test", "*c.test"}

	tests := []struct {
		url       string
		whitelist []string
		allowed   bool
	}{
		{"http://foo/image", nil, true},
		{"http://foo/image", []string{}, true},

		{"http://a.test/image", whitelist, true},
		{"http://x.a.test/image", whitelist, false},

		{"http://b.test/image", whitelist, true},
		{"http://x.b.test/image", whitelist, true},
		{"http://x.y.b.test/image", whitelist, true},

		{"http://c.test/image", whitelist, false},
		{"http://xc.test/image", whitelist, false},
		{"/image", whitelist, false},
	}

	for _, tt := range tests {
		p := NewProxy(nil, nil)
		p.Whitelist = tt.whitelist

		u, err := url.Parse(tt.url)
		if err != nil {
			t.Errorf("error parsing url %q: %v", tt.url, err)
		}
		if got, want := p.allowed(u), tt.allowed; got != want {
			t.Errorf("allowed(%q) returned %v, want %v", u, got, want)
		}
	}
}

func TestIpRanges(t *testing.T) {

	iprange := "127.0.0.1/8"
	_, ipnet, err := net.ParseCIDR(iprange)

	if err != nil {
		t.Errorf("error when parsing cidr")
		t.FailNow()
	}

	hostIpAddress := net.ParseIP("127.0.0.1")
	if !ipnet.Contains(hostIpAddress) {
		t.Errorf("ip doesnt contain a local host [%s]",hostIpAddress.String())

	}
}


func TestUrlParse(t *testing.T) {
	u, _ := url.Parse("http://10.0.0.5:8080/image")
	
	if u.Host != "10.0.0.5:8080" {
		t.Errorf("host not expected [%s]",u.Host)
		t.FailNow()
	}
	if !strings.Contains(u.Host, ":"){
		t.Errorf("host not expected [%s]",u.Host)
		t.FailNow()
	}
	
	host,port,_ := net.SplitHostPort(u.Host)
	if host != "10.0.0.5" {
		t.Errorf("host not expected [%s]",host)
		t.FailNow()
	}
	
	if port != "8080" {
		t.Errorf("port not expected [%s]",port)
		t.FailNow()
	}
}



func TestUrlParseNoPort(t *testing.T) {
	u, _ := url.Parse("http://10.0.0.5/image")
	
	if u.Host != "10.0.0.5" {
		t.Errorf("host not expected [%s]",u.Host)
		t.FailNow()
	}
	if strings.Contains(u.Host, ":"){
		t.Errorf("not expected [%s]",u.Host)
		t.FailNow()
	}
	
}

func TestBlackList(t *testing.T) {
	blacklist := []string{"127.0.0.0/8","10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16 ","test "}

	tests := []struct {
		url       string
		blacklist []string
		allowed   bool
	}{
		{"http://127.0.0.2/foo/image", blacklist, false},
		{"http://foo/image", blacklist, true},
		{"http://10.0.0.5:8080/image", blacklist, false},
		{"http://10.0.0.5:8080/image", nil, true},
		{"http://192.168.0.1/image", blacklist, false},
		{"http://localhost/image", blacklist, false},
	}

	for _, tt := range tests {
		p := NewProxy(nil, nil)
		p.Blacklist = tt.blacklist

		u, err := url.Parse(tt.url)
		if err != nil {
			t.Errorf("error parsing url %q: %v", tt.url, err)
			t.FailNow()
		}
		if got, want := p.allowed(u), tt.allowed; got != want {
			t.Errorf("allowed(%q) returned %v, want %v", u, got, want)
			t.FailNow()
		}
	}

}

func TestCheck304(t *testing.T) {
	tests := []struct {
		req, resp string
		is304     bool
	}{
		{ // etag match
			"GET / HTTP/1.1\nIf-None-Match: \"v\"\n\n",
			"HTTP/1.1 200 OK\nEtag: \"v\"\n\n",
			true,
		},
		{ // last-modified match
			"GET / HTTP/1.1\nIf-Modified-Since: Sun, 02 Jan 2000 00:00:00 GMT\n\n",
			"HTTP/1.1 200 OK\nLast-Modified: Sat, 01 Jan 2000 00:00:00 GMT\n\n",
			true,
		},

		// mismatches
		{
			"GET / HTTP/1.1\n\n",
			"HTTP/1.1 200 OK\n\n",
			false,
		},
		{
			"GET / HTTP/1.1\n\n",
			"HTTP/1.1 200 OK\nEtag: \"v\"\n\n",
			false,
		},
		{
			"GET / HTTP/1.1\nIf-None-Match: \"v\"\n\n",
			"HTTP/1.1 200 OK\n\n",
			false,
		},
		{
			"GET / HTTP/1.1\nIf-None-Match: \"a\"\n\n",
			"HTTP/1.1 200 OK\nEtag: \"b\"\n\n",
			false,
		},
		{ // last-modified match
			"GET / HTTP/1.1\n\n",
			"HTTP/1.1 200 OK\nLast-Modified: Sat, 01 Jan 2000 00:00:00 GMT\n\n",
			false,
		},
		{ // last-modified match
			"GET / HTTP/1.1\nIf-Modified-Since: Sun, 02 Jan 2000 00:00:00 GMT\n\n",
			"HTTP/1.1 200 OK\n\n",
			false,
		},
		{ // last-modified match
			"GET / HTTP/1.1\nIf-Modified-Since: Fri, 31 Dec 1999 00:00:00 GMT\n\n",
			"HTTP/1.1 200 OK\nLast-Modified: Sat, 01 Jan 2000 00:00:00 GMT\n\n",
			false,
		},
	}

	for _, tt := range tests {
		buf := bufio.NewReader(strings.NewReader(tt.req))
		req, err := http.ReadRequest(buf)
		if err != nil {
			t.Errorf("http.ReadRequest(%q) returned error: %v", tt.req, err)
		}

		buf = bufio.NewReader(strings.NewReader(tt.resp))
		resp, err := http.ReadResponse(buf, req)
		if err != nil {
			t.Errorf("http.ReadResponse(%q) returned error: %v", tt.resp, err)
		}

		if got, want := check304(req, resp), tt.is304; got != want {
			t.Errorf("check304(%q, %q) returned: %v, want %v", tt.req, tt.resp, got, want)
		}
	}
}

// testTransport is an http.RoundTripper that returns certained canned
// responses for particular requests.
type testTransport struct{}

func (t testTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var raw string

	switch req.URL.Path {
	case "/ok":
		raw = "HTTP/1.1 200 OK\n\n"
	case "/error":
		return nil, errors.New("http protocol error")
	case "/nocontent":
		raw = "HTTP/1.1 204 No Content\n\n"
	case "/etag":
		raw = "HTTP/1.1 200 OK\nEtag: \"tag\"\n\n"
	case "/png":
		m := image.NewNRGBA(image.Rect(0, 0, 1, 1))
		img := new(bytes.Buffer)
		png.Encode(img, m)

		raw = fmt.Sprintf("HTTP/1.1 200 OK\nContent-Length: %d\n\n%v", len(img.Bytes()), img.Bytes())
	default:
		raw = "HTTP/1.1 404 Not Found\n\n"
	}

	buf := bufio.NewReader(bytes.NewBufferString(raw))
	return http.ReadResponse(buf, req)
}

func TestProxy_ServeHTTP(t *testing.T) {
	p := &Proxy{
		Client: &http.Client{
			Transport: testTransport{},
		},
		Whitelist: []string{"good.test"},
		Logger:    DefaultLogger{},
	}

	tests := []struct {
		url  string // request URL
		code int    // expected response status code
	}{
		{"/favicon.ico", http.StatusOK},
		{"//foo", http.StatusBadRequest},                            // invalid request URL
		{"/http://bad.test/", http.StatusBadRequest},                // Disallowed host
		{"/http://good.test/error", http.StatusInternalServerError}, // HTTP protocol error
		{"/http://good.test/nocontent", http.StatusNoContent},       // non-OK response

		{"/100/http://good.test/ok", http.StatusOK},
	}

	for _, tt := range tests {
		req, _ := http.NewRequest("GET", "http://localhost"+tt.url, nil)
		resp := httptest.NewRecorder()
		p.ServeHTTP(resp, req)

		if got, want := resp.Code, tt.code; got != want {
			t.Errorf("ServeHTTP(%v) returned status %d, want %d", req, got, want)
		}
	}
}

// test that 304 Not Modified responses are returned properly.
func TestProxy_ServeHTTP_is304(t *testing.T) {
	p := &Proxy{
		Client: &http.Client{
			Transport: testTransport{},
		},
		Logger: DefaultLogger{},
	}

	req, _ := http.NewRequest("GET", "http://localhost/http://good.test/etag", nil)
	req.Header.Add("If-None-Match", `"tag"`)
	resp := httptest.NewRecorder()
	p.ServeHTTP(resp, req)

	if got, want := resp.Code, http.StatusNotModified; got != want {
		t.Errorf("ServeHTTP(%v) returned status %d, want %d", req, got, want)
	}
	if got, want := resp.Header().Get("Etag"), `"tag"`; got != want {
		t.Errorf("ServeHTTP(%v) returned etag header %v, want %v", req, got, want)
	}
}

func TestTransformingTransport(t *testing.T) {
	client := new(http.Client)
	tr := &TransformingTransport{testTransport{}, client, DefaultLogger{}}
	client.Transport = tr

	tests := []struct {
		url         string
		code        int
		expectError bool
	}{
		{"http://good.test/png#1", http.StatusOK, false},
		{"http://good.test/error#1", http.StatusInternalServerError, true},
		// TODO: test more than just status code... verify that image
		// is actually transformed and returned properly and that
		// non-image responses are returned as-is
	}

	for _, tt := range tests {
		req, _ := http.NewRequest("GET", tt.url, nil)

		resp, err := tr.RoundTrip(req)
		if err != nil {
			if !tt.expectError {
				t.Errorf("RoundTrip(%v) returned unexpected error: %v", tt.url, err)
			}
			continue
		} else if tt.expectError {
			t.Errorf("RoundTrip(%v) did not return expected error", tt.url)
		}
		if got, want := resp.StatusCode, tt.code; got != want {
			t.Errorf("RoundTrip(%v) returned status code %d, want %d", tt.url, got, want)
		}
	}
}
