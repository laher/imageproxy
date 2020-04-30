// Copyright 2013 Google Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package imageproxy provides an image proxy server.  For typical use of
// creating and using a Proxy, see cmd/imageproxy/main.go.
package imageproxy

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gregjones/httpcache"
)

type ImageResponseType string

// Proxy serves image requests.
//
// Note that a Proxy should not be run behind a http.ServeMux, since the
// ServeMux aggressively cleans URLs and removes the double slash in the
// embedded request URL.
type Proxy struct {
	Client *http.Client // client used to fetch remote URLs
	Cache  Cache        // cache used to cache responses

	// Whitelist specifies a list of remote hosts that images can be
	// proxied from.  An empty list means all hosts are allowed.
	Whitelist []string
	// Blacklist specifies a list of remote hosts that images can't be
	// proxied from.  An empty list means all hosts are allowed.
	Blacklist []string

	// AllowedReponseTypes specifies a list of allowed http response times
	AllowedReponseContentTypes []string

	Logger

	ImageFetcher ImageFetcher
}
type Logger interface {
	Error(msg ...interface{})
	Errorf(msg string, args ...interface{})
	Infof(msg string, args ...interface{})
}

type DefaultLogger struct {
}

func (dl DefaultLogger) Error(msg ...interface{}) {
	log.Printf("ERROR: %s", msg)
}

// Errorf ..
func (dl DefaultLogger) Errorf(msg string, args ...interface{}) {
	emsg := fmt.Sprintf(msg, args...)
	log.Printf("ERROR: %s", emsg)
}

// Infof ..
func (dl DefaultLogger) Infof(msg string, args ...interface{}) {
	imsg := fmt.Sprintf(msg, args...)
	log.Printf("INFO: %s", imsg)
}

// NewProxy constructs a new proxy.  The provided http RoundTripper will be
// used to fetch remote URLs.  If nil is provided, http.DefaultTransport will
// be used.
func NewProxy(transport http.RoundTripper, cache Cache) *Proxy {
	if transport == nil {
		transport = http.DefaultTransport
	}
	if cache == nil {
		cache = NopCache
	}

	client := new(http.Client)
	client.Transport = &httpcache.Transport{
		Transport:           &TransformingTransport{transport, client, DefaultLogger{}},
		Cache:               cache,
		MarkCachedResponses: true,
	}

	return &Proxy{
		Client:       client,
		Cache:        cache,
		Logger:       DefaultLogger{},
		ImageFetcher: NewImageProxyGroupcache(ModelGroupCacheSizeDefault, ModelGroupCacheWindowDefault),
	}
}

// ServeHTTP handles image requests.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.serveImage(w, r, false)
}

// ServeHTTPWithCache handles image requests and caches images.
func (p *Proxy) ServeHTTPWithCache(w http.ResponseWriter, r *http.Request) {
	p.serveImage(w, r, true)
}

func (p *Proxy) serveImage(w http.ResponseWriter, r *http.Request, useCache bool) {
	req, err := NewRequest(r)
	if err != nil {
		msg := fmt.Sprintf("invalid request URL: %v", err)
		p.Logger.Error(msg)
		http.Error(w, msg, http.StatusBadRequest)
		return
	}

	if !p.allowed(req.URL) {
		msg := fmt.Sprintf("remote URL is not for an allowed host: %v", req.URL)
		p.Logger.Error(msg)
		http.Error(w, msg, http.StatusBadRequest)
		return
	}

	u := req.URL.String()
	if req.Options != emptyOptions {
		u += "#" + req.Options.String()
	}

	var resp *CacheResponse
	if useCache {
		resp, err = p.ImageFetcher.GetImageByURL(u)

		if err != nil {
			msg := fmt.Sprintf("error fetching image from cache: %v", err)
			p.Logger.Error(msg)
			http.Error(w, msg, http.StatusInternalServerError)
			return
		}
	} else {
		result, err := p.Client.Get(u)

		if err != nil {
			msg := fmt.Sprintf("error fetching remote image: %v", err)
			p.Logger.Error(msg)
			http.Error(w, msg, http.StatusInternalServerError)
			return
		}

		defer result.Body.Close()
		body := new(bytes.Buffer)
		io.Copy(body, result.Body)

		if err != nil {
			msg := fmt.Sprintf("error reading data from http response: %v", err)
			p.Logger.Error(msg)
			http.Error(w, msg, http.StatusInternalServerError)
			return
		}

		resp = &CacheResponse{Status: result.Status, StatusCode: result.StatusCode, Header: result.Header, Body: body.Bytes()}
	}
	p.writeResponse(resp, w, r, req)
}

func (p *Proxy) writeResponse(resp *CacheResponse, w http.ResponseWriter, r *http.Request, req *Request) {
	contentType := resp.Header.Get("Content-Type")
	if !p.isResponseContentTypeAllowed(contentType) {
		http.Error(w, "Response type not allowed <"+contentType+">", http.StatusBadRequest)
		return
	}

	cached := resp.Header.Get(httpcache.XFromCache)
	p.Logger.Infof("request: %v (served from cache: %v)", *req, cached == "1")

	if resp.StatusCode != http.StatusOK {
		msg := fmt.Sprintf("remote URL %q returned status: %v", req.URL, resp.Status)
		p.Logger.Error(msg)
		http.Error(w, msg, resp.StatusCode)
		return
	}

	copyHeader(w, resp.Header, "Last-Modified")
	copyHeader(w, resp.Header, "Expires")
	copyHeader(w, resp.Header, "Etag")

	if is304 := check304(r, resp.Header); is304 {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	copyHeader(w, resp.Header, "Content-Length")
	copyHeader(w, resp.Header, "Content-Type")

	io.Copy(w, bytes.NewBuffer(resp.Body))
}

func copyHeader(w http.ResponseWriter, headers http.Header, header string) {
	key := http.CanonicalHeaderKey(header)
	if value, ok := headers[key]; ok {
		w.Header()[key] = value
	}
}

func (p *Proxy) isResponseContentTypeAllowed(responseType string) bool {
	responseType = strings.TrimSpace(responseType)
	if len(p.AllowedReponseContentTypes) > 0 && responseType != "" {
		for _, contentType := range p.AllowedReponseContentTypes {
			contentType = strings.TrimSpace(contentType)

			if contentType == responseType {
				return true
			}
		}
		return false
	}
	return true
}

// allowed returns whether the specified URL is on the whitelist of remote hosts.
func (p *Proxy) allowed(u *url.URL) bool {
	if len(p.Whitelist) != 0 {
		for _, host := range p.Whitelist {
			if u.Host == host {
				return true
			}
			if strings.HasPrefix(host, "*.") && strings.HasSuffix(u.Host, host[2:]) {
				return true
			}
		}
		return false
	}

	if len(p.Blacklist) != 0 {

		for _, iprange := range p.Blacklist {
			iprange := strings.TrimSpace(iprange)
			_, ipnet, err := net.ParseCIDR(iprange)

			if err != nil {
				p.Logger.Errorf("Error when reading the blacklist element [%s]. Error [%s] ", iprange, err.Error())
				continue
			}

			var hostIpAddress net.IP

			host := u.Host

			if host == "localhost" {
				host = "127.0.0.1"
			}

			if !strings.Contains(host, ":") {
				hostIpAddress = net.ParseIP(host)
			} else {
				h, _, err := net.SplitHostPort(host)

				if err != nil {
					return false
				}

				hostIpAddress = net.ParseIP(h)
			}

			if ipnet.Contains(hostIpAddress) {
				return false
			}
		}
	}

	return true
}

// check304 checks whether we should send a 304 Not Modified in response to
// req, based on the response resp.  This is determined using the last modified
// time and the entity tag of resp.
func check304(req *http.Request, headers http.Header) bool {
	// TODO(willnorris): if-none-match header can be a comma separated list
	// of multiple tags to be matched, or the special value "*" which
	// matches all etags
	etag := headers.Get("Etag")
	if etag != "" && etag == req.Header.Get("If-None-Match") {
		return true
	}

	lastModified, err := time.Parse(time.RFC1123, headers.Get("Last-Modified"))
	if err != nil {
		return false
	}
	ifModSince, err := time.Parse(time.RFC1123, req.Header.Get("If-Modified-Since"))
	if err != nil {
		return false
	}
	if lastModified.Before(ifModSince) {
		return true
	}

	return false
}

// TransformingTransport is an implementation of http.RoundTripper that
// optionally transforms images using the options specified in the request URL
// fragment.
type TransformingTransport struct {
	// Transport is the underlying http.RoundTripper used to satisfy
	// non-transform requests (those that do not include a URL fragment).
	Transport http.RoundTripper

	// CachingClient is used to fetch images to be resized.  This client is
	// used rather than Transport directly in order to ensure that
	// responses are properly cached.
	CachingClient *http.Client

	Logger Logger
}

// RoundTrip implements the http.RoundTripper interface.
func (t *TransformingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Fragment == "" {
		// normal requests pass through
		t.Logger.Infof("fetching remote URL: %v", req.URL)
		return t.Transport.RoundTrip(req)
	}

	u := *req.URL
	u.Fragment = ""
	resp, err := t.CachingClient.Get(u.String())
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	opt := ParseOptions(req.URL.Fragment)
	img, err := Transform(b, opt)
	if err != nil {
		t.Logger.Errorf("error transforming image: %v", err)
		img = b
	}

	// replay response with transformed image and updated content length
	buf := new(bytes.Buffer)
	fmt.Fprintf(buf, "%s %s\n", resp.Proto, resp.Status)
	resp.Header.WriteSubset(buf, map[string]bool{"Content-Length": true})
	fmt.Fprintf(buf, "Content-Length: %d\n\n", len(img))
	buf.Write(img)

	return http.ReadResponse(bufio.NewReader(buf), req)
}
