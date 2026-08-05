// Package webclient wraps net/http with the limits an OSINT scanner needs:
// bounded concurrency, capped response bodies, and a redirect policy that
// records where it ended up.
package webclient

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

// DefaultUserAgent mimics a mainstream browser. Several SaaS login pages serve
// a different body — or a bot interstitial — to obviously automated clients,
// which would break body matching.
const DefaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:129.0) Gecko/20100101 Firefox/129.0"

// maxBodyBytes caps how much of a response is read. Signature markers appear in
// the first few KB of a page; reading more only costs time and memory.
const maxBodyBytes = 512 << 10

// Response is a fetched HTTP response with its body already read.
type Response struct {
	// URL is the final URL after any redirects.
	URL string
	// RequestedURL is the URL originally asked for.
	RequestedURL string
	Status       int
	Body         string
	// Redirected reports whether the request moved.
	Redirected bool
}

// Client performs rate-limited HTTP GETs.
type Client struct {
	hc        *http.Client
	sem       chan struct{}
	userAgent string
	// requests is a pointer so that clients derived for slow endpoints can
	// share one counter, keeping the scan statistics complete.
	requests *atomic.Int64
}

// Options configures a Client.
type Options struct {
	// Timeout bounds a whole request including redirects. Defaults to 10s.
	Timeout time.Duration
	// Concurrency caps simultaneous requests. Defaults to 16, which is polite
	// enough not to look like an attack against any single vendor.
	Concurrency int
	// UserAgent overrides DefaultUserAgent.
	UserAgent string
	// InsecureTLS disables certificate verification. Some vendor tenant
	// endpoints present mismatched certificates for nonexistent tenants; enable
	// only when that is costing you detections.
	InsecureTLS bool
}

// New builds a Client from opts. Proxies are honoured through the standard
// HTTP_PROXY, HTTPS_PROXY and NO_PROXY environment variables.
func New(opts Options) *Client {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	conc := opts.Concurrency
	if conc <= 0 {
		conc = 16
	}
	ua := opts.UserAgent
	if ua == "" {
		ua = DefaultUserAgent
	}

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   timeout,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: opts.InsecureTLS, //nolint:gosec // opt-in, documented
			MinVersion:         tls.VersionTLS12,
		},
	}

	return &Client{
		hc: &http.Client{
			Transport: transport,
			Timeout:   timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return fmt.Errorf("stopped after 5 redirects")
				}
				return nil
			},
		},
		sem:       make(chan struct{}, conc),
		userAgent: ua,
		requests:  new(atomic.Int64),
	}
}

// Requests reports how many HTTP requests have been issued.
func (c *Client) Requests() int { return int(c.requests.Load()) }

// Derive returns a client with its own timeout and concurrency that shares this
// client's request counter. Endpoints with unusual latency — crt.sh being the
// motivating case — need their own budget without their traffic disappearing
// from the scan statistics.
func (c *Client) Derive(opts Options) *Client {
	d := New(opts)
	d.requests = c.requests
	return d
}

// Get fetches rawURL and returns the response with its body read and capped.
func (c *Client) Get(ctx context.Context, rawURL string) (*Response, error) {
	return c.do(ctx, http.MethodGet, rawURL, "", "", nil)
}

// Post sends body to rawURL. Used for the handful of discovery endpoints that
// are SOAP or JSON APIs rather than plain pages.
func (c *Client) Post(ctx context.Context, rawURL, contentType, body string, headers map[string]string) (*Response, error) {
	return c.do(ctx, http.MethodPost, rawURL, contentType, body, headers)
}

func (c *Client) do(ctx context.Context, method, rawURL, contentType, body string, headers map[string]string) (*Response, error) {
	select {
	case c.sem <- struct{}{}:
		defer func() { <-c.sem }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, reader)
	if err != nil {
		return nil, fmt.Errorf("building request for %s: %w", rawURL, err)
	}
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,application/json;q=0.8,*/*;q=0.7")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	c.requests.Add(1)
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching %s: %w", rawURL, err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil && len(raw) == 0 {
		return nil, fmt.Errorf("reading body of %s: %w", rawURL, err)
	}

	final := resp.Request.URL.String()
	return &Response{
		URL:          final,
		RequestedURL: rawURL,
		Status:       resp.StatusCode,
		Body:         string(raw),
		Redirected:   !strings.EqualFold(final, rawURL),
	}, nil
}
