package dnsclient

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/miekg/dns"
)

type DoHClient struct {
	config *Config
	client *http.Client
}

func newDoHClient(config *Config) *DoHClient {
	c := &DoHClient{config: config}
	c.client = &http.Client{Timeout: config.Timeout}
	return c
}

func newHTTPGetRequest(u *url.URL, dnsQuery []byte) (*http.Request, error) {
	q := u.Query()
	q.Set("dns", base64.URLEncoding.EncodeToString(dnsQuery))
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(context.Background(),
		http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-message")

	fmt.Println(u)
	fmt.Println(req)
	return req, nil
}

func newHTTPPostRequest(u *url.URL, dnsQuery []byte) (*http.Request, error) {
	reqBodyReader := bytes.NewReader(dnsQuery)
	req, err := http.NewRequestWithContext(context.Background(),
		http.MethodPost, u.String(), reqBodyReader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	return req, nil
}

/* (start dnsclient.Client interface) */

func (c *DoHClient) Config() *Config {
	return c.config
}

func (c *DoHClient) Exchange(req *dns.Msg) (*dns.Msg, error) {
	var httpReq *http.Request
	var err error

	// Per RFC 8484 (DNS Queries over HTTPS (DoH)), the query's ID SHOULD
	// be 0.
	req.Id = 0
	msg, err := req.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to create DNS request %w", err)
	}

	baseURL := &url.URL{
		Scheme: "https",
		Host:   c.config.Server,
		Path:   c.config.HTTPEndpoint,
	}

	if c.config.HTTPUseGET {
		httpReq, err = newHTTPGetRequest(baseURL, msg)
	} else {
		httpReq, err = newHTTPPostRequest(baseURL, msg)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("error making HTTPS request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading HTTPS response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTPS response returned an error: %v", resp.StatusCode)
	}

	var reply dns.Msg
	err = reply.Unpack(body)
	if err != nil {
		return nil, fmt.Errorf("failed to unpack DNS response message: %w", err)
	}

	return &reply, nil
}

func (c *DoHClient) Close() error {
	return nil
}

/* (end dnsclient.Client interface) */
