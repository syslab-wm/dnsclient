package dnsclient

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"

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

func (c *DoHClient) Config() *Config {
	return c.config
}

func (c *DoHClient) Close() error {
	return nil
}

func newHTTPPostRequest(url string, postData []byte) (*http.Request, error) {
	reqBodyReader := bytes.NewReader(postData)
	req, err := http.NewRequestWithContext(context.Background(),
		http.MethodPost, url, reqBodyReader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	return req, nil
}

func (c *DoHClient) Query(req *dns.Msg) (*dns.Msg, error) {
	msg, err := req.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to create DNS request %w", err)
	}

	url := fmt.Sprintf("https:%s%s", c.config.Server, c.config.HTTPEndpoint)
	post, err := newHTTPPostRequest(url, msg)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	resp, err := c.client.Do(post)
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
