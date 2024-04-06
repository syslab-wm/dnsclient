package dnsclient

import (
	"errors"
	"fmt"
	"io"
	"log"

	"github.com/miekg/dns"
	"github.com/syslab-wm/netx"
)

type Do53Client struct {
	config *Config
	client *dns.Client
	conn   *dns.Conn
}

func newDo53Client(config *Config) *Do53Client {
	c := &Do53Client{config: config}

	c.client = &dns.Client{
		Net:     config.netString(),
		Timeout: config.Timeout,
	}
	return c
}

func (c *Do53Client) dial() error {
	var err error
	addr := netx.TryJoinHostPort(c.config.Server, DefaultDo53Port)
	log.Printf("making TCP connection to DNS server %s", addr)
	c.conn, err = c.client.Dial(addr)
	if err != nil {
		return fmt.Errorf("failed to connect to DNS server %s: %w", addr, err)
	}
	return nil
}

func (c *Do53Client) isConnected() bool {
	return c.conn != nil
}

func (c *Do53Client) exchangeUDP(req *dns.Msg) (*dns.Msg, error) {
	var err error
	var resp *dns.Msg
	// even though this is UDP, from an API perspective, we still have to call
	// dial.
	if !c.isConnected() {
		err = c.dial()
		if err != nil {
			return nil, err
		}
	}

	resp, _, err = c.client.ExchangeWithConn(req, c.conn)
	if err != nil {
		return nil, err
	}

	if resp.Truncated && !c.config.IgnoreTruncation {
		// TODO: we could first try a large UDP size before falling back to TCP
		config2 := c.config.dup()
		config2.TCP = true
		tcpClient := newDo53Client(config2)
		return tcpClient.Exchange(req)
	}

	return resp, nil
}

func (c *Do53Client) exchangeTCP(req *dns.Msg) (*dns.Msg, error) {
	var err error
	var reused bool
	var retried bool
	var resp *dns.Msg

reconnect:
	if !c.isConnected() {
		err = c.dial()
		if err != nil {
			return nil, err
		}
	} else {
		reused = true
	}

	resp, _, err = c.client.ExchangeWithConn(req, c.conn)
	if !c.config.KeepOpen {
		c.Close()
	}

	if err == nil {
		return resp, nil
	}

	if !errors.Is(err, io.EOF) {
		return nil, err
	}

	// The server closed the connection on us rather than returning a response
	c.Close()

	// If we were reusing an already established connection, try once to
	// reconnect and resend the query.
	if reused && !retried {
		retried = true
		goto reconnect
	}

	return nil, err
}

/* (start dnsclient.Client interface) */

func (c *Do53Client) Config() *Config {
	return c.config
}

func (c *Do53Client) Close() error {
	if c.conn == nil {
		return nil // XXX: should we instead return an error?
	}
	err := c.conn.Close()
	c.conn = nil
	return err
}

func (c *Do53Client) Exchange(req *dns.Msg) (*dns.Msg, error) {
	if c.config.TCP {
		return c.exchangeTCP(req)
	} else {
		return c.exchangeUDP(req)
	}
}

/* (end dnsclient.Client interface) */
