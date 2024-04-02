package dnsclient

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"

	"github.com/miekg/dns"
	"github.com/syslab-wm/dnsclient/internal/netx"
)

type DoTClient struct {
	config    *Config
	tlsConfig *tls.Config // XXX probably not needed, as dns.Client already has this field
	client    *dns.Client
	conn      *dns.Conn
}

func newDoTClient(config *Config) *DoTClient {
	c := &DoTClient{config: config}
	c.client = &dns.Client{
		Net:     config.netString(),
		Timeout: config.Timeout,
	}
	return c
}

func (c *DoTClient) dial() error {
	var err error
	addr := netx.TryAddPort(c.config.Server, DefaultDoTPort)
	log.Printf("connecting to DNS server %s", addr)
	c.conn, err = c.client.Dial(addr)
	if err != nil {
		return fmt.Errorf("failed to connect to DNS server %s: %w", addr, err)
	}
	return nil
}

func (c *DoTClient) isConnected() bool {
	return c.conn != nil
}

/* (start dnsclient.Client interface) */

func (c *DoTClient) Config() *Config {
	return c.config
}

func (c *DoTClient) Exchange(req *dns.Msg) (*dns.Msg, error) {
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
	if err == nil {
		return resp, nil
	}

	if !errors.Is(err, io.EOF) {
		return nil, err
	}

	c.Close()

	// We were reusing an already established connection and the server
	// closed the connection on us when trying to make this last query.
	// In this case, try once to reconnect and resend the query.
	if reused && !retried {
		retried = true
		goto reconnect
	}

	return nil, err
}

func (c *DoTClient) Close() error {
	if c.conn == nil {
		return nil // XXX: should we instead return an error?
	}
	err := c.conn.Close()
	c.conn = nil
	return err
}

/* (end dnsclient.Client interface) */
