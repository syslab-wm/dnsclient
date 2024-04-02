package dnsclient

import (
	"fmt"
	"net/netip"
	"time"
)

const (
	MinUDPBufSize = 0
	MaxUDPBufSize = 65535

	MinMaxCNAMEs = 0
	MaxMaxCNAMEs = 10

	DefaultDo53Port     = "53"
	DefaultDoTPort      = "853"
	DefaultDoQPort      = "853"
	DefaultHTTPEndpoint = "/dns-query"
	DefaultTimeout      = 5 * time.Second
	DefaultUDPBufSize   = 4096 // in the EDNS0 opt record
)

// This is configuration that applies to all typs of clients -- it deals purely
// with the handling of the DNS requests and responses
type Config struct {
	AD               bool
	CD               bool
	ClientSubnet     netip.Addr
	DO               bool // DNSSEC
	HTTPEndpoint     string
	HTTPUseGET       bool
	IgnoreTruncation bool
	IPv4Only         bool
	IPv6Only         bool
	KeepAlive        bool
	KeepOpen         bool
	MaxCNAMEs        int
	NSID             bool
	RD               bool
	Server           string
	TCP              bool
	Timeout          time.Duration
	UDPBufSize       int
	TLS              bool
}

func (cfg *Config) Validate() error {
	if cfg.UDPBufSize < MinUDPBufSize || cfg.UDPBufSize > MaxUDPBufSize {
		return fmt.Errorf("invalid UDPBufSize; must be %d <= B <= %d", MinUDPBufSize, MaxUDPBufSize)
	}

	if cfg.MaxCNAMEs < MinMaxCNAMEs || cfg.MaxCNAMEs > MaxMaxCNAMEs {
		return fmt.Errorf("invalid MaxCNAMES; must be %d <= B <= %d", MinMaxCNAMEs, MaxMaxCNAMEs)
	}

	if (cfg.HTTPEndpoint == "") && cfg.HTTPUseGET {
		return fmt.Errorf("HTTPEndpoint must be a non-empty string")
	}

	if (cfg.HTTPEndpoint != "") && cfg.TLS {
		return fmt.Errorf("Cannot specify both DoH and DoT")
	}

	return nil
}

func (cfg *Config) netString() string {
	net := "udp"
	if cfg.IPv4Only {
		net = "udp4"
	}
	if cfg.IPv6Only {
		net = "udp6"
	}

	if cfg.TCP {
		net = "tcp"
		if cfg.IPv4Only {
			net = "tcp4"
		}
		if cfg.IPv6Only {
			net = "tcp6"
		}
	}

	if cfg.TLS {
		net = "tcp-tls"
		if cfg.IPv4Only {
			net = "tcp4-tls"
		}
		if cfg.IPv6Only {
			net = "tcp6-tls"
		}
	}

	return net
}

func (cfg *Config) usesEDNS0() bool {
	// XXX: shoudl UDPBufSize be here?
	if cfg.DO || cfg.NSID || cfg.ClientSubnet.IsValid() || cfg.UDPBufSize > 0 {
		return true
	}

	return false
}

func (cfg *Config) dup() *Config {
	c := *cfg
	// make a deep copy of the address
	c.ClientSubnet = netip.MustParseAddr(cfg.ClientSubnet.String())
	return &c
}
