package dnsclient

import (
	"fmt"
	"time"
)

const (
	MinUDPBufSize = 0
	MaxUDPBufSize = 65535

	MinMaxCNAMEs = 0
	MaxMaxCNAMEs = 10

	DefaultDo53Port     = "53"
	DefaultDoTPort      = "853"
	DefaultHTTPEndpoint = "/dns-query"
	DefaultTimeout      = 5 * time.Second
	DefaultUDPBufSize   = 4096 // in the EDNS0 opt record
)

// This is configuration that applies to all typs of clients -- it deals purely
// with the handling of the DNS requests and responses
type Config struct {
	AD               bool
	CD               bool
	DO               bool // DNSSEC
	HTTPEndpoint     string
	HTTPUseGET       bool
	IgnoreTruncation bool
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

func (config *Config) Validate() error {
	if config.UDPBufSize < MinUDPBufSize || config.UDPBufSize > MaxUDPBufSize {
		return fmt.Errorf("invalid UDPBufSize; must be %d <= B <= %d", MinUDPBufSize, MaxUDPBufSize)
	}

	if config.MaxCNAMEs < MinMaxCNAMEs || config.MaxCNAMEs > MaxMaxCNAMEs {
		return fmt.Errorf("invalid MaxCNAMES; must be %d <= B <= %d", MinMaxCNAMEs, MaxMaxCNAMEs)
	}

	if (config.HTTPEndpoint == "") && config.HTTPUseGET {
		return fmt.Errorf("HTTPEndpoint must be a non-empty string")
	}

	if (config.HTTPEndpoint != "") && config.TLS {
		return fmt.Errorf("Cannot specify both DoH and DoT")
	}

	return nil
}
