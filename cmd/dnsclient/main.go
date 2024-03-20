package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/syslab-wm/dnsclient"
	"github.com/syslab-wm/dnsclient/internal/defaults"
	"github.com/syslab-wm/mu"
)

const usage = `Usage: dnsclient [options] QNAME

Perform a DNS query.

positional arguments:
  QNAME
    The query name (domainname) to resolve.
    
general options:
  -proto PROTO
    The DNS protocol to use (case-insensitive).  Must be either:
      * Do53  
          Regular cleartext DNS (DNS-over-(Port)53)
      * DoT
          DNS-over-TLS
      * DoH
          DNS-over-HTTPS

    The default is Do53.

  -server SERVER
    The nameserver to query.  For Do53 and DoH, SERVER is of the form
    IP[:PORT].  If PORT is not provided, then port 53 is used for Do53
    and port 853 is used for DoT.  For DoH, SERVER is the URL of the
    DoH service.

    The default is to use CloudFlare's open resolver at 1.1.1.1
    (for DoH, the URL is https://cloudflare-dns.com/dns-query).

    Default: 1.1.1.1 (Cloudflare's open resolver)

  -qtype QTYPE
    The query type (e.g., A, AAAA, NS)

    Default: A

  -timeout TIMEOUT
    The timeout for the DNS request (e.g. 500ms, 1.5s).

    Default: 2s

  -max-cnames N
    The maximum of number of CNAMEs to follow.

    Default: 0

  -dnssec
    Request DNSSEC records be sent by setting the DNSSEC OK bit (DO) in the OPT
    record in the additional section of the query.

  -help
    Display this usage statement and exit.

Do53-specific options:
  -tcp
    For Do53, use TCP instead of UDP.

  -retry-with-tcp
    For Do53 using UDP, if the DNS response is truncated, then
    re-issue the query over TCP.


examples:
  $ ./dnsclient -proto doh -qtype NS www.cs.wm.edu
`

type Options struct {
	// positional
	qname string
	// general options
	proto     string
	server    string
	qtypeStr  string
	qtype     uint16 // derived
	timeout   time.Duration
	maxCNAMEs int
	dnssec    bool
	// do53-specific options
	tcp          bool
	retryWithTCP bool
}

func printUsage() {
	fmt.Fprintf(os.Stderr, "%s", usage)
}

func tryAddDefaultPort(server string, port string) (string, error) {
	_, _, err := net.SplitHostPort(server)
	if err == nil {
		return server, nil
	}

	server1 := fmt.Sprintf("%s:%s", server, port)
	_, _, err = net.SplitHostPort(server1)
	if err == nil {
		return server1, nil
	}

	return "", fmt.Errorf("invalid server name %q", server)
}

func parseOptions() *Options {
	var err error
	var ok bool
	options := Options{}

	flag.Usage = printUsage
	// general options
	flag.StringVar(&options.proto, "proto", "do53", "")
	flag.StringVar(&options.server, "server", "", "")
	flag.StringVar(&options.qtypeStr, "qtype", "A", "")
	flag.DurationVar(&options.timeout, "timeout", defaults.Timeout, "")
	flag.IntVar(&options.maxCNAMEs, "max-cnames", defaults.MaxCNAMEs, "")
	flag.BoolVar(&options.dnssec, "dnssec", false, "")
	// do53-specific options
	flag.BoolVar(&options.tcp, "tcp", false, "")
	flag.BoolVar(&options.retryWithTCP, "retry-with-tcp", false, "")

	flag.Parse()

	if flag.NArg() != 1 {
		mu.Fatalf("error: expected one positional argument but got %d", flag.NArg())
	}

	options.qname = flag.Arg(0)

	options.proto = strings.ToLower(options.proto)
	if options.proto != "do53" && options.proto != "dot" && options.proto != "doh" {
		mu.Fatalf("error: unrecognized proto %q: must be either \"do53\", \"dot\", or \"doh\"", options.proto)
	}

	options.qtypeStr = strings.ToUpper(options.qtypeStr)
	options.qtype, ok = dns.StringToType[options.qtypeStr]
	if !ok {
		mu.Fatalf("error: invalid qtype %q", options.qtypeStr)
	}

	if options.proto == "do53" {
		if options.tcp && options.retryWithTCP {
			mu.Fatalf("error: can't specify both -tcp and -retry-with-tcp")
		}

		if options.server == "" {
			options.server = defaults.Do53Server
		} else {
			options.server, err = tryAddDefaultPort(options.server, defaults.Do53Port)
			if err != nil {
				mu.Fatalf("error: %v", err)
			}
		}
	}

	if options.proto != "do53" {
		if options.tcp {
			mu.Fatalf("error: -tcp is only valid for -proto do53")
		}
		if options.retryWithTCP {
			mu.Fatalf("error: -retry-with-tcp is only valid for -proto do53")
		}
	}

	if options.proto == "dot" {
		if options.server == "" {
			options.server = defaults.DoTServer
		} else {
			options.server, err = tryAddDefaultPort(options.server, defaults.DoTPort)
			if err != nil {
				mu.Fatalf("error: %v", err)
			}
		}
	}

	if options.proto == "doh" {
		if options.server == "" {
			options.server = defaults.DoHURL
		}
		// TODO: parse the options.server URL to make sure it is a valid HTTPS url
	}

	return &options
}

func main() {
	var c dnsclient.Client

	options := parseOptions()
	baseConfig := dnsclient.Config{
		RecursionDesired: true,
		Timeout:          options.timeout,
		MaxCNAMEs:        options.maxCNAMEs,
		DNSSEC:           options.dnssec,
	}

	switch options.proto {
	case "do53":
		config := &dnsclient.Do53Config{
			Config:       baseConfig,
			UseTCP:       options.tcp,
			RetryWithTCP: options.retryWithTCP,
			Server:       options.server,
		}
		c = dnsclient.NewDo53Client(config)
	case "dot":
		config := &dnsclient.DoTConfig{
			Config: baseConfig,
			Server: options.server,
		}
		c = dnsclient.NewDoTClient(config)
	case "doh":
		config := &dnsclient.DoHConfig{
			Config: baseConfig,
			URL:    options.server,
		}
		c = dnsclient.NewDoHClient(config)
	default:
		mu.BUG("invalid proto %q", options.proto)
	}

	err := c.Dial()
	if err != nil {
		mu.Fatalf("failed to connect to DNS server: %v", err)
	}
	defer c.Close()

	//resp, err := c.Query(options.qname, options.qtype)
	resp, err := dnsclient.Query(c, options.qname, options.qtype)
	if err != nil {
		mu.Fatalf("query failed: %v", err)
	}

	fmt.Printf("%v\n", resp)
}
