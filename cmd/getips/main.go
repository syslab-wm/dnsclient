package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/syslab-wm/dnsclient"
	"github.com/syslab-wm/mu"
)

const usage = `Usage: getips [options] DOMAINNAME

Get IPS (IPv4 and IPv6) for a given domainnam.

positional arguments:
  DOMAINNAME
    The domainname to rsolve

    
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

  -timeout TIMEOUT
    The timeout for the DNS request (e.g. 500ms, 1.5s).

    Default: 2s

  -max-cnames N
    The maximum of number of CNAMEs to follow.

    Default: 0

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

const (
	defaultDo53Server = "1.1.1.1:53"
	defaultDo53Port   = "53"
	defaultDoTServer  = "1.1.1.1:853"
	defaultDoTPort    = "853"
	defaultDoHURL     = "https://cloudflare-dns.com/dns-query"
	defaultTimeout    = 2 * time.Second
	defaultMaxCNAMEs  = 0
)

type Options struct {
	// positional
	domainname string
	// general options
	proto     string
	server    string
	timeout   time.Duration
	maxCNAMEs int
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
	options := Options{}

	flag.Usage = printUsage
	// general options
	flag.StringVar(&options.proto, "proto", "do53", "")
	flag.StringVar(&options.server, "server", "", "")
	flag.DurationVar(&options.timeout, "timeout", defaultTimeout, "")
	flag.IntVar(&options.maxCNAMEs, "max-cnames", defaultMaxCNAMEs, "")
	// do53-specific options
	flag.BoolVar(&options.tcp, "tcp", false, "")
	flag.BoolVar(&options.retryWithTCP, "retry-with-tcp", false, "")

	flag.Parse()

	if flag.NArg() != 1 {
		mu.Fatalf("error: expected one positional argument but got %d", flag.NArg())
	}

	options.domainname = flag.Arg(0)

	options.proto = strings.ToLower(options.proto)
	if options.proto != "do53" && options.proto != "dot" && options.proto != "doh" {
		mu.Fatalf("error: unrecognized proto %q: must be either \"do53\", \"dot\", or \"doh\"", options.proto)
	}

	if options.proto == "do53" {
		if options.tcp && options.retryWithTCP {
			mu.Fatalf("error: can't specify both -tcp and -retry-with-tcp")
		}

		if options.server == "" {
			options.server = defaultDo53Server
		} else {
			options.server, err = tryAddDefaultPort(options.server, defaultDo53Port)
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
			options.server = defaultDoTServer
		} else {
			options.server, err = tryAddDefaultPort(options.server, defaultDoTPort)
			if err != nil {
				mu.Fatalf("error: %v", err)
			}
		}
	}

	if options.proto == "doh" {
		if options.server == "" {
			options.server = defaultDoHURL
		}
		// TODO: parse the options.server URL to make sure it is a valid HTTPS url
	}

	return &options
}

func main() {
	var c dnsclient.Client

	options := parseOptions()

	switch options.proto {
	case "do53":
		config := &dnsclient.Do53Config{
			Config: dnsclient.Config{
				RecursionDesired: true,
				Timeout:          options.timeout,
				MaxCNAMEs:        options.maxCNAMEs,
			},
			UseTCP:       options.tcp,
			RetryWithTCP: options.retryWithTCP,
			Server:       options.server,
		}
		c = dnsclient.NewDo53Client(config)
	case "dot":
		config := &dnsclient.DoTConfig{
			Config: dnsclient.Config{
				RecursionDesired: true,
				Timeout:          options.timeout,
				MaxCNAMEs:        options.maxCNAMEs,
			},
			Server: options.server,
		}
		c = dnsclient.NewDoTClient(config)
	case "doh":
		config := &dnsclient.DoHConfig{
			Config: dnsclient.Config{
				RecursionDesired: true,
				Timeout:          options.timeout,
				MaxCNAMEs:        options.maxCNAMEs,
			},
			URL: options.server,
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

	addrs, err := dnsclient.GetIPs(c, options.domainname)
	if err != nil {
		mu.Fatalf("query failed: %v", err)
	}

	for _, addr := range addrs {
		fmt.Println(addr)
	}
}
