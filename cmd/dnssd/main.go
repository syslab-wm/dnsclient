package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/syslab-wm/adt/set"
	"github.com/syslab-wm/dnsclient"
	"github.com/syslab-wm/dnsclient/internal/defaults"
	"github.com/syslab-wm/dnsclient/internal/netx"
	"github.com/syslab-wm/mu"
)

const usage = `Usage: dnssd [options] DOMAIN

Attempt to use DNS Service Discovery (DNS-SD) to enumerate the services and
service instances of a given domain.

positional arguments:
  DOMAIN
    The domain to enumerate services for
    
  -server SERVER
    The nameserver to query.  SERVER is of the form
    IP[:PORT].  If PORT is not provided, then port 53 is used.

    Default: 1.1.1.1:53 (Cloudflare's open resolver)

  -tcp
    Use TCP instead of UDP for issuing DNS queries.

  -timeout TIMEOUT
    The timeout for a DNS query (e.g. 500ms, 1.5s).

    Default: 2s

  -help
    Display this usage statement and exit.

examples:
  $ ./dnssd www.cs.wm.edu
`

type Options struct {
	// positional
	domain string
	// options
	server  string
	tcp     bool
	timeout time.Duration
}

func printUsage() {
	fmt.Fprintf(os.Stderr, "%s", usage)
}

func tryAddDefaultPort(server string, port string) string {
	if netx.HasPort(server) {
		return server
	}
	return net.JoinHostPort(server, port)
}

func parseOptions() *Options {
	opts := Options{}

	flag.Usage = printUsage
	// general options
	flag.StringVar(&opts.server, "server", defaults.Do53Server, "")
	flag.BoolVar(&opts.tcp, "tcp", false, "")
	flag.DurationVar(&opts.timeout, "timeout", defaults.Timeout, "")

	flag.Parse()

	if flag.NArg() != 1 {
		mu.Fatalf("error: expected one positional argument but got %d", flag.NArg())
	}

	opts.domain = flag.Arg(0)
	opts.server = tryAddDefaultPort(opts.server, defaults.Do53Port)

	return &opts
}

func main() {
	var c dnsclient.Client

	opts := parseOptions()

	config := &dnsclient.Do53Config{
		Config: dnsclient.Config{
			RecursionDesired: true,
			Timeout:          opts.timeout,
		},
		UseTCP: opts.tcp,
		Server: opts.server,
	}
	c = dnsclient.NewDo53Client(config)

	err := c.Dial()
	if err != nil {
		mu.Fatalf("failed to connect to DNS server: %v", err)
	}
	defer c.Close()

	browsers, err := dnsclient.GetAllServiceBrowserDomains(c, opts.domain)
	if browsers != nil {
		fmt.Printf("Service Browser Domains:\n")
		for _, browser := range browsers {
			fmt.Printf("\t%s\n", browser)
		}
	} else {
		// if we don't find any browsing domains, treat the original
		// domain as the browsing domain
		browsers = []string{opts.domain}
	}

	serviceSet := set.New[string]()
	for _, browser := range browsers {
		services, err := dnsclient.GetServices(c, browser)
		if err != nil {
			continue
		}
		serviceSet.Add(services...)
	}

	services := serviceSet.Items()

	if len(services) != 0 {
		fmt.Printf("Services:\n")
		for _, service := range serviceSet.Items() {
			fmt.Printf("\t%s\n", service)
			instances, err := dnsclient.GetServiceInstances(c, service)
			if err != nil {
				continue
			}
			for _, instance := range instances {
				fmt.Printf("\t\t%s\n", instance)
				info, err := dnsclient.GetServiceInstanceInfo(c, instance)
				if err != nil {
					continue
				}
				fmt.Printf("\t\t\t%v\n", info)
			}
		}
	}
}
