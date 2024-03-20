package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/syslab-wm/adt/set"
	"github.com/syslab-wm/dnsclient"
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

const (
	defaultDo53Server = "1.1.1.1:53"
	defaultDo53Port   = "53"
)

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
	opts := Options{}

	flag.Usage = printUsage
	// general options
	flag.StringVar(&opts.server, "server", defaultDo53Server, "")
	flag.BoolVar(&opts.tcp, "tcp", false, "")
	flag.DurationVar(&opts.timeout, "timeout", 2*time.Second, "")

	flag.Parse()

	if flag.NArg() != 1 {
		mu.Fatalf("error: expected one positional argument but got %d", flag.NArg())
	}

	opts.domain = flag.Arg(0)
	opts.server, err = tryAddDefaultPort(opts.server, defaultDo53Port)
	if err != nil {
		mu.Fatalf("error: %v", err)
	}

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

	/* TODO: need to distinguish errors from non domains found */
	browserDomains, err := dnsclient.GetAllServiceBrowserDomains(c, opts.domain)
	if err != nil {
		mu.Fatalf("QueryAllServiceBrowserDomains: %v", err)
	}

	fmt.Printf("Service Browser Domains:\n")
	for _, browser := range browserDomains {
		fmt.Printf("\t%s\n", browser)
	}

	serviceSet := set.New[string]()
	for _, browser := range browserDomains {
		services, err := dnsclient.EnumerateServices(c, browser)
		if err != nil {
			continue
		}
		serviceSet.Add(services...)
	}

	for _, service := range serviceSet.Items() {
		fmt.Printf("\t%s\n", service)
	}

	/*

	   instanceSet = set.New[string]()
	   for _, service := range serviceSet.Items() {
	       instances, err := dnsclient.EnumerateServiceInstances(c,) ([]string, error)
	       if err != nil {
	           continue
	       }
	       instanceSet.Add(services...)
	   }


	   for _, instance := range instanceSet.Items() {
	       info, err := QueryServiceInstanceInfo(c, ...)
	       if err != nil {
	           continue
	       }
	       fmt.Printf("%s: %v\n", instance, info)
	   }
	*/
}
