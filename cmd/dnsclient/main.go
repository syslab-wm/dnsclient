package main

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/syslab-wm/adt/set"
	"github.com/syslab-wm/dnsclient"
	"github.com/syslab-wm/functools"
	"github.com/syslab-wm/mu"
)

/* meta queries */

func doIPSMetaQuery(c dnsclient.Client, qname string) error {
	addrs, err := dnsclient.GetIPs(c, qname)
	if err != nil {
		return err
	}

	for _, addr := range addrs {
		fmt.Println(addr)
	}

	return nil
}

func doNameServersMetaQuery(c dnsclient.Client, qname string) error {
	nameServers, err := dnsclient.GetNameServers(c, qname)
	if err != nil {
		return err
	}

	for _, nameServer := range nameServers {
		strAddrs := functools.Map[netip.Addr, string](nameServer.Addrs, func(addr netip.Addr) string {
			return fmt.Sprintf("%v", addr)
		})
		fmt.Printf("%s: %s\n", nameServer.Name, strings.Join(strAddrs, " "))
	}

	return nil
}

func doServicesMetaQuery(c dnsclient.Client, qname string) error {
	browsers, _ := dnsclient.GetAllServiceBrowserDomains(c, qname)
	if browsers != nil {
		fmt.Printf("Service Browser Domains:\n")
		for _, browser := range browsers {
			fmt.Printf("\t%s\n", browser)
		}
	} else {
		// if we don't find any browsing domains, treat the original
		// domain as the browsing domain
		browsers = []string{qname}
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

	return nil
}

/* normal query */

func doQuery(c dnsclient.Client, qname string, qtype uint16) error {
	resp, err := dnsclient.Lookup(c, qname, qtype)
	if err != nil {
		return err
	}

	fmt.Printf("%v\n", resp)

	return nil
}

func main() {
	var err error

	opts := parseOptions()

	config := dnsclient.Config{
		AD:               opts.adflag,
		CD:               opts.cdflag,
		DO:               opts.dnssec,
		HTTPEndpoint:     opts.httpEndpoint,
		HTTPUseGET:       opts.httpUseGET,
		IgnoreTruncation: opts.ignore,
		MaxCNAMEs:        opts.maxCNAMEs,
		NSID:             opts.nsid,
		RD:               opts.rdflag,
		Server:           opts.server,
		TCP:              opts.tcp,
		Timeout:          opts.timeout,
		UDPBufSize:       opts.bufsize,
		TLS:              opts.tls,
	}

	c, err := dnsclient.New(&config)
	if err != nil {
		mu.Fatalf("error: can't create DNS client: %v", err)
	}

	switch opts.qtypeStr {
	case "@IPS":
		err = doIPSMetaQuery(c, opts.qname)
	case "@NAMESERVERS":
		err = doNameServersMetaQuery(c, opts.qname)
	case "@SERVICES":
		err = doServicesMetaQuery(c, opts.qname)
	default:
		err = doQuery(c, opts.qname, opts.qtype)
	}
	c.Close()

	if err != nil {
		mu.Fatalf("query failed: %v", err)
	}
}
