package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/syslab-wm/dnsclient"
	"github.com/syslab-wm/mu"
)

const usage = `Usage: dnsclient [options] QNAME

Perform a DNS query.

positional arguments:
  QNAME
    The query name (domainname) to resolve.

options:
  -help
    Display this usage statement and exit.
    
query options:
  -4
    Use IPv4 only

    Default: false

  -6
    Use IPv6 Only

    Default: false

  -adflag[=0|1]
    Sets the AD (authentic data) bit in the query.  This requests the
    server to validate the DNSSEC records.  If the server validated the
    records, it returns AD=1 in the response; if it cannot validate the records
    (or the records are invalid), the server returns AD=0.

    Default: 1

  -bufsize=B
    Set the UDP message buffer size advertised using EDNS0 t B bytes.  The maximum
    and minimum sizes of this buffer are 65535 and 0, respectively.  Values other
    than 0 will cause an EDNS query to be sent.

  -cdflag[=0|1]
    Sets (unsets) the CD (checking disabled) bit in the query.  The CD bit
    in a query indicates that non-DNSSEC-verified data is acceptable to the
    resolver sending the query.  Resolvers that perform DNSSEC-validation
    themselves should set the bit to reduce DNS latency time by allowing
    security aware servers to answer before they have resolved the validity of
    data.

    Default: 0

  -dnssec[=0|1]
    Request DNSSEC records be sent by setting the DNSSEC OK bit (DO) in the OPT
    record in the additional section of the query.

    Default: 0

  -https ENDPOINT
    Use DNS over HTTPS (DoH).  Th port number defaults to 443.  The HTTP POST
    request mode is used when sending the query.

    ENDPOINT is the HTTP endpoint in the query URI.  There is no standard value
    for ENDPOINT, though /dns-query is conventional.

    For example:

        dnsclient -server example.com -https /dnsquery foo.bar.example.com

    will use the URI https://example.com/dnsquery

  -https-get ENDPOINT
    Same as -https, except that the HTTP GET request mode is used when sending
    the query.

  -keepalive[=0|1]
    Send an EDNS Keepalive option.

    Default: 0

  -keepopen[=0|1]
    Keep the TCP socket open between queries, and reuse it rather than creating
    a new TCP socket for each lookup.

    Default: 0

  -ignore
    Ignore truncation in UDP responses instead of retrying with TCP.  By
    default, TCP retries are performed.

  -max-cnames N
    The maximum of number of CNAMEs to follow.

    Default: 0

  -nsid[=1|0]
    Include an EDNS name server ID request when sending a query.

    Default: 0

  -rdflag[=0|1]
    Toggle the RD (recursion desired) bit in the query.

    Default: 1

  -server SERVER
    The nameserver to query.  For Do53 and DoH, SERVER is of the form
    HOST[:PORT], where HOST may be hostname or IP address.  If PORT is not
    provided, then port 53 is used for Do53,  port 853 for DoT, and port 443
    for DoH.

    The default is the first nameserver in /etc/resolv.conf.

  -subnet ADDR
    Send an EDNS Client Subnet options with the specified IP address or network
    prefix.

  -tcp
    For Do53, use TCP.  The default is to use UDP.

  -timeout TIMEOUT
    The timeout for the DNS request (e.g. 500ms, 1.5s).

    Default: 5s

  -tls
    Use DNS over TLS (DoT).  When this option is in use, the port
    number defaults to 853.

  -type QTYPE
    The query type (e.g., A, AAAA, NS)

    Default: A

    In addition to the standard DNS queries, the tool also supports
    a few meta queries:

      @ips
        Get the IP addresses for the QNAME (performs both A and
        a AAAA queries).
        
      @nameservers
        Get the nameservers (their domainnames and IP addresses)
        that are responsible for QNAME.  This meta-query results
        in several NS, A, and AAAA queries.

      @services
        Enumerate the related services for QNAME.  This meta query
        uses the DNS Service Discovery (DNS-SD) set of DNS queries.

     Finally, a non-standard type can be specified by it's numeric value 
     as TYPE###, e.g.  -type TYPE234.


examples:
  $ ./dnsclient -https -type NS www.cs.wm.edu
`

type Options struct {
	// positional
	qname string
	// general query options
	four         bool
	six          bool
	adflag       bool
	bufsize      int
	cdflag       bool
	dnssec       bool
	https        string
	httpsGET     string
	httpEndpoint string // derived
	httpUseGET   bool   // derived
	ignore       bool
	maxCNAMEs    int
	nsid         bool
	rdflag       bool
	server       string
	subnet       string
	tcp          bool
	timeout      time.Duration
	tls          bool
	qtypeStr     string
	qtype        uint16 // derived
}

var metaQueries = map[string]bool{
	"@IPS":         true,
	"@NAMESERVERS": true,
	"@SERVICES":    true,
}

func printUsage() {
	fmt.Fprintf(os.Stderr, "%s", usage)
}

func parseOptions() *Options {
	var ok bool
	opts := Options{}

	flag.Usage = printUsage
	// general options
	flag.BoolVar(&opts.four, "4", false, "")
	flag.BoolVar(&opts.six, "6", false, "")
	flag.BoolVar(&opts.adflag, "adflag", true, "")
	flag.IntVar(&opts.bufsize, "bufsize", 0, "")
	flag.BoolVar(&opts.cdflag, "cdflag", false, "")
	flag.BoolVar(&opts.dnssec, "dnnsec", false, "")
	flag.StringVar(&opts.https, "https", "", "")
	flag.StringVar(&opts.httpsGET, "https-get", "", "")
	flag.BoolVar(&opts.ignore, "ignore", false, "")
	flag.IntVar(&opts.maxCNAMEs, "max-cnames", 0, "")
	flag.BoolVar(&opts.nsid, "nsid", false, "")
	flag.BoolVar(&opts.rdflag, "rdflag", true, "")
	flag.StringVar(&opts.server, "server", "", "")
	flag.StringVar(&opts.subnet, "subnet", "", "")
	flag.BoolVar(&opts.tcp, "tcp", false, "")
	flag.DurationVar(&opts.timeout, "timeout", dnsclient.DefaultTimeout, "")
	flag.BoolVar(&opts.tls, "tls", false, "")
	flag.StringVar(&opts.qtypeStr, "type", "A", "")

	flag.Parse()

	if flag.NArg() != 1 {
		mu.Fatalf("error: expected one positional argument but got %d", flag.NArg())
	}

	opts.qname = flag.Arg(0)

	if opts.four && opts.six {
		mu.Fatalf("error: can't specify both -4 and -6")
	}

	if opts.https != "" && opts.httpsGET != "" {
		mu.Fatalf("error: can't speicfy -https and -https-get together")
	}
	if opts.https != "" {
		opts.httpEndpoint = opts.https
	} else if opts.httpsGET != "" {
		opts.httpEndpoint = opts.httpsGET
		opts.httpUseGET = true
	}

	opts.qtypeStr = strings.ToUpper(opts.qtypeStr)
	if strings.HasPrefix(opts.qtypeStr, "@") {
		// a "meta-query"
		if !metaQueries[opts.qtypeStr] {
			mu.Fatalf("error: invalid (meta query) type %q", opts.qtypeStr)
		}
	} else if strings.HasPrefix(opts.qtypeStr, "TYPE") {
		// a query for a non-standard qtype
		i, err := strconv.ParseUint(opts.qtypeStr[4:], 10, 16)
		if err != nil {
			mu.Fatalf("error: invalid type %q", opts.qtypeStr)
		}
		opts.qtype = uint16(i)
	} else {
		opts.qtype, ok = dns.StringToType[opts.qtypeStr]
		if !ok {
			mu.Fatalf("error: invalid type %q", opts.qtypeStr)
		}
	}

	if opts.server == "" {
		conf, err := dns.ClientConfigFromFile("/etc/resolv.conf")
		if err != nil {
			mu.Fatalf("error: unable to retrieve default nameserver: %v", err)
		}
		opts.server = conf.Servers[0]
	}

	return &opts
}
