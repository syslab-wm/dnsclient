package dnsclient

import (
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/miekg/dns"
	"github.com/syslab-wm/dnsclient/internal/msgutil"
	"github.com/syslab-wm/functools"
	"github.com/syslab-wm/mu"
)

// This is configuration that applies to all typs of clients -- it deals purely
// with the handling of the DNS requests and responses
type Config struct {
	IdFunc           func() uint16
	RecursionDesired bool
	Timeout          time.Duration
	MaxCNAMEs        int
	DNSSEC           bool
}

type Client interface {
	GetConfig() *Config
	Dial() error
	Close() error
	Query(name string, qtype uint16) (*dns.Msg, error)
}

type DNSErr int

const (
	DNSErrRcodeNotSuccess DNSErr = iota
	DNSErrMissingAnswer
	DNSErrInvalidAnswer
	DNSErrInvalidCNAMEChain
	DNSErrMaxCNAMEs
)

var DNSErrToString = map[DNSErr]string{
	DNSErrRcodeNotSuccess:   "RCODE was not SUCCESS",
	DNSErrMissingAnswer:     "DNS response does not answer the query",
	DNSErrInvalidAnswer:     "DNS response has an answer that matches neither the qname nor one of its aliases",
	DNSErrInvalidCNAMEChain: "DNS response contains an invalid CNAME chain",
	DNSErrMaxCNAMEs:         "query followed max number of CNAMEs",
}

type DNSError struct {
	reason   DNSErr
	response *dns.Msg
}

func NewDNSError(reason DNSErr, response *dns.Msg) *DNSError {
	return &DNSError{reason: reason, response: response}
}

func (e *DNSError) Error() string {
	if e.reason == DNSErrRcodeNotSuccess {
		return fmt.Sprintf("%s: %s (rcode=%d)", DNSErrToString[e.reason],
			dns.RcodeToString[e.response.Rcode], e.response.Rcode)
	}
	return fmt.Sprintf("%s", DNSErrToString[e.reason])
}

func NewMsg(config *Config, name string, qtype uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.Id = dns.Id()
	m.RecursionDesired = config.RecursionDesired
	if config.DNSSEC {
		m.SetEdns0(4096, true)
	}
	// XXX: set other header bits?
	return m
}

func query(c Client, name string, qtype uint16) (*dns.Msg, error) {
	resp, err := c.Query(name, qtype)
	if err != nil {
		return nil, err
	}
	if resp.Rcode != dns.RcodeSuccess {
		return nil, NewDNSError(DNSErrRcodeNotSuccess, resp)
	}
	return resp, nil
}

// Return an error if:
//   - there was some sort of network error
//   - DNS returned a valid response but Rcode is not SUCCESS
//   - DNS returned Rcode SUCCESS, but the response doesn't have the record we requested
//   - The config is set to follow CNAMES, but we encountered some sort of
//     malformed CNAME (namely, an invalid CNAME chain in an answer; this should be rare)
//   - The config is set to follow CNAMES, and we reached MaxCNAMEs
//     without getting an answer
//
// In other words, if we ergonomics are such that if the caller invokes:
//
//	resp, err != dnsquery.Query(c, name, type)
//
// Then err == nil iff resp actually returns a positive response for the query.
// If err != nil, then err will store the response message (if there was one)
// as well as indicate the reason for the failure (basically, one of the above
// categories above.  The whole point is to make it so the caller doesn't have
// to inspect the msg to see if the query succeeded; if the caller wants the
// nitty-gritty details of why the query didn't get an answer, it can inspect
// the error value.
func Query(c Client, name string, qtype uint16) (*dns.Msg, error) {
	var err error
	var cnames []*dns.CNAME
	var resp *dns.Msg
	config := c.GetConfig()

	name = dns.Fqdn(name)
	for i := 0; i <= config.MaxCNAMEs; i++ {
		resp, err = query(c, name, qtype)
		if err != nil {
			return nil, err
		}

		// gather all RRs that are of the qtype
		var ans []dns.RR
		for _, rr := range resp.Answer {
			if rr.Header().Rrtype == qtype {
				ans = append(ans, rr)
				// if such an RR matches on the name we'r searching for, it's a
				// direct hit
				if rr.Header().Name == name {
					return resp, nil
				}
			}
		}

		// if we're following CNAMEs, get all of the CNAMES from the answer
		cnames = msgutil.CollectRRs[*dns.CNAME](resp.Answer)
		if len(cnames) == 0 {
			return nil, NewDNSError(DNSErrMissingAnswer, resp)
		}

		// validate that the CNAMEs form a chain
		ordered := msgutil.OrderCNAMEs(cnames)
		if !ordered {
			return nil, NewDNSError(DNSErrInvalidCNAMEChain, resp)

		}
		// the head of the chain must match the name we're searching for
		if cnames[0].Hdr.Name != name {
			return nil, NewDNSError(DNSErrInvalidCNAMEChain, resp)
		}

		// is the last CNAME in chain an alias for one of the RRs that are of
		// the qtype we're searching for.  If so, success.
		lastCNAME := cnames[len(cnames)-1]
		for _, rr := range ans {
			if lastCNAME.Target == rr.Header().Name {
				return resp, nil
			}
		}

		if len(ans) > 0 {
			// a really weird case: the resp has record types we're searching
			// for, but not for an alias of a name we're searching for
			return nil, NewDNSError(DNSErrInvalidAnswer, resp)
		}

		// update the domain name to query
		name = dns.Fqdn(cnames[len(cnames)-1].Target)
	}

	if len(cnames) > 0 {
		return nil, NewDNSError(DNSErrMaxCNAMEs, resp)
	}

	return nil, NewDNSError(DNSErrMissingAnswer, resp)
}

func GetIP4s(c Client, name string) ([]netip.Addr, error) {
	resp, err := Query(c, name, dns.TypeA)
	if err != nil {
		return nil, err
	}
	addrRecs := msgutil.CollectARecords(resp.Answer)
	if len(addrRecs) == 0 {
		mu.BUG("expected successful DNS query to return one or more A records, but returned none")
	}
	return functools.Map(addrRecs, func(a *msgutil.AddressRecord) netip.Addr {
		return a.Addr
	}), nil
}

func GetIP6s(c Client, name string) ([]netip.Addr, error) {
	resp, err := Query(c, name, dns.TypeAAAA)
	if err != nil {
		return nil, err
	}
	addrRecs := msgutil.CollectAAAARecords(resp.Answer)
	if len(addrRecs) == 0 {
		mu.BUG("expected succssful DNS query to return one ore more AAAA records, but returned none")
	}
	return functools.Map(addrRecs, func(a *msgutil.AddressRecord) netip.Addr {
		return a.Addr
	}), nil
}

func GetIPs(c Client, name string) ([]netip.Addr, error) {
	var addrs []netip.Addr
	var errs []error

	a, err := GetIP4s(c, name)
	if err != nil {
		errs = append(errs, err)
	} else {
		addrs = append(addrs, a...)
	}

	a, err = GetIP6s(c, name)
	if err != nil {
		errs = append(errs, err)
	} else {
		addrs = append(addrs, a...)
	}

	if len(addrs) > 0 {
		return addrs, nil
	}

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}

	mu.BUG("nither addresses nor errors")
	return nil, nil
}

type NameServer struct {
	Name  string
	Addrs []netip.Addr
}

func GetNameServers(c Client, name string) ([]*NameServer, error) {
	resp, err := Query(c, name, dns.TypeNS)
	if err != nil {
		return nil, err
	}

	fmt.Printf("A\n%v\n", resp)
	return nil, nil
}
