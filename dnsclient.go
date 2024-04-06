package dnsclient

import (
	"github.com/miekg/dns"
	"github.com/syslab-wm/dnsclient/msgutil"
	"github.com/syslab-wm/mu"
)

type Client interface {
	Config() *Config
	Exchange(req *dns.Msg) (*dns.Msg, error)
	Close() error
}

func New(config *Config) (Client, error) {
	err := config.Validate()
	if err != nil {
		return nil, err
	}
	if config.HTTPEndpoint != "" {
		return newDoHClient(config), nil
	}
	if config.TLS {
		return newDoTClient(config), nil
	}
	return newDo53Client(config), nil
}

func NewMsg(config *Config, name string, qtype uint16) *dns.Msg {
	var bufsize int

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)

	m.Id = dns.Id()
	m.RecursionDesired = config.RD
	m.AuthenticatedData = config.AD
	m.CheckingDisabled = config.CD

	if config.UDPBufSize == 0 {
		bufsize = DefaultUDPBufSize
	} else {
		bufsize = config.UDPBufSize
	}

	if config.usesEDNS0() {
		m.SetEdns0(uint16(bufsize), config.DO)
		if config.NSID {
			msgutil.AddEDNS0NSID(m)
		}
		if config.ClientSubnet.IsValid() {
			msgutil.AddEDNS0Subnet(m, config.ClientSubnet)
		}
	}

	return m
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
func Exchange(c Client, req *dns.Msg) (*dns.Msg, error) {
	var err error
	var cnames []*dns.CNAME
	var resp *dns.Msg
	config := c.Config()
	qtype := req.Question[0].Qtype

	// if following CNAMES, req will change; thus, make a copy so it
	// doesn't affect the caller
	if config.MaxCNAMEs > 0 {
		req = req.Copy()
	}

	for i := 0; i <= config.MaxCNAMEs; i++ {
		resp, err = c.Exchange(req)
		if err != nil {
			return nil, err
		}
		if resp.Rcode != dns.RcodeSuccess {
			return resp, ErrRcode
		}

		// gather all RRs that are of the qtype
		var ans []dns.RR
		for _, rr := range resp.Answer {
			if rr.Header().Rrtype == qtype {
				ans = append(ans, rr)
				// if such an RR matches on the name we're searching for, it's a
				// direct hit
				if rr.Header().Name == req.Question[0].Name {
					return resp, nil
				}
			}
		}

		// get all of the CNAMES from the answer
		cnames = msgutil.CollectRRs[*dns.CNAME](resp.Answer)
		if len(cnames) == 0 {
			return resp, ErrMissingAnswer
		}

		// validate that the CNAMEs form a chain
		ordered := msgutil.OrderCNAMEs(cnames)
		if !ordered {
			return resp, ErrInvalidCNAMEChain

		}
		// the head of the chain must match the name we're searching for
		if cnames[0].Hdr.Name != req.Question[0].Name {
			return resp, ErrInvalidCNAMEChain
		}

		// is the last CNAME in the chain an alias for one of the RRs that are
		// of the qtype we're searching for.  If so, success.
		lastCNAME := cnames[len(cnames)-1]
		for _, rr := range ans {
			if lastCNAME.Target == rr.Header().Name {
				return resp, nil
			}
		}

		if len(ans) > 0 {
			// weird case: resp has record types we're searching
			// for, but not for an alias of a name we're searching for
			return resp, ErrMismatchingAnswer
		}

		// setup to repeat query on the last CNAME in the chain
		req.SetQuestion(dns.Fqdn(cnames[len(cnames)-1].Target), qtype)
	}

	if len(cnames) > 0 {
		return resp, ErrMaxCNAMEs
	}

	// UNREACHABLE
	mu.BUG("reached what should be unreachable code: req: %v, resp: %v", req, resp)
	return resp, ErrMissingAnswer
}

func Lookup(c Client, name string, qtype uint16) (*dns.Msg, error) {
	req := NewMsg(c.Config(), name, qtype)
	return Exchange(c, req)
}
