package dnsclient

import (
	"fmt"

	"github.com/miekg/dns"
)

type DNSErr int

const (
	DNSErrRcodeNotSuccess DNSErr = iota

	DNSErrMissingAnswer
	DNSErrInvalidAnswer
	DNSErrInvalidCNAMEChain
	DNSErrMaxCNAMEs

	DNSErrBadFormatAnswer
)

var DNSErrToString = map[DNSErr]string{
	DNSErrRcodeNotSuccess: "RCODE was not SUCCESS",

	DNSErrMissingAnswer:     "DNS response does not answer the query",
	DNSErrInvalidAnswer:     "DNS response has an answer that matches neither the qname nor one of its aliases",
	DNSErrInvalidCNAMEChain: "DNS response contains an invalid CNAME chain",
	DNSErrMaxCNAMEs:         "query followed max number of CNAMEs",

	DNSErrBadFormatAnswer: "DNS response has an answer where the data does not conform to the RR type",
}

type DNSError struct {
	Reason   DNSErr
	Response *dns.Msg // optional
}

func NewDNSError(reason DNSErr, response *dns.Msg) *DNSError {
	return &DNSError{Reason: reason, Response: response}
}

func (e *DNSError) Error() string {
	if e.Reason == DNSErrRcodeNotSuccess {
		return fmt.Sprintf("%s: %s (rcode=%d)", DNSErrToString[e.Reason],
			dns.RcodeToString[e.Response.Rcode], e.Response.Rcode)
	}
	return fmt.Sprintf("%s", DNSErrToString[e.Reason])
}
