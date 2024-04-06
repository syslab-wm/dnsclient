package dnsclient

type Error struct{ err string }

func (e *Error) Error() string {
	if e == nil {
		return "dnsclient: <nil>"
	}
	return "dnsclient: " + e.err
}

var (
	ErrRcode             error = &Error{err: "response rcode is not success"} // DNS response's rcode is something other than Sucess
	ErrMissingAnswer     error = &Error{err: "response is missing an answer"} // the DNS response has a Success rcode but does not include an answer to the query
	ErrMismatchingAnswer error = &Error{err: "response has an answer that matches neither the qname nor one of its aliases"}
	ErrInvalidCNAMEChain error = &Error{err: "response contains an invalid CNAME chain"}
	ErrMaxCNAMEs         error = &Error{err: "query followed max number of CNAMEs"}
	ErrBadAnswer         error = &Error{err: "response has an answer the data does not conform to the RR type"}
)
