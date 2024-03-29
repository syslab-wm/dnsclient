package netx

import (
	"net"
)

// HostPort returns whether addr includes a port number (i.e.,
// is of the form HOST:PORT).
func HasPort(addr string) bool {
	_, _, err := net.SplitHostPort(addr)
	return err == nil
}

// TryAddPort checks whether the server string already has a port (i.e.,
// ends with ':<PORT>'.  If it does, thn the function simply returns
// that string.  If it does not, the returns th serve string with
// th port appended.
func TryAddPort(server string, port string) string {
	if HasPort(server) {
		return server
	}
	return net.JoinHostPort(server, port)
}
