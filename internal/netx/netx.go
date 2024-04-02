package netx

import (
	"net"
	"net/netip"

	"github.com/syslab-wm/mu"
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

// IsIPv4 returns true iff the addr string represents an IPv4 address.
func IsIPv4(s string) bool {
	addr, err := netip.ParseAddr(s)
	return err == nil && addr.Is4()
}

// IsIPv6 returns true iff the addr string represents an IPv6 address.
func IsIPv6(s string) bool {
	addr, err := netip.ParseAddr(s)
	return err == nil && addr.Is6()
}

func AddrAsIP(addr netip.Addr) net.IP {
	ip := net.ParseIP(addr.String())
	if ip == nil {
		mu.Panicf("can't convert netip.Addr (%v) as a netIP", addr)
	}
	return ip

}

func IPAsAddr(ip net.IP) netip.Addr {
	addr, err := netip.ParseAddr(ip.String())
	if err != nil {
		mu.Panicf("can't convert net.IP (%v) to a netip.Addr", ip)
	}
	return addr
}
