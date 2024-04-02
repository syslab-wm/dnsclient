package msgutil

import (
	"net"
	"net/netip"

	"github.com/miekg/dns"
	"github.com/syslab-wm/dnsclient/internal/netx"
	"github.com/syslab-wm/mu"
)

func AddNSIDOption(m *dns.Msg) {
	opt := m.IsEdns0()
	if opt == nil {
		m.SetEdns0(4096, false)
	}
	e := &dns.EDNS0_NSID{
		Code: dns.EDNS0NSID,
	}
	opt.Option = append(opt.Option, e)
}

func AddClientSubnetOption(m *dns.Msg, addr netip.Addr) {
	opt := m.IsEdns0()
	if opt == nil {
		m.SetEdns0(4096, false)
	}

	e := &dns.EDNS0_SUBNET{
		Code: dns.EDNS0SUBNET,
	}

	if addr.Is4() {
		e.Family = 1
		e.SourceNetmask = net.IPv4len * 8
	} else if addr.Is6() {
		e.Family = 2
		e.SourceNetmask = net.IPv6len * 8
	} else {
		mu.Panicf("netip.Addr %v is neither a valid IPv4 nor IPv6 address", addr)
	}

	e.Address = netx.AddrAsIP(addr) // convert netip.Addr to net.IP
	opt.Option = append(opt.Option, e)
}