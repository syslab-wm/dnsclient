package msgutil

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/miekg/dns"
	"github.com/syslab-wm/dnsclient/internal/netx"
	"github.com/syslab-wm/mu"
)

func AddNSIDOption(m *dns.Msg) error {
	opt := m.IsEdns0()
	if opt == nil {
		return fmt.Errorf("Cannot add NSID option: message does not have an OPT RR")
	}
	e := &dns.EDNS0_NSID{
		Code: dns.EDNS0NSID,
	}
	opt.Option = append(opt.Option, e)
	return nil
}

func AddClientSubnetOption(m *dns.Msg, subnetAddr string) error {
	opt := m.IsEdns0()
	if opt == nil {
		return fmt.Errorf("Cannot add Client Subnet option: message does not have an OPT RR")
	}

	e := &dns.EDNS0_SUBNET{
		Code: dns.EDNS0SUBNET,
	}

	addr, err := netip.ParseAddr(subnetAddr)
	if err != nil {
		return fmt.Errorf("Cannot add Client Subnet option: invalid subnet %q", subnetAddr)
	}

	if addr.Is4() {
		e.Family = 1
		e.SourceNetmask = net.IPv4len * 8
	} else if addr.Is6() {
		e.Family = 2
		e.SourceNetmask = net.IPv6len * 8
	} else {
		mu.Panicf("netip.Addr %v (%q) is neither a valid IPv4 nor IPv6 address", addr, subnetAddr)
	}

	e.Address = netx.AddrAsIP(addr) // convert netip.Addr to net.IP
	opt.Option = append(opt.Option, e)
	return nil
}
