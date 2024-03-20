package dnsclient

import (
	"fmt"

	"github.com/miekg/dns"
	"github.com/syslab-wm/adt/set"
	"github.com/syslab-wm/functools"
)

/*
type ServiceBrowserDomain struct {
	Name      string // domainname
	IsDefault bool
	IsLegacy  bool
}

func (sbd *ServiceBrowserDomain) String() string {
	return fmt.Sprintf("{name: %q, default: %t, legacy: %t}", sbd.Name, sbd.IsDefault, sbd.IsLegacy)
}
*/

func GetServiceBrowserDomains(c Client, domain string) ([]string, error) {
	var sbds []string
	browserDomain := fmt.Sprintf("b._dns-sd._udp.%s", domain)
	resp, err := c.Query(browserDomain, dns.TypePTR)
	if err != nil {
		return nil, err
	}
	if resp.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("DNS query returned error: %s", dns.RcodeToString[resp.Rcode])
	}
	ptrRRs := functools.Filter(resp.Answer, func(rr dns.RR) bool {
		_, ok := rr.(*dns.PTR)
		return ok
	})
	if len(ptrRRs) == 0 {
		return nil, fmt.Errorf("DNS query did not return any PTR records")
	}
	for _, rr := range ptrRRs {
		ptr := rr.(*dns.PTR)
		sbds = append(sbds, ptr.Ptr)
	}
	return sbds, nil
}

func GetDefaultServiceBrowserDomain(c Client, domain string) (string, error) {
	browserDomain := fmt.Sprintf("db._dns-sd._udp.%s", domain)
	resp, err := c.Query(browserDomain, dns.TypePTR)
	if err != nil {
		return "", err
	}
	if resp.Rcode != dns.RcodeSuccess {
		return "", fmt.Errorf("DNS query returned error: %s", dns.RcodeToString[resp.Rcode])
	}
	ptrRRs := functools.Filter(resp.Answer, func(rr dns.RR) bool {
		_, ok := rr.(*dns.PTR)
		return ok
	})
	if len(ptrRRs) == 0 {
		return "", fmt.Errorf("DNS query did not return any PTR records")
	}
	if len(ptrRRs) > 1 {
		return "", fmt.Errorf("DNS query returned multiple PTR records")
	}

	ptr := ptrRRs[0].(*dns.PTR)
	return ptr.Ptr, nil
}

func GetLegacyServiceBrowserDomain(c Client, domain string) (string, error) {
	browserDomain := fmt.Sprintf("lb._dns-sd._udp.%s", domain)
	resp, err := c.Query(browserDomain, dns.TypePTR)
	if err != nil {
		return "", err
	}
	if resp.Rcode != dns.RcodeSuccess {
		return "", fmt.Errorf("DNS query returned error: %s", dns.RcodeToString[resp.Rcode])
	}
	ptrRRs := functools.Filter(resp.Answer, func(rr dns.RR) bool {
		_, ok := rr.(*dns.PTR)
		return ok
	})
	if len(ptrRRs) == 0 {
		return "", fmt.Errorf("DNS query did not return any PTR records")
	}
	if len(ptrRRs) > 1 {
		return "", fmt.Errorf("DNS query returned multiple PTR records")
	}

	ptr := ptrRRs[0].(*dns.PTR)
	return ptr.Ptr, nil
}

func GetAllServiceBrowserDomains(c Client, domain string) ([]string, error) {
	sbdSet := set.New[string]()

	browsers, errb := GetServiceBrowserDomains(c, domain)
	if errb == nil {
		sbdSet.Add(browsers...)
	}

	defaultBrowser, errdb := GetDefaultServiceBrowserDomain(c, domain)
	if errdb == nil {
		sbdSet.Add(defaultBrowser)
	}

	legacyBrowser, errl := GetLegacyServiceBrowserDomain(c, domain)
	if errl == nil {
		sbdSet.Add(legacyBrowser)
	}

	if sbdSet.Size() == 0 {
		// TODO: use errors.Join to include info from errb, errdb, and errdl,
		// if non-nil
		return nil, fmt.Errorf("failed to find any service browsing domains")
	}

	return sbdSet.Items(), nil
}

func EnumerateServices(c Client, domain string) ([]string, error) {
	var services []string
	fauxDomain := fmt.Sprintf("_services._dns-sd._udp.%s", domain)
	resp, err := c.Query(fauxDomain, dns.TypePTR)
	if err != nil {
		return nil, err
	}
	if resp.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("DNS query returned error: %s", dns.RcodeToString[resp.Rcode])
	}
	ptrRRs := functools.Filter(resp.Answer, func(rr dns.RR) bool {
		_, ok := rr.(*dns.PTR)
		return ok
	})
	if len(ptrRRs) == 0 {
		return nil, fmt.Errorf("DNS query did not return any PTR records")
	}
	for _, rr := range ptrRRs {
		ptr := rr.(*dns.PTR)
		services = append(services, ptr.Ptr)
	}
	return services, nil
}

func EnumerateServiceInstances(c Client, domain, service string) ([]string, error) {
	var instances []string
	fauxDomain := fmt.Sprintf("%s.%s", service, domain)
	resp, err := c.Query(fauxDomain, dns.TypePTR)
	if err != nil {
		return nil, err
	}
	if resp.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("DNS query returned error: %s", dns.RcodeToString[resp.Rcode])
	}
	ptrRRs := functools.Filter(resp.Answer, func(rr dns.RR) bool {
		_, ok := rr.(*dns.PTR)
		return ok
	})
	if len(ptrRRs) == 0 {
		return nil, fmt.Errorf("DNS query did not return any PTR records")
	}
	for _, rr := range ptrRRs {
		ptr := rr.(*dns.PTR)
		instances = append(instances, ptr.Ptr)
	}
	return instances, nil

}

func GetServiceInstanceInfo(c Client, domain string) error {
	// Perform a SRV query on name
	// Perform a TXT query on name
	// Aggreage the results
	return nil
}
