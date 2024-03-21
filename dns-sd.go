package dnsclient

import (
	"errors"
	"fmt"
	"log"

	"github.com/miekg/dns"
	"github.com/syslab-wm/adt/set"
	"github.com/syslab-wm/dnsclient/internal/msgutil"
	"github.com/syslab-wm/functools"
	"github.com/syslab-wm/mu"
)

func doPTRQuery(c Client, domain string) ([]*dns.PTR, error) {
	resp, err := Query(c, domain, dns.TypePTR)
	if err != nil {
		return nil, err
	}
	return msgutil.CollectRRs[*dns.PTR](resp.Answer), nil
}

func doPTRQuerySingleAnswer(c Client, domain string) (*dns.PTR, error) {
	ptrs, err := doPTRQuery(c, domain)
	if err != nil {
		return nil, err
	}
	return ptrs[0], nil
}

func getPTR(c Client, domain string) ([]string, error) {
	ptrs, err := doPTRQuery(c, domain)
	if err != nil {
		return nil, err
	}
	domains := functools.Map[*dns.PTR, string](ptrs, func(ptr *dns.PTR) string {
		return ptr.Ptr
	})
	return domains, nil
}

func getPTRSingleAnswer(c Client, domain string) (string, error) {
	ptr, err := doPTRQuerySingleAnswer(c, domain)
	if err != nil {
		return "", err
	}
	return ptr.Ptr, nil
}

func doSRVQuery(c Client, domain string) ([]*dns.SRV, error) {
	resp, err := Query(c, domain, dns.TypeSRV)
	if err != nil {
		return nil, err
	}
	return msgutil.CollectRRs[*dns.SRV](resp.Answer), nil
}

func doSRVQuerySingleAnswer(c Client, domain string) (*dns.SRV, error) {
	srvs, err := doSRVQuery(c, domain)
	if err != nil {
		return nil, err
	}
	return srvs[0], nil
}

func doTXTQuery(c Client, domain string) ([]*dns.TXT, error) {
	resp, err := Query(c, domain, dns.TypeTXT)
	if err != nil {
		return nil, err
	}
	return msgutil.CollectRRs[*dns.TXT](resp.Answer), nil
}

func doTXTQuerySingleAnswer(c Client, domain string) (*dns.TXT, error) {
	txts, err := doTXTQuery(c, domain)
	if err != nil {
		return nil, err
	}
	return txts[0], nil
}

func getTXT(c Client, domain string) ([][]string, error) {
	txts, err := doTXTQuery(c, domain)
	if err != nil {
		return nil, err
	}
	values := functools.Map[*dns.TXT, []string](txts, func(txt *dns.TXT) []string {
		return txt.Txt
	})
	return values, nil
}

func getTXTSingleAnswer(c Client, domain string) ([]string, error) {
	txt, err := doTXTQuerySingleAnswer(c, domain)
	if err != nil {
		return nil, err
	}
	return txt.Txt, nil
}

func GetServiceBrowserDomains(c Client, domain string) ([]string, error) {
	fauxDomain := fmt.Sprintf("b._dns-sd._udp.%s", domain)
	return getPTR(c, fauxDomain)
}

func GetDefaultServiceBrowserDomain(c Client, domain string) (string, error) {
	fauxDomain := fmt.Sprintf("db._dns-sd._udp.%s", domain)
	return getPTRSingleAnswer(c, fauxDomain)
}

func GetLegacyServiceBrowserDomain(c Client, domain string) (string, error) {
	fauxDomain := fmt.Sprintf("lb._dns-sd._udp.%s", domain)
	return getPTRSingleAnswer(c, fauxDomain)
}

func GetAllServiceBrowserDomains(c Client, domain string) ([]string, error) {
	var errs []error
	domainSet := set.New[string]()

	names, err := GetServiceBrowserDomains(c, domain)
	if err != nil {
		log.Printf("GetServiceBrowserDomains: err: %v", err)
		errs = append(errs, err)
	} else {
		log.Printf("GetServiceBrowserDomains: names: %v", names)
		domainSet.Add(names...)
	}

	name, err := GetDefaultServiceBrowserDomain(c, domain)
	if err != nil {
		log.Printf("GetDefaultServiceBrowserDomain: err: %v", err)
		errs = append(errs, err)
	} else {
		log.Printf("GetDefaultServiceBrowserDomain: name: %s", name)
		domainSet.Add(name)
	}

	name, err = GetLegacyServiceBrowserDomain(c, domain)
	if err != nil {
		log.Printf("GetLegacyServiceBrowserDomain: err: %v", err)
		errs = append(errs, err)
	} else {
		log.Printf("GetLegacyServiceBrowserDomain: name: %s", name)
		domainSet.Add(name)
	}

	if domainSet.Size() == 0 {
		if len(errs) == 0 {
			mu.BUG("got no answers, but got no errors")
		}
		return nil, errors.Join(errs...)
	}

	return domainSet.Items(), nil
}

func GetServices(c Client, domain string) ([]string, error) {
	fauxDomain := fmt.Sprintf("_services._dns-sd._udp.%s", domain)
	return getPTR(c, fauxDomain)
}

func GetServiceInstances(c Client, serviceDomain string) ([]string, error) {
	// serviceDomain has the form, e.g.,  _ssh._tcp.<domain>
	return getPTR(c, serviceDomain)
}

// aggregation of SRV and TXT fields
type ServiceInstanceInfo struct {
	Priority uint16
	Weight   uint16
	Port     uint16
	Target   string
	Txt      []string
}

func (info *ServiceInstanceInfo) String() string {
	return fmt.Sprintf("priority:%d weight:%d port:%d target:%s txt:%v",
		info.Priority, info.Weight, info.Port, info.Target, info.Txt)
}

func GetServiceInstanceInfo(c Client, domain string) (*ServiceInstanceInfo, error) {
	info := new(ServiceInstanceInfo)

	// SRV must succeed
	srv, err := doSRVQuerySingleAnswer(c, domain)
	if err != nil {
		return nil, err
	}

	info.Priority = srv.Priority
	info.Weight = srv.Weight
	info.Port = srv.Port
	info.Target = srv.Target

	// not an error if TXT doesn't succeed
	value, err := getTXTSingleAnswer(c, domain)
	if err == nil {
		info.Txt = value
	}

	return info, nil
}
