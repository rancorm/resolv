package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/miekg/dns"
)

type ExchangeFunc func(client *dns.Client, domain string, server string) (*dns.Msg, time.Duration, error)
type HandlerFunc func(*dns.Msg)

type Record struct {
	Exchange ExchangeFunc
	Handler HandlerFunc
}

type RTTCategory struct {
	Rating string
	Description string
}

const (
	resolvConfPath = "/etc/resolv.conf"
	defaultRecordType = "a"
)

func exchangeSIP(client *dns.Client, domain string, server string) (*dns.Msg, time.Duration, error) {
	msg := new(dns.Msg)
	msg.SetQuestion("_sip._tcp." + domain, dns.TypeSRV)

	return client.Exchange(msg, server)
}

func exchangeSRV(client *dns.Client, domain string, server string) (*dns.Msg, time.Duration, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(domain, dns.TypeSRV)

	return client.Exchange(msg, server)
}

func handleSRV(result *dns.Msg) {
	for _, ans := range result.Answer {
		switch rr := ans.(type) {
		case *dns.SRV:
			fmt.Printf("%s ttl=%d p=%d w=%d port=%d\n",
				removeLastDot(rr.Target),
				rr.Hdr.Ttl,
				rr.Priority,
				rr.Weight,
				rr.Port)
		case *dns.CNAME:
			fmt.Printf("%s > %s ttl=%d\n",
				removeLastDot(rr.Hdr.Name),
				removeLastDot(rr.Target),
				rr.Hdr.Ttl)
		}
	}
}

func exchangeMX(client *dns.Client, domain string, server string) (*dns.Msg, time.Duration, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(domain, dns.TypeMX)

	return client.Exchange(msg, server)
}

func handleMX(result *dns.Msg) {
	for _, ans := range result.Answer {
		if mx, ok := ans.(*dns.MX); ok {
			fmt.Printf("%s/%d\n", removeLastDot(mx.Mx),
				mx.Preference)
		}
	}
}

func exchangeA(client *dns.Client, domain string, server string) (*dns.Msg, time.Duration, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(domain, dns.TypeA)

	return client.Exchange(msg, server)
}

func handleA(result *dns.Msg) {
	for _, ans := range result.Answer {
		if a, ok := ans.(*dns.A); ok {
			fmt.Printf("%s\n", a.A.String())
		}
	}
}

func exchangeAAAA(client *dns.Client, domain string, server string) (*dns.Msg, time.Duration, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(domain, dns.TypeAAAA)

	return client.Exchange(msg, server)
}

func handleAAAA(result *dns.Msg) {
	for _, ans := range result.Answer {
		if aaaa, ok := ans.(*dns.AAAA); ok {
			fmt.Printf("%s\n", aaaa.AAAA.String())
		}
	}
}

func exchangeSOA(client *dns.Client, domain string, server string) (*dns.Msg, time.Duration, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(domain, dns.TypeSOA)

	return client.Exchange(msg, server)
}

func handleSOA(result *dns.Msg) {
	for _, ans := range result.Answer {
		if soa, ok := ans.(*dns.SOA); ok {
			fmt.Printf("%s ttl=%d ser=%d ref=%d ret=%d min=%d %s\n",
				removeLastDot(soa.Ns),
				soa.Hdr.Ttl,
				soa.Serial,
				soa.Refresh,
				soa.Retry,
				soa.Minttl,
				mboxToEmail(soa.Mbox))
		}
	}
}


var recordMap = map[string]Record {
	"mx": { Exchange: exchangeMX, Handler: handleMX },
	"mail": { Exchange: exchangeMX, Handler: handleMX },
	"a": { Exchange: exchangeA, Handler: handleA },
	"aaaa": { Exchange: exchangeAAAA, Handler: handleAAAA },
	"soa": { Exchange: exchangeSOA, Handler: handleSOA },
	"origin": { Exchange: exchangeSOA, Handler: handleSOA },
	"srv": { Exchange: exchangeSRV, Handler: handleSRV },
	"sip": { Exchange: exchangeSIP, Handler: handleSRV },
}

func mboxToEmail(mbox string) string {
	email := removeLastDot(mbox)
	atIndex := 1

	for i, c := range email {
		if c == '.' {
			atIndex = i
			break
		}
	}

	if atIndex != -1 {
		return email[:atIndex] + "@" + email[atIndex + 1:]
	}

	return email
}

func removeLastDot(domain string) string {
	if len(domain) > 0 && domain[len(domain) - 1] == '.' {
		return domain[:len(domain) - 1]
	}

	return domain
}

func rateRTT(rtt time.Duration) RTTCategory {
	ms := rtt.Milliseconds()
	cat := RTTCategory{}

	switch {
	case ms < 0:
		cat.Rating = "invalid"
		cat.Description = "Negative RTT, check measurement."
	case ms <= 10:
		cat.Rating = "excellent"
		cat.Description = "Typically seen with local caching or very efficient resolvers"
	case ms <= 50:
		cat.Rating = "very good"
		cat.Description = "Good performance, minimal impact on page load times"
	case ms <= 100:
		cat.Rating = "good"
		cat.Description = "Acceptable for most websites, slight impact on performance"
	case ms <= 200:
		cat.Rating = "fair"
		cat.Description = "Noticeable impact on page load times, consider optimization"
	case ms <= 500:
		cat.Rating = "poor"
		cat.Description = "Significant impact on user experience, optimization recommended"
	default:
		cat.Rating = "very poor"
		cat.Description = "Major performance issue, urgent optimization needed"
	}

	return cat
}

func main() {
	if len(os.Args) < 2 {
		progname := filepath.Base(os.Args[0])
		fmt.Printf("Usage: %s <domain> <record>\n", progname)
		os.Exit(1)
	}

	domain := os.Args[1]
	recordType := defaultRecordType
 
	if len(os.Args) == 3 {
		recordType = os.Args[2]
	}

	config, _ := dns.ClientConfigFromFile(resolvConfPath)
	server := net.JoinHostPort(config.Servers[0], config.Port)
	client := new(dns.Client)

	if record, ok := recordMap[recordType]; ok {
		result, rtt, err := record.Exchange(client, domain + ".", server)

		if err != nil {
			fmt.Fprintf(os.Stderr, "err: %v\n", err)
			return
		}

		cat := rateRTT(rtt)
		numAnswers := len(result.Answer)

		fmt.Printf("code=%d num=%d rtt=%dms [%s]\n",
			result.Rcode,
			numAnswers,
			rtt.Milliseconds(),
			cat.Rating)

		// Exit with Rcode as code (scripts?)
		if result.Rcode != dns.RcodeSuccess {
			os.Exit(result.Rcode)
		}

		// Output records
		if numAnswers > 0 {
			fmt.Printf("-\n")
			record.Handler(result)
		}
	} else {
		fmt.Fprintf(os.Stderr, "Type not supported: %s\n", recordType)
	}
}
