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
	defaultRecordType = "mx"
)

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

var recordMap = map[string]Record {
	"mx": { Exchange: exchangeMX, Handler: handleMX },
	"mail": { Exchange: exchangeMX, Handler: handleMX },
	"a": { Exchange: exchangeA, Handler: handleA },
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

		fmt.Printf("rtt: %dms [%s], code: %d\n",
			rtt.Milliseconds(),
			cat.Rating,
			result.Rcode)

		if result.Rcode != dns.RcodeSuccess {
			return
		}

		// Output records
		if numAnswers > 0 {
			fmt.Printf("num: %d\n-\n", numAnswers)
			record.Handler(result)
		}
	} else {
		fmt.Fprintf(os.Stderr, "Type not supported: %s\n", recordType)
	}
}
