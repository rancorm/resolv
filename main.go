package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"
	"flag"
	"strings"

	"github.com/miekg/dns"
)

type ExchangeFunc func(client *dns.Client, domain string, server string) (*dns.Msg, time.Duration, error)
type HandlerFunc func(client *dns.Client, result *dns.Msg, server string)

type Record struct {
	Exchange ExchangeFunc
	Handler HandlerFunc
	Alias string
}

type RTTCategory struct {
	Rating string
	Description string
}

type SSHFPAlgorithm struct {
	Name string
}

type SSHFPType struct {
	Name string
}

const (
	resolvConfPath = "/etc/resolv.conf"
	defaultRecordType = "A"
)

var (
	recursionLookup bool
)

func makeMsg(domain string, what uint16) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(domain, what)
	msg.RecursionDesired = recursionLookup

	return msg
}

func exchangeDMARC(client *dns.Client, domain string, server string) (*dns.Msg, time.Duration, error) {
	msg := makeMsg("_dmarc." + domain, dns.TypeTXT)
	return client.Exchange(msg, server)
}

func exchangeSIP(client *dns.Client, domain string, server string) (*dns.Msg, time.Duration, error) {
	msg := makeMsg("_sip._tcp." + domain, dns.TypeSRV)
	return client.Exchange(msg, server)
}

func exchangeSRV(client *dns.Client, domain string, server string) (*dns.Msg, time.Duration, error) {
	msg := makeMsg(domain, dns.TypeSRV)
	return client.Exchange(msg, server)
}

func handleSRV(client *dns.Client, result *dns.Msg, server string) {
	for _, ans := range result.Answer {
		switch rr := ans.(type) {
		case *dns.SRV:
			fmt.Printf("%s [ttl=%d p=%d w=%d port=%d]\n",
				removeLastDot(rr.Target),
				rr.Hdr.Ttl,
				rr.Priority,
				rr.Weight,
				rr.Port)
		case *dns.CNAME:
			handleCNAME(client, result, server)
		}
	}
}

func exchangeMX(client *dns.Client, domain string, server string) (*dns.Msg, time.Duration, error) {
	msg := makeMsg(domain, dns.TypeMX)
	return client.Exchange(msg, server)
}

func handleMX(client *dns.Client, result *dns.Msg, server string) {
	for _, ans := range result.Answer {
		if mx, ok := ans.(*dns.MX); ok {
			fmt.Printf("%s [pref=%d]\n",
				removeLastDot(mx.Mx),
				mx.Preference)
		}
	}
}

func exchangeA(client *dns.Client, domain string, server string) (*dns.Msg, time.Duration, error) {
	msg := makeMsg(domain, dns.TypeA)
	return client.Exchange(msg, server)
}

func handleA(client *dns.Client, result *dns.Msg, server string) {
	for _, ans := range result.Answer {
		if a, ok := ans.(*dns.A); ok {
			fmt.Printf("%s [ttl=%d]\n",
				a.A.String(),
				a.Hdr.Ttl)
		}
	}
}

func exchangeAAAA(client *dns.Client, domain string, server string) (*dns.Msg, time.Duration, error) {
	msg := makeMsg(domain, dns.TypeAAAA)
	return client.Exchange(msg, server)
}

func handleAAAA(client *dns.Client, result *dns.Msg, server string) {
	for _, ans := range result.Answer {
		if aaaa, ok := ans.(*dns.AAAA); ok {
			fmt.Printf("%s [ttl=%d]\n",
				aaaa.AAAA.String(),
				aaaa.Hdr.Ttl)
		}
	}
}

func exchangeSOA(client *dns.Client, domain string, server string) (*dns.Msg, time.Duration, error) {
	msg := makeMsg(domain, dns.TypeSOA)
	return client.Exchange(msg, server)
}

func handleSOA(client *dns.Client, result *dns.Msg, server string) {
	for _, ans := range result.Answer {
		if soa, ok := ans.(*dns.SOA); ok {
			fmt.Printf("%s\t[ttl=%d ser=%d ref=%d ret=%d min=%d %s]\n",
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

func exchangeCNAME(client *dns.Client, domain string, server string) (*dns.Msg, time.Duration, error) {
	msg := makeMsg(domain, dns.TypeCNAME)
	return client.Exchange(msg, server)
}

func handleCNAME(client *dns.Client, result *dns.Msg, server string) {
	for _, ans := range result.Answer {
		if cname, ok := ans.(*dns.CNAME); ok {
			fmt.Printf("%s > %s [ttl=%d]\n",
				removeLastDot(cname.Hdr.Name),
				removeLastDot(cname.Target),
				cname.Hdr.Ttl)
		}
	}
}

func exchangeTXT(client *dns.Client, domain string, server string) (*dns.Msg, time.Duration, error) {
	msg := makeMsg(domain, dns.TypeTXT)
	return client.Exchange(msg, server)
}

func handleTXT(client *dns.Client, result *dns.Msg, server string) {
	for _, ans := range result.Answer {
		if txt, ok := ans.(*dns.TXT); ok {
			// TXT records can be multi-line (?)
			for _, value := range txt.Txt {
				fmt.Printf("%s \"%s\" [ttl=%d]\n",
					removeLastDot(txt.Hdr.Name),
					value,
					txt.Hdr.Ttl)
			}
		}
	}
}

func exchangeNS(client *dns.Client, domain string, server string) (*dns.Msg, time.Duration, error) {
	msg := makeMsg(domain, dns.TypeNS)
	return client.Exchange(msg, server)
}

func handleNS(client *dns.Client, result *dns.Msg, server string) {
	for _, ans := range result.Answer {
		if ns, ok := ans.(*dns.NS); ok {
			fmt.Printf("%s [ttl=%d]\n",
				removeLastDot(ns.Ns),
				ns.Hdr.Ttl)
		}
	}
}

func exchangePTR(client *dns.Client, domain string, server string) (*dns.Msg, time.Duration, error) {
	msg := makeMsg(domain, dns.TypePTR)
	return client.Exchange(msg, server)
}

func handlePTR(client *dns.Client, result *dns.Msg, server string) {
	for _, ans := range result.Answer {
		if ptr, ok := ans.(*dns.PTR); ok {
			fmt.Printf("%s > %s [ttl=%d]\n",
				removeLastDot(ptr.Hdr.Name),
				removeLastDot(ptr.Ptr),
				ptr.Hdr.Ttl)
		}
	}
}

func exchangeSSHFP(client *dns.Client, domain string, server string) (*dns.Msg, time.Duration, error) {
	msg := makeMsg(domain, dns.TypeSSHFP)
	return client.Exchange(msg, server)
}

func handleSSHFP(client *dns.Client, result *dns.Msg, server string) {
	for _, ans := range result.Answer {
		if sshfp, ok := ans.(*dns.SSHFP); ok {
			fmt.Printf("%s %s %s [ttl=%d]\n",
				sshfpAlgorithms[sshfp.Algorithm],
				sshfpTypes[sshfp.Type],
				sshfp.FingerPrint,
				sshfp.Hdr.Ttl)
		}
	}
}

func handleSPF(client *dns.Client, result *dns.Msg, server string) {
	var spfRecords []string


	for _, ans := range result.Answer {
		if txt, ok := ans.(*dns.TXT); ok {
			for _, line := range txt.Txt {
				if strings.HasPrefix(line, "v=spf1") {
					spfRecords = append(spfRecords,
						fmt.Sprintf("%s [ttl=%d]",
							line,
							txt.Hdr.Ttl))
				}
			}
		}
	}
	
	if len(spfRecords) == 0 {
		fmt.Println("No SPF records found.")
	} else {
		for _, record := range spfRecords {
			fmt.Printf("%s\n", record)
		}
	}
}

var recordMap = map[string]Record {
	"MX": { Exchange: exchangeMX, Handler: handleMX },
	"MAIL": { Exchange: exchangeMX, Handler: handleMX },
	"A": { Exchange: exchangeA, Handler: handleA },
	"AAAA": { Exchange: exchangeAAAA, Handler: handleAAAA },
	"SOA": { Exchange: exchangeSOA, Handler: handleSOA },
	"ORIGIN": { Exchange: exchangeSOA, Handler: handleSOA },
	"SRV": { Exchange: exchangeSRV, Handler: handleSRV },
	"SIP": { Exchange: exchangeSIP, Handler: handleSRV, Alias: "SRV" },
	"CNAME": { Exchange: exchangeCNAME, Handler: handleCNAME },
	"TXT": { Exchange: exchangeTXT, Handler: handleTXT },
	"DMARC": { Exchange: exchangeDMARC, Handler: handleTXT, Alias: "TXT" },
	"NS": { Exchange: exchangeNS, Handler: handleNS },
	"PTR": { Exchange: exchangePTR, Handler: handlePTR },
	"SSHFP": { Exchange: exchangeSSHFP, Handler: handleSSHFP },
	"SPF": { Exchange: exchangeTXT, Handler: handleSPF, Alias: "TXT" },
}

var sshfpAlgorithms = []SSHFPAlgorithm {
	{ Name: "reserved" },
    	{ Name: "RSA" },
	{ Name: "DSA" },
	{ Name: "ECDSA" },
	{ Name: "Ed25519" },
	{ Name: "Ed448" },
}

var sshfpTypes = []SSHFPType {
	{ Name: "reserved" },
	{ Name: "SHA-1" },
	{ Name: "SHA-256" },
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

func init() {
	flag.BoolVar(&recursionLookup, "Recursion", true, "Recursion look up")
}

func main() {
	flag.Usage = func() {
		w := flag.CommandLine.Output()
		progname := filepath.Base(os.Args[0])
		fmt.Fprintf(w, "Usage: %s [-h] <domain> [record]\n", progname)
		flag.PrintDefaults()
	}

	flag.Parse()

	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(255)
	}

	domain := flag.Arg(0)
	recordType := defaultRecordType
 
	if flag.NArg() == 2 {
		recordType = strings.ToUpper(flag.Arg(1))
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
		recordOutput := recordType

		if record.Alias != "" {
			recordOutput = record.Alias
		}
		
		fmt.Printf("%s %s\n",
			recordOutput,
			domain)
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
			record.Handler(client, result, server)
		}
	} else {
		fmt.Fprintf(os.Stderr, "Type not supported: %s\n", recordType)
	}
}
