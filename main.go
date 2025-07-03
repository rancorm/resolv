package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"
	"flag"
	"sort"
	"strings"
	"strconv"

	"github.com/miekg/dns"
)

type ExchangeFunc func(client *dns.Client, domain string, server string) (*dns.Msg, time.Duration, error)
type HandlerFunc func(client *dns.Client, result *dns.Msg, server string) error

type Record struct {
	Exchange ExchangeFunc
	Handler HandlerFunc
	Alias string
	Description string
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
	defaultDNSPort = "53"
)

var (
	recursionLookup bool
	listRecords bool
	recursiveCNAMELookup bool
	targetServer string
	arpaLookup bool
)

func makeMsg(domain string, what uint16) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(domain, what)
	msg.RecursionDesired = recursionLookup

	return msg
}

func exchangeLDAP(client *dns.Client, domain string, server string) (*dns.Msg, time.Duration, error) {
	msg := makeMsg("_ldap._tcp." + domain, dns.TypeSRV)
	return client.Exchange(msg, server)
}

func exchangeKDC(client *dns.Client, domain string, server string) (*dns.Msg, time.Duration, error) {
	msg := makeMsg("_kerberos._tcp." + domain, dns.TypeSRV)
	return client.Exchange(msg, server)
}

func exchangeDC(client *dns.Client, domain string, server string) (*dns.Msg, time.Duration, error) {
	msg := makeMsg("_ldap._tcp.dc._msdcs." + domain, dns.TypeSRV)
	return client.Exchange(msg, server)
}

func exchangePDC(client *dns.Client, domain string, server string) (*dns.Msg, time.Duration, error) {
	msg := makeMsg("_ldap._tcp.pdc._msdcs." + domain, dns.TypeSRV)
	return client.Exchange(msg, server)
}

func exchangeGC(client *dns.Client, domain string, server string) (*dns.Msg, time.Duration, error) {
	msg := makeMsg("_ldap._tcp.gc._msdcs." + domain, dns.TypeSRV)
	return client.Exchange(msg, server)
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

func handleSRV(client *dns.Client, result *dns.Msg, server string) error {
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

	return nil
}

func exchangeMX(client *dns.Client, domain string, server string) (*dns.Msg, time.Duration, error) {
	msg := makeMsg(domain, dns.TypeMX)
	return client.Exchange(msg, server)
}

func handleMX(client *dns.Client, result *dns.Msg, server string) error {
	for _, ans := range result.Answer {
		if mx, ok := ans.(*dns.MX); ok {
			fmt.Printf("%s [pref=%d]\n",
				removeLastDot(mx.Mx),
				mx.Preference)
		}
	}

	return nil
}

func exchangeA(client *dns.Client, domain string, server string) (*dns.Msg, time.Duration, error) {
	msg := makeMsg(domain, dns.TypeA)
	return client.Exchange(msg, server)
}

func handleA(client *dns.Client, result *dns.Msg, server string) error {
	for _, ans := range result.Answer {
		if a, ok := ans.(*dns.A); ok {
			fmt.Printf("%s [ttl=%d]\n",
				a.A.String(),
				a.Hdr.Ttl)
		}
	}

	return nil
}

func exchangeAAAA(client *dns.Client, domain string, server string) (*dns.Msg, time.Duration, error) {
	msg := makeMsg(domain, dns.TypeAAAA)
	return client.Exchange(msg, server)
}

func handleAAAA(client *dns.Client, result *dns.Msg, server string) error {
	for _, ans := range result.Answer {
		if aaaa, ok := ans.(*dns.AAAA); ok {
			fmt.Printf("%s [ttl=%d]\n",
				aaaa.AAAA.String(),
				aaaa.Hdr.Ttl)
		}
	}

	return nil
}

func exchangeSOA(client *dns.Client, domain string, server string) (*dns.Msg, time.Duration, error) {
	msg := makeMsg(domain, dns.TypeSOA)
	return client.Exchange(msg, server)
}

func handleSOA(client *dns.Client, result *dns.Msg, server string) error {
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

	return nil
}

func exchangeCNAME(client *dns.Client, domain string, server string) (*dns.Msg, time.Duration, error) {
	msg := makeMsg(domain, dns.TypeCNAME)
	return client.Exchange(msg, server)
}

func handleCNAME(client *dns.Client, result *dns.Msg, server string) error {
	visited := make(map[string]bool)
	var current string

	if len(result.Question) == 0 {
		return fmt.Errorf("No question in DNS message")
	}

	current = result.Question[0].Name

	for range [15]int{} {
		if visited[current] {
			return fmt.Errorf("CNAME loop detected at %s", removeLastDot(current))
		}

		visited[current] = true
		foundCNAME := false

		for _, ans := range result.Answer {
			if cname, ok := ans.(*dns.CNAME); ok && cname.Hdr.Name == current {
				fmt.Printf("%s > %s [ttl=%d]\n",
					removeLastDot(cname.Hdr.Name),
					removeLastDot(cname.Target),
					cname.Hdr.Ttl)
			
				if recursiveCNAMELookup {
					current = cname.Target

					msg := makeMsg(current, dns.TypeCNAME)
					nextResult, _, err := client.Exchange(msg, server)

					if err != nil {
						return err
					}

					result = nextResult
				}
				
				foundCNAME = true
				
				break
			}
		}

		if !foundCNAME {
			msg := makeMsg(current, dns.TypeA)
			aResult, _, err := client.Exchange(msg, server)

			if err != nil {
				return err
			}
			
			handleFinalRecords(aResult)

			msg.SetQuestion(current, dns.TypeAAAA)
			aaaaResult, _, err := client.Exchange(msg, server)

			if err == nil {
				handleFinalRecords(aaaaResult)
			}

			return nil
		}
	}

	return nil
}

func handleFinalRecords(result *dns.Msg) {
	found := false
    
	for _, ans := range result.Answer {
		switch rr := ans.(type) {
		case *dns.A:
			fmt.Printf("%s > %s [ttl=%d]\n",
				removeLastDot(rr.Hdr.Name),
				rr.A.String(),
				rr.Hdr.Ttl)
			found = true
		case *dns.AAAA:
			fmt.Printf("%s > %s [ttl=%d]\n",
				removeLastDot(rr.Hdr.Name),
				rr.AAAA.String(),
				rr.Hdr.Ttl)
			found = true	
		}
	}
	
	if !found {
        	fmt.Println("No A or AAAA records found in the response.")
    	}
}

func exchangeTXT(client *dns.Client, domain string, server string) (*dns.Msg, time.Duration, error) {
	msg := makeMsg(domain, dns.TypeTXT)
	return client.Exchange(msg, server)
}

func handleTXT(client *dns.Client, result *dns.Msg, server string) error {
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

	return nil
}

func exchangeNS(client *dns.Client, domain string, server string) (*dns.Msg, time.Duration, error) {
	msg := makeMsg(domain, dns.TypeNS)
	return client.Exchange(msg, server)
}

func handleNS(client *dns.Client, result *dns.Msg, server string) error {
	for _, ans := range result.Answer {
		if ns, ok := ans.(*dns.NS); ok {
			fmt.Printf("%s [ttl=%d]\n",
				removeLastDot(ns.Ns),
				ns.Hdr.Ttl)
		}
	}

	return nil
}

func exchangePTR(client *dns.Client, domain string, server string) (*dns.Msg, time.Duration, error) {
	msg := makeMsg(domain, dns.TypePTR)
	return client.Exchange(msg, server)
}

func handlePTR(client *dns.Client, result *dns.Msg, server string) error {
	for _, ans := range result.Answer {
		if ptr, ok := ans.(*dns.PTR); ok {
			fmt.Printf("%s > %s [ttl=%d]\n",
				removeLastDot(ptr.Hdr.Name),
				removeLastDot(ptr.Ptr),
				ptr.Hdr.Ttl)
		}
	}

	return nil
}

func exchangeSSHFP(client *dns.Client, domain string, server string) (*dns.Msg, time.Duration, error) {
	msg := makeMsg(domain, dns.TypeSSHFP)
	return client.Exchange(msg, server)
}

func handleSSHFP(client *dns.Client, result *dns.Msg, server string) error {
	for _, ans := range result.Answer {
		if sshfp, ok := ans.(*dns.SSHFP); ok {
			fmt.Printf("%s %s %s [ttl=%d]\n",
				sshfpAlgorithms[sshfp.Algorithm],
				sshfpTypes[sshfp.Type],
				sshfp.FingerPrint,
				sshfp.Hdr.Ttl)
		}
	}

	return nil
}

func handleSPF(client *dns.Client, result *dns.Msg, server string) error {
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

	return nil
}

func exchangeDHCID(client *dns.Client, domain string, server string) (*dns.Msg, time.Duration, error) {
	msg := makeMsg(domain, dns.TypeDHCID)
	return client.Exchange(msg, server)
}

func handleDHCID(client *dns.Client, result *dns.Msg, server string) error {
	for _, ans := range result.Answer {
		if dhcid, ok := ans.(*dns.DHCID); ok {
			fmt.Printf("%s\n",
				dhcid.Digest)
		}
	}

	return nil
}

var recordMap = map[string]Record {
	"MX": {
		Exchange: exchangeMX,
		Handler: handleMX,
		Description: "Mail server",
	},
	"MAIL": {
		Exchange: exchangeMX,
		Handler: handleMX,
		Description: "Alias to MX",
	},
	"A": {
		Exchange: exchangeA,
		Handler: handleA,
		Description: "IPv4 address",
	},
	"AAAA": {
		Exchange: exchangeAAAA,
		Handler: handleAAAA,
		Description: "IPv6 address",
	},
	"SOA": {
		Exchange: exchangeSOA,
		Handler: handleSOA,
		Description: "Start of authority",
	},
	"ORIGIN": {
		Exchange: exchangeSOA,
		Handler: handleSOA,
		Description: "Alias to SOA",
	},
	"SRV": {
		Exchange: exchangeSRV,
		Handler: handleSRV,
		Description: "Service",
	},
	"SIP": { 
		Exchange: exchangeSIP,
		Handler: handleSRV,
		Alias: "SRV",
		Description: "Alias to SIP SRV",
	},
	"CNAME": {
		Exchange: exchangeCNAME,
		Handler: handleCNAME,
		Description: "Canonical name",
	},
	"TXT": {
		Exchange: exchangeTXT,
		Handler: handleTXT,
		Description: "Text",
	},
	"DMARC": {
		Exchange: exchangeDMARC,
		Handler: handleTXT,
		Alias: "TXT",
		Description: "Alias to DMARC TXT",
	},
	"NS": {
		Exchange: exchangeNS,
		Handler: handleNS,
		Description: "Name server",
	},
	"PTR": {
		Exchange: exchangePTR,
		Handler: handlePTR,
		Description: "Pointer",
	},
	"SSHFP": {
		Exchange: exchangeSSHFP,
		Handler: handleSSHFP,
		Description: "SSH fingerprint",
	},
	"SPF": {
		Exchange: exchangeTXT,
		Handler: handleSPF,
		Alias: "TXT",
		Description: "Alias to SPF TXT",
	},
	"DHCID": {
		Exchange: exchangeDHCID,
		Handler: handleDHCID,
		Description: "DHCP identifier",
	
	},
	"DC": {
		Exchange: exchangeDC,
		Handler: handleSRV,
		Alias: "SRV",
		Description: "Domain Controllers for Active Directory domain",
	},
	"PDC": {
		Exchange: exchangePDC,
		Handler: handleSRV,
		Alias: "SRV",
		Description: "Primary Domain Controller (PDC) emulator",
	},
	"GC": {
		Exchange: exchangeGC,
		Handler: handleSRV,
		Alias: "SRV",
		Description: "Global Catalog servers",
	},
	"KDC": {
		Exchange: exchangeKDC,
		Handler: handleSRV,
		Alias: "SRV",
		Description: "Kerberos Key Distribution Centers (KDCs)",
	},
	"LDAP": {
		Exchange: exchangeLDAP,
		Handler: handleSRV,
		Alias: "SRV",
		Description: "LDAP service location",
	},
}

var sshfpAlgorithms = []SSHFPAlgorithm {
	{ Name: "Reserved" },
    	{ Name: "RSA" },
	{ Name: "DSA" },
	{ Name: "ECDSA" },
	{ Name: "Ed25519" },
	{ Name: "Ed448" },
}

var sshfpTypes = []SSHFPType {
	{ Name: "Reserved" },
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

func printRecordTypes() {
	keys := make([]string, 0, len(recordMap))

	for key := range recordMap {
		keys = append(keys, key)
	}
	
	sort.Strings(keys)

	for _, key := range keys {
		keyOutput := ""

		if recordMap[key].Alias != "" {
			keyOutput += "*"	
		}
	
		keyOutput += key

		fmt.Printf("%8s %s\n",
			keyOutput,
			recordMap[key].Description)
	}

	fmt.Printf("\n* = alias\n")
}

func endsWithInt(s string) bool {
	index := strings.LastIndex(s, ":")

	if index == -1 || index == len(s) - 1 {
		return false
	}

	_, err := strconv.Atoi(s[index + 1:])

	return err == nil
}

func ipToArpa(addr string, version int) (string, error) {
	ip := net.ParseIP(addr)

	if ip == nil {
		return "", fmt.Errorf("Invalid IP address: %s", addr)
	}

	switch version {
	case 4:
		ip4 := ip.To4()
		
		if ip4 == nil {
			return "", fmt.Errorf("Not an IPv4 address: %s", addr)
		}
		
		octets := strings.Split(ip4.String(), ".")
		
		for i, j := 0, len(octets) - 1; i < j; i, j = i + 1, j - 1 {
			octets[i], octets[j] = octets[j], octets[i]
		}
		
		return strings.Join(octets, ".") + ".in-addr.arpa", nil
	case 6:
		ip6 := ip.To16()
		
		if ip6 == nil || ip.To4() != nil {
			return "", fmt.Errorf("Not an IPv6 address: %s", addr)
		}
		
		// Correctly expand IPv6 to its full form
		var arpaAddr strings.Builder
		
		// Process each byte in reverse order
		for i := len(ip6) - 1; i >= 0; i-- {
			// Each byte becomes two hex digits
			hexStr := fmt.Sprintf("%02x", ip6[i])
			
			// Add each hex digit separately with a dot
			arpaAddr.WriteString(string(hexStr[1]))
			arpaAddr.WriteString(".")
			arpaAddr.WriteString(string(hexStr[0]))
		
			if i > 0 {
				arpaAddr.WriteString(".")
			}
		}
		
		arpaAddr.WriteString(".ip6.arpa")
        
        	return arpaAddr.String(), nil
	default:
		return "", fmt.Errorf("Unknown IP version: %d", version)
	}
}

func ipVersion(s string) int {
	ip := net.ParseIP(s)

	if ip == nil {
		return 0
	}
	if ip.To4() != nil {
		return 4
	}

	return 6
}

func init() {
	flag.BoolVar(&recursionLookup, "Recursion", true, "Recursion lookup")
	flag.BoolVar(&listRecords, "Records", false, "List record types")
	flag.BoolVar(&recursiveCNAMELookup, "Recursive", false, "Recursive CNAME lookup")
	flag.StringVar(&targetServer, "Server", "", "Target server")
	flag.BoolVar(&arpaLookup, "Arpa", false, "in-addr.arpa lookup")
}

func main() {
	flag.Usage = func() {
		w := flag.CommandLine.Output()
		progname := filepath.Base(os.Args[0])
		
		fmt.Fprintf(w, "Usage: %s [-h] " +
			"<domain> " +
			"[record | alias]\n", progname)
		flag.PrintDefaults()
	}

	flag.Parse()

	if listRecords {
		printRecordTypes()
		os.Exit(255)
	}

	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(255)
	}

	domain := flag.Arg(0)
	recordType := defaultRecordType
	server := ""

	if flag.NArg() == 2 {
		recordType = strings.ToUpper(flag.Arg(1))
	}

	// Command line provided target server
	if targetServer != "" {
		server = targetServer

		if !endsWithInt(server) {
			server += ":" + defaultDNSPort
		}

	} else {
		config, _ := dns.ClientConfigFromFile(resolvConfPath)
		server = net.JoinHostPort(config.Servers[0], config.Port)
	}

	// in-addr.arpa lookup
	if arpaLookup {
		version := ipVersion(domain)
		domain, _ = ipToArpa(domain, version)
		recordType = "PTR"
	}

	client := new(dns.Client)

	if record, ok := recordMap[recordType]; ok {
		result, rtt, err := record.Exchange(client, dns.Fqdn(domain), server)

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
			
			herr := record.Handler(client, result, server)

			if herr != nil {
				fmt.Fprintf(os.Stderr, "err: %v\n", herr)	
			}
		}
	} else {
		fmt.Fprintf(os.Stderr, "Type not supported: %s\n", recordType)
	}
}
