package main

import (
	"fmt"
	"regexp"
	"math"
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

type exchangeFunc func(client *dns.Client, domain string, server string) (*dns.Msg, time.Duration, error)
type handlerFunc func(client *dns.Client, result *dns.Msg, server string) error

type record struct {
	Exchange exchangeFunc
	Handler handlerFunc
	Alias *string
	Desc string
}

type rttCategory struct {
	Rating string
	Desc string
}

type sshfpAlgorithm struct {
	Name string
}

type sshfpType struct {
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
	listRatings bool
)

func makeMsg(domain string, what uint16) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(domain, what)
	msg.RecursionDesired = recursionLookup

	return msg
}

func exchangeMsg(client *dns.Client, domain string, server string, what uint16) (*dns.Msg, time.Duration, error) {
	msg := makeMsg(domain, what)
	return client.Exchange(msg, server) 
}

func exchangeLDAP(client *dns.Client, domain string, server string) (*dns.Msg, time.Duration, error) {
	return exchangeMsg(client, "_ldap._tcp." + domain, server, dns.TypeSRV)
}

func exchangeKDC(client *dns.Client, domain string, server string) (*dns.Msg, time.Duration, error) {
	return exchangeMsg(client, "_kerberos._tcp." + domain, server, dns.TypeSRV)
}

func exchangeDC(client *dns.Client, domain string, server string) (*dns.Msg, time.Duration, error) {
	return exchangeMsg(client, "_ldap._tcp.dc._msdcs." + domain, server, dns.TypeSRV)
}

func exchangePDC(client *dns.Client, domain string, server string) (*dns.Msg, time.Duration, error) {
	return exchangeMsg(client, "_ldap._tcp.pdc._msdcs." + domain, server, dns.TypeSRV)
}

func exchangeGC(client *dns.Client, domain string, server string) (*dns.Msg, time.Duration, error) {
	return exchangeMsg(client, "_ldap._tcp.gc._msdcs." + domain, server, dns.TypeSRV)
}

func exchangeDMARC(client *dns.Client, domain string, server string) (*dns.Msg, time.Duration, error) {
	return exchangeMsg(client, "_dmarc." + domain, server, dns.TypeTXT)
}

func exchangeSIP(client *dns.Client, domain string, server string) (*dns.Msg, time.Duration, error) {
	return exchangeMsg(client, "_sip._tcp." + domain, server, dns.TypeSRV)
}

func exchangeLOC(client *dns.Client, domain string, server string) (*dns.Msg, time.Duration, error) {
	return exchangeMsg(client, domain, server, dns.TypeLOC)
}

func handleLOC(client *dns.Client, result *dns.Msg, server string) error {
	const twoTo31 = 1 << 31
	latHemi := [2]string{ "S", "N"}
	lonHemi := [2]string{ "W", "E"}

	for _, ans := range result.Answer {
		if loc, ok := ans.(*dns.LOC); ok {
			// Latitude
			lat := float64(loc.Latitude) - twoTo31
			lat /= 3600000.0
			latIndex := 1

			if lat < 0 {
				latIndex = 0
			}

			// Longitude
			lon := float64(loc.Longitude) - twoTo31
			lon /= 3600000.0
			lonIndex := 1

			if lon < 0 {
				lonIndex = 0
			}

			// Altitude
			alt := float64(loc.Altitude) / 100.0 - 100000.0

			// Location output (decimal degrees, ISO 6709, geo URI)
			fmt.Printf(" dd:%.6f° %s, %.6f° %s, %.2f m\n",
				math.Abs(lat), latHemi[latIndex],
				math.Abs(lon), lonHemi[lonIndex],
				alt)
			fmt.Printf("iso:%+09.4f%+010.4f%+07.1f/\n",
				lat,
				lon,
				alt)
			fmt.Printf("geo:%.6f,%.6f,%.2f\n",
				lat,
				lon,
				alt)
		}
	}

	return nil
}

func exchangeSRV(client *dns.Client, domain string, server string) (*dns.Msg, time.Duration, error) {
	return exchangeMsg(client, domain, server, dns.TypeSRV)
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
	return exchangeMsg(client, domain, server, dns.TypeMX)
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
	return exchangeMsg(client, domain, server, dns.TypeA)
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
	return exchangeMsg(client, domain, server, dns.TypeAAAA)
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
	return exchangeMsg(client, domain, server, dns.TypeSOA)
}

func handleSOA(client *dns.Client, result *dns.Msg, server string) error {
	for _, ans := range result.Answer {
		if soa, ok := ans.(*dns.SOA); ok {
			fmt.Printf("%s [ttl=%d ser=%d ref=%d ret=%d min=%d %s]\n",
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
	return exchangeMsg(client, domain, server, dns.TypeCNAME)
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
					foundCNAME = true
				}
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
	return exchangeMsg(client, domain, server, dns.TypeTXT)
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
	return exchangeMsg(client, domain, server, dns.TypeNS)
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
	return exchangeMsg(client, domain, server, dns.TypePTR)
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
	return exchangeMsg(client, domain, server, dns.TypeSSHFP)
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
	return exchangeMsg(client, domain, server, dns.TypeDHCID)
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

func exchangeHTTPS(client *dns.Client, domain string, server string) (*dns.Msg, time.Duration, error) {
	return exchangeMsg(client, domain, server, dns.TypeHTTPS)
}

func handleHTTPS(client *dns.Client, result *dns.Msg, server string) error {
	for _, ans := range result.Answer {
		if https, ok := ans.(*dns.HTTPS); ok {
			targetOutput := https.Target

			// Change target to pseudonym root
			if targetOutput == "." {
				targetOutput = "<root>"
			}

			fmt.Printf("%s [p=%d ttl=%d",
				targetOutput,
				https.Priority,
				https.Hdr.Ttl)

			// HTTPS values/parameters
			var numValues = len(https.Value)

			if numValues > 0 {
				fmt.Printf(" params=(")

				for _, param := range https.Value {
					fmt.Printf("%s=%v", param.Key(), param.String())
				}

				fmt.Printf(")")
			}
			
			fmt.Printf("]\n")
		}
	}

	return nil
}

var srvRecord = "SRV"
var txtRecord = "TXT"
var ptrRecord = "PTR"

var recordMap = map[string]record {
	"MX": { exchangeMX, handleMX, nil, "Mail server" },
	"MAIL": { exchangeMX, handleMX, nil, "Alias to MX" },
	"A": { exchangeA, handleA, nil, "IPv4 address" },
	"AAAA": { exchangeAAAA, handleAAAA, nil, "IPv6 address" },
	"SOA": { exchangeSOA, handleSOA, nil, "Start of authority" },
	"ORIGIN": { exchangeSOA, handleSOA, nil, "Alias to SOA" },
	"SRV": { exchangeSRV, handleSRV, nil, "Service" },
	"SIP": { exchangeSIP, handleSRV, &srvRecord,"Alias to SIP SRV" },
	"CNAME": { exchangeCNAME, handleCNAME, nil, "Canonical name" },
	"TXT": { exchangeTXT, handleTXT, nil, "Text" },
	"DMARC": { exchangeDMARC, handleTXT, &txtRecord, "Alias to DMARC TXT" },
	"NS": { exchangeNS, handleNS, nil, "Name server" },
	"PTR": { exchangePTR, handlePTR, nil, "Pointer" },
	"SSHFP": { exchangeSSHFP, handleSSHFP, nil, "SSH fingerprint" },
	"SPF": { exchangeTXT, handleSPF, &txtRecord, "Alias to SPF TXT" },
	"DHCID": { exchangeDHCID, handleDHCID, nil, "DHCP identifier" },
	"DC": { exchangeDC, handleSRV, &srvRecord, "Domain Controllers for Active Directory domain" },
	"PDC": { exchangePDC, handleSRV, &srvRecord, "Primary Domain Controller (PDC) emulator" },
	"GC": { exchangeGC, handleSRV, &srvRecord, "Global Catalog servers" },
	"KDC": { exchangeKDC, handleSRV, &srvRecord, "Kerberos Key Distribution Centers (KDCs)" },
	"LDAP": { exchangeLDAP, handleSRV, &srvRecord, "LDAP service location" },
	"LOC": { exchangeLOC, handleLOC, nil, "Geographical location" },
	"HTTPS": { exchangeHTTPS, handleHTTPS, nil, "HTTPS binding" },
}

var sshfpAlgorithms = []sshfpAlgorithm {
	{ "Reserved" },
    	{ "RSA" },
	{ "DSA" },
	{ "ECDSA" },
	{ "Ed25519" },
	{ "Ed448" },
}

var sshfpTypes = []sshfpType {
	{ "Reserved" },
	{ "SHA-1" },
	{ "SHA-256" },
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

func rateRTT(rtt time.Duration) rttCategory {
	ms := rtt.Milliseconds()
	cat := rttCategory{}

	switch {
	case ms < 0:
		cat.Rating = "invalid"
		cat.Desc = "Negative RTT, check measurement."
	case ms <= 10:
		cat.Rating = "excellent"
		cat.Desc = "Typically seen with local caching or very efficient resolvers"
	case ms <= 50:
		cat.Rating = "very good"
		cat.Desc = "Good performance, minimal impact on page load times"
	case ms <= 100:
		cat.Rating = "good"
		cat.Desc = "Acceptable for most websites, slight impact on performance"
	case ms <= 200:
		cat.Rating = "fair"
		cat.Desc = "Noticeable impact on page load times, consider optimization"
	case ms <= 500:
		cat.Rating = "poor"
		cat.Desc = "Significant impact on user experience, optimization recommended"
	default:
		cat.Rating = "very poor"
		cat.Desc = "Major performance issue, urgent optimization needed"
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

		if recordMap[key].Alias != nil {
			keyOutput += "*"	
		}
	
		keyOutput += key

		fmt.Printf("%8s %s\n",
			keyOutput,
			recordMap[key].Desc)
	}

	fmt.Printf("\n* = alias\n")
}

func printRatings() {
	sampleRTTs := []time.Duration{
		-1 * time.Millisecond,  // invalid
		10 * time.Millisecond,  // excellent
		50 * time.Millisecond,  // very good
		100 * time.Millisecond, // good
		200 * time.Millisecond, // fair
		500 * time.Millisecond, // poor
		700 * time.Millisecond, // very poor
	}

	for _, rtt := range sampleRTTs {
		cat := rateRTT(rtt)
		
		fmt.Printf("%4dms%10s - %s\n",
			rtt.Milliseconds(),
			cat.Rating,
			cat.Desc)
	}
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
	flag.BoolVar(&arpaLookup, "Arpa", false, "Reverse lookup")
	flag.BoolVar(&listRatings, "Ratings", false, "List ratings")
}

func main() {
	flag.Usage = func() {
		w := flag.CommandLine.Output()
		progname := filepath.Base(os.Args[0])
		
		fmt.Fprintf(w, "Usage: %s [-h] " +
			"<domain | IP> " +
			"[record | alias]\n", progname)
		flag.PrintDefaults()
	}

	flag.Parse()

	if listRecords {
		printRecordTypes()
		os.Exit(255)
	}

	if listRatings {
		printRatings()
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

	// Reverse lookup
	if arpaLookup {
		version := ipVersion(domain)
		domain, _ = ipToArpa(domain, version)
		recordType = ptrRecord
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

		if record.Alias != nil {
			recordOutput = *record.Alias
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

			if herr := record.Handler(client, result, server); herr != nil {
				fmt.Fprintf(os.Stderr, "err: %v\n", herr)	
			}
		}
	} else {
		fmt.Fprintf(os.Stderr, "Type not supported: %s\n", recordType)

		// Output possible record types
		regPat := fmt.Sprintf("^%s", regexp.QuoteMeta(recordType))
		re := regexp.MustCompile(regPat)

		for key, _ := range recordMap {
			if re.MatchString(key) {
				fmt.Printf("Did you mean '%s'?\n", key)
			}
		}
	}
}
