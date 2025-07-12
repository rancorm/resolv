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
	"strings"

	"github.com/fatih/color"
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
	Color *color.Color
}

type sshfpAlgorithm struct {
	Name string
}

type sshfpType struct {
	Name string
}

type priorityLabel struct {
	Name string
}

const (
	resolvConfPath = "/etc/resolv.conf"
	defaultRecordType = "A"
	defaultDNSPort = "53"
	spfPrefix = "vspf1"
)

var (
	recursionLookup bool
	listRecords bool
	recursiveCNAMELookup bool
	targetServer string
	arpaLookup bool
	listRatings bool
	showHelp bool
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

func exchangeSIPTCP(client *dns.Client, domain string, server string) (*dns.Msg, time.Duration, error) {
	return exchangeMsg(client, "_sip._tcp." + domain, server, dns.TypeSRV)
}

func exchangeSIPUDP(client *dns.Client, domain string, server string) (*dns.Msg, time.Duration, error) {
	return exchangeMsg(client, "_sip._udp." + domain, server, dns.TypeSRV)
}

func exchangeSIPTLS(client *dns.Client, domain string, server string) (*dns.Msg, time.Duration, error) {
	return exchangeMsg(client, "_sip._tls." + domain, server, dns.TypeSRV)
}

func exchangeSIPS(client *dns.Client, domain string, server string) (*dns.Msg, time.Duration, error) {
	return exchangeMsg(client, "_sips._tcp." + domain, server, dns.TypeSRV)
}

func exchangeSIPSTLS(client *dns.Client, domain string, server string) (*dns.Msg, time.Duration, error) {
	return exchangeMsg(client, "_sips._tls." + domain, server, dns.TypeSRV)
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
	found := false

	for _, ans := range result.Answer {
		if mx, ok := ans.(*dns.MX); ok {
			fmt.Printf("%s [pref=%d]\n",
				removeLastDot(mx.Mx),
				mx.Preference)

			found = true
		}
	}

	if !found {
		return fmt.Errorf("No mail records found.")
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
			fmt.Printf("%s %s [ser=%d ref=%d ret=%d min=%d ttl=%d]\n",
				removeLastDot(soa.Ns),
				mboxToEmail(soa.Mbox),
				soa.Serial,
				soa.Refresh,
				soa.Retry,
				soa.Minttl,
				soa.Hdr.Ttl)
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

		// Final record lookup
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
	for _, ans := range result.Answer {
		switch rr := ans.(type) {
		case *dns.A:
			fmt.Printf("%s [ttl=%d]\n",
				rr.A.String(),
				rr.Hdr.Ttl)
		case *dns.AAAA:
			fmt.Printf("%s [ttl=%d]\n",
				rr.AAAA.String(),
				rr.Hdr.Ttl)
		}
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
		return fmt.Errorf("No SPF records found.")
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

func exchangeNAPTR(client *dns.Client, domain string, server string) (*dns.Msg, time.Duration, error) {
	return exchangeMsg(client, domain, server, dns.TypeNAPTR)
}

func handleNAPTR(client *dns.Client, result *dns.Msg, server string) error {
	found := false

	for _, ans := range result.Answer {
		if naptr, ok := ans.(*dns.NAPTR); ok {
			fmt.Printf(
				"%s [order=%d pref=%d flags=%s serv=%s regexp=%s ttl=%d]\n",
				naptr.Replacement,
				naptr.Order,
				naptr.Preference,
				naptr.Flags,
				naptr.Service,
				naptr.Regexp,
				naptr.Hdr.Ttl)

				found = true
		}
	}

	if !found {
		return fmt.Errorf("No NAPTR records found")
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

			// Default to alias mode
			priority := priorityLabelMap[0].Name

			if https.Priority > 0 {
				priority = priorityLabelMap[1].Name
			}

			fmt.Printf("%s [p=%s(%d) ttl=%d]\n\n",
				targetOutput,
				priority,
				https.Priority,
				https.Hdr.Ttl)

			// Values/parameters
			var numValues = len(https.Value)

			if numValues > 0 {
				for _, param := range https.Value {
					fmt.Printf("%11s=%v\n", param.Key(), param.String())
				}
			}
		}
	}

	return nil
}

func exchangeSVCB(client *dns.Client, domain string, server string) (*dns.Msg, time.Duration, error) {
	return exchangeMsg(client, domain, server, dns.TypeSVCB)
}

func handleSVCB(client *dns.Client, result *dns.Msg, server string) error {
	for _, ans := range result.Answer {
		if svcb, ok := ans.(*dns.SVCB); ok {
			targetOutput := svcb.Target

			// Change target to pseudonym root
			if targetOutput == "." {
				targetOutput = "<root>"
			}

			// Default to alias mode
			priority := priorityLabelMap[0].Name

			if svcb.Priority > 0 {
				priority = priorityLabelMap[1].Name
			}

			fmt.Printf("%s [p=%s(%d) ttl=%d]\n\n",
				targetOutput,
				priority,
				svcb.Priority,
				svcb.Hdr.Ttl)

			// Values/parameters
			var numValues = len(svcb.Value)

			if numValues > 0 {
				for _, param := range svcb.Value {
					fmt.Printf("%11s=%v\n", param.Key(), param.String())
				}
			}
		}
	}

	return nil
}

var srvRecord = "SRV"
var txtRecord = "TXT"
var ptrRecord = "PTR"
var soaRecord = "SOA"
var mxRecord = "MX"

var recordMap = map[string]record {
	"MX": { exchangeMX, handleMX, nil, "Mail server" },
	"MAIL": { exchangeMX, handleMX, &mxRecord, "Alias to MX" },
	"A": { exchangeA, handleA, nil, "IPv4 address" },
	"AAAA": { exchangeAAAA, handleAAAA, nil, "IPv6 address" },
	"SOA": { exchangeSOA, handleSOA, nil, "Start of authority" },
	"ORIGIN": { exchangeSOA, handleSOA, &soaRecord, "Alias to SOA" },
	"SRV": { exchangeSRV, handleSRV, nil, "Service" },
	"SIP": { exchangeSIPTCP, handleSRV, &srvRecord,"Alias to SIP TCP SRV" },
	"SIP-UDP": { exchangeSIPUDP, handleSRV, &srvRecord, "Alias to SIP UDP SRV" },
	"SIP-TLS": { exchangeSIPTLS, handleSRV, &srvRecord, "Alias to SIP TLS SRV" },
	"SIPS": { exchangeSIPS, handleSRV, &srvRecord, "Alias to SIPS SRV" },
	"SIPS-TLS": { exchangeSIPSTLS, handleSRV, &srvRecord, "Alias to SIPS TLS SRV" },
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
	"SVCB": { exchangeSVCB, handleSVCB, nil, "Service binding" },
	"NAPTR": { exchangeNAPTR, handleNAPTR, nil, "Name authority pointer" },
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

var priorityLabelMap = map[int]priorityLabel {
	0: { "alias" },
	1: { "service" },
}

func init() {
	const previousLine = "\x1B[1F"

	flag.BoolVar(&recursionLookup, "recursion", true, "Recursion lookup")
	flag.BoolVar(&listRecords, "records", false, "List record types")
	flag.BoolVar(&recursiveCNAMELookup, "recursive", false, "Recursive CNAME lookup")
	flag.StringVar(&targetServer, "server", "", "Target server")
	flag.StringVar(&targetServer, "s", "", previousLine)
	flag.BoolVar(&arpaLookup, "arpa", false, "Reverse lookup")
	flag.BoolVar(&listRatings, "ratings", false, "List ratings")
	flag.BoolVar(&showHelp, "help", false, "This help menu")
	flag.BoolVar(&showHelp, "h", false, "")
}

func main() {
	flag.Usage = func() {
		w := flag.CommandLine.Output()
		progname := filepath.Base(os.Args[0])

		fmt.Fprintf(w, "Usage: %s [-h -help] " +
			"[-arpa] [-records] [-ratings] " +
			"[-s -server <addr>] " +
			"<domain> " +
			"[record | alias]\n", progname)
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

		if showHelp {
			flag.PrintDefaults()
		}
		
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
		
		fmt.Printf("code=%d num=%d rtt=%dms [",
			result.Rcode,
			numAnswers,
			rtt.Milliseconds())
		colorPrintf(cat.Color, "%s", cat.Rating)
		fmt.Printf("]\n")

		// Exit with Rcode as code (scripts?)
		if result.Rcode != dns.RcodeSuccess {
			os.Exit(result.Rcode)
		}

		// Output records
		fmt.Printf("-\n")

		if herr := record.Handler(client, result, server); herr != nil {
			fmt.Fprintf(os.Stderr, "err: %v\n", herr)	
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
