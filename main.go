package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/fatih/color"
	"github.com/miekg/dns"
)

const (
	resolvConfPath = "/etc/resolv.conf"
	defaultRecordType = "A"
	defaultDNSPort = "53"
	spfPrefix = "vspf1"
 	unknown = "Unknown"
	cnameDepth = 15
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

var srvRecord = "SRV"
var txtRecord = "TXT"
var ptrRecord = "PTR"
var soaRecord = "SOA"
var mxRecord = "MX"
var organeColor = color.RGB(255, 160, 0)

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
	"TLSA": { exchangeTLSA, handleTLSA, nil, "DANE TLS authentication" },
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
		
		if numAnswers > 0 {
			fmt.Printf("-\n")
		}

		// Handle record
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
