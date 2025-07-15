package main

import (
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type exchangeFunc func(client *dns.Client, domain string, server string) (*dns.Msg, time.Duration, error)
type handlerFunc func(client *dns.Client, result *dns.Msg, server string) error

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
			fmt.Printf("%s %s [ser=",
				removeLastDot(soa.Ns),
				mboxToEmail(soa.Mbox))

			colorPrintf(serColor, "%d", soa.Serial)

			fmt.Printf(" ref=%d ret=%d min=%d ttl=%d]\n",
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
				
				// CNAMEs all the way down
				if recursiveCNAMELookup {
					msg := makeMsg(current, dns.TypeCNAME)
					nextResult, _, err := client.Exchange(msg, server)

					if err != nil {
						return err
					}

					result = nextResult
					foundCNAME = true
				} 
			
				// CNAME target will be next record lookup
				current = cname.Target
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
			alg := ""
			typ := ""

			// Check for SSHFP algorithm and type labels
			if int(sshfp.Algorithm) < len(sshfpAlgorithms) {
				alg = sshfpAlgorithms[sshfp.Algorithm].Name
			} else {
				alg = fmt.Sprintf("%s(%d)",
					unknown,
					sshfp.Algorithm)
			}

			if int(sshfp.Type) < len(sshfpTypes) {
				typ = sshfpTypes[sshfp.Type].Name
			} else {
				typ = fmt.Sprintf("%s(%d)",
					unknown,
					sshfp.Type)
			}

			fmt.Printf("%s %s %s [ttl=%d]\n",
				alg,
				typ,
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
