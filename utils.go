package main

import (
	"fmt"
	"sort"
	"net"
	"time"
	"strings"
	"strconv"

	"github.com/fatih/color"
)

func printRecordTypes() {
	keys := make([]string, 0, len(recordMap))

	// Records & aliases
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

		fmt.Printf("%10s %s\n",
			keyOutput,
			recordMap[key].Desc)
	}

	fmt.Printf("\n* = alias\n")
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
		cat.Color = color.RGB(255, 255, 255)
	case ms <= 10:
		cat.Rating = "excellent"
		cat.Desc = "Typically seen with local caching or very efficient resolvers"
		cat.Color = color.RGB(0, 128, 0)
	case ms <= 50:
		cat.Rating = "very good"
		cat.Desc = "Good performance, minimal impact on page load times"
		cat.Color = color.RGB(0, 128, 0)
	case ms <= 100:
		cat.Rating = "good"
		cat.Desc = "Acceptable for most websites, slight impact on performance"
		cat.Color = color.RGB(255, 255, 0)
	case ms <= 200:
		cat.Rating = "fair"
		cat.Desc = "Noticeable impact on page load times, consider optimization"
		cat.Color = color.RGB(255, 165, 0)
	case ms <= 500:
		cat.Rating = "poor"
		cat.Desc = "Significant impact on user experience, optimization recommended"
		cat.Color = color.RGB(240, 0, 0)
	default:
		cat.Rating = "very poor"
		cat.Desc = "Major performance issue, urgent optimization needed"
		cat.Color = color.RGB(255, 0, 0)
	}

	return cat
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

func colorPrintf(c *color.Color, format string, a ...any) {
	c.Printf(format, a...)
}
