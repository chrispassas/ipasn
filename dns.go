package ipasn

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	tcIPv4ASNDomain  = "origin.asn.cymru.com"
	tcIPv6ASNDomain  = "origin6.asn.cymru.com"
	tcIPv6PeerDomain = "peer.asn.cymru.com"
	tcIPASNDomain    = "asn.cymru.com"
)

type ASResult struct {
	ASN       int    `json:"asn"`
	CC        string `json:"cc"`
	Registry  string `json:"registry"`
	Allocated string `json:"allocated"`
	ASName    string `json:"as_name"`
}

// SearchByASN search by ASN
func SearchByASN(ctx context.Context, asn int) (result ASResult, err error) {

	domain := convertIPToDNSASN(asn)
	var asnResults []string
	if asnResults, err = lookupTXT(ctx, domain); err != nil {
		return result, ErrASNLookupFailed
	}
	var pipe = []byte("|")
	asnResultsBytes := []byte(asnResults[0])
	pieces := bytes.Split(asnResultsBytes, pipe)
	if result, err = dnsASNResult(pieces); err != nil {
		return result, ErrASNLookupFailed
	}
	return result, err
}

// SearchByIPString get Result for IP using dns API, asname true makes an extra dns lookup to populate the asname
func SearchByIPString(ctx context.Context, ipStr string, asname bool) (result Result, err error) {
	var ip net.IP
	if ip = net.ParseIP(ipStr); ip == nil {
		err = ErrIPNotValid
		return result, err
	}

	result, err = SearchByIP(ctx, ip, asname)

	return result, err
}

// SearchByIP get Result for IP using dns API, asname true makes an extra dns lookup to populate the asname
func SearchByIP(ctx context.Context, ip net.IP, asname bool) (result Result, err error) {

	name := convertIPToDNS(ip)

	var results []string
	if results, err = lookupTXT(ctx, name); err != nil {
		err = fmt.Errorf("lookupTXT() error:%w", err)
		return result, err
	}

	var pipe = []byte("|")
	pieces := bytes.Split([]byte(results[0]), pipe)

	if result, err = dnsIPResult(ip, pieces); err != nil {
		return result, err
	}

	if result.ASN > 0 && asname {
		domain := convertIPToDNSASN(result.ASN)
		var asnResults []string
		if asnResults, err = lookupTXT(ctx, domain); err != nil {
			return result, ErrASNLookupFailed
		}
		var pipe = []byte("|")
		asnResultsBytes := []byte(asnResults[0])
		pieces := bytes.Split(asnResultsBytes, pipe)
		var tmpASNResult ASResult
		if tmpASNResult, err = dnsASNResult(pieces); err != nil {
			return result, ErrASNLookupFailed
		}
		result.ASName = tmpASNResult.ASName
	}

	return result, err
}

func dnsASNResult(pieces [][]byte) (result ASResult, err error) {
	if len(pieces) != 5 {
		err = ErrUnexpectedFormat
		return result, err
	}

	for x, p := range pieces {
		p = bytes.TrimSpace(p)
		switch x {
		case 0:
			// If no data it seems API returns "NA" in this field
			if string(p) == "NA" {
				break
			}

			if result.ASN, err = strconv.Atoi(string(p)); err != nil {
				err = fmt.Errorf("failed parsing asn %w", err)
				return result, err
			}
		case 1:
			result.CC = string(p)
		case 2:
			result.Registry = string(p)
		case 3:
			result.Allocated = string(p)
		case 4:
			result.ASName = string(p)
		}
	}

	return result, err
}

func dnsIPResult(ip net.IP, pieces [][]byte) (result Result, err error) {
	if len(pieces) != 5 {
		err = ErrUnexpectedFormat
		return result, err
	}

	result.IP = ip.String()

	for x, p := range pieces {
		p = bytes.TrimSpace(p)
		switch x {
		case 0:
			// If no data it seems API returns "NA" in this field
			if string(p) == "NA" {
				break
			}

			if result.ASN, err = strconv.Atoi(string(p)); err != nil {
				err = fmt.Errorf("failed parsing asn %w", err)
				return result, err
			}
		case 1:
			result.BGPPrefix = string(p)
		case 2:
			result.CC = string(p)
		case 3:
			result.Registry = string(p)
		case 4:
			result.Allocated = string(p)
		}
	}

	return result, err
}

func convertIPToDNSASN(asn int) (name string) {
	name = fmt.Sprintf("as%d.%s", asn, tcIPASNDomain)
	return name
}

func convertIPToDNS(ip net.IP) (name string) {

	if ip.To4() != nil { // IPv4
		pieces := strings.Split(ip.To4().String(), ".")
		slices.Reverse(pieces)
		for x, p := range pieces {
			if x == 0 {
				name = p
			} else {
				name += "." + p
			}
		}
		name += "." + tcIPv4ASNDomain
	} else { // IPv6
		ipStrNoColons := strings.ReplaceAll(ip.To16().String(), ":", "")
		pieces := reverseString(ipStrNoColons)
		for x, p := range pieces {
			if x == 0 {
				name = p
			} else {
				name += "." + p
			}
		}
		name += "." + tcIPv6ASNDomain
	}

	return name
}

func reverseString(s string) []string {
	runes := []rune(s)
	n := len(runes)

	// Reverse the string
	for i := 0; i < n/2; i++ {
		runes[i], runes[n-i-1] = runes[n-i-1], runes[i]
	}

	// Convert runes to slice of strings
	result := make([]string, n)
	for i, r := range runes {
		result[i] = string(r)
	}

	return result
}

// lookupTXT performs a TXT record lookup for the given domain.
func lookupTXT(ctx context.Context, domain string) ([]string, error) {
	// Custom dialer with context
	dialer := &net.Dialer{
		Timeout: 2 * time.Second,
	}

	// Custom resolver with the dialer
	resolver := &net.Resolver{
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, address)
		},
	}

	// Perform the lookup
	txtRecords, err := resolver.LookupTXT(ctx, domain)
	if err != nil {
		return nil, err
	}

	return txtRecords, nil
}
