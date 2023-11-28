package ipasn

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
)

// AS      | CC | Registry | Allocated  | AS Name

// Result represents the data returned from mhr api per-submitted hash
type Result struct {
	ASN       int    `json:"asn"`
	IP        string `json:"ip"`
	BGPPrefix string `json:"bgp_prefix"`
	CC        string `json:"cc"`
	Registry  string `json:"registry"`
	Allocated string `json:"allocated"`
	ASName    string `json:"as_name"`
}

var (
	// ErrMaxBatchSize max batch size 1000 exceeded
	ErrMaxBatchSize = fmt.Errorf("Exceeded max per-request of 1,000")
)

// func Search(ctx context.Context, ipStr string) (result Result, err error) {

// 	if ip := net.ParseIP(ip); ip == nil {
// 		err = fmt.Errorf("not a valid ip")
// 		return result, err
// 	}

// 	return result, err
// }

// func convertIPToDNS(ip string) (name string) {

// 	return name
// }

// func lookupTXT(ctx context.Context, name string) ([]string, error) {
// 	r := &net.Resolver{
// 		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
// 			d := net.Dialer{
// 				Timeout: time.Second * 2,
// 			}
// 			return d.DialContext(ctx, network, "localhost:53")
// 		},
// 	}
// 	return r.LookupTXT(ctx, name)
// }

// BulkSearch submit IP, CIDR, ASN bulk search
func BulkSearch(ctx context.Context, values []string) (results []Result, err error) {

	if len(values) > 1000 {
		err = ErrMaxBatchSize
		return results, err
	}

	var (
		d        = &net.Dialer{}
		conn     net.Conn
		message  []byte
		response []byte
	)

	if conn, err = d.DialContext(ctx, "tcp", "whois.cymru.com:43"); err != nil {
		err = fmt.Errorf("d.DialContext() error:%w", err)
		return results, err
	}
	defer conn.Close()

	message = createMessage(values)
	var n int
	if n, err = conn.Write(message); err != nil {
		err = fmt.Errorf("conn.Write() n:%d error:%w", n, err)
		return results, err
	}

	if response, err = io.ReadAll(conn); err != nil {
		err = fmt.Errorf("io.ReadAll() error:%w", err)
		return results, err
	}

	// log.Printf("%s", string(response))

	results, err = parseResponse(response)

	return results, err
}

func parseResponse(response []byte) (results []Result, err error) {
	var pipe = []byte("|")
	for _, line := range bytes.Split(response, []byte("\n")) {
		// log.Printf("line:%s", string(line))

		pieces := bytes.Split(line, pipe)
		var result Result

		if bytes.HasPrefix(line, []byte("Bulk mode;")) {
			continue
		}

		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}

		switch len(pieces) {
		case 5:
			if result, err = asnResult(pieces); err != nil {
				return results, err
			}
		case 7:
			if result, err = ipResult(pieces); err != nil {
				return results, err
			}
		default:
			// continue
			err = fmt.Errorf("Unexpected response:%s", string(line))
			return results, err
		}

		results = append(results, result)
	}

	return results, err
}

func asnResult(pieces [][]byte) (result Result, err error) {

	for x, p := range pieces {
		p = bytes.TrimSpace(p)

		switch x {
		case 0:
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

func ipResult(pieces [][]byte) (result Result, err error) {

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
			result.IP = string(p)
		case 2:
			result.BGPPrefix = string(p)
		case 3:
			result.CC = string(p)
		case 4:
			result.Registry = string(p)
		case 5:
			result.Allocated = string(p)
		case 6:
			result.ASName = string(p)
		}
	}

	return result, err
}

func createMessage(ips []string) (message []byte) {
	var msg bytes.Buffer
	msg.WriteString("begin\n")
	msg.WriteString("verbose\n")

	for _, ip := range ips {
		msg.WriteString(ip + "\n")
	}

	msg.WriteString("end\n")
	message = msg.Bytes()
	return message
}
