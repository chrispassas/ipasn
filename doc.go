/*
# IP to ASN Mapping Service
https://team-cymru.com/community-services/ip-asn-mapping

This Go Module supports bulk queries to the Team Cymru IP ASN Mapping Service.

Example:

	package main

	import (
		"context"
		"log"

		"github.com/chrispassas/ipasn"
	)

	func main() {
		log.SetFlags(log.Ldate | log.Lmicroseconds | log.Lshortfile)

		var values = []string{
			"1.1.1.0/24",
			"8.8.8.8",
			"9.9.9.9",
			"AS13335",
			"2001:0db8:85a3:0000:0000:8a2e:0370:7334",
		}
		var results []ipasn.Result
		var err error
		if results, err = ipasn.BulkSearch(context.Background(), values); err != nil {
			log.Fatalf("ipasn.Search() error:%v", err)
		}

		for _, r := range results {
			log.Printf("----------------------")
			log.Printf("asn:%d", r.ASN)
			log.Printf("asname:%s", r.ASName)
			log.Printf("allocated:%s", r.Allocated)
			log.Printf("prefix:%s", r.BGPPrefix)
			log.Printf("cc:%s", r.CC)
			log.Printf("registry:%s", r.Registry)
		}
	}
*/
package ipasn
