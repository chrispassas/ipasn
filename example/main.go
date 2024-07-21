package main

import (
	"context"
	"log"
	"time"

	"github.com/chrispassas/ipasn"
)

func main() {
	log.SetFlags(log.Ldate | log.Lmicroseconds | log.Lshortfile)

	var values = []string{
		// "1.1.1.0/24",
		// "8.8.8.8",
		// "9.9.9.9",
		// "AS13335",
		// "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
		"2607:f8b0:4005:801::200e",
		"1.1.1.1",
	}
	var results []ipasn.Result
	var err error
	var timer = time.Now()
	if results, err = ipasn.BulkSearch(context.Background(), values); err != nil {
		log.Fatalf("ipasn.BulkSearch() error:%v", err)
	}
	log.Printf("timer:%s", time.Since(timer))

	log.Printf("----------------------")
	log.Printf("Lookup via bulk")
	log.Printf("----------------------")
	for _, r := range results {
		log.Printf("----------------------")
		log.Printf("asn:%d", r.ASN)
		log.Printf("asname:%s", r.ASName)
		log.Printf("allocated:%s", r.Allocated)
		log.Printf("prefix:%s", r.BGPPrefix)
		log.Printf("cc:%s", r.CC)
		log.Printf("registry:%s", r.Registry)
		log.Printf("ip:%s", r.IP)
	}
	log.Printf("----------------------")
	log.Printf("----------------------")

	log.Printf("----------------------")
	log.Printf("Lookup via dns")
	log.Printf("----------------------")
	timer = time.Now()
	for _, v := range values {
		var r ipasn.Result
		if r, err = ipasn.SearchByIPString(context.Background(), v, true); err != nil {
			log.Fatalf("ipasn.Search() error:%v", err)
		}

		log.Printf("----------------------")
		log.Printf("asn:%d", r.ASN)
		log.Printf("asname:%s", r.ASName)
		log.Printf("allocated:%s", r.Allocated)
		log.Printf("prefix:%s", r.BGPPrefix)
		log.Printf("cc:%s", r.CC)
		log.Printf("registry:%s", r.Registry)
		log.Printf("ip:%s", r.IP)
	}
	log.Printf("timer:%s", time.Since(timer))

	log.Printf("----------------------")
	log.Printf("Lookup ASN via dns")
	log.Printf("----------------------")
	timer = time.Now()
	var asResult ipasn.ASResult
	if asResult, err = ipasn.SearchByASN(context.Background(), 23028); err != nil {
		log.Fatalf("ipasn.SearchByASN() error:%v", err)
	}
	log.Printf("asn:%d", asResult.ASN)
	log.Printf("cc:%s", asResult.CC)
	log.Printf("registry:%s", asResult.Registry)
	log.Printf("allocated:%s", asResult.Allocated)
	log.Printf("asname:%s", asResult.ASName)
	log.Printf("timer:%s", time.Since(timer))

}
