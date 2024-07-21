[![Go Reference](https://pkg.go.dev/badge/github.com/chrispassas/ipasn.svg)](https://pkg.go.dev/github.com/chrispassas/ipasn) [![Go Report Card](https://goreportcard.com/badge/github.com/chrispassas/ipasn)](https://goreportcard.com/report/github.com/chrispassas/ipasn)


# IP to ASN Mapping Service
https://team-cymru.com/community-services/ip-asn-mapping

This Go Module supports bulk queries to the Team Cymru IP ASN Mapping Service.

## Description
Using this module you can submit IPv4, IPv6 or ASN's and get BGP data.

## Go Doc
https://pkg.go.dev/github.com/chrispassas/ipasn



## Example - Lookup using whois protocol

```go
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

```



## Example - Lookup using dns

```go
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
		"2001:0db8:85a3:0000:0000:8a2e:0370:7334",
	}

	for _, v := range values {
		var r ipasn.Result
		if r, err = ipasn.SearchByIPString(context.Background(), v); err != nil {
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
}

```

## Example - Lookup ASN using dns

```go
package main

import (
	"context"
	"log"

	"github.com/chrispassas/ipasn"
)

func main() {
	log.SetFlags(log.Ldate | log.Lmicroseconds | log.Lshortfile)
	var r ipasn.Result
	var err error
	if r, err = ipasn.SearchByIPString(context.Background(), 23028, true); err != nil {
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
```