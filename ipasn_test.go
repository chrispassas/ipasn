package ipasn

import (
	"context"
	"errors"
	"testing"
)

func TestBulkSearch_RejectsInjectedNewline(t *testing.T) {
	// A value containing an embedded newline could inject extra whois
	// protocol commands (e.g. "end"/"begin") into the bulk request stream.
	// BulkSearch must reject it before ever dialing whois.cymru.com.
	values := []string{"1.1.1.1", "1.2.3.4\nend\nbegin\nverbose\n8.8.8.8"}

	_, err := BulkSearch(context.Background(), values)
	if !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("expected ErrInvalidValue, got %v", err)
	}
}

func TestValidateBulkValues(t *testing.T) {
	tests := []struct {
		name    string
		values  []string
		wantErr bool
	}{
		{name: "valid ip and asn", values: []string{"1.1.1.1", "AS15169"}, wantErr: false},
		{name: "embedded newline", values: []string{"1.1.1.1\n8.8.8.8"}, wantErr: true},
		{name: "embedded carriage return", values: []string{"1.1.1.1\r8.8.8.8"}, wantErr: true},
		{name: "empty slice", values: []string{}, wantErr: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateBulkValues(tt.values)
			if tt.wantErr && !errors.Is(err, ErrInvalidValue) {
				t.Fatalf("expected ErrInvalidValue, got %v", err)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
		})
	}
}

func TestParseResponse_UnexpectedFormat(t *testing.T) {
	// A line that doesn't split into 5 (ASN) or 7 (IP) pipe-delimited pieces
	// should surface as the ErrUnexpectedFormat sentinel so callers can use
	// errors.Is(), matching the behavior of the DNS-based search functions.
	response := []byte("this is not a valid response line\n")

	_, err := parseResponse(response)
	if !errors.Is(err, ErrUnexpectedFormat) {
		t.Fatalf("expected ErrUnexpectedFormat, got %v", err)
	}
}

func TestParseResponse_ASNAndIPResults(t *testing.T) {
	response := []byte(
		"15169   | US | arin     | 2000-03-30 | GOOGLE - Google LLC, US\n" +
			"15169   | 8.8.8.8          | 8.8.8.0/24          | US | arin     | 2000-03-30 | GOOGLE - Google LLC, US\n",
	)

	results, err := parseResponse(response)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	if results[0].ASN != 15169 || results[0].ASName != "GOOGLE - Google LLC, US" {
		t.Fatalf("unexpected asn result: %+v", results[0])
	}
	if results[1].IP != "8.8.8.8" || results[1].BGPPrefix != "8.8.8.0/24" {
		t.Fatalf("unexpected ip result: %+v", results[1])
	}
}
