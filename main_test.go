package main

import "testing"

func TestNormalizeCountry(t *testing.T) {
	if got := normalizeCountry("KR, Republic of Korea"); got != "Republic of Korea" {
		t.Fatalf("unexpected country: %q", got)
	}
	if got := normalizeCountry("KR"); got != "KR" {
		t.Fatalf("unexpected legacy country code: %q", got)
	}
}

func TestSummarizeCountries(t *testing.T) {
	ips := []ipRecord{
		{Address: "1.1.1.1", Country: "US, United States"},
		{Address: "8.8.8.8", Country: "US, United States"},
		{Address: "9.9.9.9", Country: "JP, Japan"},
		{Address: "2.2.2.2", Country: ""},
	}

	stats := summarizeCountries(ips)
	if len(stats) != 3 {
		t.Fatalf("unexpected stats length: %d", len(stats))
	}
	if stats[0].Name != "United States" || stats[0].Count != 2 {
		t.Fatalf("unexpected top country: %+v", stats[0])
	}
	if stats[1].Name != "Japan" || stats[1].Count != 1 {
		t.Fatalf("unexpected second country: %+v", stats[1])
	}
	if stats[2].Name != "Unknown" || stats[2].Count != 1 {
		t.Fatalf("unexpected unknown country: %+v", stats[2])
	}
}

func TestIPRange(t *testing.T) {
	if got := ipRange("203.0.113.0", "203.0.113.255"); got != "203.0.113.0 - 203.0.113.255" {
		t.Fatalf("unexpected range: %q", got)
	}
}
