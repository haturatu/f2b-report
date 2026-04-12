package main

import "testing"

func TestFirstCIDRNoMatch(t *testing.T) {
	if got := firstCIDR("no cidr or route fields here"); got != "" {
		t.Fatalf("expected empty result, got %q", got)
	}
}

func TestFirstCIDRMatch(t *testing.T) {
	input := "inetnum: 203.0.113.0 - 203.0.113.255\nnetname: EXAMPLE-NET"
	if got := firstCIDR(input); got != "203.0.113.0 - 203.0.113.255" {
		t.Fatalf("unexpected cidr/range: %q", got)
	}
}

func TestNormalizeCountry(t *testing.T) {
	if got := normalizeCountry("KR, Republic of Korea"); got != "Republic of Korea" {
		t.Fatalf("unexpected country: %q", got)
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
