//go:build legacygeoip && cgo

package main

import "github.com/abh/geoip"

type legacyCountryLookup interface {
	LookupCountry(ip string) string
}

type legacyCountryReader struct {
	db *geoip.GeoIP
}

func openLegacyCountryLookup(path string) (legacyCountryLookup, error) {
	db, err := geoip.Open(path, "")
	if err != nil {
		return nil, err
	}
	return &legacyCountryReader{db: db}, nil
}

func (r *legacyCountryReader) LookupCountry(ip string) string {
	if r == nil || r.db == nil {
		return ""
	}
	code, _ := r.db.GetCountry(ip)
	return cleanValue(code)
}
