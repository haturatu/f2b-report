//go:build !legacygeoip || !cgo

package main

import "errors"

type legacyCountryLookup interface {
	LookupCountry(ip string) string
}

func openLegacyCountryLookup(_ string) (legacyCountryLookup, error) {
	return nil, errors.New("legacy GeoIP support is disabled; rebuild with -tags legacygeoip and cgo/libGeoIP available")
}
