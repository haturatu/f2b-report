package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var validSource = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

type snapshotIP struct {
	IP           string  `json:"ip"`
	Country      *string `json:"country"`
	ASN          *uint32 `json:"asn"`
	Organization *string `json:"organization"`
	Network      *string `json:"network"`
}

type snapshot struct {
	SchemaVersion   int          `json:"schema_version"`
	Source          string       `json:"source"`
	Jail            string       `json:"jail"`
	ObservedAt      string       `json:"observed_at"`
	CurrentlyBanned int          `json:"currently_banned"`
	TotalBanned     int          `json:"total_banned"`
	IPs             []snapshotIP `json:"ips"`
}

func nonempty(value string) *string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	return &value
}

func makeSnapshot(data reportData, source string) (snapshot, error) {
	observed, err := time.Parse(time.RFC3339, data.GeneratedAt)
	if err != nil {
		return snapshot{}, err
	}
	result := snapshot{1, source, data.Jail, observed.UTC().Format(time.RFC3339), data.CurrentlyBanned, data.TotalBanned, make([]snapshotIP, 0, len(data.IPs))}
	seen := map[string]bool{}
	for _, record := range data.IPs {
		address, err := netip.ParseAddr(record.Address)
		if err != nil {
			return snapshot{}, fmt.Errorf("invalid address: %w", err)
		}
		ip := address.Unmap().String()
		if seen[ip] {
			continue
		}
		seen[ip] = true
		item := snapshotIP{IP: ip, Organization: nonempty(record.Org), Network: nonempty(record.NetName)}
		code := strings.ToUpper(strings.TrimSpace(strings.SplitN(record.Country, ",", 2)[0]))
		if len(code) == 2 && code[0] >= 'A' && code[0] <= 'Z' && code[1] >= 'A' && code[1] <= 'Z' {
			item.Country = &code
		}
		if value, err := strconv.ParseUint(strings.TrimPrefix(strings.ToUpper(record.ASN), "AS"), 10, 32); err == nil && value > 0 {
			asn := uint32(value)
			item.ASN = &asn
		}
		result.IPs = append(result.IPs, item)
	}
	return result, nil
}

func encodeSnapshot(writer io.Writer, data snapshot) error {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(data)
}

func writeSnapshot(path string, data snapshot) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".f2b-snapshot-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if err := encodeSnapshot(file, data); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}
