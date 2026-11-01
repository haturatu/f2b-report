package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestIncompleteSnapshotCannotDeactivateRemoteBans(t *testing.T) {
	if _, err := makeSnapshot(reportData{Jail: "sshd", GeneratedAt: "2026-11-01T11:00:00Z", CurrentlyBanned: 2}, "oci"); err == nil {
		t.Fatal("a truncated IP list must not become an empty remote snapshot")
	}
	if _, err := parseStatus("Status for the jail: sshd\n"); err == nil {
		t.Fatal("missing action status must not become a zero-ban report")
	}
}

func TestSnapshotNormalizesMetadataAndAddresses(t *testing.T) {
	data := reportData{Jail: "sshd", GeneratedAt: "2026-11-01T20:00:00+09:00", CurrentlyBanned: 3, IPs: []ipRecord{
		{Address: "::ffff:1.1.1.1", Country: "AU, Australia", ASN: "AS13335", Org: "Cloudflare"},
		{Address: "1.1.1.1"}, {Address: "2001:4860:4860:0:0:0:0:8888"},
	}}
	got, err := makeSnapshot(data, "freebsd")
	if err != nil {
		t.Fatal(err)
	}
	if got.ObservedAt != "2026-11-01T11:00:00Z" || len(got.IPs) != 2 || got.IPs[0].IP != "1.1.1.1" || got.IPs[1].IP != "2001:4860:4860::8888" {
		t.Fatalf("invalid normalized snapshot: %+v", got)
	}
	if *got.IPs[0].Country != "AU" || *got.IPs[0].ASN != 13335 || got.IPs[1].ASN != nil {
		t.Fatalf("invalid metadata: %+v", got.IPs)
	}
}

func TestEmptySnapshotWritesArrayAndPrivateFile(t *testing.T) {
	data, err := makeSnapshot(reportData{Jail: "nginx", GeneratedAt: "2026-11-01T11:00:00Z"}, "oci")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "snapshot.json")
	if err := writeSnapshot(path, data); err != nil {
		t.Fatal(err)
	}
	file, _ := os.ReadFile(path)
	var decoded map[string]any
	if err := json.Unmarshal(file, &decoded); err != nil {
		t.Fatal(err)
	}
	if values, ok := decoded["ips"].([]any); !ok || len(values) != 0 {
		t.Fatalf("empty ips must be an array: %s", file)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatalf("snapshot permissions: %o", info.Mode().Perm())
	}
}
