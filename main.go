package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"net"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type reportData struct {
	GeneratedAt     string
	Jail            string
	CurrentlyFailed int
	TotalFailed     int
	CurrentlyBanned int
	TotalBanned     int
	IPs             []ipRecord
	Countries       []countryStat
	CountryChart    template.HTML
	HasLookupData   bool
}

type ipRecord struct {
	Address string
	Country string
	ASN     string
	NetName string
	Org     string
}

type countryStat struct {
	Name    string
	Count   int
	Percent string
}

var (
	reDigits = regexp.MustCompile(`\d+`)
	reCIDR   = regexp.MustCompile(`(?i)\broute:\s*([0-9./:]+)|\broute6:\s*([0-9./:]+)|\bcidr:\s*([0-9./:]+)|\binetnum:\s*([0-9./:]+ - [0-9./:]+)|\bnetrange:\s*([0-9./:]+ - [0-9./:]+)`)
)

func main() {
	concurrency := flag.Int("concurrency", 8, "max concurrent IP enrichments")
	flag.Parse()

	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		exitf("failed to read stdin: %v", err)
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		exitf("stdin is empty")
	}

	data, err := parseStatus(string(raw))
	if err != nil {
		exitf("failed to parse fail2ban status: %v", err)
	}

	annotateIPs(&data, *concurrency)
	data.Countries = summarizeCountries(data.IPs)
	data.CountryChart = renderCountryChart(data.Countries)
	data.GeneratedAt = time.Now().Format(time.RFC3339)

	if err := pageTemplate.Execute(os.Stdout, data); err != nil {
		exitf("failed to render html: %v", err)
	}
}

func parseStatus(input string) (reportData, error) {
	var data reportData
	lines := splitLines(input)
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "Status for the jail:"):
			data.Jail = strings.TrimSpace(strings.TrimPrefix(trimmed, "Status for the jail:"))
		case strings.Contains(trimmed, "Currently failed:"):
			data.CurrentlyFailed = extractInt(trimmed)
		case strings.Contains(trimmed, "Total failed:"):
			data.TotalFailed = extractInt(trimmed)
		case strings.Contains(trimmed, "Currently banned:"):
			data.CurrentlyBanned = extractInt(trimmed)
		case strings.Contains(trimmed, "Total banned:"):
			data.TotalBanned = extractInt(trimmed)
		case strings.Contains(trimmed, "Banned IP list:"):
			rest := strings.TrimSpace(strings.SplitN(trimmed, "Banned IP list:", 2)[1])
			data.IPs = append(data.IPs, parseIPs(rest)...)
		default:
			if len(data.IPs) > 0 && looksLikeIPListContinuation(trimmed) {
				data.IPs = append(data.IPs, parseIPs(trimmed)...)
			}
		}
	}

	data.IPs = uniqueAndSortIPs(data.IPs)
	if data.Jail == "" {
		return data, errors.New("missing jail name")
	}
	if len(data.IPs) == 0 {
		return data, errors.New("no banned IPs found")
	}
	return data, nil
}

func splitLines(s string) []string {
	scanner := bufio.NewScanner(strings.NewReader(s))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lines := make([]string, 0, 32)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines
}

func extractInt(s string) int {
	match := reDigits.FindString(s)
	if match == "" {
		return 0
	}
	n, _ := strconv.Atoi(match)
	return n
}

func parseIPs(s string) []ipRecord {
	fields := strings.Fields(s)
	out := make([]ipRecord, 0, len(fields))
	for _, field := range fields {
		if ip := net.ParseIP(field); ip != nil {
			out = append(out, ipRecord{Address: field})
		}
	}
	return out
}

func looksLikeIPListContinuation(s string) bool {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return false
	}
	valid := 0
	for _, field := range fields {
		if net.ParseIP(field) != nil {
			valid++
		}
	}
	return valid > 0 && valid == len(fields)
}

func uniqueAndSortIPs(in []ipRecord) []ipRecord {
	seen := make(map[string]struct{}, len(in))
	out := make([]ipRecord, 0, len(in))
	for _, rec := range in {
		if _, ok := seen[rec.Address]; ok {
			continue
		}
		seen[rec.Address] = struct{}{}
		out = append(out, rec)
	}
	sort.Slice(out, func(i, j int) bool {
		return compareIP(out[i].Address, out[j].Address) < 0
	})
	return out
}

func compareIP(a, b string) int {
	ab := net.ParseIP(a).To16()
	bb := net.ParseIP(b).To16()
	return bytes.Compare(ab, bb)
}

func annotateIPs(data *reportData, concurrency int) {
	hasGeo := commandExists("geoiplookup")
	hasWhois := commandExists("whois")
	if !hasGeo && !hasWhois {
		return
	}
	if concurrency < 1 {
		concurrency = 1
	}

	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	for i := range data.IPs {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			rec := data.IPs[idx]
			var innerWG sync.WaitGroup
			if hasGeo {
				innerWG.Add(1)
				go func() {
					defer innerWG.Done()
					rec.Country = geoLookup(rec.Address)
				}()
			}
			if hasWhois {
				innerWG.Add(1)
				go func() {
					defer innerWG.Done()
					rec.ASN, rec.NetName, rec.Org = whoisLookup(rec.Address)
				}()
			}
			innerWG.Wait()
			mu.Lock()
			if rec.Country != "" || rec.ASN != "" || rec.NetName != "" || rec.Org != "" {
				data.HasLookupData = true
			}
			data.IPs[idx] = rec
			mu.Unlock()
		}(i)
	}
	wg.Wait()
}

func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func geoLookup(ip string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "geoiplookup", ip).CombinedOutput()
	if err != nil {
		return ""
	}
	line := strings.TrimSpace(string(out))
	if idx := strings.Index(line, ":"); idx >= 0 {
		line = strings.TrimSpace(line[idx+1:])
	}
	line = strings.TrimPrefix(line, "GeoIP Country Edition:")
	line = strings.TrimSpace(line)
	if strings.HasPrefix(strings.ToUpper(line), "IP ADDRESS NOT FOUND") {
		return ""
	}
	return line
}

func summarizeCountries(ips []ipRecord) []countryStat {
	counts := map[string]int{}
	total := 0
	for _, ip := range ips {
		name := normalizeCountry(ip.Country)
		if name == "" {
			name = "Unknown"
		}
		counts[name]++
		total++
	}
	if total == 0 {
		return nil
	}

	stats := make([]countryStat, 0, len(counts))
	for name, count := range counts {
		stats = append(stats, countryStat{
			Name:    name,
			Count:   count,
			Percent: fmt.Sprintf("%.1f%%", float64(count)*100/float64(total)),
		})
	}
	sort.Slice(stats, func(i, j int) bool {
		if stats[i].Count == stats[j].Count {
			return stats[i].Name < stats[j].Name
		}
		return stats[i].Count > stats[j].Count
	})
	return stats
}

func normalizeCountry(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	parts := strings.Split(raw, ",")
	if len(parts) == 1 {
		return raw
	}
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	if len(parts[0]) <= 3 {
		name := strings.TrimSpace(strings.Join(parts[1:], ", "))
		if name != "" {
			return name
		}
	}
	return raw
}

func renderCountryChart(stats []countryStat) template.HTML {
	if len(stats) == 0 {
		return ""
	}

	maxCount := stats[0].Count
	if maxCount < 1 {
		maxCount = 1
	}
	barHeight := 18
	gap := 8
	leftPad := 120
	rightPad := 60
	width := 720
	height := len(stats)*(barHeight+gap) + 20

	var b strings.Builder
	fmt.Fprintf(&b, `<svg viewBox="0 0 %d %d" width="100%%" height="%d" role="img" aria-label="Banned IPs by country" xmlns="http://www.w3.org/2000/svg">`, width, height, height)
	fmt.Fprintf(&b, `<style>text{font-family:monospace;font-size:12px;fill:#111} .bar{fill:#444}</style>`)
	y := 16
	for _, stat := range stats {
		barWidth := int(float64(width-leftPad-rightPad) * float64(stat.Count) / float64(maxCount))
		label := template.HTMLEscapeString(stat.Name)
		fmt.Fprintf(&b, `<text x="0" y="%d">%s</text>`, y+12, label)
		fmt.Fprintf(&b, `<rect class="bar" x="%d" y="%d" width="%d" height="%d"/>`, leftPad, y, barWidth, barHeight)
		fmt.Fprintf(&b, `<text x="%d" y="%d">%d</text>`, leftPad+barWidth+8, y+12, stat.Count)
		y += barHeight + gap
	}
	b.WriteString(`</svg>`)
	return template.HTML(b.String())
}

func whoisLookup(ip string) (asn, netname, org string) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "whois", ip).CombinedOutput()
	if err != nil {
		return "", "", ""
	}

	lines := splitLines(string(out))
	for _, line := range lines {
		key, value, ok := splitField(line)
		if !ok {
			continue
		}
		switch strings.ToLower(key) {
		case "origin", "originas", "aut-num":
			if asn == "" {
				asn = value
			}
		case "netname":
			if netname == "" {
				netname = value
			}
		case "orgname", "org-name", "org", "organisation", "organization", "owner", "descr":
			if org == "" {
				org = value
			}
		}
	}

	if asn == "" {
		asn = firstASN(string(out))
	}
	if netname == "" {
		netname = firstCIDR(string(out))
	}
	return cleanValue(asn), cleanValue(netname), cleanValue(org)
}

func splitField(line string) (key, value string, ok bool) {
	if strings.HasPrefix(strings.TrimSpace(line), "%") || strings.HasPrefix(strings.TrimSpace(line), "#") {
		return "", "", false
	}
	idx := strings.Index(line, ":")
	if idx < 0 {
		return "", "", false
	}
	key = strings.TrimSpace(line[:idx])
	value = strings.TrimSpace(line[idx+1:])
	if key == "" || value == "" {
		return "", "", false
	}
	return key, value, true
}

func firstASN(s string) string {
	for _, line := range splitLines(s) {
		upper := strings.ToUpper(strings.TrimSpace(line))
		idx := strings.Index(upper, "AS")
		if idx < 0 {
			continue
		}
		word := strings.Fields(upper[idx:])
		if len(word) > 0 && strings.HasPrefix(word[0], "AS") {
			return word[0]
		}
	}
	return ""
}

func firstCIDR(s string) string {
	match := reCIDR.FindStringSubmatch(s)
	if len(match) < 2 {
		return ""
	}
	for _, part := range match[1:] {
		if strings.TrimSpace(part) != "" {
			return strings.TrimSpace(part)
		}
	}
	return ""
}

func cleanValue(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, ",")
	return s
}

func exitf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

var pageTemplate = template.Must(template.New("report").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>fail2ban report - {{.Jail}}</title>
  <style>
    body {
      margin: 0 auto;
      max-width: 980px;
      padding: 16px;
      line-height: 1.45;
      font-family: monospace;
      color: #111;
      background: #fff;
    }
    h1, h2 { margin: 1.2em 0 0.5em; font-size: 1.1rem; }
    h1 { margin-top: 0; font-size: 1.3rem; }
    p, pre { margin: 0.5em 0; }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.95rem;
    }
    th, td {
      text-align: left;
      padding: 4px 6px;
      border-bottom: 1px solid #ddd;
      vertical-align: top;
    }
    th { font-weight: 700; }
    code { font-family: monospace; }
    .meta { white-space: pre-wrap; }
    .chart { border: 1px solid #ddd; padding: 8px; }
    .muted { color: #555; }
  </style>
</head>
<body>
  <h1>fail2ban report: {{.Jail}}</h1>
  <pre class="meta">generated_at: {{.GeneratedAt}}
currently_failed: {{.CurrentlyFailed}}
total_failed: {{.TotalFailed}}
currently_banned: {{.CurrentlyBanned}}
total_banned: {{.TotalBanned}}
unique_banned_ips: {{len .IPs}}
lookup_data: {{if .HasLookupData}}enabled{{else}}none{{end}}</pre>

  <h2>country summary</h2>
  {{if .Countries}}
  <div class="chart">{{.CountryChart}}</div>
  <table>
    <thead>
      <tr>
        <th>country</th>
        <th>count</th>
        <th>share</th>
      </tr>
    </thead>
    <tbody>
      {{range .Countries}}
      <tr>
        <td>{{.Name}}</td>
        <td>{{.Count}}</td>
        <td>{{.Percent}}</td>
      </tr>
      {{end}}
    </tbody>
  </table>
  {{else}}
  <p class="muted">no country data</p>
  {{end}}

  <h2>ip details</h2>
  <table>
    <thead>
      <tr>
        <th>ip</th>
        <th>country</th>
        <th>asn</th>
        <th>net</th>
        <th>organization</th>
      </tr>
    </thead>
    <tbody>
      {{range .IPs}}
      <tr>
        <td><code>{{.Address}}</code></td>
        <td>{{if .Country}}{{.Country}}{{else}}n/a{{end}}</td>
        <td>{{if .ASN}}{{.ASN}}{{else}}n/a{{end}}</td>
        <td>{{if .NetName}}{{.NetName}}{{else}}n/a{{end}}</td>
        <td>{{if .Org}}{{.Org}}{{else}}n/a{{end}}</td>
      </tr>
      {{end}}
    </tbody>
  </table>

  <p class="muted">missing lookup results are rendered as n/a. geo source: <code>geoiplookup</code>. network source: <code>whois</code>.</p>
</body>
</html>`))
