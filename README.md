# f2b-report

`f2b-report` reads `fail2ban-client status <jail>` output from stdin and writes a simple HTML report to stdout.

If `geoiplookup` and `whois` are available, it also enriches each IP with country and network metadata and builds a country summary. The output is intentionally minimal and text-site-like.

## Install

```bash
go build -o f2b-report .
```

## Usage

Run directly:

```bash
fail2ban-client status sshd | go run . > report.html
```

Use the built binary:

```bash
fail2ban-client status sshd | ./f2b-report > report.html
```

Increase concurrency:

```bash
fail2ban-client status sshd | ./f2b-report -concurrency 16 > report.html
```

Open the result in a browser:

```bash
fail2ban-client status sshd | ./f2b-report > report.html
xdg-open report.html
```

## Input

Expected input is the output of `fail2ban-client status <jail>`, for example:

```text
Status for the jail: sshd
|- Filter
|  |- Currently failed: 9
|  |- Total failed:     136
`- Actions
   |- Currently banned: 217
   |- Total banned:     217
   `- Banned IP list:   1.2.3.4 5.6.7.8
```

## Output

The generated HTML can include:

- jail name
- currently failed / total failed
- currently banned / total banned
- banned IP list
- country data from `geoiplookup`
- country totals and percentages
- a lightweight inline SVG bar chart
- ASN / netname / organization from `whois`

The chart is embedded directly in the HTML. No separate image file is generated.

## Dependencies

Required:

- Go

Optional:

- `geoiplookup`
- `whois`

The report still renders if these commands are missing. Unavailable lookup fields are shown as `n/a`.

## Flags

- `-concurrency`
  - maximum number of concurrent IP enrichment workers
  - default: `8`

## Notes

- `whois` can be slow depending on the remote server and network conditions
- lookup failures are tolerated; one failed lookup does not stop the whole report
- `geoiplookup` country names depend on the local GeoIP database
- duplicate IPs in the input are deduplicated before reporting

## Development

Run tests:

```bash
GOCACHE=/tmp/go-build-cache go test ./...
```

Try the bundled sample input:

```bash
GOCACHE=/tmp/go-build-cache go run . < sample.txt > /tmp/f2b-report.html
```
