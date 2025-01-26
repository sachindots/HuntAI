# Reconnaissance Methodology

## Passive (no packets to target)
- Subdomain enumeration via certificate transparency, passive DNS: `subfinder`.
- WHOIS / ASN / netblock ownership.
- Public exposure: search engines, code leaks, S3 buckets.

## Active (packets to target — requires approval)
- Port discovery: `naabu` (fast top-ports) then `nmap -sV` for service/version.
- HTTP probing: `httpx` for live hosts, titles, tech stack, status codes.
- Content discovery: `ffuf` / `feroxbuster` on discovered web roots.
- Vulnerability templates: `nuclei` (tag by severity, start info/low).

## Order of operations
1. Passive subdomain + OSINT.
2. Resolve + port scan the in-scope hosts.
3. Service/version fingerprint the open ports.
4. HTTP probe + tech detect.
5. Targeted nuclei templates by detected tech.
