# Web Application Checks (OWASP-aligned)

## Common high-value findings
- Default / weak credentials on admin panels (e.g. DVWA admin/password).
- SQL injection on parameters — test with `sqlmap` after manual confirmation.
- Reflected / stored XSS in input fields.
- Exposed `.git`, backup files, config files via content discovery.
- Outdated components with known CVEs (map version -> CVE).

## Tech-driven next steps
- Apache/PHP -> check `.php` endpoints, phpinfo, path traversal.
- WordPress -> `wpscan` for plugin/theme vulns.
- Node/Express (Juice Shop) -> client-side routes, JWT handling, API abuse.
