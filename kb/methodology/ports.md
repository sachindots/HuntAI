# Common Ports & Services Cheatsheet

| Port | Service | Recon focus |
|------|---------|-------------|
| 21   | FTP     | anonymous login, version CVEs |
| 22   | SSH     | version, weak creds, key auth |
| 80   | HTTP    | httpx probe, tech detect, content discovery |
| 443  | HTTPS   | tls cert, testssl, same web checks |
| 3000 | Node    | dev servers, Juice Shop, source maps |
| 3306 | MySQL   | version, default creds, exposure |
| 8080 | HTTP-alt| proxies, admin consoles, Tomcat manager |
