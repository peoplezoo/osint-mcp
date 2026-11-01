# osint-mcp 2.0 — Hybrid OSINT MCP Server

**Pure-Python collectors + optional classic binaries + composite investigation tools.**

Give Claude, Cursor, or any MCP client a full OSINT workstation: domain/IP/email/username/phone recon, methodology playbooks, and deep identity coverage when Sherlock, Maigret, Holehe, theHarvester, subfinder (and friends) are on the host — or use the Docker image for batteries-included.

## Why hybrid?

| Mode | What you get | Install cost |
|------|----------------|--------------|
| **Pure Python** (default) | DNS, WHOIS/RDAP, crt.sh, email-auth, ASN, reverse IP, Wayback, light username checks, dorks, playbooks | `pip install` only |
| **Hybrid** | Above **+** Sherlock / Maigret / Holehe / theHarvester / subfinder / dnstwist / PhoneInfoga / ExifTool | binaries on PATH or Docker |
| **Active** (opt-in) | Nmap top ports | `OSINT_ALLOW_ACTIVE=1` |

Most OSINT MCP servers are either thin HTTP wrappers **or** binary wrappers. This one does both and adds **composite `investigate_*` tools** so agents get one structured package instead of ten raw calls.

## Preferred tools (start here)

| Tool | Use for |
|------|---------|
| `investigate_domain` | Full domain package (Python + optional subfinder/theHarvester/dnstwist) |
| `investigate_username` | Handle search (Python + optional Sherlock/Maigret) |
| `investigate_email` | Breach + Gravatar + optional Holehe |
| `investigate_ip` | Geo / ASN / reverse / RDAP / optional Shodan / nmap |
| `investigate_phone` | libphonenumber + optional PhoneInfoga |
| `investigation_playbook` | Phased methodology, OPSEC, discipline map |
| `list_binaries` / `server_info` | What is installed and which keys are set |

## Quick start

### Minimal (pure Python)

```bash
cd osint-mcp
python -m venv .venv && source .venv/bin/activate
pip install -e .

export HIBP_API_KEY=...      # optional
export SHODAN_API_KEY=...    # optional
export GITHUB_TOKEN=...      # optional

osint-mcp   # stdio MCP server
```

### Hybrid extras on the host

```bash
pip install sherlock-project maigret holehe dnstwist
pip install theHarvester
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

### Docker (recommended workstation)

```bash
docker build -t osint-mcp .
docker run -i --rm \
  -e HIBP_API_KEY \
  -e SHODAN_API_KEY \
  -e GITHUB_TOKEN \
  -e OSINT_ALLOW_ACTIVE=0 \
  osint-mcp
```

### Claude Desktop

```json
{
  "mcpServers": {
    "osint": {
      "command": "osint-mcp",
      "env": {
        "HIBP_API_KEY": "",
        "SHODAN_API_KEY": "",
        "GITHUB_TOKEN": "",
        "OSINT_ALLOW_ACTIVE": "0"
      }
    }
  }
}
```

## Tool catalog

### Composite (hybrid)

- `investigate_domain` · `investigate_username` · `investigate_email` · `investigate_ip` · `investigate_phone`

### Pure-Python collectors

- `recon_domain` · `dns_lookup` · `whois_lookup` · `rdap_lookup` · `subdomain_enum`
- `email_security` · `http_headers` · `reverse_ip` · `asn_lookup`
- `username_search` · `email_breach_check` · `email_patterns` · `gravatar_lookup`
- `phone_analyze` · `ip_geolocate` · `wayback_snapshots` · `github_search` · `shodan_host`
- `extract_crypto_addresses` · `generate_dorks`

### Binary adapters (graceful if missing)

- `list_binaries`
- `binary_sherlock` · `binary_maigret` · `binary_holehe`
- `binary_theharvester` · `binary_subfinder` · `binary_dnstwist`
- `binary_phoneinfoga` · `binary_exiftool` · `binary_nmap`

### Methodology

- `investigation_playbook` · `osint_resource_catalog` · `server_info`
- `investigate_domain_advanced` (legacy pure-Python package)

## Design principles

1. **Passive by default** — no port scans unless `OSINT_ALLOW_ACTIVE=1`.
2. **Graceful degradation** — missing binaries return `status: not_installed` with install hints.
3. **Agent-native** — composite tools return structured sections + summary for chaining.
4. **Methodology included** — playbooks and resource catalog, not just collectors.
5. **Authorized use only** — investigate systems and people you have permission to assess.

## Environment variables

| Variable | Purpose |
|----------|---------|
| `HIBP_API_KEY` | Have I Been Pwned |
| `SHODAN_API_KEY` | Shodan host lookup |
| `GITHUB_TOKEN` | Higher GitHub rate limits |
| `OSINT_ALLOW_ACTIVE` | `1` enables nmap |
| `OSINT_BINARY_TIMEOUT` | Seconds (default 180) |
| `OSINT_HTTP_TIMEOUT` | Seconds (default 20) |
| `OSINT_USER_AGENT` | Override User-Agent |

## Docs

- [docs/ADVANCED_OSINT.md](docs/ADVANCED_OSINT.md) — disciplines, protocols, tradecraft, resource map

## License

Apache-2.0
