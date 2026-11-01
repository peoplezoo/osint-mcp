"""
Configuration, environment keys, and runtime defaults for osint-mcp.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any


def env(name: str, default: str | None = None) -> str | None:
    val = os.environ.get(name, "").strip()
    return val or default


def env_bool(name: str, default: bool = False) -> bool:
    val = env(name)
    if val is None:
        return default
    return val.lower() in ("1", "true", "yes", "on")


@dataclass
class Settings:
    """Runtime settings resolved from the environment."""

    # Optional API keys
    hibp_api_key: str | None = field(default_factory=lambda: env("HIBP_API_KEY"))
    shodan_api_key: str | None = field(default_factory=lambda: env("SHODAN_API_KEY"))
    github_token: str | None = field(
        default_factory=lambda: env("GITHUB_TOKEN") or env("GITHUB_API_TOKEN")
    )
    virustotal_api_key: str | None = field(default_factory=lambda: env("VIRUSTOTAL_API_KEY"))
    abuseipdb_api_key: str | None = field(default_factory=lambda: env("ABUSEIPDB_API_KEY"))
    otx_api_key: str | None = field(default_factory=lambda: env("OTX_API_KEY"))

    # Behavior
    allow_active: bool = field(default_factory=lambda: env_bool("OSINT_ALLOW_ACTIVE", False))
    binary_timeout: int = field(
        default_factory=lambda: int(env("OSINT_BINARY_TIMEOUT", "180") or "180")
    )
    http_timeout: int = field(
        default_factory=lambda: int(env("OSINT_HTTP_TIMEOUT", "20") or "20")
    )
    user_agent: str = field(
        default_factory=lambda: env(
            "OSINT_USER_AGENT",
            "osint-mcp/2.0 (+hybrid; authorized research only)",
        )
        or "osint-mcp/2.0"
    )

    def key_status(self) -> dict[str, bool]:
        return {
            "HIBP_API_KEY": bool(self.hibp_api_key),
            "SHODAN_API_KEY": bool(self.shodan_api_key),
            "GITHUB_TOKEN": bool(self.github_token),
            "VIRUSTOTAL_API_KEY": bool(self.virustotal_api_key),
            "ABUSEIPDB_API_KEY": bool(self.abuseipdb_api_key),
            "OTX_API_KEY": bool(self.otx_api_key),
        }


settings = Settings()


# Binary tool registry — name → (common executable names, description, category)
BINARY_TOOLS: dict[str, dict[str, Any]] = {
    "sherlock": {
        "executables": ["sherlock"],
        "description": "Username search across 400+ sites",
        "category": "identity",
        "passive": True,
    },
    "maigret": {
        "executables": ["maigret"],
        "description": "Advanced username search (3000+ sites) with profile extraction",
        "category": "identity",
        "passive": True,
    },
    "holehe": {
        "executables": ["holehe"],
        "description": "Email registration check on 120+ platforms",
        "category": "identity",
        "passive": True,
    },
    "theharvester": {
        "executables": ["theHarvester", "theharvester"],
        "description": "Emails, subdomains, hosts from public sources",
        "category": "domain",
        "passive": True,
    },
    "subfinder": {
        "executables": ["subfinder"],
        "description": "Passive subdomain enumeration",
        "category": "domain",
        "passive": True,
    },
    "amass": {
        "executables": ["amass"],
        "description": "OWASP Amass subdomain / asset enumeration",
        "category": "domain",
        "passive": True,
    },
    "dnstwist": {
        "executables": ["dnstwist"],
        "description": "Typosquatting / lookalike domain discovery",
        "category": "domain",
        "passive": True,
    },
    "phoneinfoga": {
        "executables": ["phoneinfoga"],
        "description": "Phone number OSINT (carriers, reputation)",
        "category": "identity",
        "passive": True,
    },
    "blackbird": {
        "executables": ["blackbird"],
        "description": "Fast username enumeration (WhatsMyName list)",
        "category": "identity",
        "passive": True,
    },
    "exiftool": {
        "executables": ["exiftool"],
        "description": "File / image metadata extraction",
        "category": "techint",
        "passive": True,
    },
    "nmap": {
        "executables": ["nmap"],
        "description": "Network port scanning (active — requires OSINT_ALLOW_ACTIVE=1)",
        "category": "infra",
        "passive": False,
    },
}
