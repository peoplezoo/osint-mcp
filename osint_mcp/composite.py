"""
Composite investigation tools.

These orchestrate pure-Python collectors and optional binary tools into
single structured intelligence packages that agents can reason over.
"""

from __future__ import annotations

import asyncio
from typing import Any

from osint_mcp import advanced as adv
from osint_mcp import binaries as b
from osint_mcp import collectors as c
from osint_mcp.collectors import _now
from osint_mcp.config import settings


def _section(name: str, data: Any, *, source: str = "python") -> dict[str, Any]:
    return {"name": name, "source": source, "data": data}


async def investigate_domain(domain: str, use_binaries: bool = True) -> dict[str, Any]:
    """
    Full-spectrum domain investigation.

    Pure-Python core always runs. Optional binaries (subfinder, theHarvester,
    dnstwist) enrich when installed and use_binaries=True.
    """
    domain = domain.strip().lower().rstrip(".")
    out: dict[str, Any] = {
        "target": domain,
        "target_type": "domain",
        "mode": "hybrid" if use_binaries else "python-only",
        "sections": {},
        "summary": {},
        "timestamp": _now(),
    }

    # Core parallel pure-Python (async only inside gather)
    core = await asyncio.gather(
        c.recon_domain(domain),
        adv.rdap_lookup(domain),
        adv.email_security(domain),
        adv.http_headers(f"https://{domain}"),
        return_exceptions=True,
    )
    labels = ["recon", "rdap", "email_security", "http_headers"]
    for label, result in zip(labels, core):
        if isinstance(result, Exception):
            out["sections"][label] = _section(label, {"error": str(result)})
        else:
            out["sections"][label] = _section(label, result)

    out["sections"]["dorks"] = _section("dorks", adv.generate_dorks(domain, "domain"))

    # Reverse IP + ASN from first A record when available
    recon = out["sections"].get("recon", {}).get("data") or {}
    ips = recon.get("ips") or recon.get("dns", {}).get("ips") or []
    if not ips and isinstance(recon.get("dns"), dict):
        ips = recon["dns"].get("ips") or []
    try:
        dns_block = recon.get("dns") or {}
        if isinstance(dns_block, dict):
            ips = ips or dns_block.get("ips") or []
    except Exception:
        pass

    if ips:
        ip0 = ips[0]
        extra = await asyncio.gather(
            adv.reverse_ip(ip0),
            adv.asn_lookup(ip0),
            return_exceptions=True,
        )
        for label, result in zip(["reverse_ip", "asn"], extra):
            if isinstance(result, Exception):
                out["sections"][label] = _section(label, {"error": str(result)})
            else:
                out["sections"][label] = _section(label, result)

    if use_binaries:
        bin_tasks = await asyncio.gather(
            b.run_subfinder(domain),
            b.run_theharvester(domain),
            b.run_dnstwist(domain),
            return_exceptions=True,
        )
        for result in bin_tasks:
            if isinstance(result, Exception):
                continue
            tool = result.get("tool", "binary")
            out["sections"][tool] = _section(tool, result, source="binary")

    sub_count = 0
    recon_data = out["sections"].get("recon", {}).get("data") or {}
    if isinstance(recon_data.get("subdomains"), dict):
        sub_count = recon_data["subdomains"].get("count") or len(
            recon_data["subdomains"].get("names") or []
        )
    sf = out["sections"].get("subfinder", {}).get("data") or {}
    if sf.get("status") == "ok":
        sub_count = max(sub_count, sf.get("count") or 0)

    out["summary"] = {
        "domain": domain,
        "subdomain_signal": sub_count,
        "email_security_issues": (out["sections"].get("email_security", {}).get("data") or {}).get(
            "issues"
        )
        or [],
        "binaries_used": [
            k
            for k, v in out["sections"].items()
            if v.get("source") == "binary" and (v.get("data") or {}).get("status") == "ok"
        ],
        "keys_configured": settings.key_status(),
    }
    return out


async def investigate_username(username: str, use_binaries: bool = True) -> dict[str, Any]:
    """Username / handle investigation with optional Sherlock/Maigret."""
    username = username.strip().lstrip("@")
    out: dict[str, Any] = {
        "target": username,
        "target_type": "username",
        "mode": "hybrid" if use_binaries else "python-only",
        "sections": {},
        "summary": {},
        "timestamp": _now(),
    }

    pure = await c.username_search(username)
    out["sections"]["username_search"] = _section("username_search", pure)
    out["sections"]["dorks"] = _section("dorks", adv.generate_dorks(username, "username"))

    if use_binaries:
        bin_results = await asyncio.gather(
            b.run_sherlock(username),
            b.run_maigret(username),
            return_exceptions=True,
        )
        for result in bin_results:
            if isinstance(result, Exception):
                continue
            tool = result.get("tool", "binary")
            out["sections"][tool] = _section(tool, result, source="binary")

    found: set[str] = set()
    pure_hits = pure.get("found") or pure.get("results") or []
    if isinstance(pure_hits, list):
        for item in pure_hits:
            if isinstance(item, dict) and item.get("url"):
                found.add(item["url"])
            elif isinstance(item, dict) and item.get("exists"):
                found.add(item.get("platform") or item.get("site") or str(item))

    for key in ("sherlock", "maigret"):
        data = (out["sections"].get(key) or {}).get("data") or {}
        if data.get("status") != "ok":
            continue
        if key == "sherlock":
            found.update(data.get("sites_found") or [])
        else:
            for acc in data.get("accounts") or []:
                if isinstance(acc, dict) and acc.get("url"):
                    found.add(acc["url"])

    out["summary"] = {
        "username": username,
        "sites_found_count": len(found),
        "sites_sample": sorted(found)[:30],
        "binaries_used": [
            k
            for k, v in out["sections"].items()
            if v.get("source") == "binary" and (v.get("data") or {}).get("status") == "ok"
        ],
    }
    return out


async def investigate_email(email: str, use_binaries: bool = True) -> dict[str, Any]:
    """Email investigation: breach check, Gravatar, patterns, optional Holehe."""
    email = email.strip().lower()
    out: dict[str, Any] = {
        "target": email,
        "target_type": "email",
        "mode": "hybrid" if use_binaries else "python-only",
        "sections": {},
        "summary": {},
        "timestamp": _now(),
    }

    pure_tasks = await asyncio.gather(
        c.email_breach_check(email),
        adv.gravatar_lookup(email),
        return_exceptions=True,
    )
    for label, result in zip(["breach", "gravatar"], pure_tasks):
        if isinstance(result, Exception):
            out["sections"][label] = _section(label, {"error": str(result)})
        else:
            out["sections"][label] = _section(label, result)

    domain = email.split("@")[-1] if "@" in email else ""
    if domain:
        out["sections"]["email_security"] = _section(
            "email_security", await adv.email_security(domain)
        )
        out["sections"]["dorks"] = _section("dorks", adv.generate_dorks(email, "email"))

    if use_binaries:
        holehe = await b.run_holehe(email)
        out["sections"]["holehe"] = _section("holehe", holehe, source="binary")

    holehe_data = (out["sections"].get("holehe") or {}).get("data") or {}
    out["summary"] = {
        "email": email,
        "breach_available": bool(settings.hibp_api_key),
        "holehe_registrations": holehe_data.get("count") if holehe_data.get("status") == "ok" else None,
        "binaries_used": [
            k
            for k, v in out["sections"].items()
            if v.get("source") == "binary" and (v.get("data") or {}).get("status") == "ok"
        ],
    }
    return out


async def investigate_ip(ip: str, use_binaries: bool = True) -> dict[str, Any]:
    """IP investigation: geo, ASN, reverse hosts, optional Shodan / nmap."""
    ip = ip.strip()
    out: dict[str, Any] = {
        "target": ip,
        "target_type": "ip",
        "mode": "hybrid" if use_binaries else "python-only",
        "sections": {},
        "summary": {},
        "timestamp": _now(),
    }

    pure = await asyncio.gather(
        c.ip_geolocate(ip),
        adv.asn_lookup(ip),
        adv.reverse_ip(ip),
        adv.rdap_lookup(ip),
        return_exceptions=True,
    )
    for label, result in zip(["geo", "asn", "reverse_ip", "rdap"], pure):
        if isinstance(result, Exception):
            out["sections"][label] = _section(label, {"error": str(result)})
        else:
            out["sections"][label] = _section(label, result)

    if settings.shodan_api_key:
        try:
            out["sections"]["shodan"] = _section("shodan", await c.shodan_host(ip))
        except Exception as exc:
            out["sections"]["shodan"] = _section("shodan", {"error": str(exc)})

    if use_binaries and settings.allow_active:
        nmap = await b.run_nmap_top_ports(ip)
        out["sections"]["nmap"] = _section("nmap", nmap, source="binary")

    out["summary"] = {
        "ip": ip,
        "shodan": bool(settings.shodan_api_key),
        "active_scan_enabled": settings.allow_active,
        "binaries_used": [
            k
            for k, v in out["sections"].items()
            if v.get("source") == "binary" and (v.get("data") or {}).get("status") == "ok"
        ],
    }
    return out


async def investigate_phone(phone: str, default_region: str = "US", use_binaries: bool = True) -> dict[str, Any]:
    """Phone analysis with optional PhoneInfoga."""
    out: dict[str, Any] = {
        "target": phone,
        "target_type": "phone",
        "mode": "hybrid" if use_binaries else "python-only",
        "sections": {},
        "summary": {},
        "timestamp": _now(),
    }

    out["sections"]["phone_analyze"] = _section(
        "phone_analyze", c.phone_analyze(phone, default_region=default_region)
    )
    out["sections"]["dorks"] = _section("dorks", adv.generate_dorks(phone, "phone"))

    if use_binaries:
        pi = await b.run_phoneinfoga(phone)
        out["sections"]["phoneinfoga"] = _section("phoneinfoga", pi, source="binary")

    out["summary"] = {
        "phone": phone,
        "binaries_used": [
            k
            for k, v in out["sections"].items()
            if v.get("source") == "binary" and (v.get("data") or {}).get("status") == "ok"
        ],
    }
    return out
