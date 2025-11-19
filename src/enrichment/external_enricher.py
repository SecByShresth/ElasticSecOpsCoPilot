# src/enrichment/external_enricher.py
"""
ExternalEnricher - runs VirusTotal, AbuseIPDB, Shodan, MaxMind GeoIP, and WHOIS
for given IOCs and returns a merged enrichment dict.

Drop-in usage:
  from src.enrichment.external_enricher import ExternalEnricher
  enricher = ExternalEnricher()
  external_data = enricher.enrich_iocs(iocs)
  enriched_event["external_enrichment"] = external_data
"""

from __future__ import annotations
import os
import time
import threading
from typing import Any, Dict, List, Iterable, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timedelta

# third-party libs (assumed in requirements.txt)
import requests
import whois
import geoip2.database

# virustotal-python client
try:
    from virustotal_python import Virustotal
except Exception:
    Virustotal = None

# abuseipdb client (community wrappers use requests; import if available)
try:
    from abuseipdb import AbuseIPDB
except Exception:
    AbuseIPDB = None

# shodan client
try:
    import shodan
except Exception:
    shodan = None


# Simple in-memory TTL cache
@dataclass
class TTLCache:
    ttl_seconds: int = 300
    _store: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            rec = self._store.get(key)
            if not rec:
                return None
            if datetime.utcnow() > rec["expires_at"]:
                del self._store[key]
                return None
            return rec["value"]

    def set(self, key: str, value: Any) -> None:
        with self._lock:
            self._store[key] = {
                "value": value,
                "expires_at": datetime.utcnow() + timedelta(seconds=self.ttl_seconds),
            }


# naive rate-limiter (token-bucket like)
class RateLimiter:
    def __init__(self, calls: int, per_seconds: int):
        self.calls = calls
        self.per_seconds = per_seconds
        self._lock = threading.Lock()
        self._tokens = calls
        self._last = time.monotonic()

    def allow(self) -> bool:
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last
            # refill tokens
            refill = int(elapsed * (self.calls / self.per_seconds))
            if refill > 0:
                self._tokens = min(self.calls, self._tokens + refill)
                self._last = now
            if self._tokens > 0:
                self._tokens -= 1
                return True
            return False

    def wait(self):
        while not self.allow():
            # sleep a little and retry
            time.sleep(max(0.1, self.per_seconds / max(1, self.calls)))


class ExternalEnricher:
    """
    ExternalEnricher integrates with:
      - VirusTotal (file/url/domain)
      - AbuseIPDB (IP reputation)
      - Shodan (host info)
      - MaxMind GeoIP (local mmdb reader)
      - python-whois (domain whois)
    """

    def __init__(self, cache_ttl: int = 300, max_workers: int = 8):
        # load credentials from env
        self.vt_api_key = os.getenv("VT_API_KEY") or os.getenv("VIRUSTOTAL_API_KEY")
        self.abuse_api_key = os.getenv("ABUSEIPDB_API_KEY")
        self.shodan_api_key = os.getenv("SHODAN_API_KEY")
        self.maxmind_db_path = os.getenv("MAXMIND_DB_PATH", os.getenv("MAXMIND_DB", "/opt/GeoLite2-City.mmdb"))
        self.cache = TTLCache(ttl_seconds=cache_ttl)
        self.executor_workers = max_workers

        # init clients where possible
        self.vt_client = None
        if Virustotal and self.vt_api_key:
            try:
                self.vt_client = Virustotal(api_key=self.vt_api_key)
            except Exception:
                self.vt_client = None

        self.shodan_client = None
        if shodan and self.shodan_api_key:
            try:
                self.shodan_client = shodan.Shodan(self.shodan_api_key)
            except Exception:
                self.shodan_client = None

        # AbuseIPDB: we'll use HTTP requests if no client available
        # MaxMind reader
        self.geo_reader = None
        try:
            if os.path.exists(self.maxmind_db_path):
                self.geo_reader = geoip2.database.Reader(self.maxmind_db_path)
        except Exception:
            self.geo_reader = None

        # rate limiters (conservative defaults)
        self.vt_rl = RateLimiter(calls=4, per_seconds=1)          # VT: small bursts
        self.abuse_rl = RateLimiter(calls=2, per_seconds=1)       # AbuseIPDB
        self.shodan_rl = RateLimiter(calls=1, per_seconds=1)      # Shodan
        self.whois_rl = RateLimiter(calls=1, per_seconds=1)       # whois
        self.geo_rl = RateLimiter(calls=10, per_seconds=1)        # local DB is fast, but keep check

    # -------------------------------
    # Helpers
    # -------------------------------
    def _cache_key(self, prefix: str, value: str) -> str:
        return f"{prefix}:{value}"

    def _safe_request(self, fn, *args, **kwargs):
        """Wrap API call with try/except and return None on failure."""
        try:
            return fn(*args, **kwargs)
        except Exception as e:
            # do not log here directly; caller can handle debugging/logging
            return {"error": str(e)}

    # -------------------------------
    # IP enrichment
    # -------------------------------
    def enrich_ip(self, ip: str) -> Dict[str, Any]:
        key = self._cache_key("ip", ip)
        cached = self.cache.get(key)
        if cached:
            return cached

        result: Dict[str, Any] = {"ip": ip, "abuseipdb": None, "shodan": None, "geoip": None, "whois": None}

        # AbuseIPDB
        if self.abuse_api_key:
            try:
                self.abuse_rl.wait()
                headers = {"Key": self.abuse_api_key, "Accept": "application/json"}
                params = {"ipAddress": ip, "maxAgeInDays": 3650}
                r = requests.get("https://api.abuseipdb.com/api/v2/check", headers=headers, params=params, timeout=10)
                if r.status_code == 200:
                    result["abuseipdb"] = r.json().get("data")
                else:
                    result["abuseipdb"] = {"status_code": r.status_code, "message": r.text[:500]}
            except Exception as e:
                result["abuseipdb"] = {"error": str(e)}

        # Shodan
        if self.shodan_client:
            try:
                self.shodan_rl.wait()
                host = self.shodan_client.host(ip)
                result["shodan"] = host
            except Exception as e:
                result["shodan"] = {"error": str(e)}

        # MaxMind GeoIP
        if self.geo_reader:
            try:
                self.geo_rl.wait()
                rec = self.geo_reader.city(ip)
                geo = {
                    "country": getattr(rec.country, "name", None),
                    "country_iso": getattr(rec.country, "iso_code", None),
                    "city": getattr(rec.city, "name", None),
                    "latitude": getattr(rec.location, "latitude", None),
                    "longitude": getattr(rec.location, "longitude", None),
                    "timezone": getattr(rec.location, "time_zone", None),
                }
                result["geoip"] = geo
            except Exception as e:
                result["geoip"] = {"error": str(e)}

        # WHOIS - for IP (reverse whois is unreliable), attempt RDAP via whoisjson APIs? We'll do a basic placeholder.
        # Keep it light: do not call external whois for IP here to avoid expensive network calls.
        result["whois"] = None

        self.cache.set(key, result)
        return result

    # -------------------------------
    # Hash enrichment (VirusTotal)
    # -------------------------------
    def enrich_hash(self, hash_value: str) -> Dict[str, Any]:
        key = self._cache_key("hash", hash_value)
        cached = self.cache.get(key)
        if cached:
            return cached

        data = {"hash": hash_value, "virustotal": None}

        if self.vt_client:
            try:
                self.vt_rl.wait()
                # virustotal-python: client.request("file/report", params={"resource": hash})
                # But modern client supports files API. Use general request wrapper for compatibility:
                resp = None
                try:
                    # preferred modern endpoint usage - try file report (older VTv2 compatibility)
                    resp = self.vt_client.request(f"/files/{hash_value}")
                except Exception:
                    # fallback to legacy (if configured)
                    resp = self.vt_client.request("files/" + hash_value)
                # resp is Response-like object; try to parse
                if hasattr(resp, "json"):
                    data["virustotal"] = resp.json()
                else:
                    data["virustotal"] = resp
            except Exception as e:
                data["virustotal"] = {"error": str(e)}
        else:
            data["virustotal"] = {"error": "vt_client_unavailable_or_api_key_missing"}

        self.cache.set(key, data)
        return data

    # -------------------------------
    # Domain enrichment (WHOIS + VT + DNS)
    # -------------------------------
    def enrich_domain(self, domain: str) -> Dict[str, Any]:
        key = self._cache_key("domain", domain)
        cached = self.cache.get(key)
        if cached:
            return cached

        result: Dict[str, Any] = {"domain": domain, "whois": None, "virustotal": None, "dns": None}

        # WHOIS
        try:
            self.whois_rl.wait()
            who = whois.whois(domain)
            # whois library returns objects/dicts; keep raw but safe
            result["whois"] = {
                "registrar": getattr(who, "registrar", None),
                "name": getattr(who, "name", None),
                "creation_date": str(getattr(who, "creation_date", None)),
                "expiration_date": str(getattr(who, "expiration_date", None)),
                "raw": str(who)[:1000],
            }
        except Exception as e:
            result["whois"] = {"error": str(e)}

        # VirusTotal domain
        if self.vt_client:
            try:
                self.vt_rl.wait()
                resp = self.vt_client.request(f"/domains/{domain}")
                if hasattr(resp, "json"):
                    result["virustotal"] = resp.json()
                else:
                    result["virustotal"] = resp
            except Exception as e:
                result["virustotal"] = {"error": str(e)}
        else:
            result["virustotal"] = {"error": "vt_client_unavailable_or_api_key_missing"}

        # DNS resolve (passive - try system resolve to gather A records)
        try:
            # Use socket.getaddrinfo for quick resolution (not passive DNS)
            import socket

            addrs = []
            try:
                for fam, socktype, proto, canonname, sockaddr in socket.getaddrinfo(domain, None):
                    addr = sockaddr[0]
                    if addr not in addrs:
                        addrs.append(addr)
            except Exception:
                addrs = []
            result["dns"] = {"resolved": addrs}
        except Exception as e:
            result["dns"] = {"error": str(e)}

        self.cache.set(key, result)
        return result

    # -------------------------------
    # URL enrichment (VirusTotal)
    # -------------------------------
    def enrich_url(self, url: str) -> Dict[str, Any]:
        key = self._cache_key("url", url)
        cached = self.cache.get(key)
        if cached:
            return cached

        result = {"url": url, "virustotal": None, "whois": None}

        # VirusTotal URL analysis
        if self.vt_client:
            try:
                self.vt_rl.wait()
                # VT modern URL endpoints expect URL id or /urls endpoint
                resp = None
                try:
                    # encode url as needed by vt client
                    resp = self.vt_client.request("/urls", params={"url": url})
                except Exception:
                    # fallback: pass raw
                    resp = self.vt_client.request("/urls", data={"url": url})
                if hasattr(resp, "json"):
                    result["virustotal"] = resp.json()
                else:
                    result["virustotal"] = resp
            except Exception as e:
                result["virustotal"] = {"error": str(e)}
        else:
            result["virustotal"] = {"error": "vt_client_unavailable_or_api_key_missing"}

        # WHOIS of the domain portion (best-effort)
        try:
            from urllib.parse import urlparse

            domain = urlparse(url).hostname or ""
            if domain:
                result["whois"] = self.enrich_domain(domain).get("whois")
        except Exception:
            result["whois"] = None

        self.cache.set(key, result)
        return result

    # -------------------------------
    # Top-level orchestration
    # -------------------------------
    def enrich_iocs(
        self, iocs: Dict[str, Iterable[str]], concurrency: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Enrich incoming iocs dict with structure:
          { "ips": [...], "domains": [...], "urls": [...], "hashes": [...], "emails": [...] }

        Returns:
          {
            "ip_enrichment": { ip: {...}, ... },
            "domain_enrichment": { domain: {...}, ... },
            "url_enrichment": { url: {...}, ... },
            "hash_enrichment": { hash: {...}, ... },
            "emails": { email: {...}, ... }
          }
        """

        concurrency = concurrency or self.executor_workers
        external_results: Dict[str, Dict[str, Any]] = {
            "ip_enrichment": {},
            "domain_enrichment": {},
            "url_enrichment": {},
            "hash_enrichment": {},
            "emails": {},
        }

        tasks = []
        with ThreadPoolExecutor(max_workers=concurrency) as ex:
            # IPs
            for ip in set(iocs.get("ips", [])):
                if not ip:
                    continue
                tasks.append(ex.submit(self._safe_request, self.enrich_ip, ip))

            # Domains
            for d in set(iocs.get("domains", [])):
                if not d:
                    continue
                tasks.append(ex.submit(self._safe_request, self.enrich_domain, d))

            # URLs
            for u in set(iocs.get("urls", [])):
                if not u:
                    continue
                tasks.append(ex.submit(self._safe_request, self.enrich_url, u))

            # Hashes
            for h in set(iocs.get("hashes", [])):
                if not h:
                    continue
                tasks.append(ex.submit(self._safe_request, self.enrich_hash, h))

            # Emails - placeholder behavior
            for e in set(iocs.get("emails", [])):
                if not e:
                    continue
                # simple placeholder enrichment (could add phishing databases later)
                tasks.append(ex.submit(lambda x: {"email": x, "note": "no_enrichment_configured"}, e))

            # Collect results in order of completion
            for future in as_completed(tasks):
                try:
                    res = future.result()
                except Exception as e:
                    res = {"error": str(e)}

                # place into correct result bucket by detecting keys
                if isinstance(res, dict):
                    # ip enrichment detection
                    if "ip" in res:
                        ip_val = res.get("ip")
                        external_results["ip_enrichment"][ip_val] = res
                    elif "domain" in res:
                        d = res.get("domain")
                        external_results["domain_enrichment"][d] = res
                    elif "url" in res:
                        u = res.get("url")
                        external_results["url_enrichment"][u] = res
                    elif "hash" in res:
                        h = res.get("hash")
                        external_results["hash_enrichment"][h] = res
                    elif "email" in res:
                        e = res.get("email")
                        external_results["emails"][e] = res
                    else:
                        # unknown shape; stash in a misc bucket
                        external_results.setdefault("misc", []).append(res)
                else:
                    external_results.setdefault("misc", []).append(res)

        return external_results


# -------------------------------
# Example integration snippet
# -------------------------------
"""
In your existing `enrich_log()` (EnhancedEnrichmentService.enrich_log), after you compute iocs:

    from src.enrichment.external_enricher import ExternalEnricher

    enricher = ExternalEnricher()          # create once globally if possible
    external_data = enricher.enrich_iocs(iocs)
    enriched_event["external_enrichment"] = external_data

Example merge (in your code):

    # after enriched_event created
    try:
        enricher = getattr(self, "_external_enricher", None)
        if enricher is None:
            self._external_enricher = ExternalEnricher()   # cache on service instance
            enricher = self._external_enricher

        external_data = enricher.enrich_iocs(iocs)
        enriched_event["external_enrichment"] = external_data
    except Exception as e:
        logger.debug(f"External enrichment failed: {e}")
        enriched_event["external_enrichment"] = {"error": str(e)}

Note:
- Create the ExternalEnricher once (e.g., in EnhancedEnrichmentService.__init__) and reuse it.
- Set environment variables in your .env or system:
    VT_API_KEY, ABUSEIPDB_API_KEY, SHODAN_API_KEY, MAXMIND_DB_PATH
"""
