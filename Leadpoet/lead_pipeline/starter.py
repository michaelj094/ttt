from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import time
from collections import Counter
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, Mapping, MutableMapping, Optional, Tuple
from urllib.parse import urlparse


def _truthy_env(value: Optional[str]) -> bool:
    if value is None:
        return False
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


def _collapse_ws(value: str) -> str:
    return " ".join(value.strip().split())


def _as_str(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return str(value)


def _normalize_email(email: str) -> str:
    return _collapse_ws(email).lower()


def _normalize_domain(domain: str) -> str:
    domain = _collapse_ws(domain).lower()
    if domain.startswith("www."):
        domain = domain[4:]
    domain = domain.rstrip(".")
    if ":" in domain:
        domain = domain.split(":", 1)[0]
    return domain


def website_domain(website_url: str) -> str:
    website_url = _collapse_ws(website_url)
    if not website_url:
        return ""
    try:
        parsed = urlparse(website_url)
    except Exception:
        return ""
    if parsed.scheme not in {"http", "https"}:
        return ""
    host = parsed.netloc or ""
    return _normalize_domain(host)


def email_domain(email: str) -> str:
    email = _normalize_email(email)
    if "@" not in email:
        return ""
    return _normalize_domain(email.rsplit("@", 1)[1])


def is_http_url(value: str) -> bool:
    value = _collapse_ws(value)
    if not value:
        return False
    try:
        parsed = urlparse(value)
    except Exception:
        return False
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def domains_match(email_dom: str, website_dom: str) -> bool:
    email_dom = _normalize_domain(email_dom)
    website_dom = _normalize_domain(website_dom)
    if not email_dom or not website_dom:
        return False
    if email_dom == website_dom:
        return True
    if email_dom.endswith("." + website_dom):
        return True
    if website_dom.endswith("." + email_dom):
        return True
    return False


@dataclass(frozen=True)
class MinerRequest:
    num_leads: int
    business_desc: str = ""
    industry: str = ""
    region: str = ""
    caller_hotkey: str = ""

    @classmethod
    def from_synapse(cls, synapse: Any) -> "MinerRequest":
        return cls(
            num_leads=int(getattr(synapse, "num_leads", 0) or 0),
            business_desc=_as_str(getattr(synapse, "business_desc", "")),
            industry=_as_str(getattr(synapse, "industry", "")),
            region=_as_str(getattr(synapse, "region", "")),
            caller_hotkey=_as_str(getattr(getattr(synapse, "dendrite", None), "hotkey", "")),
        )


@dataclass(frozen=True)
class StarterConfig:
    enabled: bool = False
    max_leads: int = 3
    dedupe_ttl_hours: int = 48

    @classmethod
    def from_env(cls, environ: Optional[Mapping[str, str]] = None) -> "StarterConfig":
        env = os.environ if environ is None else environ
        enabled = _truthy_env(env.get("STARTER_MODE"))
        try:
            max_leads = int(env.get("STARTER_MAX_LEADS", "3"))
        except Exception:
            max_leads = 3
        try:
            ttl = int(env.get("DEDUPE_TTL_HOURS", "48"))
        except Exception:
            ttl = 48
        return cls(enabled=enabled, max_leads=max(0, max_leads), dedupe_ttl_hours=max(0, ttl))


@dataclass(frozen=True)
class StarterMetrics:
    accepted: int
    rejected: Dict[str, int]
    duplicate_dropped: int
    latency_ms: int


class LeadCache:
    def __init__(self, ttl_seconds: int, time_fn: Callable[[], float] = time.time):
        self._ttl_seconds = ttl_seconds
        self._time_fn = time_fn
        self._lock = threading.Lock()
        self._expires_at: Dict[str, float] = {}

    def _prune(self, now: float) -> None:
        expired = [k for k, exp in self._expires_at.items() if exp <= now]
        for k in expired:
            self._expires_at.pop(k, None)

    def check_and_mark(self, key: str) -> bool:
        now = self._time_fn()
        with self._lock:
            self._prune(now)
            if key in self._expires_at:
                return True
            self._expires_at[key] = now + self._ttl_seconds
            return False


class LeadHardValidator:
    _email_re = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

    _free_domains = {
        "gmail.com",
        "yahoo.com",
        "hotmail.com",
        "outlook.com",
        "aol.com",
        "icloud.com",
        "gmx.com",
        "proton.me",
        "protonmail.com",
        "live.com",
        "msn.com",
    }

    _senior_keywords = (
        "founder",
        "co-founder",
        "ceo",
        "cto",
        "cfo",
        "coo",
        "chief",
        "president",
        "vp",
        "vice president",
        "head",
        "director",
        "owner",
        "principal",
        "partner",
        "managing",
        "general manager",
        "gm",
        "executive",
    )

    def __init__(self):
        self._disposable_domains: Optional[set[str]] = None
        try:
            # Optional dependency: https://pypi.org/project/disposable-email-domains/
            from disposable_email_domains import blocklist  # type: ignore

            self._disposable_domains = {d.lower() for d in blocklist}
        except Exception:
            self._disposable_domains = None

    def validate(self, lead: Mapping[str, Any]) -> Tuple[bool, Optional[str]]:
        email = _normalize_email(_as_str(lead.get("email", "")))
        website = _collapse_ws(_as_str(lead.get("website", "")))
        business = _collapse_ws(_as_str(lead.get("business", lead.get("company", ""))))
        role = _collapse_ws(_as_str(lead.get("role", lead.get("title", ""))))
        source_url = _collapse_ws(_as_str(lead.get("source_url", ""))) or website

        if not email or not website or not business or not role or not source_url:
            return False, "missing_fields"

        if not self._email_re.fullmatch(email):
            return False, "invalid_email"

        email_dom = email_domain(email)
        if not email_dom or email_dom in self._free_domains:
            return False, "invalid_email"
        if self._disposable_domains is not None and email_dom in self._disposable_domains:
            return False, "invalid_email"

        web_dom = website_domain(website)
        if not web_dom or not domains_match(email_dom, web_dom):
            return False, "domain_mismatch"

        role_l = role.lower()
        if not any(k in role_l for k in self._senior_keywords):
            return False, "not_senior"

        if not is_http_url(source_url):
            return False, "missing_fields"

        return True, None


class LeadLimiter:
    def __init__(self, max_leads: int):
        self._max = max(0, int(max_leads))

    def limit(self, leads: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if self._max <= 0:
            return []
        return leads[: self._max]


class ResponseFormatter:
    _field_order = (
        "business",
        "full_name",
        "first",
        "last",
        "email",
        "role",
        "industry",
        "sub_industry",
        "website",
        "source_url",
        "linkedin",
        "company_linkedin",
        "country",
        "state",
        "city",
        "region",
        "description",
        "phone_numbers",
        "founded_year",
        "ownership_type",
        "company_type",
        "number_of_locations",
        "employee_count",
        "socials",
        "source",
    )

    def normalize_lead(self, lead: Mapping[str, Any]) -> Dict[str, Any]:
        raw: Dict[str, Any] = dict(lead)

        normalized: Dict[str, Any] = {}
        for key in self._field_order:
            normalized[key] = raw.get(key, "")

        normalized["business"] = _collapse_ws(_as_str(normalized.get("business", raw.get("company", ""))))
        normalized["email"] = _normalize_email(_as_str(normalized.get("email", "")))
        normalized["website"] = _collapse_ws(_as_str(normalized.get("website", "")))
        normalized["role"] = _collapse_ws(_as_str(normalized.get("role", raw.get("title", ""))))

        source_url = _collapse_ws(_as_str(raw.get("source_url", ""))) or normalized["website"]
        normalized["source_url"] = source_url

        for k in ("full_name", "first", "last", "linkedin", "company_linkedin", "industry", "sub_industry", "country", "state", "city", "region", "description"):
            normalized[k] = _collapse_ws(_as_str(normalized.get(k, "")))

        return normalized

    def sort_key(self, lead: Mapping[str, Any]) -> Tuple[str, str]:
        return (
            _collapse_ws(_as_str(lead.get("business", ""))).lower(),
            _normalize_email(_as_str(lead.get("email", ""))),
        )

    def sort(self, leads: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return sorted(leads, key=self.sort_key)


class StarterMiner:
    def __init__(
        self,
        config: StarterConfig,
        lead_cache: LeadCache,
        validator: Optional[LeadHardValidator] = None,
        formatter: Optional[ResponseFormatter] = None,
        limiter: Optional[LeadLimiter] = None,
        time_fn: Callable[[], float] = time.time,
    ):
        self._config = config
        self._cache = lead_cache
        self._validator = validator or LeadHardValidator()
        self._formatter = formatter or ResponseFormatter()
        self._limiter = limiter or LeadLimiter(config.max_leads)
        self._time_fn = time_fn

    @property
    def enabled(self) -> bool:
        return self._config.enabled

    def _dedupe_key(self, email: str, website: str) -> str:
        dom = website_domain(website)
        payload = f"{_normalize_email(email)}|{_normalize_domain(dom)}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def handle_request(self, request: MinerRequest, candidates: Iterable[Mapping[str, Any]]) -> Tuple[List[Dict[str, Any]], StarterMetrics]:
        t0 = self._time_fn()
        rejected = Counter()
        accepted: List[Dict[str, Any]] = []
        duplicate_dropped = 0

        for cand in candidates:
            normalized = self._formatter.normalize_lead(cand)
            ok, reason = self._validator.validate(normalized)
            if not ok:
                rejected[reason or "unknown"] += 1
                continue

            key = self._dedupe_key(normalized.get("email", ""), normalized.get("website", ""))
            if self._cache.check_and_mark(key):
                duplicate_dropped += 1
                rejected["duplicate"] += 1
                continue

            accepted.append(normalized)

        accepted = self._formatter.sort(accepted)

        limit = min(max(0, int(request.num_leads or 0)), self._config.max_leads) if request.num_leads else self._config.max_leads
        accepted = LeadLimiter(limit).limit(accepted)

        latency_ms = int((self._time_fn() - t0) * 1000)
        metrics = StarterMetrics(
            accepted=len(accepted),
            rejected=dict(rejected),
            duplicate_dropped=duplicate_dropped,
            latency_ms=latency_ms,
        )
        return accepted, metrics


def load_local_pool_candidates(path: str = os.path.join("data", "leads.json")) -> List[Dict[str, Any]]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            return [d for d in data if isinstance(d, dict)]
    except Exception:
        return []
    return []

