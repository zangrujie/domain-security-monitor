#!/usr/bin/env python3
"""
Multi-dimensional risk engine for proactive typosquatting monitoring.
FULL IMPLEMENTATION — production-ready for your domain security platform
"""

#from __future__ import annotations

import asyncio
import json
import logging
import socket
from dataclasses import dataclass
from datetime import datetime, timezone
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import dns.resolver
except Exception:
    dns = None

from modules.http_scanner.scanner import scan_domain
from modules.whois_enhanced import query_domain_whois_structured
from modules.threat_intelligence.intel_scanner_enhanced import (
    EnhancedThreatIntelligenceScanner,
)

logger = logging.getLogger(__name__)

# =========================================================
# Utils
# =========================================================

def now_iso():
    return datetime.now(timezone.utc).isoformat()


# Backwards-compatible helper used across the module (some code calls _now_iso())
def _now_iso():
    return now_iso()


# Lightweight dnspython query wrapper to avoid NameError when dnspython is present
def _query_dns_with_dnspython(domain: str, timeout: float, record_types: List[str]) -> Dict[str, Any]:
    records: Dict[str, List[str]] = {r: [] for r in record_types}
    ttls: Dict[str, Optional[int]] = {r: None for r in record_types}
    if dns is None:
        return {"domain": domain, "records": records, "ttls": ttls, "source": "dnspython_unavailable", "timestamp": _now_iso()}
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        for r in record_types:
            try:
                ans = resolver.resolve(domain, r)
                records[r] = [str(x) for x in ans]
                ttls[r] = int(getattr(ans.rrset, "ttl", 0) or 0)
            except Exception:
                continue
    except Exception:
        pass
    return {"domain": domain, "records": records, "ttls": ttls, "source": "dnspython", "timestamp": _now_iso()}


# Simple async wrapper to reuse existing HTTP scanner
def _run_async_scan_domain(domain: str, timeout: int) -> Dict[str, Any]:
    try:
        return run_http_scan(domain, timeout)
    except Exception:
        return {"http_results": {}, "http_risk_score": 0.0}


# Safe datetime parser used by the engine
def _safe_parse_dt(value: Any) -> Optional[datetime]:
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    try:
        # try common ISO formats
        return datetime.fromisoformat(str(value))
    except Exception:
        try:
            # fallback: parse date-like strings
            return datetime.strptime(str(value), "%Y-%m-%d")
        except Exception:
            return None


def extract_dynamic_seeds(target_domain: str) -> List[str]:
    parts = target_domain.lower().split(".")
    ignored = {"com", "net", "org", "cn", "gov", "edu"}
    return [p for p in parts if p not in ignored and len(p) > 2]


# =========================================================
# DNS
# =========================================================

def collect_dns_evidence(domain: str, timeout: float = 3.0) -> Dict[str, Any]:
    record_types = ["A", "AAAA", "MX", "NS"]

    records = {r: [] for r in record_types}
    ttl_map = {r: None for r in record_types}

    if dns:
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout

        for r in record_types:
            try:
                ans = resolver.resolve(domain, r)
                records[r] = [str(x) for x in ans]
                ttl_map[r] = int(ans.rrset.ttl)
            except Exception:
                pass
    else:
        try:
            info = socket.getaddrinfo(domain, None)
            records["A"] = list({i[4][0] for i in info if i[0] == socket.AF_INET})
        except Exception:
            pass

    return {
        "domain": domain,
        "records": records,
        "ttls": ttl_map,
        "timestamp": now_iso(),
    }


# =========================================================
# HTTP
# =========================================================

def run_http_scan(domain: str, timeout: int):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(scan_domain(domain, timeout=timeout))
    finally:
        loop.close()


# =========================================================
# Feature Extraction
# =========================================================

def extract_features(target_domain: str, domain: str, evidence: Dict):
    dns_data = evidence["dns"]
    http_data = evidence["http"]
    whois_data = evidence["whois"]
    threat_data = evidence["threat"]

    similarity = SequenceMatcher(
        a=target_domain.lower(), b=domain.lower()
    ).ratio()

    seeds = extract_dynamic_seeds(target_domain)
    seed_collision = any(s in domain for s in seeds)

    a_records = dns_data["records"].get("A", [])

    features = {
        "similarity": similarity,
        "seed_collision": seed_collision,
        "dns_fastflux": len(a_records) >= 4,
        "has_login_form": http_data.get("has_login_form", False),
        "http_risk": http_data.get("http_risk_score", 0),
        "whois_new": whois_data.get("is_new_registration", False),
        "whois_privacy": whois_data.get("privacy_flag", False),
        "threat_score": threat_data.get("risk_analysis", {}).get(
            "total_risk_score", 0
        ),
    }

    return features


# =========================================================
# Risk Model
# =========================================================

def calculate_dynamic_weights(features: Dict) -> Dict[str, float]:
    weights = {
        "similarity": 0.25,
        "registration": 0.20,
        "dns": 0.15,
        "web": 0.20,
        "threat": 0.20,
    }

    if features["whois_new"]:
        weights["registration"] += 0.15
        weights["web"] -= 0.10

    if features["has_login_form"]:
        weights["web"] += 0.15
        weights["similarity"] -= 0.05

    total = sum(weights.values())
    return {k: v / total for k, v in weights.items()}


def compute_risk(features: Dict):
    weights = calculate_dynamic_weights(features)

    similarity_score = features["similarity"] * 100

    registration_score = 0
    if features["whois_new"]:
        registration_score += 50
    if features["whois_privacy"]:
        registration_score += 20

    dns_score = 40 if features["dns_fastflux"] else 10

    web_score = features["http_risk"]
    if features["has_login_form"]:
        web_score += 30

    threat_score = features["threat_score"]

    final = (
        similarity_score * weights["similarity"]
        + registration_score * weights["registration"]
        + dns_score * weights["dns"]
        + web_score * weights["web"]
        + threat_score * weights["threat"]
    )

    if final >= 85:
        level = "critical"
    elif final >= 70:
        level = "high"
    elif final >= 50:
        level = "medium"
    elif final >= 30:
        level = "low"
    else:
        level = "info"

    return round(final, 2), level


# =========================================================
# Main Runner
# =========================================================

@dataclass
class RunConfig:
    max_domains: int = 50
    http_timeout: int = 10


def run_multidimensional_analysis(
    target_domain: str,
    domains: List[str],
    output_dir: str,
    config: Optional[RunConfig] = None,
):

    cfg = config or RunConfig()
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    threat_scanner = EnhancedThreatIntelligenceScanner()

    results = []

    for d in domains[: cfg.max_domains]:
        logger.info("Analyzing %s", d)

        evidence = {
            "dns": collect_dns_evidence(d),
            "http": run_http_scan(d, cfg.http_timeout),
            "whois": query_domain_whois_structured(d),
            "threat": threat_scanner.check_domain_reputation_enhanced(d),
        }

        features = extract_features(target_domain, d, evidence)
        score, level = compute_risk(features)

        results.append(
            {
                "domain": d,
                "score": score,
                "risk_level": level,
                "features": features,
                "timestamp": now_iso(),
            }
        )

    results.sort(key=lambda x: x["score"], reverse=True)

    output_file = Path(output_dir) / "multidimensional_results.json"
    output_file.write_text(json.dumps(results, indent=2))

    return {
        "target_domain": target_domain,
        "result_count": len(results),
        "top_risky": results[:10],
        "output_file": str(output_file),
    }
    records: Dict[str, List[str]] = {r: [] for r in record_types}
    ttl_map: Dict[str, Optional[int]] = {r: None for r in record_types}

    for rtype in record_types:
        try:
            answer = resolver.resolve(domain, rtype)
            records[rtype] = [str(item).strip() for item in answer]
            ttl_map[rtype] = int(getattr(answer.rrset, "ttl", 0) or 0)
        except Exception:
            continue

    return {
        "domain": domain,
        "records": records,
        "ttls": ttl_map,
        "source": "dnspython",
        "timestamp": _now_iso(),
    }


def _query_dns_with_socket(domain: str) -> Dict[str, Any]:
    records: Dict[str, List[str]] = {"A": [], "AAAA": [], "CNAME": [], "MX": [], "TXT": [], "NS": [], "CAA": []}
    try:
        info = socket.getaddrinfo(domain, None)
        for item in info:
            family = item[0]
            ip = item[4][0]
            if family == socket.AF_INET:
                records["A"].append(ip)
            elif family == socket.AF_INET6:
                records["AAAA"].append(ip)
    except Exception:
        pass

    records["A"] = sorted(set(records["A"]))
    records["AAAA"] = sorted(set(records["AAAA"]))
    return {
        "domain": domain,
        "records": records,
        "ttls": {"A": None, "AAAA": None, "CNAME": None, "MX": None, "TXT": None, "NS": None, "CAA": None},
        "source": "socket_fallback",
        "timestamp": _now_iso(),
    }


def collect_dns_evidence(domain: str, timeout: float = 3.0) -> Dict[str, Any]:
    record_types = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "CAA"]
    if dns is not None:
        return _query_dns_with_dnspython(domain, timeout, record_types)
    return _query_dns_with_socket(domain)


def _extract_cert_names(http_result: Dict[str, Any]) -> Tuple[str, List[str]]:
    cert = (
        http_result.get("http_results", {})
        .get("https", {})
        .get("ssl_certificate", {})
    ) or {}
    subject = cert.get("subject", {}) if isinstance(cert, dict) else {}
    cn = (subject.get("commonName") or subject.get("CN") or "").lower()

    san_list: List[str] = []
    if isinstance(cert, dict):
        raw_san = cert.get("subjectAltName", [])
        if isinstance(raw_san, list):
            for item in raw_san:
                if isinstance(item, (list, tuple)) and len(item) == 2:
                    san_list.append(str(item[1]).lower())
                elif isinstance(item, str):
                    san_list.append(item.lower())
    return cn, san_list


def extract_multidim_features(target_domain: str, domain: str, evidence: Dict[str, Any]) -> Dict[str, Any]:
    dns_data = evidence.get("dns", {})
    http_data = evidence.get("http", {})
    whois_data = evidence.get("whois", {})
    threat_data = evidence.get("threat", {})

    # 提取种子并检查碰撞 (Seed Collision)
    seeds = extract_dynamic_seeds(target_domain)
    seed_collision = any(s in domain.lower() for s in seeds)

    dns_records = dns_data.get("records", {})
    dns_ttls = dns_data.get("ttls", {})
    http_results = http_data.get("http_results", {})
    preferred = http_results.get("preferred")
    preferred_data = http_results.get(preferred, {}) if preferred in ("http", "https") else {}
    page_analysis = preferred_data.get("page_analysis", {})

    creation_date = ((whois_data.get("whois_info") or {}).get("creation_date"))
    created_dt = _safe_parse_dt(creation_date)
    age_days = None
    if created_dt is not None:
        age_days = max(0, (datetime.now(timezone.utc) - created_dt).days)

    whois_info = whois_data.get("whois_info", {}) if isinstance(whois_data, dict) else {}
    statuses = [str(s).lower() for s in (whois_info.get("status") or [])]
    registrar = str(whois_info.get("registrar") or "").lower()
    emails = [str(e).lower() for e in (whois_info.get("emails") or [])]

    similarity = SequenceMatcher(a=target_domain.lower(), b=domain.lower()).ratio()
    cn, san = _extract_cert_names(http_data)
    cert_mismatch = False
    if preferred == "https":
        if cn and (domain.lower() not in cn) and not any(domain.lower() in x for x in san):
            cert_mismatch = True

    return {
        "visual_similarity": round(similarity, 4),
        "dns": {
            "a_count": len(dns_records.get("A", [])),
            "aaaa_count": len(dns_records.get("AAAA", [])),
            "mx_count": len(dns_records.get("MX", [])),
            "ns_count": len(dns_records.get("NS", [])),
            "cname_count": len(dns_records.get("CNAME", [])),
            "txt_count": len(dns_records.get("TXT", [])),
            "caa_count": len(dns_records.get("CAA", [])),
            "low_ttl": any((dns_ttls.get(k) or 0) > 0 and (dns_ttls.get(k) or 0) < 300 for k in dns_ttls),
            "multi_a_records": len(dns_records.get("A", [])) >= 4,
        },
        "http": {
            "preferred_protocol": preferred or "none",
            "http_status": (http_results.get("http") or {}).get("status"),
            "https_status": (http_results.get("https") or {}).get("status"),
            "redirect_count": preferred_data.get("redirect_count", 0),
            "has_login_form": bool(page_analysis.get("has_login_form", False)),
            "keyword_hits": len(page_analysis.get("found_keywords", [])),
            "external_resources_count": int(page_analysis.get("external_resources_count", 0)),
            "cert_mismatch": cert_mismatch,
            "http_risk_score": float(http_data.get("http_risk_score", 0.0) or 0.0),
        },
        "whois": {
            "age_days": age_days,
            "is_new_registration": (age_days is not None and age_days <= 30),
            "is_recent_registration": (age_days is not None and age_days <= 90),
            "privacy_flag": any(x in " ".join(statuses) for x in ("privacy", "proxy", "redacted")),
            "risky_registrar_hint": any(x in registrar for x in ("privacy", "anonymous", "proxy", "cheap")),
            "suspicious_email_hint": any(x in e for x in emails for x in ("tempmail", "mailinator", "10minutemail")),
            "whois_risk_score": float(whois_data.get("whois_risk_score", 0.0) or 0.0),
        },
        "threat": {
            "threat_risk_score": float((threat_data.get("risk_analysis") or {}).get("total_risk_score", 0.0) or 0.0),
            "threat_confidence": float((threat_data.get("risk_analysis") or {}).get("confidence", 0.0) or 0.0),
            "api_success_rate": float(threat_data.get("api_success_rate", 0.0) or 0.0),
            "risk_level": str((threat_data.get("risk_analysis") or {}).get("risk_level", "unknown")),
        },
    }


def model_domain_risk(features: Dict[str, Any]) -> Dict[str, Any]:
    f_dns = features["dns"]
    f_http = features["http"]
    f_whois = features["whois"]
    f_threat = features["threat"]

    similarity_score = min(100.0, features["visual_similarity"] * 100.0)

    registration_score = 0.0
    if f_whois["is_new_registration"]:
        registration_score += 40
    elif f_whois["is_recent_registration"]:
        registration_score += 20
    if f_whois["privacy_flag"]:
        registration_score += 25
    if f_whois["risky_registrar_hint"]:
        registration_score += 15
    if f_whois["suspicious_email_hint"]:
        registration_score += 20
    registration_score += min(20.0, f_whois["whois_risk_score"])
    registration_score = min(100.0, registration_score)

    dns_score = 0.0
    if f_dns["a_count"] == 0 and f_dns["aaaa_count"] == 0 and f_dns["mx_count"] == 0:
        dns_score += 10
    if f_dns["low_ttl"]:
        dns_score += 20
    if f_dns["multi_a_records"]:
        dns_score += 20
    if f_dns["ns_count"] == 0:
        dns_score += 10
    dns_score = min(100.0, dns_score)

    web_score = 0.0
    web_score += min(100.0, f_http["http_risk_score"])
    if f_http["has_login_form"]:
        web_score += 20
    if f_http["keyword_hits"] >= 3:
        web_score += 20
    elif f_http["keyword_hits"] >= 1:
        web_score += 10
    if f_http["redirect_count"] >= 2:
        web_score += 10
    if f_http["cert_mismatch"]:
        web_score += 25
    web_score = min(100.0, web_score)

    threat_score = min(100.0, f_threat["threat_risk_score"])

    # Weighted multidimensional score.
    final_score = (
        similarity_score * 0.24
        + registration_score * 0.20
        + dns_score * 0.14
        + web_score * 0.22
        + threat_score * 0.20
    )
    final_score = round(min(100.0, final_score), 2)

    if final_score >= 85:
        level = "critical"
    elif final_score >= 70:
        level = "high"
    elif final_score >= 50:
        level = "medium"
    elif final_score >= 30:
        level = "low"
    else:
        level = "info"

    reasons: List[str] = []
    if features["visual_similarity"] >= 0.90:
        reasons.append("high_visual_similarity")
    if f_whois["is_new_registration"]:
        reasons.append("new_registration")
    if f_whois["privacy_flag"]:
        reasons.append("whois_privacy_enabled")
    if f_http["has_login_form"]:
        reasons.append("login_form_detected")
    if f_http["cert_mismatch"]:
        reasons.append("certificate_mismatch")
    if threat_score >= 60:
        reasons.append("threat_intel_high_score")
    if f_dns["low_ttl"] or f_dns["multi_a_records"]:
        reasons.append("dns_instability_pattern")

    return {
        "score": final_score,
        "risk_level": level,
        "component_scores": {
            "similarity": round(similarity_score, 2),
            "registration": round(registration_score, 2),
            "dns": round(dns_score, 2),
            "web": round(web_score, 2),
            "threat": round(threat_score, 2),
        },
        "reasons": reasons,
    }


def generate_alerts(target_domain: str, modeled: List[Dict[str, Any]]) -> Dict[str, Any]:
    alerts: List[Dict[str, Any]] = []
    for item in modeled:
        risk = item["risk"]
        if risk["risk_level"] not in ("critical", "high"):
            continue
        alerts.append(
            {
                "target_domain": target_domain,
                "domain": item["domain"],
                "risk_level": risk["risk_level"],
                "risk_score": risk["score"],
                "reasons": risk["reasons"],
                "recommended_actions": [
                    "prioritize_manual_triage",
                    "track_dns_http_changes",
                    "create_block_or_sinkhole_ticket_if_confirmed",
                ],
                "timestamp": _now_iso(),
            }
        )

    return {
        "target_domain": target_domain,
        "alert_count": len(alerts),
        "alerts": sorted(alerts, key=lambda x: x["risk_score"], reverse=True),
        "timestamp": _now_iso(),
    }


@dataclass
class MultiDimRunConfig:
    max_domains: int = 50
    dns_timeout: float = 3.0
    http_timeout: int = 10
    whois_delay_seconds: float = 1.0
    threat_workers: int = 3
    threat_delay_seconds: float = 1.0


def run_multidimensional_analysis(
    target_domain: str,
    domains: List[str],
    output_dir: str,
    config: Optional[MultiDimRunConfig] = None,
) -> Dict[str, Any]:
    cfg = config or MultiDimRunConfig()
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    candidate_domains = sorted(set(d.strip().lower() for d in domains if d and d.strip()))
    candidate_domains = candidate_domains[: max(1, cfg.max_domains)]

    threat_scanner = EnhancedThreatIntelligenceScanner(
        max_workers=max(1, cfg.threat_workers),
        rate_limit_delay=max(0.1, cfg.threat_delay_seconds),
    )

    modeled_results: List[Dict[str, Any]] = []
    for idx, domain in enumerate(candidate_domains, start=1):
        logger.info("Multi-dimensional analysis %d/%d: %s", idx, len(candidate_domains), domain)
        evidence = {
            "dns": collect_dns_evidence(domain, timeout=cfg.dns_timeout),
            "http": _run_async_scan_domain(domain, timeout=cfg.http_timeout),
            "whois": query_domain_whois_structured(domain),
            "threat": threat_scanner.check_domain_reputation_enhanced(domain),
        }
        features = extract_multidim_features(target_domain=target_domain, domain=domain, evidence=evidence)
        risk = model_domain_risk(features)
        modeled_results.append(
            {
                "domain": domain,
                "target_domain": target_domain,
                "evidence": evidence,
                "features": features,
                "risk": risk,
                "timestamp": _now_iso(),
            }
        )

    modeled_results.sort(key=lambda x: x["risk"]["score"], reverse=True)
    alerts = generate_alerts(target_domain=target_domain, modeled=modeled_results)

    summary = {
        "target_domain": target_domain,
        "analyzed_domain_count": len(modeled_results),
        "risk_distribution": {
            "critical": sum(1 for x in modeled_results if x["risk"]["risk_level"] == "critical"),
            "high": sum(1 for x in modeled_results if x["risk"]["risk_level"] == "high"),
            "medium": sum(1 for x in modeled_results if x["risk"]["risk_level"] == "medium"),
            "low": sum(1 for x in modeled_results if x["risk"]["risk_level"] == "low"),
            "info": sum(1 for x in modeled_results if x["risk"]["risk_level"] == "info"),
        },
        "top_high_risk_domains": [x["domain"] for x in modeled_results[:10]],
        "timestamp": _now_iso(),
    }

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    analysis_file = output_path / f"multidimensional_analysis_{target_domain}_{ts}.json"
    alerts_file = output_path / f"alerts_{target_domain}_{ts}.json"
    latest_analysis_file = output_path / "multidimensional_analysis_latest.json"
    latest_alerts_file = output_path / "alerts_latest.json"

    analysis_payload = {
        "summary": summary,
        "results": modeled_results,
        "config": {
            "max_domains": cfg.max_domains,
            "dns_timeout": cfg.dns_timeout,
            "http_timeout": cfg.http_timeout,
            "threat_workers": cfg.threat_workers,
            "threat_delay_seconds": cfg.threat_delay_seconds,
        },
        "timestamp": _now_iso(),
    }

    analysis_file.write_text(json.dumps(analysis_payload, ensure_ascii=False, indent=2), encoding="utf-8")
    alerts_file.write_text(json.dumps(alerts, ensure_ascii=False, indent=2), encoding="utf-8")
    latest_analysis_file.write_text(json.dumps(analysis_payload, ensure_ascii=False, indent=2), encoding="utf-8")
    latest_alerts_file.write_text(json.dumps(alerts, ensure_ascii=False, indent=2), encoding="utf-8")

    return {
        "summary": summary,
        "analysis_file": str(analysis_file),
        "alerts_file": str(alerts_file),
        "latest_analysis_file": str(latest_analysis_file),
        "latest_alerts_file": str(latest_alerts_file),
    }
'''

#!/usr/bin/env python3
"""
Multi-dimensional risk engine for proactive typosquatting monitoring.
FULL IMPLEMENTATION — production-ready for your domain security platform
"""

#from __future__ import annotations

import asyncio
import json
import logging
import socket
from dataclasses import dataclass
from datetime import datetime, timezone
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import dns.resolver
except Exception:
    dns = None

from modules.http_scanner.scanner import scan_domain
from modules.whois_enhanced import query_domain_whois_structured
from modules.threat_intelligence.intel_scanner_enhanced import (
    EnhancedThreatIntelligenceScanner,
)

logger = logging.getLogger(__name__)

# =========================================================
# Utils
# =========================================================

def now_iso():
    return datetime.now(timezone.utc).isoformat()


def extract_dynamic_seeds(target_domain: str) -> List[str]:
    parts = target_domain.lower().split(".")
    ignored = {"com", "net", "org", "cn", "gov", "edu"}
    return [p for p in parts if p not in ignored and len(p) > 2]


# =========================================================
# DNS
# =========================================================

def collect_dns_evidence(domain: str, timeout: float = 3.0) -> Dict[str, Any]:
    record_types = ["A", "AAAA", "MX", "NS"]

    records = {r: [] for r in record_types}
    ttl_map = {r: None for r in record_types}

    if dns:
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout

        for r in record_types:
            try:
                ans = resolver.resolve(domain, r)
                records[r] = [str(x) for x in ans]
                ttl_map[r] = int(ans.rrset.ttl)
            except Exception:
                pass
    else:
        try:
            info = socket.getaddrinfo(domain, None)
            records["A"] = list({i[4][0] for i in info if i[0] == socket.AF_INET})
        except Exception:
            pass

    return {
        "domain": domain,
        "records": records,
        "ttls": ttl_map,
        "timestamp": now_iso(),
    }


# =========================================================
# HTTP
# =========================================================

def run_http_scan(domain: str, timeout: int):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(scan_domain(domain, timeout=timeout))
    finally:
        loop.close()


# =========================================================
# Feature Extraction
# =========================================================

def extract_features(target_domain: str, domain: str, evidence: Dict):
    dns_data = evidence["dns"]
    http_data = evidence["http"]
    whois_data = evidence["whois"]
    threat_data = evidence["threat"]

    similarity = SequenceMatcher(
        a=target_domain.lower(), b=domain.lower()
    ).ratio()

    seeds = extract_dynamic_seeds(target_domain)
    seed_collision = any(s in domain for s in seeds)

    a_records = dns_data["records"].get("A", [])

    features = {
        "similarity": similarity,
        "seed_collision": seed_collision,
        "dns_fastflux": len(a_records) >= 4,
        "has_login_form": http_data.get("has_login_form", False),
        "http_risk": http_data.get("http_risk_score", 0),
        "whois_new": whois_data.get("is_new_registration", False),
        "whois_privacy": whois_data.get("privacy_flag", False),
        "threat_score": threat_data.get("risk_analysis", {}).get(
            "total_risk_score", 0
        ),
    }

    return features


# =========================================================
# Risk Model
# =========================================================

def calculate_dynamic_weights(features: Dict) -> Dict[str, float]:
    weights = {
        "similarity": 0.25,
        "registration": 0.20,
        "dns": 0.15,
        "web": 0.20,
        "threat": 0.20,
    }

    if features["whois_new"]:
        weights["registration"] += 0.15
        weights["web"] -= 0.10

    if features["has_login_form"]:
        weights["web"] += 0.15
        weights["similarity"] -= 0.05

    total = sum(weights.values())
    return {k: v / total for k, v in weights.items()}


def compute_risk(features: Dict):
    weights = calculate_dynamic_weights(features)

    similarity_score = features["similarity"] * 100

    registration_score = 0
    if features["whois_new"]:
        registration_score += 50
    if features["whois_privacy"]:
        registration_score += 20

    dns_score = 40 if features["dns_fastflux"] else 10

    web_score = features["http_risk"]
    if features["has_login_form"]:
        web_score += 30

    threat_score = features["threat_score"]

    final = (
        similarity_score * weights["similarity"]
        + registration_score * weights["registration"]
        + dns_score * weights["dns"]
        + web_score * weights["web"]
        + threat_score * weights["threat"]
    )

    if final >= 85:
        level = "critical"
    elif final >= 70:
        level = "high"
    elif final >= 50:
        level = "medium"
    elif final >= 30:
        level = "low"
    else:
        level = "info"

    return round(final, 2), level


# =========================================================
# Main Runner
# =========================================================

@dataclass
class RunConfig:
    max_domains: int = 50
    http_timeout: int = 10


def run_multidimensional_analysis(
    target_domain: str,
    domains: List[str],
    output_dir: str,
    config: Optional[RunConfig] = None,
):

    cfg = config or RunConfig()
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    threat_scanner = EnhancedThreatIntelligenceScanner()

    results = []

    for d in domains[: cfg.max_domains]:
        logger.info("Analyzing %s", d)

        evidence = {
            "dns": collect_dns_evidence(d),
            "http": run_http_scan(d, cfg.http_timeout),
            "whois": query_domain_whois_structured(d),
            "threat": threat_scanner.check_domain_reputation_enhanced(d),
        }

        features = extract_features(target_domain, d, evidence)
        score, level = compute_risk(features)

        results.append(
            {
                "domain": d,
                "score": score,
                "risk_level": level,
                "features": features,
                "timestamp": now_iso(),
            }
        )

    results.sort(key=lambda x: x["score"], reverse=True)

    output_file = Path(output_dir) / "multidimensional_results.json"
    output_file.write_text(json.dumps(results, indent=2))

    return {
        "target_domain": target_domain,
        "result_count": len(results),
        "top_risky": results[:10],
        "output_file": str(output_file),
    }
'''