#!/usr/bin/env python3
"""
主动Web探测器
支持基础HTTP探测、可疑指标提取、可选截图、可选视觉比对。
"""

from __future__ import annotations

import os
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup

from .visual_compare import compare_images

try:
    from playwright.sync_api import sync_playwright

    PLAYWRIGHT_AVAILABLE = True
except Exception:
    PLAYWRIGHT_AVAILABLE = False


PHISHING_KEYWORDS = [
    "login",
    "signin",
    "password",
    "verify account",
    "security alert",
    "bank",
    "wallet",
    "apple id",
    "microsoft account",
]


class ActiveWebScanner:
    """主动Web探测器。"""

    def __init__(
        self,
        timeout: int = 15,
        screenshot_dir: Optional[str] = None,
        user_agent: Optional[str] = None,
    ):
        self.timeout = timeout
        self.user_agent = user_agent or (
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        )
        default_dir = os.getenv("SCREENSHOT_DIR", "monitoring_results/screenshots")
        self.screenshot_dir = Path(screenshot_dir or default_dir)
        self.screenshot_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _normalize_url(domain_or_url: str) -> str:
        value = (domain_or_url or "").strip()
        if not value:
            return ""
        if value.startswith("http://") or value.startswith("https://"):
            return value
        return f"https://{value}"

    def _http_fetch(self, url: str) -> Dict[str, Any]:
        headers = {"User-Agent": self.user_agent}
        start = time.time()
        response = requests.get(url, headers=headers, timeout=self.timeout, allow_redirects=True)
        duration_ms = int((time.time() - start) * 1000)
        return {
            "ok": True,
            "status_code": response.status_code,
            "final_url": response.url,
            "headers": dict(response.headers),
            "html": response.text or "",
            "response_ms": duration_ms,
        }

    @staticmethod
    def _extract_page_features(html: str) -> Dict[str, Any]:
        if not html:
            return {
                "title": "",
                "script_count": 0,
                "form_count": 0,
                "external_script_count": 0,
                "password_input_count": 0,
            }
        soup = BeautifulSoup(html, "lxml")
        title = soup.title.text.strip() if soup.title and soup.title.text else ""
        scripts = soup.find_all("script")
        forms = soup.find_all("form")
        external_scripts = [s for s in scripts if s.get("src")]
        password_inputs = soup.find_all("input", {"type": "password"})
        return {
            "title": title,
            "script_count": len(scripts),
            "form_count": len(forms),
            "external_script_count": len(external_scripts),
            "password_input_count": len(password_inputs),
        }

    @staticmethod
    def _build_suspicious_indicators(domain: str, html: str, page_features: Dict[str, Any]) -> Dict[str, Any]:
        html_lower = (html or "").lower()
        keyword_hits = [kw for kw in PHISHING_KEYWORDS if kw in html_lower]
        has_punycode = "xn--" in (domain or "").lower()
        has_login_form = page_features.get("password_input_count", 0) > 0
        js_heavy = page_features.get("script_count", 0) >= 15
        score = min(100, len(keyword_hits) * 8 + (20 if has_login_form else 0) + (15 if has_punycode else 0) + (10 if js_heavy else 0))
        severity = "high" if score >= 60 else "medium" if score >= 30 else "low"
        return {
            "keyword_hits": keyword_hits,
            "has_login_form": has_login_form,
            "has_punycode": has_punycode,
            "js_heavy_page": js_heavy,
            "suspicion_score": score,
            "severity": severity,
        }

    def _capture_screenshot(self, url: str, screenshot_name: str) -> Optional[str]:
        if not PLAYWRIGHT_AVAILABLE:
            return None
        image_path = self.screenshot_dir / f"{screenshot_name}.png"
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page()
                page.goto(url, wait_until="networkidle", timeout=max(self.timeout * 1000, 5000))
                page.screenshot(path=str(image_path), full_page=True)
                browser.close()
            return str(image_path)
        except Exception:
            return None

    def scan_url(
        self,
        domain_or_url: str,
        reference_image: Optional[str] = None,
        enable_screenshot: bool = True,
    ) -> Dict[str, Any]:
        url = self._normalize_url(domain_or_url)
        domain = urlparse(url).netloc or domain_or_url
        now = datetime.now(timezone.utc).isoformat()
        if not url:
            return {
                "success": False,
                "domain": domain_or_url,
                "error": "empty_url",
                "timestamp": now,
            }

        try:
            http_data = self._http_fetch(url)
        except Exception as exc:
            return {
                "success": False,
                "domain": domain,
                "url": url,
                "error": str(exc),
                "timestamp": now,
            }

        html = http_data.get("html", "")
        page_features = self._extract_page_features(html)
        indicators = self._build_suspicious_indicators(domain, html, page_features)
        screenshot_path = None
        visual_similarity = None

        if enable_screenshot:
            safe_name = re.sub(r"[^a-zA-Z0-9._-]", "_", domain)
            screenshot_path = self._capture_screenshot(url, safe_name)

        if reference_image and screenshot_path and os.path.exists(reference_image):
            visual_similarity = compare_images(reference_image, screenshot_path)

        return {
            "success": True,
            "domain": domain,
            "url": url,
            "status_code": http_data.get("status_code"),
            "final_url": http_data.get("final_url"),
            "response_ms": http_data.get("response_ms"),
            "page_features": page_features,
            "suspicious_indicators": indicators,
            "screenshot_path": screenshot_path,
            "visual_similarity": visual_similarity,
            "timestamp": now,
        }

    def scan_domains(
        self,
        domains: List[str],
        max_workers: int = 4,
        reference_image: Optional[str] = None,
        enable_screenshot: bool = True,
    ) -> Dict[str, Any]:
        started = time.time()
        results: Dict[str, Any] = {}
        with ThreadPoolExecutor(max_workers=max(1, max_workers)) as pool:
            future_map = {
                pool.submit(self.scan_url, d, reference_image, enable_screenshot): d for d in (domains or [])
            }
            for future in as_completed(future_map):
                domain = future_map[future]
                try:
                    results[domain] = future.result()
                except Exception as exc:
                    results[domain] = {"success": False, "domain": domain, "error": str(exc)}

        success_count = sum(1 for v in results.values() if v.get("success"))
        return {
            "success": True,
            "total": len(domains or []),
            "success_count": success_count,
            "failure_count": (len(domains or []) - success_count),
            "duration_seconds": round(time.time() - started, 2),
            "results": results,
        }
