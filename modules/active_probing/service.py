#!/usr/bin/env python3
"""
主动探测服务层
对扫描器提供更稳定的调用接口，便于在 pipeline 中接入。
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .web_scanner import ActiveWebScanner


class ActiveProbingService:
    def __init__(self, timeout: int = 15, screenshot_dir: Optional[str] = None):
        self.scanner = ActiveWebScanner(timeout=timeout, screenshot_dir=screenshot_dir)

    def probe_domain(
        self,
        domain: str,
        reference_image: Optional[str] = None,
        enable_screenshot: bool = True,
    ) -> Dict[str, Any]:
        return self.scanner.scan_url(
            domain_or_url=domain,
            reference_image=reference_image,
            enable_screenshot=enable_screenshot,
        )

    def probe_batch(
        self,
        domains: List[str],
        reference_image: Optional[str] = None,
        enable_screenshot: bool = True,
        max_workers: int = 4,
    ) -> Dict[str, Any]:
        return self.scanner.scan_domains(
            domains=domains,
            reference_image=reference_image,
            enable_screenshot=enable_screenshot,
            max_workers=max_workers,
        )
