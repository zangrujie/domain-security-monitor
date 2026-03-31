#!/usr/bin/env python3
"""
被动DNS聚合器
将多数据源结果进行标准化、去重、合并和质量打分。
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional


def _to_iso_time(value: Any) -> Optional[str]:
    """尽力将时间值转换为 ISO8601 字符串。"""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(value).isoformat()
        except Exception:
            return None
    if isinstance(value, str):
        return value
    return None


class PassiveDNSAggregator:
    """被动DNS结果聚合器。"""

    DEFAULT_SOURCE_WEIGHT = {
        "virus_total": 0.95,
        "dnsdb": 0.95,
        "securitytrails": 0.90,
        "circl": 0.75,
        "internal_sensor": 0.85,
        "self_collector": 0.70,
        "unknown": 0.60,
    }

    def __init__(self, source_weight: Optional[Dict[str, float]] = None):
        self.source_weight = dict(self.DEFAULT_SOURCE_WEIGHT)
        if source_weight:
            self.source_weight.update(source_weight)

    def normalize_record(self, record: Dict[str, Any], fallback_source: str = "unknown") -> Dict[str, Any]:
        """标准化单条记录字段，保证后续可合并。"""
        source = (record.get("source") or fallback_source or "unknown").strip()
        domain = (record.get("domain") or "").strip().lower()
        query_type = (record.get("query_type") or record.get("rrtype") or "A").strip().upper()
        rdata = (record.get("rdata") or record.get("ip_address") or "").strip()
        first_seen = _to_iso_time(record.get("first_seen") or record.get("time_first"))
        last_seen = _to_iso_time(record.get("last_seen") or record.get("time_last") or record.get("last_resolved"))

        return {
            "domain": domain,
            "query_type": query_type,
            "rdata": rdata,
            "source": source,
            "count": int(record.get("count", 1) or 1),
            "first_seen": first_seen,
            "last_seen": last_seen,
            "raw": record,
        }

    def dedupe_records(self, records: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        跨源去重：
        key = (domain, query_type, rdata)
        同一解析结果在不同 source 中会被合并。
        """
        merged: Dict[str, Dict[str, Any]] = {}

        for raw in records:
            normalized = self.normalize_record(raw, fallback_source=raw.get("source", "unknown"))
            if not normalized["domain"] or not normalized["rdata"]:
                continue

            key = f"{normalized['domain']}|{normalized['query_type']}|{normalized['rdata']}"
            item = merged.get(key)
            if not item:
                merged[key] = {
                    "domain": normalized["domain"],
                    "query_type": normalized["query_type"],
                    "rdata": normalized["rdata"],
                    "count": normalized["count"],
                    "first_seen": normalized["first_seen"],
                    "last_seen": normalized["last_seen"],
                    "sources": [normalized["source"]],
                    "source_count": 1,
                    "confidence": self.source_weight.get(normalized["source"], self.source_weight["unknown"]),
                }
                continue

            item["count"] = max(int(item.get("count", 1)), int(normalized.get("count", 1)))

            existing_first = item.get("first_seen")
            incoming_first = normalized.get("first_seen")
            if incoming_first and (not existing_first or incoming_first < existing_first):
                item["first_seen"] = incoming_first

            existing_last = item.get("last_seen")
            incoming_last = normalized.get("last_seen")
            if incoming_last and (not existing_last or incoming_last > existing_last):
                item["last_seen"] = incoming_last

            if normalized["source"] not in item["sources"]:
                item["sources"].append(normalized["source"])
                item["source_count"] = len(item["sources"])

            current_conf = float(item.get("confidence", 0))
            incoming_conf = self.source_weight.get(normalized["source"], self.source_weight["unknown"])
            item["confidence"] = max(current_conf, incoming_conf)

        records_out = list(merged.values())
        records_out.sort(key=lambda x: (x["domain"], x["query_type"], x["rdata"]))
        return records_out

    def build_indicators(self, records: List[Dict[str, Any]]) -> Dict[str, Any]:
        """生成基础可疑指标。"""
        unique_ips = len({r.get("rdata") for r in records if r.get("rdata")})
        multi_source_hits = sum(1 for r in records if len(r.get("sources", [])) >= 2)

        indicators = {
            "unique_resolution_count": unique_ips,
            "multi_source_confirmed_count": multi_source_hits,
            "possible_fast_flux": unique_ips >= 5,
        }
        return indicators

    def merge_source_results(
        self,
        source_results: Dict[str, Dict[str, Any]],
        domain: Optional[str] = None,
        query_type: str = "A",
    ) -> Dict[str, Any]:
        """聚合多 source 的查询结果。"""
        all_records: List[Dict[str, Any]] = []

        for source_name, source_result in (source_results or {}).items():
            if not isinstance(source_result, dict):
                continue
            for record in source_result.get("records", []) or []:
                if isinstance(record, dict):
                    if "source" not in record:
                        record = {**record, "source": source_name}
                    all_records.append(record)

        merged_records = self.dedupe_records(all_records)
        indicators = self.build_indicators(merged_records)

        return {
            "domain": (domain or "").lower(),
            "query_type": query_type,
            "total_records": len(merged_records),
            "records": merged_records,
            "indicators": indicators,
        }
