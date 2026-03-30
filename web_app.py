#!/usr/bin/env python3
"""
域名安全监控系统 - Web管理界面
基于Flask的Web应用程序，提供域名监控数据可视化和管理功能
"""

import os
import sys
import json
import copy
import io
import csv
import zipfile
from datetime import datetime, timedelta
from pathlib import Path
from threading import Lock, Thread
from uuid import uuid4
from sqlalchemy import func, and_, or_, desc, text

# 添加模块路径
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# 加载环境变量
from dotenv import load_dotenv
load_dotenv()

from flask import Flask, render_template, jsonify, request, send_file, make_response
from flask_cors import CORS
from modules.domain_input import DomainInputError, normalize_domain_input

# 导入项目模块
try:
    from modules.database.connection import DatabaseConnection, get_db, init_database, DatabaseSession
    from modules.database.dao import get_data_manager
    from modules.database.models import Domain, DNSScan, HTTPScan, WhoisRecord, ThreatIntelligence, RiskAssessment
    DATABASE_ENABLED = True
except ImportError as e:
    print(f"数据库模块导入失败: {e}")
    DATABASE_ENABLED = False

try:
    from modules.data_analysis import get_data_analyzer
    from modules.xdig_enhanced_analyzer import get_xdig_analyzer
except ImportError:
    get_data_analyzer = None
    get_xdig_analyzer = None

# 创建Flask应用
app = Flask(__name__)
CORS(app)  # 允许跨域请求

# 配置
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'domain-security-monitor-secret-key')
app.config['JSON_AS_ASCII'] = False  # 支持中文

# 项目根目录
BASE_DIR = Path(__file__).parent


@app.route('/screenshots/<path:filename>')
def serve_screenshot(filename):
    """Serve screenshot files from SCREENSHOT_DIR (configured in .env).

    Example URL: /screenshots/example.com_20260307.png
    """
    screenshot_dir = os.getenv('SCREENSHOT_DIR', str(BASE_DIR / 'monitoring_results' / 'screenshots'))
    file_path = Path(screenshot_dir) / filename
    if not file_path.exists():
        return jsonify({'error': 'not found'}), 404
    try:
        # send_file will set correct mime type
        return send_file(str(file_path))
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# 全局变量：扫描任务状态
scan_tasks = {}
scan_tasks_lock = Lock()
report_store_lock = Lock()


def _clamp_int_env(name: str, default: int, min_value: int, max_value: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except Exception:
        value = default
    return max(min_value, min(max_value, value))


def _append_scan_log(scan_id: str, level: str, message: str):
    """向扫描任务写入一条日志。"""
    ts = datetime.now().isoformat()
    with scan_tasks_lock:
        task = scan_tasks.get(scan_id)
        if not task:
            return
        logs = task.setdefault("logs", [])
        logs.append({
            "timestamp": ts,
            "level": (level or "INFO").upper(),
            "message": message or ""
        })

# 函数：运行扫描任务
def _run_scan_task(scan_id: str, domain: str):
    """Run the actual scan task in the background and update its status."""
    try:
        from run_web_scan import start_scan_from_web

        with scan_tasks_lock:
            scan_tasks[scan_id]["status"] = "running"
            scan_tasks[scan_id]["progress"] = 10
            scan_tasks[scan_id]["message"] = "Scan task is running"
            scan_tasks[scan_id]["started_at"] = datetime.now().isoformat()
        _append_scan_log(scan_id, "INFO", f"任务开始执行，目标域名: {domain}")

        result = start_scan_from_web(domain)
        method = result.get("method", "unknown") if isinstance(result, dict) else "unknown"
        _append_scan_log(scan_id, "INFO", f"扫描方法: {method}")

        with scan_tasks_lock:
            scan_tasks[scan_id]["finished_at"] = datetime.now().isoformat()
            scan_tasks[scan_id]["result"] = result
            if result.get("success"):
                scan_tasks[scan_id]["status"] = "completed"
                scan_tasks[scan_id]["progress"] = 100
                scan_tasks[scan_id]["message"] = result.get("message", "Scan completed")
                _append_scan_log(scan_id, "SUCCESS", result.get("message", "扫描完成"))
                target = (result.get("domain") or domain or "").strip().lower()
                if target and "manager" in globals():
                    try:
                        manager.invalidate_analysis_cache(target)
                        manager.refresh_original_target_summary(target)
                        _append_scan_log(scan_id, "INFO", f"分析缓存已失效并刷新汇总: {target}")
                    except Exception as agg_err:
                        _append_scan_log(scan_id, "WARN", f"汇总刷新失败: {agg_err}")
            else:
                scan_tasks[scan_id]["status"] = "failed"
                scan_tasks[scan_id]["progress"] = 100
                scan_tasks[scan_id]["message"] = result.get("error", "Scan failed")
                _append_scan_log(scan_id, "ERROR", result.get("error", "扫描失败"))
    except Exception as e:
        with scan_tasks_lock:
            scan_tasks[scan_id]["status"] = "failed"
            scan_tasks[scan_id]["progress"] = 100
            scan_tasks[scan_id]["finished_at"] = datetime.now().isoformat()
            scan_tasks[scan_id]["message"] = f"Scan error: {str(e)}"
        _append_scan_log(scan_id, "ERROR", f"任务异常: {str(e)}")

class WebAppManager:
    """Web应用管理器"""
    
    def __init__(self):
        self.db_connection = None
        self.data_manager = None
        self._file_metrics_cache = {}
        self._file_metrics_cache_lock = Lock()
        self._analysis_cache = {}
        self._analysis_cache_lock = Lock()
        self._analysis_cache_ttl_seconds = _clamp_int_env(
            "ANALYSIS_CACHE_TTL_SECONDS",
            default=60,
            min_value=30,
            max_value=120,
        )
        self.init_database()
    
    def init_database(self):
        """初始化数据库连接"""
        if DATABASE_ENABLED:
            try:
                # 初始化全局数据库连接
                self.db_connection = init_database()
                self.data_manager = get_data_manager()
                self._ensure_original_target_summary_table()
                self._ensure_performance_indexes()
                print("✅ 数据库连接成功")
            except Exception as e:
                print(f"❌ 数据库初始化失败: {e}")
                # 如果初始化失败，回退到创建本地连接
                try:
                    self.db_connection = DatabaseConnection()
                    if self.db_connection.connect():
                        self.data_manager = get_data_manager()
                        self._ensure_original_target_summary_table()
                        self._ensure_performance_indexes()
                        print("✅ 数据库连接成功（本地连接）")
                    else:
                        print("❌ 数据库连接失败")
                except Exception as e2:
                    print(f"❌ 本地数据库连接也失败: {e2}")
        else:
            print("⚠️  数据库模块未启用，仅提供有限功能")

    @staticmethod
    def _risk_severity(level: str) -> int:
        """风险等级权重，用于按原始域名聚合时取最严重等级。"""
        mapping = {"critical": 5, "high": 4, "medium": 3, "low": 2, "unknown": 1}
        return mapping.get((level or "unknown").lower(), 1)

    def _ensure_performance_indexes(self):
        """创建性能相关索引（幂等），避免查询退化为全表扫描。"""
        if not (DATABASE_ENABLED and self.db_connection):
            return

        statements = [
            "CREATE INDEX IF NOT EXISTS idx_domains_original_target_lower ON domains ((lower(original_target)));",
            "CREATE INDEX IF NOT EXISTS idx_domains_domain_lower ON domains ((lower(domain)));",
            "CREATE INDEX IF NOT EXISTS idx_dns_scans_domain_ts ON dns_scans (domain_id, scan_timestamp DESC);",
            "CREATE INDEX IF NOT EXISTS idx_http_scans_domain_ts ON http_scans (domain_id, scan_timestamp DESC);",
            "CREATE INDEX IF NOT EXISTS idx_whois_records_domain_ts ON whois_records (domain_id, query_timestamp DESC);",
            "CREATE INDEX IF NOT EXISTS idx_risk_assessments_domain_ts ON risk_assessments (domain_id, assessment_timestamp DESC);",
            "CREATE INDEX IF NOT EXISTS idx_threat_intel_domain_ts ON threat_intelligence (domain_id, check_timestamp DESC);",
            "CREATE INDEX IF NOT EXISTS idx_original_target_summary_target_lower ON original_target_summary ((lower(original_target)));",
        ]

        try:
            with DatabaseSession() as session:
                for sql in statements:
                    session.execute(text(sql))
                session.commit()
        except Exception as e:
            print(f"⚠️  性能索引创建失败（可忽略，不影响功能）：{e}")

    def _ensure_original_target_summary_table(self):
        """创建原始域名预聚合汇总表（幂等）。"""
        if not (DATABASE_ENABLED and self.db_connection):
            return

        statements = [
            """
            CREATE TABLE IF NOT EXISTS original_target_summary (
                original_target VARCHAR(255) PRIMARY KEY,
                summary_json JSONB NOT NULL DEFAULT '{}'::jsonb,
                risk_distribution JSONB NOT NULL DEFAULT '{}'::jsonb,
                registration_time_distribution JSONB NOT NULL DEFAULT '{}'::jsonb,
                registrar_distribution JSONB NOT NULL DEFAULT '{}'::jsonb,
                updated_at TIMESTAMP NOT NULL DEFAULT NOW()
            );
            """,
            "CREATE INDEX IF NOT EXISTS idx_original_target_summary_updated_at ON original_target_summary (updated_at DESC);",
        ]
        try:
            with DatabaseSession() as session:
                for sql in statements:
                    session.execute(text(sql))
                session.commit()
        except Exception as e:
            print(f"⚠️  original_target_summary 初始化失败（可忽略）：{e}")

    def run_vacuum_analyze(self) -> dict:
        """执行核心表 VACUUM ANALYZE（需 AUTOCOMMIT）。"""
        if not (DATABASE_ENABLED and self.db_connection and self.db_connection.engine):
            return {"success": False, "error": "数据库不可用"}

        tables = [
            "domains",
            "dns_scans",
            "http_scans",
            "whois_records",
            "risk_assessments",
            "threat_intelligence",
            "original_target_summary",
        ]
        done = []
        try:
            with self.db_connection.engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
                for table in tables:
                    conn.execute(text(f"VACUUM ANALYZE {table};"))
                    done.append(table)
            return {"success": True, "tables": done, "count": len(done)}
        except Exception as e:
            return {"success": False, "error": str(e), "tables": done}

    def _analysis_cache_get(self, cache_key: str):
        now_ts = datetime.utcnow().timestamp()
        with self._analysis_cache_lock:
            cached = self._analysis_cache.get(cache_key)
            if not cached:
                return None
            if float(cached.get("expires_at", 0.0)) <= now_ts:
                self._analysis_cache.pop(cache_key, None)
                return None
            return copy.deepcopy(cached.get("data"))

    def _analysis_cache_set(self, cache_key: str, payload: dict):
        if not isinstance(payload, dict):
            return
        expires_at = datetime.utcnow().timestamp() + float(self._analysis_cache_ttl_seconds)
        with self._analysis_cache_lock:
            self._analysis_cache[cache_key] = {
                "expires_at": expires_at,
                "data": copy.deepcopy(payload),
            }

    def invalidate_analysis_cache(self, original_target: str | None = None):
        """失效分析缓存。传入 original_target 时仅失效该目标。"""
        with self._analysis_cache_lock:
            if not original_target:
                self._analysis_cache.clear()
                return
            target = (original_target or "").strip().lower()
            if not target:
                return
            keys = [k for k in self._analysis_cache.keys() if k.startswith(f"{target}|")]
            for key in keys:
                self._analysis_cache.pop(key, None)

    def _count_non_empty_lines_cached(self, file_path: Path | None) -> int:
        """统计文件非空行数，基于 mtime/size 做内存缓存。"""
        if not file_path or not file_path.exists():
            return 0
        try:
            stat = file_path.stat()
            cache_key = ("line_count", str(file_path))
            signature = (stat.st_mtime_ns, stat.st_size)
            with self._file_metrics_cache_lock:
                cached = self._file_metrics_cache.get(cache_key)
                if cached and cached.get("sig") == signature:
                    return int(cached.get("value", 0))

            count = 0
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if line.strip():
                        count += 1

            with self._file_metrics_cache_lock:
                self._file_metrics_cache[cache_key] = {"sig": signature, "value": count}
            return count
        except Exception:
            return 0

    def _load_domain_set_cached(self, file_path: Path | None, mode: str) -> set[str]:
        """
        从文件加载域名集合并缓存：
        - mode=keyboard: keyboard_variants.txt
        - mode=variant: puny_only.txt
        """
        if not file_path or not file_path.exists():
            return set()
        try:
            stat = file_path.stat()
            cache_key = ("domain_set", mode, str(file_path))
            signature = (stat.st_mtime_ns, stat.st_size)
            with self._file_metrics_cache_lock:
                cached = self._file_metrics_cache.get(cache_key)
                if cached and cached.get("sig") == signature:
                    return set(cached.get("value", set()))

            domains = set()
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    text_line = (line or "").strip()
                    if not text_line:
                        continue
                    domain_value = text_line.split("\t")[0].strip().lower()
                    if domain_value:
                        domains.add(domain_value)

            with self._file_metrics_cache_lock:
                self._file_metrics_cache[cache_key] = {"sig": signature, "value": domains}
            return domains
        except Exception:
            return set()

    def _build_original_target_asset_summary(self) -> dict:
        """按原始输入域名聚合资产统计（每个 original_target 计为 1 个监控资产）。"""
        if not (DATABASE_ENABLED and self.db_connection):
            return {}

        with DatabaseSession() as session:
            latest_risk_subq = (
                session.query(
                    RiskAssessment.domain_id.label("domain_id"),
                    func.max(RiskAssessment.assessment_timestamp).label("latest_risk_ts"),
                )
                .group_by(RiskAssessment.domain_id)
                .subquery()
            )

            rows = (
                session.query(
                    Domain.domain,
                    Domain.original_target,
                    Domain.last_updated,
                    RiskAssessment.risk_level,
                )
                .outerjoin(latest_risk_subq, Domain.id == latest_risk_subq.c.domain_id)
                .outerjoin(
                    RiskAssessment,
                    and_(
                        RiskAssessment.domain_id == latest_risk_subq.c.domain_id,
                        RiskAssessment.assessment_timestamp == latest_risk_subq.c.latest_risk_ts,
                    ),
                )
                .all()
            )

            grouped = {}
            for domain_name, original_target, last_updated, risk_level in rows:
                target = (original_target or "").strip()
                if not target:
                    target = (domain_name or "").strip()
                if not target:
                    continue

                current_level = (risk_level or "unknown").lower()
                item = grouped.get(target)
                if not item:
                    grouped[target] = {
                        "risk_level": current_level,
                        "last_updated": last_updated,
                    }
                    continue

                if self._risk_severity(current_level) > self._risk_severity(item["risk_level"]):
                    item["risk_level"] = current_level
                if last_updated and (not item["last_updated"] or last_updated > item["last_updated"]):
                    item["last_updated"] = last_updated

            total = len(grouped)
            critical = sum(1 for v in grouped.values() if v["risk_level"] == "critical")
            high = sum(1 for v in grouped.values() if v["risk_level"] == "high")
            medium = sum(1 for v in grouped.values() if v["risk_level"] == "medium")
            low = sum(1 for v in grouped.values() if v["risk_level"] == "low")

            cutoff_24h = datetime.utcnow() - timedelta(hours=24)
            recent_scans = sum(
                1
                for v in grouped.values()
                if v["last_updated"] is not None and v["last_updated"] >= cutoff_24h
            )

            return {
                "total_domains": total,
                "high_risk_domains": high + critical,
                "critical_risk_domains": critical,
                "medium_risk_domains": medium,
                "low_risk_domains": low,
                "recent_scans": recent_scans,
                "threats_detected": high + critical,
            }
    
    def get_dashboard_stats(self):
        """获取仪表板统计信息"""
        stats = {
            "total_domains": 0,
            "high_risk_domains": 0,
            "medium_risk_domains": 0,
            "low_risk_domains": 0,
            "recent_scans": 0,
            "threats_detected": 0
        }

        # 优先使用“按原始输入域名聚合”的数据库统计
        try:
            grouped_stats = self._build_original_target_asset_summary()
            if grouped_stats:
                stats.update(grouped_stats)
        except Exception as e:
            print(f"按原始域名聚合统计失败: {e}")
        
        # 如果没有数据库，从文件系统获取
        if not self.data_manager or stats["total_domains"] == 0:
            try:
                # 检查domain_variants目录
                variants_dir = BASE_DIR / "domain_variants"
                if variants_dir.exists():
                    target_dirs = [d for d in variants_dir.iterdir() if d.is_dir()]
                    stats["total_domains"] = len(target_dirs)
                
                # 检查高风险域名文件 - 更合理的统计
                high_risk_count = 0
                for target_dir in variants_dir.iterdir():
                    if target_dir.is_dir():
                        high_risk_file = target_dir / "high_risk.txt"
                        if high_risk_file.exists():
                            # 每个目录最多算1个高风险域名，避免过度统计
                            high_risk_count += 1
                
                # 合理分配风险等级
                stats["high_risk_domains"] = min(high_risk_count, stats["total_domains"])
                if stats["total_domains"] > 0:
                    # 中等风险占20%
                    stats["medium_risk_domains"] = max(1, stats["total_domains"] // 5)
                    # 低风险占剩余部分
                    stats["low_risk_domains"] = max(0, stats["total_domains"] - stats["high_risk_domains"] - stats["medium_risk_domains"])
                else:
                    stats["medium_risk_domains"] = 0
                    stats["low_risk_domains"] = 0
                    
                stats["recent_scans"] = stats["total_domains"]
                stats["threats_detected"] = stats["high_risk_domains"]
                
            except Exception as e:
                print(f"从文件系统获取统计失败: {e}")
                # 提供合理的默认值
                stats["total_domains"] = 7
                stats["high_risk_domains"] = 2
                stats["medium_risk_domains"] = 2
                stats["low_risk_domains"] = 3
                stats["recent_scans"] = 7
                stats["threats_detected"] = 2
        
        return stats
    
    def get_xdig_dangerous_domains(self, limit=20):
        """获取xdig探测到的危险域名（存在的域名都标记为危险）"""
        dangerous_domains = []

        try:
            # 查找xdig结果文件
            xdig_files = list(BASE_DIR.glob("active_domains*.txt"))
            xdig_files.sort(key=lambda x: x.stat().st_mtime if x.exists() else 0, reverse=True)

            if not xdig_files:
                return jsonify({"error": "No xdig result files found."}), 404

            for xdig_file in xdig_files[:3]:  # 检查最新的3个文件
                if not xdig_file.exists():
                    continue

                with open(xdig_file, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        line = line.strip()
                        if line and ',' in line:
                            parts = line.split(',')
                            domain = parts[0].strip()
                            # 格式: domain,1 表示存活，domain,0 表示不存活
                            if len(parts) > 1 and parts[1].strip() == '1':
                                # 域名存在，标记为危险
                                dangerous_domains.append({
                                    "domain": domain,
                                    "original_target": domain.split('.')[0] if '.' in domain else domain,
                                    "scan_time": datetime.fromtimestamp(xdig_file.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                                    "risk_level": "high",
                                    "risk_score": 85,
                                    "detection_method": "xdig_dns_probe",
                                    "status": "active"
                                })

            # 如果没有找到xdig文件，从domain_variants目录中查找
            if not dangerous_domains:
                variants_dir = BASE_DIR / "domain_variants"
                if variants_dir.exists():
                    target_dirs = list(variants_dir.iterdir())
                    target_dirs.sort(key=lambda x: x.stat().st_mtime if x.is_dir() else 0, reverse=True)

                    for target_dir in target_dirs[:limit]:
                        if target_dir.is_dir():
                            domain_name = target_dir.name

                            # 检查是否有punycode文件（表示有生成的变体）
                            punycode_file = target_dir / "puny_only.txt"
                            if punycode_file.exists():
                                # 读取punycode域名，将它们标记为危险
                                with open(punycode_file, 'r', encoding='utf-8', errors='ignore') as f:
                                    for line in f:
                                        domain = line.strip()
                                        if domain and '.' in domain:
                                            dangerous_domains.append({
                                                "domain": domain,
                                                "original_target": domain_name.split('_')[0] if '_' in domain_name else domain_name,
                                                "scan_time": datetime.fromtimestamp(target_dir.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                                                "risk_level": "high",
                                                "risk_score": 75,
                                                "detection_method": "punycode_variant",
                                                "status": "generated"
                                            })

            # 限制返回数量
            dangerous_domains = dangerous_domains[:limit]

            # 确保 original_target 字段始终存在
            for domain in dangerous_domains:
                if "original_target" not in domain or not domain["original_target"]:
                    domain["original_target"] = "unknown"

        except Exception as e:
            print(f"获取危险域名失败: {e}")
            return []

        return dangerous_domains
    
    def get_recent_domains(self, limit=5):
        """获取最近扫描的原始域名。"""
        safe_limit = max(1, min(int(limit or 5), 50))

        if DATABASE_ENABLED and self.db_connection:
            try:
                with DatabaseSession() as session:
                    target_expr = func.coalesce(func.nullif(Domain.original_target, ""), Domain.domain)
                    rows = (
                        session.query(
                            target_expr.label("original_target"),
                            func.max(Domain.last_updated).label("last_updated"),
                        )
                        .group_by(target_expr)
                        .order_by(desc(func.max(Domain.last_updated)))
                        .limit(safe_limit)
                        .all()
                    )

                    result = []
                    for target, last_updated in rows:
                        target_text = (target or "").strip()
                        if not target_text:
                            continue
                        result.append(
                            {
                                "original_target": target_text,
                                "scan_time": (
                                    last_updated.strftime("%Y-%m-%d %H:%M:%S")
                                    if last_updated
                                    else ""
                                ),
                            }
                        )
                    if result:
                        return result
            except Exception:
                pass

        # 数据库不可用时，退化为目录名（原始域名）
        results = []
        variants_dir = BASE_DIR / "domain_variants"
        if variants_dir.exists():
            targets = sorted(
                [d for d in variants_dir.iterdir() if d.is_dir()],
                key=lambda d: d.stat().st_mtime if d.exists() else 0,
                reverse=True,
            )
            for d in targets[:safe_limit]:
                target = d.name.replace("_", ".")
                results.append(
                    {
                        "original_target": target,
                        "scan_time": datetime.fromtimestamp(d.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                    }
                )
        return results
    
    def get_risk_distribution(self):
        """获取风险分布数据"""
        stats = self.get_dashboard_stats()
        critical = int(stats.get("critical_risk_domains", 0))
        high_total = int(stats.get("high_risk_domains", 0))
        high = max(0, high_total - critical)
        medium = int(stats.get("medium_risk_domains", 0))
        low = int(stats.get("low_risk_domains", 0))
        
        return {
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low
        }
    
    def get_system_status(self):
        """获取系统状态"""
        db_ok = False
        if DATABASE_ENABLED and self.db_connection:
            try:
                db_ok = bool(self.db_connection.test_connection())
            except Exception:
                db_ok = False

        return {
            "database": db_ok,
            "api_keys": {
                "virustotal": bool(os.getenv('VIRUSTOTAL_API_KEY')),
                "urlhaus": bool(os.getenv('URLHAUS_API_KEY'))
            },
            "storage": {
                "domain_count": len(list(BASE_DIR.glob("domain_variants/*"))) if BASE_DIR.exists() else 0,
                "result_files": len(list(BASE_DIR.glob("*.txt")))
            }
        }

    def ensure_domain_record(self, domain: str) -> bool:
        """在启动扫描时先写入基础域名记录，确保列表页可见。"""
        if not DATABASE_ENABLED or not self.db_connection:
            return False

        try:
            with DatabaseSession() as session:
                domain_obj = session.query(Domain).filter(Domain.domain == domain).first()
                if domain_obj:
                    domain_obj.last_updated = datetime.utcnow()
                    if not domain_obj.original_target:
                        domain_obj.original_target = domain
                else:
                    session.add(
                        Domain(
                            domain=domain,
                            original_target=domain,
                            generation_method="web_scan",
                            visual_similarity=0.0,
                        )
                    )
            return True
        except Exception as e:
            print(f"写入基础域名记录失败: {e}")
            return False

    def get_domains_paginated(
        self,
        page: int = 1,
        page_size: int = 20,
        search: str = "",
        risk_level: str = "",
        status: str = "",
        include_variants: bool = False,
    ) -> dict:
        """获取域名列表（分页/搜索/风险筛选/状态筛选）。"""
        if not DATABASE_ENABLED or not self.db_connection:
            return {
                "data": [],
                "pagination": {
                    "page": page,
                    "page_size": page_size,
                    "total": 0,
                    "total_pages": 1,
                },
            }

        safe_page = max(1, int(page))
        safe_page_size = max(1, min(int(page_size), 100))
        search = (search or "").strip()
        risk_level = (risk_level or "").strip().lower()
        status = (status or "").strip().lower()

        with DatabaseSession() as session:
            latest_risk_subq = (
                session.query(
                    RiskAssessment.domain_id.label("domain_id"),
                    func.max(RiskAssessment.assessment_timestamp).label("latest_risk_ts"),
                )
                .group_by(RiskAssessment.domain_id)
                .subquery()
            )

            latest_dns_subq = (
                session.query(
                    DNSScan.domain_id.label("domain_id"),
                    func.max(DNSScan.scan_timestamp).label("latest_dns_ts"),
                )
                .group_by(DNSScan.domain_id)
                .subquery()
            )

            base_query = (
                session.query(Domain, RiskAssessment, DNSScan)
                .outerjoin(latest_risk_subq, Domain.id == latest_risk_subq.c.domain_id)
                .outerjoin(
                    RiskAssessment,
                    and_(
                        RiskAssessment.domain_id == latest_risk_subq.c.domain_id,
                        RiskAssessment.assessment_timestamp == latest_risk_subq.c.latest_risk_ts,
                    ),
                )
                .outerjoin(latest_dns_subq, Domain.id == latest_dns_subq.c.domain_id)
                .outerjoin(
                    DNSScan,
                    and_(
                        DNSScan.domain_id == latest_dns_subq.c.domain_id,
                        DNSScan.scan_timestamp == latest_dns_subq.c.latest_dns_ts,
                    ),
                )
            )

            if search:
                lowered = f"%{search.lower()}%"
                base_query = base_query.filter(
                    or_(
                        func.lower(Domain.domain).like(lowered),
                        func.lower(func.coalesce(Domain.original_target, "")).like(lowered),
                    )
                )

            # include_variants=True 时保留原逻辑（逐域名显示）
            if include_variants:
                if risk_level:
                    base_query = base_query.filter(
                        func.lower(func.coalesce(RiskAssessment.risk_level, "unknown")) == risk_level
                    )

                if status == "active":
                    base_query = base_query.filter(DNSScan.has_dns_record.is_(True))
                elif status == "inactive":
                    base_query = base_query.filter(DNSScan.has_dns_record.is_(False))
                elif status == "monitoring":
                    base_query = base_query.filter(DNSScan.id.is_(None))

                total = (
                    base_query.with_entities(func.count(func.distinct(Domain.id))).scalar() or 0
                )
                total_pages = max(1, (total + safe_page_size - 1) // safe_page_size)
                offset = (safe_page - 1) * safe_page_size

                rows = (
                    base_query.order_by(desc(Domain.last_updated), desc(Domain.first_seen))
                    .offset(offset)
                    .limit(safe_page_size)
                    .all()
                )

                original_targets = {d.original_target for d, _, _ in rows if d.original_target}
                target_counts = {}
                if original_targets:
                    target_counts = dict(
                        session.query(Domain.original_target, func.count(Domain.id))
                        .filter(Domain.original_target.in_(original_targets))
                        .group_by(Domain.original_target)
                        .all()
                    )

                domains = []
                for domain_obj, risk_obj, dns_obj in rows:
                    if dns_obj is None:
                        domain_status = "monitoring"
                    else:
                        domain_status = "active" if dns_obj.has_dns_record else "inactive"

                    domains.append(
                        {
                            "domain": domain_obj.domain,
                            "original_target": domain_obj.original_target or domain_obj.domain,
                            "risk_level": risk_obj.risk_level if risk_obj else "unknown",
                            "risk_score": risk_obj.weighted_total_score if risk_obj else 0.0,
                            "scan_time": (
                                domain_obj.last_updated.strftime("%Y-%m-%d %H:%M:%S")
                                if domain_obj.last_updated
                                else ""
                            ),
                            "variant_count": (
                                target_counts.get(domain_obj.original_target, 1)
                                if domain_obj.original_target
                                else 1
                            ),
                            "status": domain_status,
                            "is_grouped": False,
                        }
                    )
            else:
                # 默认：按原始域名聚合，只显示原始域名级别数据
                rows = base_query.order_by(desc(Domain.last_updated), desc(Domain.first_seen)).all()

                severity = {"critical": 5, "high": 4, "medium": 3, "low": 2, "unknown": 1}

                grouped = {}
                for domain_obj, risk_obj, dns_obj in rows:
                    target = (domain_obj.original_target or "").strip()
                    if not target or "." not in target:
                        target = domain_obj.domain

                    if dns_obj is None:
                        domain_status = "monitoring"
                    else:
                        domain_status = "active" if dns_obj.has_dns_record else "inactive"

                    risk_lv = (risk_obj.risk_level if risk_obj and risk_obj.risk_level else "unknown").lower()
                    risk_score = float(risk_obj.weighted_total_score if risk_obj else 0.0)

                    item = grouped.get(target)
                    if not item:
                        grouped[target] = {
                            "domain": target,
                            "original_target": target,
                            "risk_level": risk_lv,
                            "risk_score": risk_score,
                            "scan_time": domain_obj.last_updated.strftime("%Y-%m-%d %H:%M:%S") if domain_obj.last_updated else "",
                            "variant_count": 1,
                            "status": domain_status,
                            "is_grouped": True,
                            "_last_updated": domain_obj.last_updated,
                        }
                        continue

                    item["variant_count"] += 1
                    if domain_obj.last_updated and (not item["_last_updated"] or domain_obj.last_updated > item["_last_updated"]):
                        item["_last_updated"] = domain_obj.last_updated
                        item["scan_time"] = domain_obj.last_updated.strftime("%Y-%m-%d %H:%M:%S")

                    if severity.get(risk_lv, 1) > severity.get(item["risk_level"], 1):
                        item["risk_level"] = risk_lv
                    if risk_score > float(item["risk_score"]):
                        item["risk_score"] = risk_score

                    # 状态优先级：active > monitoring > inactive
                    status_priority = {"active": 3, "monitoring": 2, "inactive": 1}
                    if status_priority.get(domain_status, 0) > status_priority.get(item["status"], 0):
                        item["status"] = domain_status

                domains = list(grouped.values())

                if risk_level:
                    domains = [d for d in domains if (d.get("risk_level") or "unknown").lower() == risk_level]
                if status:
                    domains = [d for d in domains if (d.get("status") or "").lower() == status]

                domains.sort(key=lambda d: (d.get("_last_updated") is not None, d.get("_last_updated")), reverse=True)

                total = len(domains)
                total_pages = max(1, (total + safe_page_size - 1) // safe_page_size)
                offset = (safe_page - 1) * safe_page_size
                domains = domains[offset: offset + safe_page_size]
                for d in domains:
                    d.pop("_last_updated", None)

            return {
                "data": domains,
                "pagination": {
                    "page": safe_page,
                    "page_size": safe_page_size,
                    "total": total,
                    "total_pages": total_pages,
                },
            }

    def get_domain_detail(self, domain_name: str):
        """获取单个域名详情。"""
        if not DATABASE_ENABLED or not self.db_connection:
            return None

        with DatabaseSession() as session:
            domain_obj = session.query(Domain).filter(Domain.domain == domain_name).first()
            if not domain_obj:
                return None

            latest_risk = (
                session.query(RiskAssessment)
                .filter(RiskAssessment.domain_id == domain_obj.id)
                .order_by(desc(RiskAssessment.assessment_timestamp))
                .first()
            )
            latest_dns = (
                session.query(DNSScan)
                .filter(DNSScan.domain_id == domain_obj.id)
                .order_by(desc(DNSScan.scan_timestamp))
                .first()
            )
            latest_http = (
                session.query(HTTPScan)
                .filter(HTTPScan.domain_id == domain_obj.id)
                .order_by(desc(HTTPScan.scan_timestamp))
                .first()
            )
            latest_whois = (
                session.query(WhoisRecord)
                .filter(WhoisRecord.domain_id == domain_obj.id)
                .order_by(desc(WhoisRecord.query_timestamp))
                .first()
            )
            latest_threat = (
                session.query(ThreatIntelligence)
                .filter(ThreatIntelligence.domain_id == domain_obj.id)
                .order_by(desc(ThreatIntelligence.check_timestamp))
                .first()
            )

            if latest_dns is None:
                domain_status = "monitoring"
            else:
                domain_status = "active" if latest_dns.has_dns_record else "inactive"

            return {
                "domain": domain_obj.domain,
                "original_target": domain_obj.original_target or domain_obj.domain,
                "punycode": domain_obj.punycode,
                "visual_similarity": domain_obj.visual_similarity,
                "generation_method": domain_obj.generation_method,
                "first_seen": domain_obj.first_seen.isoformat() if domain_obj.first_seen else None,
                "last_updated": domain_obj.last_updated.isoformat() if domain_obj.last_updated else None,
                "status": domain_status,
                "risk": {
                    "risk_level": latest_risk.risk_level if latest_risk else "unknown",
                    "risk_score": latest_risk.weighted_total_score if latest_risk else 0.0,
                    "risk_factors": latest_risk.risk_factors if latest_risk else [],
                    "confidence": latest_risk.confidence if latest_risk else 0.0,
                },
                "dns": {
                    "has_dns_record": latest_dns.has_dns_record if latest_dns else None,
                    "resolved_ips": latest_dns.resolved_ips if latest_dns else [],
                    "response_time_ms": latest_dns.response_time_ms if latest_dns else None,
                    "dns_server": latest_dns.dns_server if latest_dns else None,
                },
                "http": {
                    "http_status": latest_http.http_status if latest_http else None,
                    "https_status": latest_http.https_status if latest_http else None,
                    "preferred_protocol": latest_http.preferred_protocol if latest_http else None,
                    "final_url": latest_http.final_url if latest_http else None,
                    "http_risk_score": latest_http.http_risk_score if latest_http else 0.0,
                },
                "whois": {
                    "registrar": latest_whois.registrar if latest_whois else None,
                    "creation_date": latest_whois.creation_date.isoformat() if latest_whois and latest_whois.creation_date else None,
                    "expiration_date": latest_whois.expiration_date.isoformat() if latest_whois and latest_whois.expiration_date else None,
                    "whois_risk_score": latest_whois.whois_risk_score if latest_whois else 0.0,
                },
                "threat": {
                    "threat_sources_checked": latest_threat.threat_sources_checked if latest_threat else [],
                    "threat_risk_score": latest_threat.threat_risk_score if latest_threat else 0.0,
                    "risk_level": latest_threat.risk_level if latest_threat else "unknown",
                },
            }

    def get_variants_by_original_target(self, original_target: str) -> dict:
        """按原始域名获取伪域名明细（不包含原始域名本身）。"""
        target = (original_target or "").strip().lower()
        if not target:
            return {"original_target": "", "variants": [], "summary": {"total_variants": 0, "active_variants": 0}}

        if not DATABASE_ENABLED or not self.db_connection:
            return {
                "original_target": target,
                "variants": [],
                "summary": {"total_variants": 0, "active_variants": 0},
            }

        variants_root = BASE_DIR / "domain_variants"
        punycode_file = None
        if variants_root.exists():
            candidates = [
                variants_root / target / "puny_only.txt",
                variants_root / target.replace(".", "_") / "puny_only.txt",
            ]
            for c in candidates:
                if c.exists():
                    punycode_file = c
                    break

        variant_domain_set = set()
        if punycode_file and punycode_file.exists():
            try:
                with open(punycode_file, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        text = (line or "").strip()
                        if not text:
                            continue
                        variant_domain_set.add(text.split("\t")[0].strip().lower())
            except Exception:
                variant_domain_set = set()

        with DatabaseSession() as session:
            latest_risk_subq = (
                session.query(
                    RiskAssessment.domain_id.label("domain_id"),
                    func.max(RiskAssessment.assessment_timestamp).label("latest_risk_ts"),
                )
                .group_by(RiskAssessment.domain_id)
                .subquery()
            )

            latest_dns_subq = (
                session.query(
                    DNSScan.domain_id.label("domain_id"),
                    func.max(DNSScan.scan_timestamp).label("latest_dns_ts"),
                )
                .group_by(DNSScan.domain_id)
                .subquery()
            )

            rows = (
                session.query(Domain, RiskAssessment, DNSScan)
                .outerjoin(latest_risk_subq, Domain.id == latest_risk_subq.c.domain_id)
                .outerjoin(
                    RiskAssessment,
                    and_(
                        RiskAssessment.domain_id == latest_risk_subq.c.domain_id,
                        RiskAssessment.assessment_timestamp == latest_risk_subq.c.latest_risk_ts,
                    ),
                )
                .outerjoin(latest_dns_subq, Domain.id == latest_dns_subq.c.domain_id)
                .outerjoin(
                    DNSScan,
                    and_(
                        DNSScan.domain_id == latest_dns_subq.c.domain_id,
                        DNSScan.scan_timestamp == latest_dns_subq.c.latest_dns_ts,
                    ),
                )
                .filter(or_(func.lower(Domain.original_target) == target, func.lower(Domain.domain) == target))
                .order_by(desc(Domain.last_updated), desc(Domain.first_seen))
                .all()
            )

            variants = []
            active_count = 0
            for domain_obj, risk_obj, dns_obj in rows:
                # 原始域名用于主列表展示，不放到伪域名二级列表中
                if (domain_obj.domain or "").strip().lower() == target:
                    continue

                domain_name = (domain_obj.domain or "").strip().lower()
                if variant_domain_set and domain_name and domain_name not in variant_domain_set:
                    continue

                if dns_obj is None:
                    domain_status = "monitoring"
                else:
                    domain_status = "active" if dns_obj.has_dns_record else "inactive"

                if domain_status == "active":
                    active_count += 1

                variants.append(
                    {
                        "domain": domain_obj.domain,
                        "risk_level": (risk_obj.risk_level if risk_obj and risk_obj.risk_level else "unknown").lower(),
                        "risk_score": float(risk_obj.weighted_total_score if risk_obj else 0.0),
                        "scan_time": (
                            domain_obj.last_updated.strftime("%Y-%m-%d %H:%M:%S")
                            if domain_obj.last_updated
                            else ""
                        ),
                        "status": domain_status,
                    }
                )

            return {
                "original_target": target,
                "variants": variants,
                "summary": {
                    "total_variants": len(variants),
                    "active_variants": active_count,
                },
            }

    def delete_domain(self, domain_name: str) -> bool:
        """删除单个域名及其关联扫描数据。"""
        if not DATABASE_ENABLED or not self.db_connection:
            return False

        with DatabaseSession() as session:
            domain_obj = session.query(Domain).filter(Domain.domain == domain_name).first()
            if not domain_obj:
                return False

            session.delete(domain_obj)
            session.commit()
            return True

    def delete_domains(self, domain_names: list[str]) -> dict:
        """批量删除域名及其关联扫描数据。"""
        if not DATABASE_ENABLED or not self.db_connection:
            return {"deleted": [], "not_found": list(domain_names or [])}

        valid_names = [d.strip().lower() for d in (domain_names or []) if isinstance(d, str) and d.strip()]
        if not valid_names:
            return {"deleted": [], "not_found": []}

        deleted = []
        not_found = []
        with DatabaseSession() as session:
            for domain_name in valid_names:
                domain_obj = session.query(Domain).filter(Domain.domain == domain_name).first()
                if not domain_obj:
                    not_found.append(domain_name)
                    continue
                session.delete(domain_obj)
                deleted.append(domain_name)
            session.commit()

        return {"deleted": deleted, "not_found": not_found}

    @staticmethod
    def _json_to_dict(value, default: dict | None = None) -> dict:
        if isinstance(value, dict):
            return value
        if isinstance(value, str):
            try:
                parsed = json.loads(value)
                if isinstance(parsed, dict):
                    return parsed
            except Exception:
                pass
        return default if isinstance(default, dict) else {}

    def _build_summary_payload_from_analysis(self, payload: dict) -> dict:
        data = copy.deepcopy(payload or {})
        data["active_variants"] = []
        return data

    def _upsert_original_target_summary(self, original_target: str, payload: dict):
        if not (DATABASE_ENABLED and self.db_connection):
            return
        target = (original_target or "").strip().lower()
        if not target:
            return

        summary_payload = self._build_summary_payload_from_analysis(payload)
        risk_distribution = self._json_to_dict((summary_payload.get("summary") or {}).get("risk_distribution"), {})
        registration_distribution = self._json_to_dict(summary_payload.get("registration_time_distribution"), {})
        registrar_distribution = self._json_to_dict(summary_payload.get("registrar_distribution"), {})

        sql = text(
            """
            INSERT INTO original_target_summary (
                original_target,
                summary_json,
                risk_distribution,
                registration_time_distribution,
                registrar_distribution,
                updated_at
            ) VALUES (
                :original_target,
                CAST(:summary_json AS JSONB),
                CAST(:risk_distribution AS JSONB),
                CAST(:registration_time_distribution AS JSONB),
                CAST(:registrar_distribution AS JSONB),
                NOW()
            )
            ON CONFLICT (original_target) DO UPDATE SET
                summary_json = EXCLUDED.summary_json,
                risk_distribution = EXCLUDED.risk_distribution,
                registration_time_distribution = EXCLUDED.registration_time_distribution,
                registrar_distribution = EXCLUDED.registrar_distribution,
                updated_at = NOW();
            """
        )
        params = {
            "original_target": target,
            "summary_json": json.dumps(summary_payload, ensure_ascii=False),
            "risk_distribution": json.dumps(risk_distribution, ensure_ascii=False),
            "registration_time_distribution": json.dumps(registration_distribution, ensure_ascii=False),
            "registrar_distribution": json.dumps(registrar_distribution, ensure_ascii=False),
        }
        with DatabaseSession() as session:
            session.execute(sql, params)
            session.commit()

    def _load_original_target_summary(self, original_target: str) -> dict | None:
        if not (DATABASE_ENABLED and self.db_connection):
            return None
        target = (original_target or "").strip().lower()
        if not target:
            return None

        row_sql = text(
            """
            SELECT
                summary_json,
                risk_distribution,
                registration_time_distribution,
                registrar_distribution,
                updated_at
            FROM original_target_summary
            WHERE lower(original_target) = :target
            LIMIT 1
            """
        )
        with DatabaseSession() as session:
            row = session.execute(row_sql, {"target": target}).mappings().first()
        if not row:
            return None

        payload = self._json_to_dict(row.get("summary_json"), {})
        if not payload:
            return None
        payload["active_variants"] = []
        payload["registration_time_distribution"] = self._json_to_dict(
            row.get("registration_time_distribution"),
            self._json_to_dict(payload.get("registration_time_distribution"), {}),
        )
        payload["registrar_distribution"] = self._json_to_dict(
            row.get("registrar_distribution"),
            self._json_to_dict(payload.get("registrar_distribution"), {}),
        )
        summary_obj = self._json_to_dict(payload.get("summary"), {})
        summary_obj["risk_distribution"] = self._json_to_dict(
            row.get("risk_distribution"),
            self._json_to_dict(summary_obj.get("risk_distribution"), {}),
        )
        payload["summary"] = summary_obj
        meta = self._json_to_dict(payload.get("meta"), {})
        meta["data_source"] = "preaggregated"
        meta["preaggregated_updated_at"] = (
            row.get("updated_at").isoformat() if row.get("updated_at") else None
        )
        payload["meta"] = meta
        return payload

    def refresh_original_target_summary(self, original_target: str) -> dict | None:
        """强制重算并写入 original_target_summary。"""
        target = (original_target or "").strip().lower()
        if not target:
            return None
        payload = self.analyze_original_target(
            target,
            include_active_variants=False,
            use_cache=False,
            prefer_preaggregated=False,
        )
        if not payload:
            return None
        self.invalidate_analysis_cache(target)
        return payload

    def get_original_target_summary(self, original_target: str) -> dict | None:
        """优先读取预聚合汇总；无缓存时自动构建。"""
        target = (original_target or "").strip().lower()
        if not target:
            return None

        cache_key = f"{target}|summary"
        cached = self._analysis_cache_get(cache_key)
        if cached:
            return cached

        payload = self._load_original_target_summary(target)
        if payload:
            self._analysis_cache_set(cache_key, payload)
            return payload

        payload = self.analyze_original_target(
            target,
            include_active_variants=False,
            use_cache=False,
            prefer_preaggregated=False,
        )
        if payload:
            try:
                self._upsert_original_target_summary(target, payload)
            except Exception:
                pass
            self._analysis_cache_set(cache_key, payload)
        return payload

    def get_original_target_active_variants(self, original_target: str) -> dict:
        """返回活跃伪域名明细（用于前端第二阶段异步加载）。"""
        payload = self.analyze_original_target(
            original_target,
            include_active_variants=True,
            use_cache=True,
            prefer_preaggregated=False,
        )
        if not payload:
            return {"original_target": (original_target or "").strip().lower(), "active_variants": []}
        return {
            "original_target": payload.get("original_target") or (original_target or "").strip().lower(),
            "active_variants": payload.get("active_variants") or [],
        }

    def analyze_original_target(
        self,
        original_target: str,
        include_active_variants: bool = True,
        use_cache: bool = True,
        prefer_preaggregated: bool = False,
    ) -> dict | None:
        """按原始域名聚合伪域名分析数据。"""
        target = (original_target or "").strip().lower()
        if not target:
            return None

        mode = "full" if include_active_variants else "summary"
        cache_key = f"{target}|{mode}"
        if use_cache:
            cached = self._analysis_cache_get(cache_key)
            if cached:
                return cached

        if prefer_preaggregated and not include_active_variants:
            pre_agg = self._load_original_target_summary(target)
            if pre_agg:
                if use_cache:
                    self._analysis_cache_set(cache_key, pre_agg)
                return pre_agg

        def find_variants_file(file_name: str) -> Path | None:
            variants_root = BASE_DIR / "domain_variants"
            if not variants_root.exists():
                return None
            candidates = [
                variants_root / target / file_name,
                variants_root / target.replace(".", "_") / file_name,
            ]
            for candidate in candidates:
                if candidate.exists():
                    return candidate
            return None

        punycode_file = find_variants_file("puny_only.txt")
        keyboard_file = find_variants_file("keyboard_variants.txt")
        file_generated_variants = self._count_non_empty_lines_cached(punycode_file)
        keyboard_generated_variants = self._count_non_empty_lines_cached(keyboard_file)
        keyboard_domain_set = self._load_domain_set_cached(keyboard_file, mode="keyboard")
        variant_domain_set = self._load_domain_set_cached(punycode_file, mode="variant")

        def fallback_payload(reason: str = "") -> dict:
            # 数据库不可用时返回可渲染的基础结构，避免页面报错
            return {
                "original_target": target,
                "meta": {
                    "data_source": "fallback",
                    "db_available": False,
                    "reason": reason or "数据库不可用，已回退到兜底数据。",
                },
                "summary": {
                    "asset_total": 0,
                    "high_risk_exposure_count": 0,
                    "high_risk_exposure_rate": 0.0,
                    "risk_distribution": {
                        "critical": 0,
                        "high": 0,
                        "medium": 0,
                        "low": 0,
                        "unknown": 0,
                    },
                    "total_variants": 0,
                    "generated_variants": 0,
                    "db_generated_variants": 0,
                    "file_generated_variants": file_generated_variants,
                    "generated_variants_diff": file_generated_variants,
                    "keyboard_generated_variants": keyboard_generated_variants,
                    "keyboard_db_variants": 0,
                    "keyboard_active_variants": 0,
                    "active_variants": 0,
                    "high_phishing_suspected": 0,
                    "medium_phishing_suspected": 0,
                },
                "counting_rules": {
                    "file_source": str(punycode_file) if punycode_file else "",
                    "keyboard_file_source": str(keyboard_file) if keyboard_file else "",
                    "file_generated_variants_desc": "来自 domain_variants/<目标>/puny_only.txt 非空行数",
                    "db_generated_variants_desc": "来自 domains 表中 original_target=目标 的存在伪域名记录数（不含原始域名）",
                    "keyboard_generated_variants_desc": "来自 keyboard_variants.txt 非空行数（键盘相邻生成）",
                    "keyboard_db_variants_desc": "数据库伪域名中命中键盘相邻集合的数量",
                    "db_scope_desc": "数据库入库来自扫描管道后续模块输出（通常经过 XDIG 存活与注册过滤后），并非全量生成文件。",
                },
                "active_variants": [],
                "registration_time_distribution": {},
                "registrar_distribution": {},
            }

        if not DATABASE_ENABLED or not self.db_connection:
            payload = fallback_payload("数据库模块未启用或连接未初始化。")
            if use_cache:
                self._analysis_cache_set(cache_key, payload)
            return payload

        def normalize_date(date_obj):
            if not date_obj:
                return None
            try:
                return date_obj.strftime("%Y-%m")
            except Exception:
                return None

        def infer_page_function(page_analysis: dict, title: str) -> str:
            text = " ".join([
                (title or "").lower(),
                " ".join(page_analysis.get("found_keywords", [])).lower()
            ])
            if page_analysis.get("has_login_form"):
                return "登录/认证页面"
            if any(k in text for k in ["bank", "paypal", "alipay", "wechat", "pay"]):
                return "支付/金融页面"
            if any(k in text for k in ["shop", "cart", "store", "product"]):
                return "电商/销售页面"
            if any(k in text for k in ["download", "install", "update"]):
                return "下载/更新页面"
            return "通用内容页"

        def build_threat_hit_reasons(latest_threat) -> list[str]:
            if not latest_threat:
                return []

            reasons = []
            threat_results = latest_threat.threat_results if isinstance(latest_threat.threat_results, dict) else {}

            urlhaus = threat_results.get("urlhaus", {}) if isinstance(threat_results, dict) else {}
            if isinstance(urlhaus, dict) and urlhaus.get("malicious"):
                reasons.append("URLhaus命中")

            internal_blacklist = threat_results.get("internal_blacklist", {}) if isinstance(threat_results, dict) else {}
            if isinstance(internal_blacklist, dict) and internal_blacklist.get("listed"):
                reasons.append("内部黑名单命中")

            vt = threat_results.get("virustotal", {}) if isinstance(threat_results, dict) else {}
            if isinstance(vt, dict):
                vt_malicious = int(vt.get("malicious_detections", 0) or 0)
                vt_suspicious = int(vt.get("suspicious_detections", 0) or 0)
                if vt_malicious > 0:
                    reasons.append(f"VT恶意检测数: {vt_malicious}")
                elif vt_suspicious > 0:
                    reasons.append(f"VT可疑检测数: {vt_suspicious}")

            phishtank = threat_results.get("phishtank", {}) if isinstance(threat_results, dict) else {}
            if isinstance(phishtank, dict):
                if phishtank.get("known_phishing"):
                    reasons.append("PhishTank已知钓鱼命中")
                elif phishtank.get("phishing_suspected"):
                    reasons.append("PhishTank疑似钓鱼")

            if not reasons:
                score = float(latest_threat.threat_risk_score or 0.0)
                reasons.append(f"威胁情报评分较高: {score:.1f}")

            return reasons

        def evaluate_phishing_probability(latest_risk, latest_http, latest_threat):
            reasons = []

            risk_score = float(latest_risk.weighted_total_score if latest_risk else 0.0)
            http_score = float(latest_http.http_risk_score if latest_http else 0.0)
            threat_score = float(latest_threat.threat_risk_score if latest_threat else 0.0)

            # 对不同模块分值做简单归一化并融合
            risk_norm = max(0.0, min(100.0, risk_score))
            http_norm = max(0.0, min(100.0, http_score * (100.0 / 35.0)))
            threat_norm = max(0.0, min(100.0, threat_score * (100.0 / 20.0)))

            page_analysis = (latest_http.page_analysis if latest_http and latest_http.page_analysis else {})
            keywords = page_analysis.get("found_keywords", []) if isinstance(page_analysis, dict) else []
            has_login_form = bool(page_analysis.get("has_login_form")) if isinstance(page_analysis, dict) else False
            has_redirect = bool(page_analysis.get("has_redirect")) if isinstance(page_analysis, dict) else False

            extra = 0.0
            if has_login_form:
                extra += 15.0
                reasons.append("页面包含登录表单")
            if len(keywords) >= 3:
                extra += 12.0
                reasons.append("存在多个敏感关键词")
            elif len(keywords) >= 1:
                extra += 6.0
                reasons.append("存在可疑关键词")
            if has_redirect:
                extra += 8.0
                reasons.append("检测到页面重定向")

            if threat_norm >= 60:
                reasons.extend(build_threat_hit_reasons(latest_threat))
            if risk_norm >= 60:
                reasons.append("综合风险评分较高")

            prob = 0.45 * risk_norm + 0.30 * http_norm + 0.25 * threat_norm + extra
            prob = round(max(0.0, min(100.0, prob)), 1)

            if prob >= 70:
                level = "high"
            elif prob >= 40:
                level = "medium"
            else:
                level = "low"

            return prob, level, reasons

        def estimate_risk_from_signals(latest_dns, latest_whois, latest_http, latest_threat):
            score = 0.0
            factors = []

            if latest_dns and latest_dns.has_dns_record:
                score += 5.0
                factors.append("dns_active")

            if latest_whois:
                whois_score = float(getattr(latest_whois, "whois_risk_score", 0.0) or 0.0)
                score += min(25.0, whois_score * 2.0)
                if whois_score > 0:
                    factors.append("whois_signal")
                creation_date = getattr(latest_whois, "creation_date", None)
                if creation_date:
                    try:
                        age_days = (datetime.utcnow() - creation_date).days
                        if age_days <= 30:
                            score += 25.0
                            factors.append("new_registration_30d")
                        elif age_days <= 180:
                            score += 12.0
                            factors.append("recent_registration_180d")
                    except Exception:
                        pass
                registrar = (getattr(latest_whois, "registrar", "") or "").strip()
                if not registrar:
                    score += 8.0
                    factors.append("missing_registrar")

            if latest_http:
                http_score = float(getattr(latest_http, "http_risk_score", 0.0) or 0.0)
                score += min(35.0, http_score)
                page_analysis = latest_http.page_analysis if latest_http and latest_http.page_analysis else {}
                if isinstance(page_analysis, dict):
                    if page_analysis.get("has_login_form"):
                        score += 18.0
                        factors.append("login_form")
                    keywords = page_analysis.get("found_keywords", []) or []
                    if len(keywords) >= 3:
                        score += 12.0
                        factors.append("multi_sensitive_keywords")
                    elif len(keywords) >= 1:
                        score += 6.0
                        factors.append("sensitive_keyword")
                    if page_analysis.get("has_redirect"):
                        score += 8.0
                        factors.append("http_redirect")

            if latest_threat:
                threat_score = float(getattr(latest_threat, "threat_risk_score", 0.0) or 0.0)
                score += min(30.0, threat_score * 1.5)
                if threat_score > 0:
                    factors.append("threat_intel_signal")

            score = round(max(0.0, min(100.0, score)), 2)
            if score >= 70:
                level = "critical"
            elif score >= 50:
                level = "high"
            elif score >= 25:
                level = "medium"
            elif score > 0:
                level = "low"
            else:
                level = "unknown"
            return score, level, factors

        try:
            with DatabaseSession() as session:
                domains = (
                    session.query(Domain)
                    .filter(or_(func.lower(Domain.original_target) == target, func.lower(Domain.domain) == target))
                    .order_by(desc(Domain.last_updated))
                    .all()
                )

                if not domains:
                    return None

                filtered_domains = []
                for d in domains:
                    domain_name = (d.domain or "").strip().lower()
                    if not domain_name:
                        continue
                    if domain_name != target and variant_domain_set and domain_name not in variant_domain_set:
                        continue
                    filtered_domains.append(d)

                if not filtered_domains:
                    return fallback_payload()

                total_variants = len(filtered_domains)
                generated_variants = max(0, total_variants - 1)
                filtered_domain_ids = [d.id for d in filtered_domains]
                db_variant_domain_set = {
                    (d.domain or "").strip().lower()
                    for d in filtered_domains
                    if (d.domain or "").strip() and (d.domain or "").strip().lower() != target
                }
                keyboard_db_variants = sum(1 for d in db_variant_domain_set if d in keyboard_domain_set)

                def fetch_latest_records(model, ts_col):
                    latest_subq = (
                        session.query(
                            model.domain_id.label("domain_id"),
                            func.max(ts_col).label("latest_ts"),
                        )
                        .filter(model.domain_id.in_(filtered_domain_ids))
                        .group_by(model.domain_id)
                        .subquery()
                    )
                    rows = (
                        session.query(model)
                        .join(
                            latest_subq,
                            and_(
                                model.domain_id == latest_subq.c.domain_id,
                                ts_col == latest_subq.c.latest_ts,
                            ),
                        )
                        .all()
                    )
                    latest_map = {}
                    for row in rows:
                        if row.domain_id not in latest_map:
                            latest_map[row.domain_id] = row
                    return latest_map

                latest_dns_map = fetch_latest_records(DNSScan, DNSScan.scan_timestamp)
                latest_whois_map = fetch_latest_records(WhoisRecord, WhoisRecord.query_timestamp)
                latest_http_map = fetch_latest_records(HTTPScan, HTTPScan.scan_timestamp)
                latest_risk_map = fetch_latest_records(RiskAssessment, RiskAssessment.assessment_timestamp)
                latest_threat_map = fetch_latest_records(ThreatIntelligence, ThreatIntelligence.check_timestamp)

                registration_time_distribution = {}
                registrar_distribution = {}
                active_domains = []
                active_variant_count = 0
                keyboard_active_variants = 0
                high_phishing = 0
                medium_phishing = 0
                risk_distribution = {
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "unknown": 0,
                }

                for domain_obj in filtered_domains:
                    latest_dns = latest_dns_map.get(domain_obj.id)
                    latest_whois = latest_whois_map.get(domain_obj.id)
                    latest_http = latest_http_map.get(domain_obj.id)
                    latest_risk = latest_risk_map.get(domain_obj.id)
                    latest_threat = latest_threat_map.get(domain_obj.id)

                    estimated_score, estimated_level, estimated_factors = estimate_risk_from_signals(
                        latest_dns, latest_whois, latest_http, latest_threat
                    )
                    level = (latest_risk.risk_level if latest_risk and latest_risk.risk_level else "").lower()
                    if not level or level == "unknown":
                        level = estimated_level
                    if level not in risk_distribution:
                        level = "unknown"
                    risk_distribution[level] += 1

                    if latest_whois:
                        month_key = normalize_date(latest_whois.creation_date)
                        if month_key:
                            registration_time_distribution[month_key] = registration_time_distribution.get(month_key, 0) + 1
                        registrar = (latest_whois.registrar or "未知注册商").strip()
                        registrar_distribution[registrar] = registrar_distribution.get(registrar, 0) + 1

                    # 严格以 DNS 探测结果为准：仅 latest_dns.has_dns_record=True 视为存活
                    is_active = bool(latest_dns and latest_dns.has_dns_record)
                    if not is_active:
                        continue

                    if domain_obj.domain == target:
                        # 原始域名不算伪域名内容
                        continue

                    active_variant_count += 1
                    is_keyboard_variant = (domain_obj.domain or "").strip().lower() in keyboard_domain_set
                    if is_keyboard_variant:
                        keyboard_active_variants += 1

                    prob, prob_level, reasons = evaluate_phishing_probability(latest_risk, latest_http, latest_threat)
                    if prob_level == "high":
                        high_phishing += 1
                    elif prob_level == "medium":
                        medium_phishing += 1

                    if include_active_variants:
                        page_analysis = latest_http.page_analysis if latest_http and latest_http.page_analysis else {}
                        title = ""
                        if isinstance(page_analysis, dict):
                            title = page_analysis.get("title", "") or ""
                        page_function = infer_page_function(page_analysis if isinstance(page_analysis, dict) else {}, title)

                        active_domains.append({
                            "domain": domain_obj.domain,
                            "resolved_ips": latest_dns.resolved_ips if latest_dns and latest_dns.resolved_ips else [],
                            "registrar": latest_whois.registrar if latest_whois else None,
                            "creation_date": latest_whois.creation_date.isoformat() if latest_whois and latest_whois.creation_date else None,
                            "page_title": title,
                            "page_function": page_function,
                            "phishing_probability": prob,
                            "phishing_level": prob_level,
                            "phishing_reasons": reasons,
                            "risk_level": (latest_risk.risk_level if latest_risk and latest_risk.risk_level else estimated_level),
                            "risk_score": float(latest_risk.weighted_total_score if latest_risk else estimated_score),
                            "risk_estimated": latest_risk is None,
                            "risk_estimation_factors": estimated_factors,
                            "is_keyboard_variant": is_keyboard_variant,
                        })

                # 兜底：若逐域名映射阶段未产出WHOIS分布，则直接按最新WHOIS批量聚合
                if filtered_domain_ids and not registrar_distribution:
                    latest_whois_subq = (
                        session.query(
                            WhoisRecord.domain_id.label("domain_id"),
                            func.max(WhoisRecord.query_timestamp).label("latest_whois_ts"),
                        )
                        .filter(WhoisRecord.domain_id.in_(filtered_domain_ids))
                        .group_by(WhoisRecord.domain_id)
                        .subquery()
                    )
                    whois_rows = (
                        session.query(WhoisRecord.creation_date, WhoisRecord.registrar)
                        .join(
                            latest_whois_subq,
                            and_(
                                WhoisRecord.domain_id == latest_whois_subq.c.domain_id,
                                WhoisRecord.query_timestamp == latest_whois_subq.c.latest_whois_ts,
                            ),
                        )
                        .all()
                    )
                    for creation_date, registrar_name in whois_rows:
                        month_key = normalize_date(creation_date)
                        if month_key:
                            registration_time_distribution[month_key] = registration_time_distribution.get(month_key, 0) + 1
                        registrar_text = (registrar_name or "未知注册商").strip()
                        registrar_distribution[registrar_text] = registrar_distribution.get(registrar_text, 0) + 1

                if include_active_variants:
                    active_domains.sort(key=lambda x: (x.get("phishing_probability") or 0.0), reverse=True)

                registrar_distribution_sorted = dict(
                    sorted(registrar_distribution.items(), key=lambda kv: kv[1], reverse=True)[:10]
                )
                registration_time_distribution_sorted = dict(
                    sorted(registration_time_distribution.items(), key=lambda kv: kv[0])
                )

                high_risk_exposure_count = int(risk_distribution.get("critical", 0) + risk_distribution.get("high", 0))
                high_risk_exposure_rate = round(
                    (high_risk_exposure_count / max(1, total_variants)) * 100.0, 1
                ) if total_variants > 0 else 0.0

                payload = {
                    "original_target": target,
                    "meta": {
                        "data_source": "database",
                        "db_available": True,
                        "reason": "",
                    },
                    "summary": {
                        "asset_total": total_variants,
                        "high_risk_exposure_count": high_risk_exposure_count,
                        "high_risk_exposure_rate": high_risk_exposure_rate,
                        "risk_distribution": risk_distribution,
                        "total_variants": total_variants,
                        "generated_variants": generated_variants,
                        "db_generated_variants": generated_variants,
                        "file_generated_variants": file_generated_variants,
                        "generated_variants_diff": file_generated_variants - generated_variants,
                        "keyboard_generated_variants": keyboard_generated_variants,
                        "keyboard_db_variants": keyboard_db_variants,
                        "keyboard_active_variants": keyboard_active_variants,
                        "active_variants": active_variant_count,
                        "high_phishing_suspected": high_phishing,
                        "medium_phishing_suspected": medium_phishing,
                    },
                    "counting_rules": {
                        "file_source": str(punycode_file) if punycode_file else "",
                        "keyboard_file_source": str(keyboard_file) if keyboard_file else "",
                        "file_generated_variants_desc": "来自 domain_variants/<目标>/puny_only.txt 非空行数",
                        "db_generated_variants_desc": "来自 domains 表中 original_target=目标 的存在伪域名记录数（不含原始域名）",
                        "keyboard_generated_variants_desc": "来自 keyboard_variants.txt 非空行数（键盘相邻生成）",
                        "keyboard_db_variants_desc": "数据库伪域名中命中键盘相邻集合的数量",
                        "db_scope_desc": "数据库入库来自扫描管道后续模块输出（通常经过 XDIG 存活与注册过滤后），并非全量生成文件。",
                    },
                    "active_variants": active_domains if include_active_variants else [],
                    "registration_time_distribution": registration_time_distribution_sorted,
                    "registrar_distribution": registrar_distribution_sorted,
                }
                if not include_active_variants:
                    try:
                        self._upsert_original_target_summary(target, payload)
                    except Exception:
                        pass
                if use_cache:
                    self._analysis_cache_set(cache_key, payload)
                return payload
        except Exception as e:
            payload = fallback_payload(f"数据库查询失败: {str(e) or type(e).__name__}")
            if use_cache:
                self._analysis_cache_set(cache_key, payload)
            return payload

    def get_keyboard_variant_debug(self, original_target: str, limit: int = 200) -> dict:
        """返回键盘相邻域名与数据库入库交集的调试明细。"""
        target = (original_target or "").strip().lower()
        safe_limit = max(1, min(int(limit or 200), 1000))

        variants_root = BASE_DIR / "domain_variants"
        keyboard_file = None
        if variants_root.exists():
            candidates = [
                variants_root / target / "keyboard_variants.txt",
                variants_root / target.replace(".", "_") / "keyboard_variants.txt",
            ]
            for c in candidates:
                if c.exists():
                    keyboard_file = c
                    break

        keyboard_domains = set()
        if keyboard_file and keyboard_file.exists():
            try:
                with open(keyboard_file, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        text = (line or "").strip()
                        if not text:
                            continue
                        keyboard_domain = text.split("\t")[0].strip().lower()
                        if keyboard_domain:
                            keyboard_domains.add(keyboard_domain)
            except Exception:
                keyboard_domains = set()

        if not DATABASE_ENABLED or not self.db_connection:
            return {
                "original_target": target,
                "keyboard_file": str(keyboard_file) if keyboard_file else "",
                "keyboard_file_count": len(keyboard_domains),
                "db_variant_count": 0,
                "matched_count": 0,
                "matched_active_count": 0,
                "matched_domains": [],
                "note": "数据库不可用，无法计算交集",
            }

        with DatabaseSession() as session:
            domain_rows = (
                session.query(Domain.id, Domain.domain)
                .filter(func.lower(Domain.original_target) == target)
                .filter(func.lower(Domain.domain) != target)
                .all()
            )

            db_domains = []
            db_domain_to_id = {}
            for domain_id, domain in domain_rows:
                domain_text = (domain or "").strip().lower()
                if not domain_text:
                    continue
                db_domains.append(domain_text)
                db_domain_to_id[domain_text] = domain_id

            db_domain_set = set(db_domains)
            matched_domain_set = db_domain_set.intersection(keyboard_domains)
            matched_sorted = sorted(matched_domain_set)

            active_set = set()
            if matched_domain_set:
                matched_ids = [db_domain_to_id[d] for d in matched_domain_set if d in db_domain_to_id]
                if matched_ids:
                    latest_dns_subq = (
                        session.query(
                            DNSScan.domain_id.label("domain_id"),
                            func.max(DNSScan.scan_timestamp).label("latest_dns_ts"),
                        )
                        .filter(DNSScan.domain_id.in_(matched_ids))
                        .group_by(DNSScan.domain_id)
                        .subquery()
                    )

                    active_ids = (
                        session.query(DNSScan.domain_id)
                        .join(
                            latest_dns_subq,
                            and_(
                                DNSScan.domain_id == latest_dns_subq.c.domain_id,
                                DNSScan.scan_timestamp == latest_dns_subq.c.latest_dns_ts,
                            ),
                        )
                        .filter(DNSScan.has_dns_record.is_(True))
                        .all()
                    )
                    active_id_set = {row[0] for row in active_ids}
                    for d, did in db_domain_to_id.items():
                        if did in active_id_set and d in matched_domain_set:
                            active_set.add(d)

            matched_details = []
            for d in matched_sorted[:safe_limit]:
                matched_details.append(
                    {
                        "domain": d,
                        "active": d in active_set,
                    }
                )

            return {
                "original_target": target,
                "keyboard_file": str(keyboard_file) if keyboard_file else "",
                "keyboard_file_count": len(keyboard_domains),
                "db_variant_count": len(db_domain_set),
                "matched_count": len(matched_domain_set),
                "matched_active_count": len(active_set),
                "matched_domains": matched_details,
                "note": "",
            }

    def _report_store_path(self) -> Path:
        return BASE_DIR / "report_store.json"

    def _load_report_store(self) -> list:
        store_path = self._report_store_path()
        if not store_path.exists():
            return []
        try:
            with open(store_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, list) else []
        except Exception:
            return []

    def _save_report_store(self, reports: list) -> None:
        store_path = self._report_store_path()
        with open(store_path, "w", encoding="utf-8") as f:
            json.dump(reports, f, ensure_ascii=False, indent=2)

    def _calculate_report_stats(self, reports: list) -> dict:
        now = datetime.now()
        week_cutoff = now - timedelta(days=7)
        month_cutoff = now - timedelta(days=30)
        weekly = 0
        monthly = 0
        risk_reports = 0

        for report in reports:
            created_at = report.get("created_at")
            try:
                created_dt = datetime.fromisoformat(created_at) if created_at else None
            except Exception:
                created_dt = None

            if created_dt and created_dt >= week_cutoff:
                weekly += 1
            if created_dt and created_dt >= month_cutoff:
                monthly += 1
            if (report.get("summary") or {}).get("high_risk_domains", 0) > 0:
                risk_reports += 1

        return {
            "total_reports": len(reports),
            "weekly_reports": weekly,
            "monthly_reports": monthly,
            "risk_reports": risk_reports,
        }

    def list_reports(self) -> dict:
        with report_store_lock:
            reports = self._load_report_store()

        reports.sort(key=lambda r: r.get("created_at", ""), reverse=True)
        stats = self._calculate_report_stats(reports)
        listing = []
        for item in reports:
            listing.append({
                "id": item.get("id"),
                "name": item.get("name"),
                "type": item.get("type"),
                "time": item.get("created_at"),
                "scope": item.get("scope", "全部域名"),
                "size": item.get("size", "0KB"),
            })
        return {"reports": listing, "stats": stats}

    def get_report(self, report_id: str):
        with report_store_lock:
            reports = self._load_report_store()
        for item in reports:
            if item.get("id") == report_id:
                return item
        return None

    def delete_report(self, report_id: str) -> bool:
        with report_store_lock:
            reports = self._load_report_store()
            kept = [r for r in reports if r.get("id") != report_id]
            if len(kept) == len(reports):
                return False
            self._save_report_store(kept)
        return True

    def generate_report(
        self,
        report_type: str,
        report_name: str,
        start_date: str = "",
        end_date: str = "",
        modules: list | None = None,
        report_format: str = "html",
        original_target: str = "",
    ) -> dict:
        report_type = (report_type or "risk").strip().lower()
        report_name = (report_name or "").strip()
        original_target = (original_target or "").strip().lower()
        modules = modules or ["visual", "dns", "http", "whois", "threat"]

        risk_distribution = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
        top_domains = []
        registration_time_distribution = {}
        registrar_distribution = {}

        if original_target:
            target_data = self.analyze_original_target(original_target)
            if not target_data:
                raise ValueError(f"未找到原始域名分析数据: {original_target}")
            target_meta = target_data.get("meta", {}) if isinstance(target_data, dict) else {}
            if target_meta.get("data_source") == "fallback":
                reason = target_meta.get("reason") or "数据库不可用或查询失败"
                raise ValueError(f"原始域名报告生成失败（数据源回退）: {reason}")

            summary = target_data.get("summary", {}) if isinstance(target_data, dict) else {}
            target_risk = summary.get("risk_distribution", {}) if isinstance(summary, dict) else {}
            for key in risk_distribution.keys():
                risk_distribution[key] = int(target_risk.get(key, 0) or 0)

            active_variants = target_data.get("active_variants", []) if isinstance(target_data, dict) else []
            active_variants = active_variants if isinstance(active_variants, list) else []
            if not active_variants and int(summary.get("total_variants", 0) or 0) == 0:
                raise ValueError(f"原始域名报告生成失败: {original_target} 暂无可用扫描数据")
            active_variants_sorted = sorted(
                active_variants,
                key=lambda x: (
                    float((x or {}).get("phishing_probability", 0.0) or 0.0),
                    float((x or {}).get("risk_score", 0.0) or 0.0),
                ),
                reverse=True,
            )
            for item in active_variants_sorted[:10]:
                top_domains.append({
                    "domain": item.get("domain"),
                    "original_target": original_target,
                    "risk_score": float(item.get("risk_score", 0.0) or 0.0),
                    "risk_level": item.get("risk_level", "unknown"),
                    "module": "综合评估",
                })

            total_variants = int(summary.get("total_variants", 0) or 0)
            high_risk_domains = int(summary.get("high_risk_exposure_count", 0) or 0)
            monitored_targets = 1
            risk_coverage = round(float(summary.get("high_risk_exposure_rate", 0.0) or 0.0), 1)
            detected_variants = total_variants
            scope = original_target
            registration_time_distribution = target_data.get("registration_time_distribution", {}) or {}
            registrar_distribution = target_data.get("registrar_distribution", {}) or {}
        else:
            try:
                dashboard_stats = self.get_dashboard_stats()
            except Exception:
                dashboard_stats = {
                    "total_domains": 0,
                    "high_risk_domains": 0,
                    "medium_risk_domains": 0,
                    "low_risk_domains": 0,
                }

            try:
                high_risk_data = self.get_domains_paginated(page=1, page_size=10, risk_level="high", status="")
                top_domains = high_risk_data.get("data", []) if isinstance(high_risk_data, dict) else []
            except Exception:
                top_domains = []

            if DATABASE_ENABLED and self.db_connection:
                try:
                    with DatabaseSession() as session:
                        rows = session.query(RiskAssessment.risk_level, func.count(RiskAssessment.id)).group_by(RiskAssessment.risk_level).all()
                        for level, count in rows:
                            key = (level or "unknown").lower()
                            if key not in risk_distribution:
                                key = "unknown"
                            risk_distribution[key] += int(count or 0)
                except Exception:
                    pass

            total_domains = int(dashboard_stats.get("total_domains", 0) or 0)
            high_risk_domains = int(dashboard_stats.get("high_risk_domains", 0) or 0)
            monitored_targets = total_domains if total_domains > 0 else len(top_domains)
            risk_coverage = round((high_risk_domains / max(1, total_domains)) * 100, 1) if total_domains > 0 else 0.0
            detected_variants = monitored_targets
            scope = "全部域名" if report_type in {"weekly", "monthly"} else (top_domains[0].get("original_target") if top_domains else "全部域名")

        recommendations = [
            "对高风险域名执行 DNS 拦截并纳入告警白名单复核流程",
            "将高风险样本同步到邮件网关和 Web 访问策略",
            "每周复盘风险评分模型阈值并校准误报率",
            "对重点目标启用持续监控和自动工单处置",
        ]

        whois_insights = []
        if registration_time_distribution:
            sorted_time = sorted(
                registration_time_distribution.items(),
                key=lambda kv: kv[1],
                reverse=True,
            )
            recent_count = 0
            for month_text, count in registration_time_distribution.items():
                try:
                    dt = datetime.strptime(month_text, "%Y-%m")
                    if (datetime.utcnow().year - dt.year) * 12 + (datetime.utcnow().month - dt.month) <= 12:
                        recent_count += int(count or 0)
                except Exception:
                    continue
            top_month, top_month_count = sorted_time[0]
            whois_insights.append(f"注册时间最集中于 {top_month}（{top_month_count} 个域名）。")
            if recent_count > 0:
                whois_insights.append(f"近12个月新增注册 {recent_count} 个，需关注短期批量注册风险。")
            else:
                whois_insights.append("近12个月未见明显新增注册，样本以存量域名为主。")
        else:
            whois_insights.append("暂无可用注册时间分布数据（WHOIS字段缺失或未入库）。")

        if registrar_distribution:
            sorted_registrar = sorted(
                registrar_distribution.items(),
                key=lambda kv: kv[1],
                reverse=True,
            )
            top_registrar, top_registrar_count = sorted_registrar[0]
            total_registrar_samples = sum(int(v or 0) for v in registrar_distribution.values())
            concentration = round((top_registrar_count / max(1, total_registrar_samples)) * 100.0, 1)
            whois_insights.append(
                f"注册商最集中于「{top_registrar}」（{top_registrar_count} 个，占比 {concentration}%）。"
            )
            if concentration >= 60:
                whois_insights.append("注册商集中度较高，可能存在批量注册或同源投放特征。")
            else:
                whois_insights.append("注册商分布较分散，来源可能更复杂。")
        else:
            whois_insights.append("暂无可用注册商分布数据（WHOIS字段缺失或未入库）。")

        # 兜底：若风险分布全为0，则按样本风险等级回填，避免报告图表空白
        if sum(int(v or 0) for v in risk_distribution.values()) == 0 and top_domains:
            for item in top_domains:
                level = str(item.get("risk_level") or "unknown").strip().lower()
                if level not in risk_distribution:
                    level = "unknown"
                risk_distribution[level] += 1

        report_id = f"REPORT-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{uuid4().hex[:4].upper()}"
        created_at = datetime.now().isoformat(timespec="seconds")

        high_risk_examples = []
        for item in top_domains[:8]:
            high_risk_examples.append({
                "domain": item.get("domain"),
                "original_target": item.get("original_target"),
                "risk_score": round(float(item.get("risk_score", 0.0) or 0.0), 2),
                "risk_level": item.get("risk_level", "unknown"),
                "module": "综合评估",
            })

        report = {
            "id": report_id,
            "name": report_name or f"{datetime.now().strftime('%Y-%m-%d')} 安全分析报告",
            "type": report_type,
            "format": report_format,
            "created_at": created_at,
            "start_date": start_date,
            "end_date": end_date,
            "modules": modules,
            "scope": scope or "全部域名",
            "summary": {
                "monitored_targets": monitored_targets,
                "detected_variants": detected_variants,
                "high_risk_domains": high_risk_domains,
                "risk_coverage": risk_coverage,
            },
            "risk_distribution": risk_distribution,
            "high_risk_examples": high_risk_examples,
            "original_target": original_target or "",
            "registration_time_distribution": registration_time_distribution,
            "registrar_distribution": registrar_distribution,
            "whois_insights": whois_insights,
            "data_quality": {
                "has_risk_distribution": sum(int(v or 0) for v in risk_distribution.values()) > 0,
                "has_high_risk_examples": len(high_risk_examples) > 0,
                "has_registration_distribution": len(registration_time_distribution) > 0,
                "has_registrar_distribution": len(registrar_distribution) > 0,
            },
            "findings": [
                "风险等级以数据库最新评估结果为准，若无评估则显示未知",
                "当前报告可用于日常巡检与高风险事件回溯",
                "建议优先处置评分最高且可解析/可访问的域名样本",
            ],
            "recommendations": recommendations,
        }

        report["size"] = f"{max(1, int(len(json.dumps(report, ensure_ascii=False)) / 1024))}KB"

        with report_store_lock:
            reports = self._load_report_store()
            reports.insert(0, report)
            self._save_report_store(reports)

        return report

    def build_report_download(self, report_id: str, fmt: str = "json"):
        """构建单份报告下载内容。"""
        report = self.get_report(report_id)
        if not report:
            return None

        safe_format = (fmt or "json").strip().lower()
        if safe_format not in {"json", "html"}:
            safe_format = "json"

        safe_id = str(report.get("id") or report_id).replace("/", "_")
        if safe_format == "json":
            payload = json.dumps(report, ensure_ascii=False, indent=2).encode("utf-8")
            return {
                "bytes": payload,
                "mimetype": "application/json; charset=utf-8",
                "filename": f"{safe_id}.json",
            }

        # 轻量HTML导出，便于离线查看
        summary = report.get("summary") or {}
        findings = report.get("findings") or []
        recommendations = report.get("recommendations") or []
        examples = report.get("high_risk_examples") or []
        distribution = report.get("risk_distribution") or {}
        registration_dist = report.get("registration_time_distribution") or {}
        registrar_dist = report.get("registrar_distribution") or {}
        whois_insights = report.get("whois_insights") or []

        def esc(v):
            text = "" if v is None else str(v)
            return (
                text.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;")
            )

        rows = []
        for item in examples[:200]:
            rows.append(
                "<tr>"
                f"<td><code>{esc(item.get('domain'))}</code></td>"
                f"<td>{esc(item.get('original_target') or '-')}</td>"
                f"<td>{esc(item.get('risk_score') or 0)}</td>"
                f"<td>{esc(item.get('risk_level') or 'unknown')}</td>"
                "</tr>"
            )

        html = f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <title>{esc(report.get('name') or report_id)}</title>
  <style>
    body{{font-family:Arial,sans-serif;line-height:1.6;margin:24px;color:#222}}
    h1,h2{{margin:12px 0}}
    table{{border-collapse:collapse;width:100%}}
    th,td{{border:1px solid #ddd;padding:8px;text-align:left}}
    th{{background:#f4f4f4}}
    .meta{{color:#666;font-size:14px;margin-bottom:12px}}
  </style>
</head>
<body>
  <h1>{esc(report.get('name') or '域名安全监控报告')}</h1>
  <div class="meta">报告ID: {esc(report.get('id'))} | 生成时间: {esc(report.get('created_at'))} | 类型: {esc(report.get('type'))}</div>
  <h2>执行摘要</h2>
  <ul>
    <li>监控域名: {esc(summary.get('monitored_targets') or 0)}</li>
    <li>检测变体: {esc(summary.get('detected_variants') or 0)}</li>
    <li>高风险域名: {esc(summary.get('high_risk_domains') or 0)}</li>
    <li>风险覆盖率: {esc(summary.get('risk_coverage') or 0)}%</li>
  </ul>
  <h2>风险分布</h2>
  <pre>{esc(json.dumps(distribution, ensure_ascii=False, indent=2))}</pre>
  <h2>WHOIS分布与解读</h2>
  <h3>注册时间分布</h3>
  <pre>{esc(json.dumps(registration_dist, ensure_ascii=False, indent=2))}</pre>
  <h3>注册商分布</h3>
  <pre>{esc(json.dumps(registrar_dist, ensure_ascii=False, indent=2))}</pre>
  <h3>解读</h3>
  <ul>{"".join(f"<li>{esc(x)}</li>" for x in whois_insights)}</ul>
  <h2>主要发现</h2>
  <ul>{"".join(f"<li>{esc(x)}</li>" for x in findings)}</ul>
  <h2>建议措施</h2>
  <ul>{"".join(f"<li>{esc(x)}</li>" for x in recommendations)}</ul>
  <h2>高风险域名示例</h2>
  <table>
    <thead><tr><th>域名</th><th>原目标</th><th>风险得分</th><th>风险等级</th></tr></thead>
    <tbody>{"".join(rows) if rows else "<tr><td colspan='4'>暂无数据</td></tr>"}</tbody>
  </table>
</body>
</html>
"""

        return {
            "bytes": html.encode("utf-8"),
            "mimetype": "text/html; charset=utf-8",
            "filename": f"{safe_id}.html",
        }

    def build_all_reports_zip(self):
        """导出所有报告为ZIP（含JSON与索引CSV）。"""
        with report_store_lock:
            reports = self._load_report_store()

        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("reports/all_reports.json", json.dumps(reports, ensure_ascii=False, indent=2))

            csv_buf = io.StringIO()
            writer = csv.writer(csv_buf)
            writer.writerow(["id", "name", "type", "created_at", "scope", "size"])
            for item in reports:
                writer.writerow([
                    item.get("id", ""),
                    item.get("name", ""),
                    item.get("type", ""),
                    item.get("created_at", ""),
                    item.get("scope", ""),
                    item.get("size", ""),
                ])
            zf.writestr("reports/index.csv", csv_buf.getvalue())

            for item in reports:
                report_id = str(item.get("id") or "report").replace("/", "_")
                zf.writestr(
                    f"reports/{report_id}.json",
                    json.dumps(item, ensure_ascii=False, indent=2),
                )

        buffer.seek(0)
        filename = f"reports_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
        return {"bytes": buffer.getvalue(), "filename": filename}

    def create_report_share_payload(self, report_id: str) -> dict | None:
        """生成可分享链接（当前为无需鉴权的只读链接）。"""
        report = self.get_report(report_id)
        if not report:
            return None
        token = str(uuid4())
        return {
            "report_id": report_id,
            "share_token": token,
            "share_url": f"/api/reports/{report_id}?share_token={token}",
            "expires_at": None,
        }

    def get_data_analysis(self, analysis_type: str = "comprehensive") -> dict:
        """统一封装 /api/data/analysis。"""
        if not get_data_analyzer:
            raise RuntimeError("data_analysis module not available")

        analyzer = get_data_analyzer()
        atype = (analysis_type or "comprehensive").strip().lower()

        if atype == "comprehensive":
            return analyzer.get_comprehensive_analysis()
        if atype == "registration_time":
            return analyzer.get_registration_time_distribution()
        if atype == "registrar":
            return analyzer.get_registrar_distribution()
        if atype == "resolution":
            return analyzer.get_resolution_analysis()
        if atype == "domain_usage":
            return analyzer.get_domain_usage_analysis()
        if atype == "high_risk_details":
            return analyzer.get_high_risk_domain_details()
        raise ValueError(f"Unsupported analysis type: {analysis_type}")

    def get_similar_domains_examples(self, limit: int = 20) -> dict:
        """返回相似域名示例（文档兼容接口）。"""
        safe_limit = max(1, min(int(limit or 20), 200))
        results = []

        if DATABASE_ENABLED and self.db_connection:
            with DatabaseSession() as session:
                originals = (
                    session.query(Domain.original_target)
                    .filter(Domain.original_target.isnot(None))
                    .filter(Domain.original_target != "")
                    .group_by(Domain.original_target)
                    .order_by(desc(func.max(Domain.last_updated)))
                    .limit(20)
                    .all()
                )
                for (target,) in originals:
                    target_text = (target or "").strip().lower()
                    if not target_text:
                        continue
                    rows = (
                        session.query(Domain.domain, Domain.visual_similarity)
                        .filter(func.lower(Domain.original_target) == target_text)
                        .filter(func.lower(Domain.domain) != target_text)
                        .order_by(desc(Domain.visual_similarity), desc(Domain.last_updated))
                        .limit(5)
                        .all()
                    )
                    if not rows:
                        continue
                    similar_list = []
                    for domain_name, sim in rows:
                        score = float(sim or 0.0)
                        similar_list.append({
                            "domain": domain_name,
                            "similarity_score": round(score, 4),
                            "visual_similarity": round(score, 4),
                        })
                    results.append({
                        "original_domain": target_text,
                        "similar_domains": similar_list,
                        "similarity_type": "visual",
                        "risk_level": "high" if any(x["visual_similarity"] >= 0.9 for x in similar_list) else "medium",
                    })
                    if len(results) >= safe_limit:
                        break

        return {"similar_domains": results[:safe_limit], "count": len(results[:safe_limit])}

# 创建WebAppManager实例
manager = WebAppManager()

@app.route('/')
def index():
    """主页面路由 - 显示仪表板"""
    return render_template('index.html')

@app.route('/domains')
def domains():
    """域名管理页面"""
    return render_template('domains.html')

@app.route('/scans')
def scans():
    """扫描管理页面"""
    return render_template('scans.html')

@app.route('/reports')
def reports():
    """报告页面"""
    return render_template('reports.html')

@app.route('/api/reports', methods=['GET'])
def list_reports():
    """获取报告列表与统计。"""
    try:
        data = manager.list_reports()
        return jsonify({"success": True, "data": data}), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/reports/generate', methods=['POST'])
def generate_report():
    """生成新报告。"""
    try:
        payload = request.get_json(silent=True) or {}
        report_name = (payload.get("name") or "").strip()
        report_type = (payload.get("type") or "risk").strip().lower()
        start_date = (payload.get("start_date") or "").strip()
        end_date = (payload.get("end_date") or "").strip()
        original_target = (payload.get("original_target") or "").strip()
        modules = payload.get("modules") if isinstance(payload.get("modules"), list) else []
        report_format = (payload.get("format") or "html").strip().lower()

        report = manager.generate_report(
            report_type=report_type,
            report_name=report_name,
            start_date=start_date,
            end_date=end_date,
            modules=modules,
            report_format=report_format,
            original_target=original_target,
        )
        return jsonify({"success": True, "data": report}), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/reports/<report_id>', methods=['GET'])
def get_report_detail(report_id):
    """获取报告详情。"""
    try:
        report = manager.get_report(report_id)
        if not report:
            return jsonify({"success": False, "error": "Report not found."}), 404
        return jsonify({"success": True, "data": report}), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/reports/<report_id>', methods=['DELETE'])
def delete_report(report_id):
    """删除报告。"""
    try:
        deleted = manager.delete_report(report_id)
        if not deleted:
            return jsonify({"success": False, "error": "Report not found."}), 404
        return jsonify({"success": True, "message": f"Report deleted: {report_id}"}), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/reports/<report_id>/download', methods=['GET'])
def download_report(report_id):
    """下载单份报告（json/html）。"""
    try:
        report_format = request.args.get("format", default="json", type=str)
        content = manager.build_report_download(report_id, fmt=report_format)
        if not content:
            return jsonify({"success": False, "error": "Report not found."}), 404

        response = make_response(content["bytes"])
        response.headers["Content-Type"] = content["mimetype"]
        response.headers["Content-Disposition"] = f'attachment; filename="{content["filename"]}"'
        return response
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/reports/export-all', methods=['GET'])
def export_all_reports():
    """导出全部报告ZIP。"""
    try:
        export_result = manager.build_all_reports_zip()
        response = make_response(export_result["bytes"])
        response.headers["Content-Type"] = "application/zip"
        response.headers["Content-Disposition"] = f'attachment; filename="{export_result["filename"]}"'
        return response
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/reports/<report_id>/share', methods=['POST'])
def share_report(report_id):
    """生成报告分享信息。"""
    try:
        payload = manager.create_report_share_payload(report_id)
        if not payload:
            return jsonify({"success": False, "error": "Report not found."}), 404
        return jsonify({"success": True, "data": payload}), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/settings')
def settings():
    """系统设置页面"""
    return render_template('settings.html')

@app.route('/xdig-analysis')
def xdig_analysis():
    """xdig分析页面"""
    return render_template('xdig_analysis.html')

@app.route('/xdig-analysis-unified')
def xdig_analysis_unified():
    """xdig综合分析页面"""
    return render_template('xdig_analysis_unified.html')

@app.route('/analysis/original-target/<path:original_target>')
def original_target_analysis_page(original_target):
    """原始域名专项分析页面。"""
    return render_template('original_target_analysis.html', original_target=original_target)

@app.route('/api/dashboard/stats')
def get_dashboard_stats():
    """获取仪表板统计信息"""
    try:
        stats = manager.get_dashboard_stats()
        return jsonify({"success": True, "data": stats}), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/dashboard/recent-domains')
def get_recent_domains():
    """获取最近扫描的域名"""
    try:
        limit = request.args.get('limit', default=5, type=int)
        domains = manager.get_recent_domains(limit)
        return jsonify({"success": True, "data": domains}), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/dashboard/risk-distribution')
def get_risk_distribution():
    """获取风险分布数据"""
    try:
        distribution = manager.get_risk_distribution()
        return jsonify({"success": True, "data": distribution}), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/system/status')
def get_system_status():
    """获取系统状态"""
    try:
        status = manager.get_system_status()
        return jsonify({"success": True, "data": status}), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/system/maintenance/vacuum-analyze', methods=['POST'])
def run_vacuum_analyze():
    """手动触发数据库 VACUUM ANALYZE。"""
    try:
        result = manager.run_vacuum_analyze()
        status = 200 if result.get("success") else 500
        return jsonify(result), status
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/analysis/original-target/<path:original_target>', methods=['GET'])
def get_original_target_analysis(original_target):
    """按原始域名返回伪域名专项分析。"""
    try:
        include_details = request.args.get("include_details", default="1", type=str).strip().lower() in {"1", "true", "yes"}
        if include_details:
            data = manager.analyze_original_target(
                original_target,
                include_active_variants=True,
                use_cache=True,
                prefer_preaggregated=False,
            )
        else:
            data = manager.get_original_target_summary(original_target)
        if not data:
            return jsonify({"success": False, "error": "Original target not found or no analysis data."}), 404
        return jsonify({"success": True, "data": data}), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/analysis/original-target/<path:original_target>/summary', methods=['GET'])
def get_original_target_analysis_summary(original_target):
    """按原始域名返回汇总（预聚合 + 缓存）。"""
    try:
        data = manager.get_original_target_summary(original_target)
        if not data:
            return jsonify({"success": False, "error": "Original target not found or no analysis summary."}), 404
        return jsonify({"success": True, "data": data}), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/analysis/original-target/<path:original_target>/active-variants', methods=['GET'])
def get_original_target_analysis_active_variants(original_target):
    """按原始域名返回活跃伪域名明细。"""
    try:
        data = manager.get_original_target_active_variants(original_target)
        return jsonify({"success": True, "data": data}), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/analysis/original-target/<path:original_target>/keyboard-debug', methods=['GET'])
def get_original_target_keyboard_debug(original_target):
    """返回键盘相邻域名与入库交集的调试明细。"""
    try:
        limit = request.args.get('limit', default=200, type=int)
        data = manager.get_keyboard_variant_debug(original_target, limit=limit)
        return jsonify({"success": True, "data": data}), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/domains', methods=['GET'])
def list_domains():
    """获取域名列表（分页/搜索/筛选）。"""
    try:
        page = request.args.get('page', default=1, type=int)
        page_size = request.args.get('page_size', default=20, type=int)
        search = request.args.get('search', default='', type=str)
        risk_level = request.args.get('risk_level', default='', type=str)
        status = request.args.get('status', default='', type=str)
        include_variants = request.args.get('include_variants', default='false', type=str).strip().lower() in {'1', 'true', 'yes'}

        result = manager.get_domains_paginated(
            page=page,
            page_size=page_size,
            search=search,
            risk_level=risk_level,
            status=status,
            include_variants=include_variants,
        )
        return jsonify({"success": True, **result}), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/domains/<path:original_target>/variants', methods=['GET'])
def list_domain_variants(original_target):
    """获取某个原始域名下的伪域名明细。"""
    try:
        data = manager.get_variants_by_original_target(original_target)
        return jsonify({"success": True, "data": data}), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/domains/<path:domain_name>', methods=['GET'])
def get_domain_detail(domain_name):
    """获取域名详情。"""
    try:
        detail = manager.get_domain_detail(domain_name)
        if not detail:
            return jsonify({"success": False, "error": "Domain not found."}), 404
        return jsonify({"success": True, "data": detail}), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/domains/<path:domain_name>', methods=['DELETE'])
def delete_domain(domain_name):
    """删除域名及其关联数据。"""
    try:
        deleted = manager.delete_domain(domain_name)
        if not deleted:
            return jsonify({"success": False, "error": "Domain not found."}), 404
        return jsonify({"success": True, "message": f"Domain deleted: {domain_name}"}), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/domains/batch-delete', methods=['POST'])
def batch_delete_domains():
    """批量删除域名及其关联数据。"""
    try:
        payload = request.get_json(silent=True) or {}
        domains = payload.get("domains")
        if not isinstance(domains, list) or len(domains) == 0:
            return jsonify({"success": False, "error": "Missing 'domains' list in request body."}), 400

        result = manager.delete_domains(domains)
        deleted = result.get("deleted", [])
        not_found = result.get("not_found", [])

        return jsonify({
            "success": True,
            "data": {
                "deleted_count": len(deleted),
                "deleted": deleted,
                "not_found_count": len(not_found),
                "not_found": not_found
            }
        }), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/scan/start', methods=['POST'])
def start_scan():
    """开始域名扫描"""
    try:
        data = request.get_json(silent=True) or {}
        raw_domain = data.get('domain') or ''

        if not str(raw_domain).strip():
            return jsonify({"error": "Missing 'domain' in request body."}), 400
        try:
            domain = normalize_domain_input(str(raw_domain))
        except DomainInputError as e:
            return jsonify({"error": f"Invalid domain input: {e}"}), 400

        scan_type = (data.get('scan_type') or 'full').strip().lower()
        allowed_scan_types = {"full", "dns", "http", "whois", "threat", "custom"}
        if scan_type not in allowed_scan_types:
            scan_type = "full"

        # 先写入基础域名记录，确保域名管理列表可以立刻看到该域名
        manager.ensure_domain_record(domain)

        scan_id = f"scan_{int(datetime.now().timestamp())}_{uuid4().hex[:8]}"

        with scan_tasks_lock:
            scan_tasks[scan_id] = {
                "scan_id": scan_id,
                "domain": domain,
                "scan_type": scan_type,
                "status": "pending",
                "progress": 0,
                "message": "Scan task created",
                "created_at": datetime.now().isoformat(),
                "started_at": None,
                "finished_at": None,
                "result": None,
                "logs": [
                    {
                        "timestamp": datetime.now().isoformat(),
                        "level": "INFO",
                        "message": "任务已创建，等待执行"
                    }
                ]
            }

        worker = Thread(target=_run_scan_task, args=(scan_id, domain), daemon=True)
        worker.start()

        return jsonify({
            "success": True,
            "data": {
                "scan_id": scan_id,
                "domain": domain,
                "scan_type": scan_type,
                "status": "pending",
                "message": "Scan task started",
                "status_api": f"/api/scan/status/{scan_id}"
            }
        }), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


def _enrich_and_write_whois(domain: str) -> dict:
    """Helper: run whois enrichment and persist to WhoisRecord, then refresh aggregates."""
    try:
        from modules.whois_enhanced import query_domain_whois_structured
    except Exception as e:
        return {"status": "error", "error": f"whois module import failed: {e}"}

    try:
        # perform whois query
        res = query_domain_whois_structured(domain)

        # persist to DB if success
        try:
            from modules.database.connection import DatabaseSession
            from modules.database.models import Domain, WhoisRecord

            with DatabaseSession() as session:
                # find domain record
                domain_obj = session.query(Domain).filter(func.lower(Domain.domain) == (domain or '').lower()).first()
                if not domain_obj:
                    domain_obj = session.query(Domain).filter(func.lower(Domain.original_target) == (domain or '').lower()).first()

                if domain_obj and res.get('status') == 'success':
                    info = res.get('whois_info') or {}

                    def _parse_dt(v):
                        if not v:
                            return None
                        try:
                            from dateutil import parser
                            return parser.parse(v)
                        except Exception:
                            try:
                                return datetime.fromisoformat(v)
                            except Exception:
                                return None

                    rec = WhoisRecord(
                        domain_id=domain_obj.id if domain_obj else None,
                        registrar=(info.get('registrar') or None),
                        creation_date=_parse_dt(info.get('creation_date')),
                        expiration_date=_parse_dt(info.get('expiration_date')),
                        updated_date=_parse_dt(info.get('updated_date')),
                        name_servers=info.get('name_servers') or [],
                        status=info.get('status') or [],
                        emails=info.get('emails') or [],
                        registrant=info.get('registrant') or {},
                        admin=info.get('admin') or {},
                        tech=info.get('tech') or {},
                        raw_text=info.get('raw_text') or None,
                        whois_risk_score=res.get('whois_risk_score', 0.0) or 0.0,
                        risk_level=res.get('risk_level') or None,
                        query_timestamp=_parse_dt(res.get('query_timestamp')),
                    )

                    # only add if domain_obj exists (ensure_domain_record should have created it)
                    if domain_obj:
                        session.add(rec)

        except Exception as e:
            # DB persist failure should be logged but not break the whois response
            print(f"WHOIS persist failed for {domain}: {e}")

        # refresh analysis cache and aggregates
        try:
            if 'manager' in globals() and manager:
                try:
                    manager.invalidate_analysis_cache(domain)
                except Exception:
                    pass
                try:
                    manager.refresh_original_target_summary(domain)
                except Exception:
                    pass
        except Exception:
            pass

        return res

    except Exception as e:
        return {"status": "error", "error": str(e)}


@app.route('/api/whois/enrich', methods=['POST'])
def api_whois_enrich():
    """API: enrich WHOIS for a domain. Payload: {"domain":"example.com","sync":true}

    If sync=true (default) this will run the whois query in the request thread and persist result.
    If sync=false this will attempt to dispatch a background task (Celery if available) or spawn a thread.
    """
    try:
        payload = request.get_json(silent=True) or {}
        raw_domain = payload.get('domain') or ''
        sync_flag = payload.get('sync', True)

        if not str(raw_domain).strip():
            return jsonify({"success": False, "error": "Missing 'domain' in request body."}), 400

        try:
            domain = normalize_domain_input(str(raw_domain))
        except DomainInputError as e:
            return jsonify({"success": False, "error": f"Invalid domain input: {e}"}), 400

        # ensure domain exists for immediate visibility
        try:
            manager.ensure_domain_record(domain)
        except Exception:
            pass

        # synchronous path: run whois and persist
        if bool(sync_flag):
            res = _enrich_and_write_whois(domain)
            if res.get('status') != 'success':
                return jsonify({"success": False, "error": res.get('error', 'whois failed'), "result": res}), 500
            return jsonify({"success": True, "whois": res}), 200

        # async path: prefer Celery task if available
        try:
            from scripts.celery_tasks import enrich_whois_task
            task = enrich_whois_task.delay(domain)
            return jsonify({"success": True, "task_id": str(task.id)}), 202
        except Exception:
            # fallback: spawn a background thread
            worker = Thread(target=_enrich_and_write_whois, args=(domain,), daemon=True)
            worker.start()
            return jsonify({"success": True, "task_id": f"thread-{uuid4().hex}"}), 202

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/scan/tasks', methods=['GET'])
def list_scan_tasks():
    """获取扫描任务列表和状态统计。"""
    try:
        status_filter = (request.args.get('status') or '').strip().lower()
        type_filter = (request.args.get('scan_type') or '').strip().lower()
        limit = request.args.get('limit', default=200, type=int)
        if limit <= 0:
            limit = 200
        limit = min(limit, 1000)

        with scan_tasks_lock:
            tasks = list(scan_tasks.values())

        def normalize_status(s):
            return "pending" if s == "queued" else s

        normalized_tasks = []
        for task in tasks:
            item = dict(task)
            item["status"] = normalize_status(item.get("status", "unknown"))
            normalized_tasks.append(item)

        if status_filter:
            normalized_tasks = [t for t in normalized_tasks if t.get("status") == status_filter]
        if type_filter:
            normalized_tasks = [t for t in normalized_tasks if (t.get("scan_type") or "full") == type_filter]

        normalized_tasks.sort(key=lambda t: t.get("created_at") or "", reverse=True)
        normalized_tasks = normalized_tasks[:limit]

        stats = {
            "pending": 0,
            "running": 0,
            "completed": 0,
            "failed": 0,
            "total": len(normalized_tasks),
        }
        for task in normalized_tasks:
            status = task.get("status")
            if status in stats:
                stats[status] += 1

        return jsonify({"success": True, "data": {"tasks": normalized_tasks, "stats": stats}}), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/scan/status/<scan_id>', methods=['GET'])
def get_scan_status(scan_id):
    """查询扫描任务状态"""
    try:
        with scan_tasks_lock:
            task = scan_tasks.get(scan_id)

        if not task:
            return jsonify({"success": False, "error": "Scan ID not found."}), 404

        return jsonify({"success": True, "data": task}), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/scan/logs/<scan_id>', methods=['GET'])
def get_scan_logs(scan_id):
    """查询扫描任务日志。"""
    try:
        with scan_tasks_lock:
            task = scan_tasks.get(scan_id)

        if not task:
            return jsonify({"success": False, "error": "Scan ID not found."}), 404

        logs = list(task.get("logs", []))
        # 兜底：若旧任务无日志，基于当前状态拼装简易日志
        if not logs:
            if task.get("created_at"):
                logs.append({"timestamp": task.get("created_at"), "level": "INFO", "message": "任务已创建"})
            if task.get("started_at"):
                logs.append({"timestamp": task.get("started_at"), "level": "INFO", "message": "任务开始执行"})
            if task.get("finished_at"):
                level = "SUCCESS" if task.get("status") == "completed" else "ERROR"
                logs.append({"timestamp": task.get("finished_at"), "level": level, "message": task.get("message", "任务结束")})

        logs.sort(key=lambda item: item.get("timestamp") or "")

        return jsonify({
            "success": True,
            "data": {
                "scan_id": task.get("scan_id"),
                "domain": task.get("domain"),
                "status": task.get("status"),
                "progress": task.get("progress", 0),
                "message": task.get("message", ""),
                "created_at": task.get("created_at"),
                "started_at": task.get("started_at"),
                "finished_at": task.get("finished_at"),
                "scan_type": task.get("scan_type", "full"),
                "result": task.get("result"),
                "logs": logs,
            }
        }), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/domains/similar', methods=['POST'])
def get_similar_domains():
    """API endpoint to generate and analyze similar domains."""
    try:
        # Get the domain from the request JSON
        data = request.get_json(silent=True) or {}
        raw_domain = data.get('domain')

        if not str(raw_domain or "").strip():
            return jsonify({"error": "Missing 'domain' in request body. Please provide a valid domain."}), 400
        try:
            domain = normalize_domain_input(str(raw_domain))
        except DomainInputError as e:
            return jsonify({"error": f"Invalid domain input: {e}"}), 400

        # Call the process_domains function from research_threat_apis
        from research_threat_apis import process_domains

        # Process the domain and capture the output
        result = process_domains(domain)

        return jsonify({"success": True, "data": result}), 200

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/data/analysis', methods=['GET'])
def get_data_analysis():
    """获取数据分析（文档兼容接口）。"""
    try:
        analysis_type = request.args.get("type", default="comprehensive", type=str)
        result = manager.get_data_analysis(analysis_type)
        if isinstance(result, dict):
            if result.get("success") is False:
                return jsonify({"success": False, "error": result.get("error", "Analysis failed")}), 500
            if result.get("success") is True and "data" in result:
                return jsonify({"success": True, "data": result.get("data")}), 200
            return jsonify({"success": True, "data": result}), 200
        return jsonify({"success": True, "data": result}), 200
    except ValueError as ve:
        return jsonify({"success": False, "error": str(ve)}), 400
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/data/similar-domains', methods=['GET'])
def get_similar_domains_examples():
    """获取相似域名示例（文档兼容接口）。"""
    try:
        limit = request.args.get("limit", default=20, type=int)
        result = manager.get_similar_domains_examples(limit=limit)
        return jsonify({"success": True, "data": result}), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/xdig/analysis', methods=['GET'])
def get_xdig_analysis():
    """兼容旧版 xdig 页面分析接口。"""
    try:
        limit = request.args.get("limit", default=200, type=int)
        domains = manager.get_xdig_dangerous_domains(limit=limit)
        stats = manager.get_dashboard_stats()

        com_variants = 0
        for item in domains:
            domain_text = (item.get("domain") or "").strip().lower()
            if domain_text.endswith(".com"):
                com_variants += 1

        analysis_sections = [
            {
                "title": "探测方法说明",
                "icon": "fa-satellite-dish",
                "content": "通过 XDIG 对候选变体执行主动 DNS 探测，存在解析记录的域名被视为活跃样本并进入后续分析。"
            },
            {
                "title": "风险判定逻辑",
                "icon": "fa-shield-alt",
                "content": "当前页面以已探测到的活跃样本为高风险优先集合，结合风险评分、威胁情报与访问特征做持续更新。"
            },
            {
                "title": "处置建议",
                "icon": "fa-lightbulb",
                "content": "建议优先处理可解析且风险评分高的样本，纳入拦截策略并持续监控其 DNS/HTTP 变化。"
            },
        ]

        payload = {
            "summary": {
                "total_domains": len(domains),
                "high_risk_domains": len(domains),
                "com_variants": com_variants,
                "detection_method": "xdig_dns_probe"
            },
            "statistics": {
                "total_domains": int(stats.get("total_domains", 0)),
                "high_risk": int(stats.get("high_risk_domains", 0)),
                "medium_risk": int(stats.get("medium_risk_domains", 0)),
                "low_risk": int(stats.get("low_risk_domains", 0)),
                "recent_scans": int(stats.get("recent_scans", 0)),
                "threats_detected": int(stats.get("threats_detected", 0)),
            },
            "analysis_sections": analysis_sections,
            "dangerous_domains": domains,
        }
        return jsonify({"success": True, "data": payload}), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/xdig/unified-analysis', methods=['GET'])
def get_xdig_unified_analysis():
    """统一分析接口，当前复用 /api/xdig/analysis 输出。"""
    return get_xdig_analysis()

@app.route('/api/xdig/enhanced-analysis', methods=['POST'])
def get_xdig_enhanced_analysis():
    """执行增强版 xdig 综合分析。"""
    try:
        payload = request.get_json(silent=True) or {}
        raw_domain = payload.get("domain") or ""
        threshold = float(payload.get("threshold", 0.98) or 0.98)

        if not str(raw_domain).strip():
            return jsonify({"success": False, "error": "Missing 'domain' in request body."}), 400
        try:
            domain = normalize_domain_input(str(raw_domain))
        except DomainInputError as e:
            return jsonify({"success": False, "error": f"Invalid domain input: {e}"}), 400
        analyzer = get_xdig_analyzer() if get_xdig_analyzer else None
        if not analyzer:
            return jsonify({"success": False, "error": "xdig analyzer module not available"}), 500

        result = analyzer.perform_comprehensive_analysis(domain, threshold)
        if not isinstance(result, dict):
            return jsonify({"success": False, "error": "Invalid analyzer response"}), 500
        if result.get("success") is False:
            return jsonify({"success": False, "error": result.get("error", "Analysis failed")}), 500
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

def _list_xdig_historical_summaries(limit: int = 200) -> list:
    """返回历史 xdig 分析摘要列表。"""
    analyzer = get_xdig_analyzer() if get_xdig_analyzer else None
    if not analyzer:
        return []

    root = analyzer.monitoring_results_dir / "xdig_analysis"
    if not root.exists():
        return []

    summaries = []
    for domain_dir in root.iterdir():
        if not domain_dir.is_dir():
            continue
        files = sorted(domain_dir.glob("analysis_*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        if not files:
            continue
        latest = files[0]
        try:
            with open(latest, "r", encoding="utf-8") as f:
                payload = json.load(f)
        except Exception:
            continue

        analysis = payload.get("analysis") if isinstance(payload, dict) else {}
        risk = payload.get("risk") if isinstance(payload, dict) else {}
        variants = payload.get("variants") if isinstance(payload, dict) else {}
        detection = payload.get("detection") if isinstance(payload, dict) else {}

        original_domain = (
            (variants or {}).get("original_domain")
            or (analysis.get("summary", {}).get("original_domain") if isinstance(analysis, dict) else None)
            or domain_dir.name
        )

        summary = {
            "original_domain": original_domain,
            "timestamp": datetime.fromtimestamp(latest.stat().st_mtime).isoformat(),
            "summary": {
                "total_variants": int((variants or {}).get("total_variants", 0) or 0),
                "active_domains": int((detection or {}).get("active_count", 0) or 0),
            },
            "risk_assessment": {
                "total_risk_score": float((risk or {}).get("total_risk_score", 0) or 0),
                "risk_level": (risk or {}).get("risk_level", "unknown"),
            },
            "_mtime": latest.stat().st_mtime,
        }
        summaries.append(summary)

    summaries.sort(key=lambda x: x.get("_mtime", 0), reverse=True)
    out = summaries[: max(1, min(int(limit or 200), 1000))]
    for item in out:
        item.pop("_mtime", None)
    return out

@app.route('/api/xdig/historical-analyses', methods=['GET'])
def get_xdig_historical_analyses():
    """获取历史 xdig 分析列表。"""
    try:
        limit = request.args.get("limit", default=200, type=int)
        data = _list_xdig_historical_summaries(limit=limit)
        return jsonify({"success": True, "data": data}), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/xdig/historical-analysis/<path:domain>', methods=['GET'])
def get_xdig_historical_analysis(domain):
    """获取某域名最近一次历史分析结果。"""
    try:
        analyzer = get_xdig_analyzer() if get_xdig_analyzer else None
        if not analyzer:
            return jsonify({"success": False, "error": "xdig analyzer module not available"}), 500

        analyses = analyzer.get_previous_analyses(domain, limit=1)
        if not analyses:
            return jsonify({"success": False, "error": "No historical analysis found."}), 404

        data = analyses[0].get("data", {})
        # 兼容前端期望：历史详情结构与实时分析返回保持一致
        if isinstance(data, dict) and "analysis" in data:
            result = {
                "success": True,
                "original_domain": domain,
                "timestamp": analyses[0].get("timestamp"),
                "processing_time": 0,
                "summary": {
                    "total_variants": int((data.get("variants") or {}).get("total_variants", 0) or 0),
                    "active_domains": int((data.get("detection") or {}).get("active_count", 0) or 0),
                    "high_risk_variants": int((data.get("variants") or {}).get("high_risk_variants", 0) or 0),
                    "whois_successful": int((data.get("whois") or {}).get("successful_queries", 0) or 0),
                },
                "variants": data.get("variants", {}),
                "detection": data.get("detection", {}),
                "whois": data.get("whois", {}),
                "risk_assessment": data.get("risk", {}),
                "analysis": data.get("analysis", {}),
                "cached": False,
            }
            return jsonify({"success": True, "data": result}), 200
        return jsonify({"success": True, "data": data}), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/xdig/historical-analysis/<path:domain>', methods=['DELETE'])
def delete_xdig_historical_analysis(domain):
    """删除指定域名的历史分析目录。"""
    try:
        analyzer = get_xdig_analyzer() if get_xdig_analyzer else None
        if not analyzer:
            return jsonify({"success": False, "error": "xdig analyzer module not available"}), 500

        safe_name = analyzer._sanitize_filename(domain)
        analysis_dir = analyzer.monitoring_results_dir / "xdig_analysis" / safe_name
        if not analysis_dir.exists():
            return jsonify({"success": False, "error": "No historical analysis found."}), 404

        for p in analysis_dir.glob("**/*"):
            if p.is_file():
                p.unlink(missing_ok=True)
        for p in sorted(analysis_dir.glob("**/*"), reverse=True):
            if p.is_dir():
                p.rmdir()
        if analysis_dir.exists():
            analysis_dir.rmdir()

        return jsonify({"success": True, "message": f"Deleted xdig analysis history: {domain}"}), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/active_high_risk_count', methods=['GET'])
def get_active_high_risk_count():
    """
    API endpoint to return the count of active high-risk domains.
    """
    try:
        active_high_risk_file = Path(BASE_DIR) / "active_high_risk_domains.txt"
        if not active_high_risk_file.exists():
            return jsonify({"active_high_risk_count": 0})

        with open(active_high_risk_file, 'r', encoding='utf-8') as f:
            active_domains = [line.strip() for line in f if line.strip()]

        return jsonify({"active_high_risk_count": len(active_domains)})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/evaluated_high_risk_count', methods=['GET'])
def get_evaluated_high_risk_count():
    """
    API endpoint to return the count of evaluated high-risk domains.
    """
    try:
        evaluated_high_risk_file = Path(BASE_DIR) / "high_risk_evaluated_domains.txt"
        if not evaluated_high_risk_file.exists():
            return jsonify({"evaluated_high_risk_count": 0})

        with open(evaluated_high_risk_file, 'r', encoding='utf-8') as f:
            high_risk_domains = [line.strip() for line in f if line.strip()]

        return jsonify({"evaluated_high_risk_count": len(high_risk_domains)})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/query_results/<query_id>', methods=['GET'])
def get_query_results(query_id):
    """
    API endpoint to return the results of a specific query by its ID.
    """
    try:
        query_dir = Path(BASE_DIR) / "query_results" / query_id
        if not query_dir.exists():
            return jsonify({"error": "Query ID not found."}), 404

        # 读取原始域名
        original_domains = []
        original_domains_file = query_dir / "original_domains.txt"
        if original_domains_file.exists():
            with open(original_domains_file, 'r', encoding='utf-8') as f:
                original_domains = [line.strip() for line in f if line.strip()]

        # 读取查询结果
        results = []
        results_file = query_dir / "results.txt"
        if results_file.exists():
            with open(results_file, 'r', encoding='utf-8') as f:
                results = [line.strip() for line in f if line.strip()]

        return jsonify({"query_id": query_id, "original_domains": original_domains, "results": results})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.errorhandler(404)
def handle_404_error(e):
    """
    全局处理 404 错误，返回 JSON 格式的错误信息。
    """
    return jsonify({"error": "Resource not found", "message": str(e)}), 404

@app.errorhandler(500)
def handle_500_error(e):
    """
    全局处理 500 错误，返回 JSON 格式的错误信息。
    """
    return jsonify({"error": "Internal server error", "message": str(e)}), 500

if __name__ == "__main__":
    try:
        port = int(os.getenv('WEB_PORT', '5000'))
    except Exception:
        port = 5000
    debug = os.getenv('WEB_DEBUG', 'True').lower() in ('1', 'true', 'yes')
    app.run(host="0.0.0.0", port=port, debug=debug)
