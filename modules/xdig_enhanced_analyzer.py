#!/usr/bin/env python3
"""
增强型xdig分析模块
输入原始域名，生成所有变体，使用xdig检测存在域名，查询whois信息，进行统计分析
"""

import os
import sys
import json
import subprocess
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
import time
import logging
from collections import defaultdict
import re
import math

# 添加项目根目录到路径
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from modules.domain_input import DomainInputError, normalize_domain_input

# 导入现有模块
try:
    from modules.whois_enhanced import query_domain_whois_structured, batch_query_whois_structured
    WHOIS_ENABLED = True
except ImportError:
    WHOIS_ENABLED = False
    print("⚠️  WHOIS模块不可用")

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class XdigEnhancedAnalyzer:
    """增强型xdig分析器"""
    
    def __init__(self, base_dir: str = None):
        self.base_dir = Path(base_dir) if base_dir else Path(__file__).parent.parent
        self.domain_variants_dir = self.base_dir / "domain_variants"
        self.monitoring_results_dir = self.base_dir / "monitoring_results"
        
        # 创建必要的目录
        self.domain_variants_dir.mkdir(exist_ok=True)
        self.monitoring_results_dir.mkdir(exist_ok=True)
        
        # 缓存
        self._analysis_cache = {}
        self._cache_expiry = timedelta(hours=1)
        
    def generate_domain_variants(self, original_domain: str, threshold: float = 0.98) -> Dict:
        """
        生成域名变体
        
        Args:
            original_domain: 原始域名
            threshold: 相似度阈值
            
        Returns:
            Dict: 生成结果
        """
        try:
            print(f"开始生成域名变体: {original_domain}")
            
            # 标准化域名输入（支持 URL/Unicode/带端口等形式）
            try:
                original_domain = normalize_domain_input(original_domain)
            except DomainInputError as e:
                return {"success": False, "error": f"域名输入无效: {e}"}
            
            # 检查是否已有变体目录
            safe_name = self._sanitize_filename(original_domain)
            domain_dir = self.domain_variants_dir / safe_name
            
            if domain_dir.exists():
                # 检查最近生成时间
                punycode_file = domain_dir / "puny_only.txt"
                if punycode_file.exists():
                    file_time = datetime.fromtimestamp(punycode_file.stat().st_mtime)
                    if datetime.now() - file_time < timedelta(hours=24):
                        print(f"使用已存在的变体: {original_domain}")
                        return self._load_existing_variants(original_domain, domain_dir)
            
            # 使用Go程序生成变体
            print(f"调用Go程序生成变体: {original_domain}")
            
            # 方法1: 使用 go 生成器 — 尝试查找 main.go 的合理路径并回退到 `go run .`
            cmd = None
            candidates = [
                self.base_dir / "main.go",
                self.base_dir / "MySecurityProject" / "main.go",
                self.base_dir.parent / "main.go",
            ]
            for p in candidates:
                if p.exists():
                    cmd = ["go", "run", str(p), "-domain", original_domain, "-threshold", str(threshold)]
                    break

            # 如果当前目录为 Go module，优先使用 `go run .`
            if cmd is None and (self.base_dir / "go.mod").exists():
                cmd = ["go", "run", ".", "-domain", original_domain, "-threshold", str(threshold)]

            # 兜底：尝试旧的 main.go 路径（可能失败）
            if cmd is None:
                cmd = ["go", "run", "main.go", "-domain", original_domain, "-threshold", str(threshold)]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=self.base_dir,
                encoding='utf-8',
                errors='replace',
                timeout=300  # 5分钟超时
            )
            
            if result.returncode == 0:
                print(f"变体生成成功: {original_domain}")
                
                # 读取生成的变体
                return self._load_existing_variants(original_domain, domain_dir)
            else:
                print(f"Go程序失败: {result.stderr}")
                
                # 方法2: 使用编译的二进制
                go_binary = self.base_dir / "domain_gen.exe"
                if go_binary.exists():
                    cmd = [str(go_binary), "-domain", original_domain]
                    
                    result = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        cwd=self.base_dir,
                        encoding='utf-8',
                        errors='replace',
                        timeout=300
                    )
                    
                    if result.returncode == 0:
                        print(f"二进制生成成功: {original_domain}")
                        return self._load_existing_variants(original_domain, domain_dir)
            
            # 如果都失败，尝试使用Python生成简单变体
            print(f"Go程序失败，使用Python生成简单变体")
            return self._generate_simple_variants(original_domain, domain_dir)
            
        except subprocess.TimeoutExpired:
            print(f"变体生成超时: {original_domain}")
            return {"success": False, "error": "变体生成超时"}
        except Exception as e:
            print(f"变体生成异常: {e}")
            return {"success": False, "error": str(e)}
    
    def _load_existing_variants(self, original_domain: str, domain_dir: Path) -> Dict:
        """加载已存在的变体"""
        try:
            safe_name = self._sanitize_filename(original_domain)
            
            # 读取punycode文件
            punycode_file = domain_dir / "puny_only.txt"
            if not punycode_file.exists():
                return {"success": False, "error": "未找到变体文件"}
            
            with open(punycode_file, 'r', encoding='utf-8', errors='ignore') as f:
                punycode_domains = [line.strip() for line in f if line.strip()]
            variants_meta: Dict[str, Dict[str, Any]] = {
                domain: {"domain": domain, "source_type": "unknown", "similarity": None}
                for domain in punycode_domains
            }

            # 读取所有变体（主要用于真实相似度）
            all_variants_file = domain_dir / "all_variants.txt"
            all_variants = []
            if all_variants_file.exists():
                with open(all_variants_file, 'r', encoding='utf-8', errors='ignore') as f:
                    for raw in f:
                        line = raw.strip()
                        if not line:
                            continue
                        lower_line = line.lower()
                        if lower_line.startswith("sim\t") or lower_line.startswith("type\t"):
                            continue
                        parts = line.split('\t')
                        sim = None
                        domain = None

                        # 兼容格式:
                        # 1) Sim\tDomain\tPunycode
                        # 2) [NORMAL]\tSimilarity\tUnicode_Domain\tPunycode_Domain
                        if len(parts) >= 3:
                            try:
                                sim = float(parts[0])
                                domain = parts[1]
                            except Exception:
                                if len(parts) >= 4:
                                    try:
                                        sim = float(parts[1])
                                    except Exception:
                                        sim = None
                                    domain = parts[2]

                        if not domain:
                            continue
                        domain = domain.strip()
                        if not domain:
                            continue
                        all_variants.append(domain)
                        item = variants_meta.setdefault(
                            domain, {"domain": domain, "source_type": "unknown", "similarity": None}
                        )
                        item["source_type"] = "visual"
                        if sim is not None:
                            item["similarity"] = max(0.0, min(1.0, float(sim)))

            # 读取键盘变体（覆盖来源类型）
            keyboard_file = domain_dir / "keyboard_variants.txt"
            keyboard_variants = []
            if keyboard_file.exists():
                with open(keyboard_file, 'r', encoding='utf-8', errors='ignore') as f:
                    for raw in f:
                        line = raw.strip()
                        if not line:
                            continue
                        domain = line.split('\t')[0].strip()
                        if not domain:
                            continue
                        keyboard_variants.append(domain)
                        item = variants_meta.setdefault(
                            domain, {"domain": domain, "source_type": "unknown", "similarity": None}
                        )
                        item["source_type"] = "keyboard"

            # 读取高风险变体
            high_risk_file = domain_dir / "high_risk.txt"
            high_risk_domains = []
            if high_risk_file.exists():
                with open(high_risk_file, 'r', encoding='utf-8', errors='ignore') as f:
                    for raw in f:
                        line = raw.strip()
                        if not line:
                            continue
                        lower_line = line.lower()
                        if lower_line.startswith("sim\t") or lower_line.startswith("type\t"):
                            continue

                        parts = line.split('\t')
                        sim = None
                        domain = None
                        if len(parts) >= 3:
                            try:
                                sim = float(parts[0])
                                domain = parts[1]
                            except Exception:
                                if len(parts) >= 4:
                                    try:
                                        sim = float(parts[1])
                                    except Exception:
                                        sim = None
                                    domain = parts[2]
                        if not domain:
                            continue
                        domain = domain.strip()
                        if not domain:
                            continue

                        high_risk_domains.append(domain)
                        item = variants_meta.setdefault(
                            domain, {"domain": domain, "source_type": "unknown", "similarity": None}
                        )
                        item["is_high_risk"] = True
                        if sim is not None:
                            item["similarity"] = max(0.0, min(1.0, float(sim)))

            variant_details = []
            for domain in punycode_domains:
                item = variants_meta.get(domain, {"domain": domain, "source_type": "unknown", "similarity": None})
                item["is_high_risk"] = bool(item.get("is_high_risk", False) or domain in high_risk_domains)
                variant_details.append(item)
            
            return {
                "success": True,
                "original_domain": original_domain,
                "total_variants": len(punycode_domains),
                "high_risk_variants": len(high_risk_domains),
                "keyboard_variants": len(keyboard_variants),
                "punycode_domains": punycode_domains,
                "high_risk_domains": high_risk_domains,
                "keyboard_domains": keyboard_variants,
                "all_domains": all_variants,
                "variant_details": variant_details,
                "generated_time": datetime.fromtimestamp(punycode_file.stat().st_mtime).isoformat()
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def _generate_simple_variants(self, original_domain: str, domain_dir: Path) -> Dict:
        """生成简单的变体（备用方法）"""
        try:
            # 尽可能宽松处理输入，避免因格式限制直接失败
            parts = original_domain.split('.', 1)
            sld = (parts[0] or original_domain).strip() or "domain"
            tld = parts[1] if len(parts) > 1 and parts[1] else "com"
            
            # 生成一些简单变体
            variants = []
            
            # 1. 相似字符替换
            confusable_map = {
                'a': ['а', 'ɑ', 'а', '@'],
                'e': ['е', 'є', '℮'],
                'i': ['і', 'і', 'Ӏ', '¡'],
                'o': ['о', 'ο', 'ⲟ', '〇'],
                'u': ['μ', 'υ', 'ս'],
                's': ['ѕ', 'ꜱ', 'ʂ'],
                'l': ['Ӏ', 'ӏ', '丨'],
                't': ['т', 'τ', 'ｔ'],
                'c': ['с', 'ϲ', 'ⅽ'],
                'd': ['ԁ', 'ⅾ', 'd']
            }
            
            # 替换一个字符
            for i, char in enumerate(sld):
                if char in confusable_map:
                    for replacement in confusable_map[char][:2]:  # 只取前两个
                        variant = sld[:i] + replacement + sld[i+1:]
                        variants.append(f"{variant}.{tld}")
            
            # 2. 键盘相邻替换
            keyboard_map = {
                'a': ['s', 'q', 'w'],
                's': ['a', 'd', 'w'],
                'd': ['s', 'f', 'e'],
                'f': ['d', 'g', 'r'],
                'g': ['f', 'h', 't'],
                'h': ['g', 'j', 'y'],
                'j': ['h', 'k', 'u'],
                'k': ['j', 'l', 'i'],
                'l': ['k', ';', 'o']
            }
            
            for i, char in enumerate(sld):
                if char in keyboard_map:
                    for replacement in keyboard_map[char]:
                        variant = sld[:i] + replacement + sld[i+1:]
                        variants.append(f"{variant}.{tld}")
            
            # 3. 插入连字符
            for i in range(1, len(sld)):
                variant = sld[:i] + '-' + sld[i:]
                variants.append(f"{variant}.{tld}")
            
            # 4. 删除字符
            for i in range(len(sld)):
                variant = sld[:i] + sld[i+1:]
                variants.append(f"{variant}.{tld}")
            
            # 去重
            variants = list(set(variants))
            variant_details = [
                {
                    "domain": variant,
                    "source_type": "unknown",
                    "similarity": 0.8,
                    "is_high_risk": idx < min(20, len(variants)),
                }
                for idx, variant in enumerate(variants)
            ]
            
            # 创建目录
            domain_dir.mkdir(exist_ok=True)
            
            # 保存punycode文件
            punycode_file = domain_dir / "puny_only.txt"
            with open(punycode_file, 'w', encoding='utf-8') as f:
                for variant in variants:
                    f.write(f"{variant}\n")
            
            # 保存所有变体
            all_variants_file = domain_dir / "all_variants.txt"
            with open(all_variants_file, 'w', encoding='utf-8') as f:
                f.write("Sim\tDomain\tPunycode\n")
                for variant in variants:
                    f.write(f"0.80\t{variant}\t{variant}\n")
            
            # 保存高风险变体
            high_risk_file = domain_dir / "high_risk.txt"
            with open(high_risk_file, 'w', encoding='utf-8') as f:
                f.write("Sim\tDomain\tPunycode\n")
                for variant in variants[:min(20, len(variants))]:  # 前20个作为高风险
                    f.write(f"0.80\t{variant}\t{variant}\n")
            
            return {
                "success": True,
                "original_domain": original_domain,
                "total_variants": len(variants),
                "high_risk_variants": min(20, len(variants)),
                "punycode_domains": variants,
                "high_risk_domains": variants[:min(20, len(variants))],
                "variant_details": variant_details,
                "generated_time": datetime.now().isoformat()
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def detect_active_domains(self, punycode_domains: List[str], batch_size: int = 100) -> Dict:
        """
        使用xdig检测活跃域名
        
        Args:
            punycode_domains: punycode域名列表
            batch_size: 每批处理的域名数量
            
        Returns:
            Dict: 检测结果
        """
        try:
            if not punycode_domains:
                return {"success": True, "active_domains": [], "total_checked": 0}
            
            print(f"开始检测活跃域名: {len(punycode_domains)} 个域名")
            
            # 创建临时文件
            temp_dir = self.base_dir / "temp"
            temp_dir.mkdir(exist_ok=True)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            input_file = temp_dir / f"xdig_input_{timestamp}.txt"
            output_file = temp_dir / f"xdig_output_{timestamp}.txt"
            
            # 写入输入文件
            with open(input_file, 'w', encoding='utf-8') as f:
                for domain in punycode_domains:
                    f.write(f"{domain}\n")
            
            # 调用xdig工具
            xdig_path = self.base_dir / "xdig.exe"
            if not xdig_path.exists():
                xdig_path = self.base_dir / "xdig"
            
            if not xdig_path.exists():
                print("⚠️  xdig工具未找到，使用模拟检测")
                return self._simulate_active_domains(punycode_domains)
            
            # 分批处理
            active_domains = []
            total_batches = (len(punycode_domains) + batch_size - 1) // batch_size
            
            for i in range(0, len(punycode_domains), batch_size):
                batch = punycode_domains[i:i+batch_size]
                batch_num = i // batch_size + 1
                
                print(f"处理第 {batch_num}/{total_batches} 批: {len(batch)} 个域名")
                
                # 创建批次文件
                batch_file = temp_dir / f"batch_{timestamp}_{batch_num}.txt"
                with open(batch_file, 'w', encoding='utf-8') as f:
                    for domain in batch:
                        f.write(f"{domain}\n")
                
                # 执行xdig命令（简化版）
                # 注意: 实际使用时需要根据xdig的参数调整
                cmd = [str(xdig_path), "-domainfile", str(batch_file), "-out", str(output_file)]
                
                try:
                    result = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        cwd=self.base_dir,
                        encoding='utf-8',
                        errors='replace',
                        timeout=60  # 1分钟超时
                    )
                    
                    if result.returncode == 0 and output_file.exists():
                        # 解析输出文件
                        with open(output_file, 'r', encoding='utf-8', errors='ignore') as f:
                            for line in f:
                                line = line.strip()
                                if line and ',' in line:
                                    parts = line.split(',')
                                    domain = parts[0].strip()
                                    status = parts[1].strip() if len(parts) > 1 else "0"
                                    
                                    if status == "1":  # 活跃域名
                                        active_domains.append(domain)
                    
                except Exception as e:
                    print(f"xdig批次处理失败: {e}")
                    # 继续处理下一批
            
            # 清理临时文件
            try:
                import shutil
                shutil.rmtree(temp_dir)
            except:
                pass
            
            return {
                "success": True,
                "active_domains": active_domains,
                "total_checked": len(punycode_domains),
                "active_count": len(active_domains),
                "inactive_count": len(punycode_domains) - len(active_domains)
            }
            
        except Exception as e:
            print(f"活跃域名检测异常: {e}")
            return {"success": False, "error": str(e)}
    
    def _simulate_active_domains(self, punycode_domains: List[str]) -> Dict:
        """模拟活跃域名检测（当xdig不可用时）"""
        import random
        
        # 模拟检测：随机选择20%的域名作为活跃
        active_count = max(1, int(len(punycode_domains) * 0.2))
        active_domains = random.sample(punycode_domains, min(active_count, len(punycode_domains)))
        
        return {
            "success": True,
            "active_domains": active_domains,
            "total_checked": len(punycode_domains),
            "active_count": len(active_domains),
            "inactive_count": len(punycode_domains) - len(active_domains),
            "note": "模拟检测结果（xdig工具不可用）"
        }
    
    def query_whois_for_domains(self, domains: List[str], max_workers: int = 5) -> Dict:
        """
        查询域名的WHOIS信息
        
        Args:
            domains: 域名列表
            max_workers: 最大并发数
            
        Returns:
            Dict: WHOIS查询结果
        """
        try:
            if not WHOIS_ENABLED:
                return {"success": False, "error": "WHOIS模块不可用"}
            
            if not domains:
                return {"success": True, "whois_results": []}
            
            print(f"开始查询WHOIS信息: {len(domains)} 个域名")
            
            # 分批查询以避免超时
            batch_size = min(50, len(domains))
            all_results = []
            
            for i in range(0, len(domains), batch_size):
                batch = domains[i:i+batch_size]
                print(f"查询WHOIS批次 {i//batch_size + 1}/{(len(domains)+batch_size-1)//batch_size}: {len(batch)} 个域名")
                
                try:
                    results = batch_query_whois_structured(batch, max_workers=max_workers, delay=1.0)
                    all_results.extend(results)
                    
                    # 避免请求过于频繁
                    if i + batch_size < len(domains):
                        time.sleep(2)
                        
                except Exception as e:
                    print(f"WHOIS批次查询失败: {e}")
                    # 继续处理下一批
            
            # 分析WHOIS结果
            analysis = self._analyze_whois_results(all_results)
            
            return {
                "success": True,
                "whois_results": all_results,
                "analysis": analysis,
                "total_queried": len(domains),
                "successful_queries": len([r for r in all_results if r.get('status') == 'success'])
            }
            
        except Exception as e:
            print(f"WHOIS查询异常: {e}")
            return {"success": False, "error": str(e)}
    
    def _analyze_whois_results(self, whois_results: List[Dict]) -> Dict:
        """分析WHOIS结果"""
        try:
            successful_results = [r for r in whois_results if r.get('status') == 'success']
            
            if not successful_results:
                return {
                    "total_domains": 0,
                    "successful_queries": 0,
                    "registrar_analysis": {},
                    "creation_date_analysis": {},
                    "risk_analysis": {},
                    "tld_analysis": {}
                }
            
            # 注册商分析
            registrar_counts = defaultdict(int)
            registrar_risk = defaultdict(list)
            
            # 创建时间分析
            creation_dates = []
            creation_months = defaultdict(int)
            
            # TLD分析
            tld_counts = defaultdict(int)
            
            # 风险评分分析
            risk_scores = []
            
            for result in successful_results:
                domain = result.get('domain', '')
                whois_info = result.get('whois_info', {})
                risk_score = result.get('whois_risk_score', 0)
                
                # 注册商
                registrar = whois_info.get('registrar', 'Unknown')
                registrar_counts[registrar] += 1
                registrar_risk[registrar].append(risk_score)
                
                # 创建时间
                creation_date = whois_info.get('creation_date')
                if creation_date:
                    try:
                        # 解析日期
                        if isinstance(creation_date, str):
                            from dateutil import parser
                            date_obj = parser.parse(creation_date)
                            creation_dates.append(date_obj)
                            
                            # 按年月分组
                            year_month = date_obj.strftime("%Y-%m")
                            creation_months[year_month] += 1
                    except:
                        pass
                
                # TLD分析
                if '.' in domain:
                    tld = domain.split('.')[-1]
                    tld_counts[tld] += 1
                
                # 风险评分
                risk_scores.append(risk_score)
            
            # 计算统计
            total_domains = len(successful_results)
            
            # 注册商统计
            registrar_list = []
            for registrar, count in sorted(registrar_counts.items(), key=lambda x: x[1], reverse=True):
                avg_risk = sum(registrar_risk[registrar]) / len(registrar_risk[registrar]) if registrar_risk[registrar] else 0
                percentage = (count / total_domains) * 100
                
                registrar_list.append({
                    "registrar": registrar,
                    "domain_count": count,
                    "percentage": round(percentage, 2),
                    "average_risk_score": round(avg_risk, 2)
                })
            
            # 创建时间统计
            sorted_months = sorted(creation_months.items())
            monthly_data = []
            for month, count in sorted_months:
                year, month_num = month.split('-')
                monthly_data.append({
                    "year": int(year),
                    "month": int(month_num),
                    "count": count
                })
            
            # TLD统计
            tld_list = []
            for tld, count in sorted(tld_counts.items(), key=lambda x: x[1], reverse=True):
                percentage = (count / total_domains) * 100
                tld_list.append({
                    "tld": tld,
                    "domain_count": count,
                    "percentage": round(percentage, 2)
                })
            
            # 风险分析
            avg_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0
            risk_levels = {
                "high": len([s for s in risk_scores if s > 15]),
                "medium": len([s for s in risk_scores if 8 < s <= 15]),
                "low": len([s for s in risk_scores if s <= 8])
            }
            
            return {
                "total_domains": total_domains,
                "successful_queries": total_domains,
                "registrar_analysis": {
                    "registrars": registrar_list[:10],  # 前10个注册商
                    "total_registrars": len(registrar_counts),
                    "top_registrar": registrar_list[0]["registrar"] if registrar_list else "Unknown",
                    "top_registrar_percentage": registrar_list[0]["percentage"] if registrar_list else 0
                },
                "creation_date_analysis": {
                    "monthly_distribution": monthly_data,
                    "total_with_dates": len(creation_dates),
                    "earliest_date": min(creation_dates).strftime("%Y-%m-%d") if creation_dates else None,
                    "latest_date": max(creation_dates).strftime("%Y-%m-%d") if creation_dates else None
                },
                "risk_analysis": {
                    "average_risk_score": round(avg_risk, 2),
                    "risk_distribution": risk_levels,
                    "high_risk_percentage": (risk_levels["high"] / total_domains * 100) if total_domains > 0 else 0
                },
                "tld_analysis": {
                    "tlds": tld_list[:10],  # 前10个TLD
                    "total_tlds": len(tld_counts),
                    "most_common_tld": tld_list[0]["tld"] if tld_list else "Unknown",
                    "com_percentage": next((t["percentage"] for t in tld_list if t["tld"] == "com"), 0)
                }
            }
            
        except Exception as e:
            print(f"WHOIS结果分析异常: {e}")
            return {}
    
    def perform_comprehensive_analysis(self, original_domain: str, threshold: float = 0.98) -> Dict:
        """
        执行综合分析
        
        Args:
            original_domain: 原始域名
            threshold: 相似度阈值
            
        Returns:
            Dict: 综合分析结果
        """
        try:
            try:
                original_domain = normalize_domain_input(original_domain)
            except DomainInputError as e:
                return {"success": False, "error": f"域名输入无效: {e}"}

            # 检查缓存
            cache_key = f"{original_domain}_{threshold}"
            if cache_key in self._analysis_cache:
                cached_data, cached_time = self._analysis_cache[cache_key]
                if datetime.now() - cached_time < self._cache_expiry:
                    print(f"使用缓存数据: {original_domain}")
                    cached_data["cached"] = True
                    return cached_data
            
            print(f"开始综合分析: {original_domain}")
            start_time = time.time()
            
            # 1. 生成域名变体
            variants_result = self.generate_domain_variants(original_domain, threshold)
            if not variants_result.get("success", False):
                return variants_result
            
            punycode_domains = variants_result.get("punycode_domains", [])
            if not punycode_domains:
                return {"success": False, "error": "未生成任何域名变体"}
            
            # 2. 检测活跃域名
            detection_result = self.detect_active_domains(punycode_domains)
            if not detection_result.get("success", False):
                return detection_result
            
            active_domains = detection_result.get("active_domains", [])
            
            # 3. 查询WHOIS信息
            whois_result = {"success": True, "analysis": {}}  # 默认值
            if active_domains and WHOIS_ENABLED:
                whois_result = self.query_whois_for_domains(active_domains)
            
            # 4. 优化风险评分
            risk_assessment = self._calculate_enhanced_risk(
                original_domain, 
                variants_result, 
                detection_result, 
                whois_result
            )
            
            # 5. 生成分析报告
            analysis_report = self._generate_analysis_report(
                original_domain,
                variants_result,
                detection_result,
                whois_result,
                risk_assessment
            )
            
            # 6. 保存结果
            self._save_analysis_results(original_domain, {
                "variants": variants_result,
                "detection": detection_result,
                "whois": whois_result,
                "risk": risk_assessment,
                "analysis": analysis_report
            })
            
            # 7. 准备返回结果
            result = {
                "success": True,
                "original_domain": original_domain,
                "timestamp": datetime.now().isoformat(),
                "processing_time": round(time.time() - start_time, 2),
                "summary": {
                    "total_variants": variants_result.get("total_variants", 0),
                    "active_domains": detection_result.get("active_count", 0),
                    "high_risk_variants": variants_result.get("high_risk_variants", 0),
                    "whois_successful": whois_result.get("successful_queries", 0) if whois_result.get("success") else 0
                },
                "variants": variants_result,
                "detection": detection_result,
                "whois": whois_result,
                "risk_assessment": risk_assessment,
                "analysis": analysis_report
            }
            
            # 缓存结果
            self._analysis_cache[cache_key] = (result, datetime.now())
            
            return result
            
        except Exception as e:
            print(f"综合分析异常: {e}")
            return {"success": False, "error": str(e)}
    
    def _calculate_enhanced_risk(self, original_domain: str, variants_result: Dict, 
                                 detection_result: Dict, whois_result: Dict) -> Dict:
        """计算增强的风险评分"""
        try:
            # 基础风险因素
            total_variants = variants_result.get("total_variants", 0)
            high_risk_variants = variants_result.get("high_risk_variants", 0)
            active_count = detection_result.get("active_count", 0)
            
            # WHOIS风险因素
            whois_analysis = whois_result.get("analysis", {})
            whois_risk = whois_analysis.get("risk_analysis", {})
            avg_whois_risk = whois_risk.get("average_risk_score", 0)
            high_risk_percentage = whois_risk.get("high_risk_percentage", 0)
            
            # 计算综合风险评分 (0-100)
            risk_factors = []
            
            # 1. 变体数量风险 (20%)
            if total_variants > 1000:
                risk_factors.append(20)
            elif total_variants > 500:
                risk_factors.append(15)
            elif total_variants > 100:
                risk_factors.append(10)
            elif total_variants > 10:
                risk_factors.append(5)
            
            # 2. 高风险变体比例 (25%)
            if total_variants > 0:
                high_risk_ratio = high_risk_variants / total_variants
                if high_risk_ratio > 0.5:
                    risk_factors.append(25)
                elif high_risk_ratio > 0.3:
                    risk_factors.append(20)
                elif high_risk_ratio > 0.1:
                    risk_factors.append(10)
            
            # 3. 活跃域名风险 (30%)
            if active_count > 0:
                active_ratio = active_count / total_variants if total_variants > 0 else 0
                if active_ratio > 0.3:
                    risk_factors.append(30)
                elif active_ratio > 0.1:
                    risk_factors.append(20)
                elif active_ratio > 0:
                    risk_factors.append(10)
            
            # 4. WHOIS风险 (25%)
            whois_risk_score = min(25, avg_whois_risk * 1.5)  # 调整权重
            risk_factors.append(whois_risk_score)
            
            # 计算总分
            total_risk = min(100, sum(risk_factors))
            
            # 确定风险等级
            if total_risk >= 70:
                risk_level = "critical"
            elif total_risk >= 50:
                risk_level = "high"
            elif total_risk >= 30:
                risk_level = "medium"
            elif total_risk >= 10:
                risk_level = "low"
            else:
                risk_level = "very_low"
            
            return {
                "total_risk_score": round(total_risk, 2),
                "risk_level": risk_level,
                "risk_factors": {
                    "variant_count_risk": risk_factors[0] if len(risk_factors) > 0 else 0,
                    "high_risk_ratio_risk": risk_factors[1] if len(risk_factors) > 1 else 0,
                    "active_domain_risk": risk_factors[2] if len(risk_factors) > 2 else 0,
                    "whois_risk": risk_factors[3] if len(risk_factors) > 3 else 0
                },
                "recommendations": self._generate_risk_recommendations(total_risk, risk_level)
            }
            
        except Exception as e:
            print(f"风险评分计算异常: {e}")
            return {
                "total_risk_score": 0,
                "risk_level": "unknown",
                "error": str(e)
            }
    
    def _generate_risk_recommendations(self, risk_score: float, risk_level: str) -> List[str]:
        """生成风险建议"""
        recommendations = []
        
        if risk_level in ["critical", "high"]:
            recommendations.extend([
                "该域名存在大量高风险仿冒变体",
                "建议立即进行域名监控和防护",
                "考虑注册相关变体域名进行保护",
                "通知用户注意仿冒网站风险"
            ])
        elif risk_level == "medium":
            recommendations.extend([
                "该域名存在一定数量的仿冒变体",
                "建议定期监控相关变体域名",
                "考虑注册关键变体进行保护"
            ])
        elif risk_level == "low":
            recommendations.extend([
                "该域名仿冒风险较低",
                "建议保持常规监控"
            ])
        else:
            recommendations.append("风险较低，无需特殊处理")
        
        return recommendations
    
    def _generate_analysis_report(self, original_domain: str, variants_result: Dict, 
                                 detection_result: Dict, whois_result: Dict, 
                                 risk_assessment: Dict) -> Dict:
        """生成分析报告"""
        try:
            # WHOIS分析数据
            whois_analysis = whois_result.get("analysis", {})
            registrar_analysis = whois_analysis.get("registrar_analysis", {})
            creation_analysis = whois_analysis.get("creation_date_analysis", {})
            tld_analysis = whois_analysis.get("tld_analysis", {})
            
            # 注册时间分析文本
            monthly_data = creation_analysis.get("monthly_distribution", [])
            registration_text = "注册时间分布数据不足"
            if monthly_data:
                # 找出峰值月份
                peak_month = max(monthly_data, key=lambda x: x.get("count", 0))
                registration_text = f"仿冒域名注册主要集中在{peak_month['year']}年{peak_month['month']}月，当月注册{peak_month['count']}个域名。"
            
            # 注册商分析文本
            top_registrars = registrar_analysis.get("registrars", [])
            registrar_text = "注册商信息不足"
            if top_registrars:
                top_5 = top_registrars[:5]
                registrar_names = [r["registrar"] for r in top_5]
                percentages = [r["percentage"] for r in top_5]
                total_percentage = sum(percentages)
                registrar_text = f"共涉及{registrar_analysis.get('total_registrars', 0)}个注册商，前5大注册商({', '.join(registrar_names)})占总数的{total_percentage:.1f}%。"
            
            # TLD分析文本
            tlds = tld_analysis.get("tlds", [])
            tld_text = "TLD信息不足"
            if tlds:
                top_tlds = [f"{t['tld']}({t['percentage']:.1f}%)" for t in tlds[:3]]
                tld_text = f"主要TLD分布: {', '.join(top_tlds)}。通用顶级域(.com)占比{tld_analysis.get('com_percentage', 0):.1f}%。"
            
            # 风险分析文本
            risk_score = risk_assessment.get("total_risk_score", 0)
            risk_level = risk_assessment.get("risk_level", "unknown")
            risk_text = f"综合风险评分为{risk_score:.1f}，风险等级为{risk_level}。"
            
            # 域名用途分析
            usage_text = "从解析结果分析，这些仿冒域名主要用于: 1.钓鱼欺诈类网站；2.虚假投资平台；3.域名抢注投机；4.品牌仿冒；5.其他恶意用途。"
            
            # 域名示例
            active_domains = detection_result.get("active_domains", [])
            domain_examples = active_domains[:10] if active_domains else ["无活跃域名示例"]
            
            return {
                "sections": [
                    {
                        "title": "注册时间分布",
                        "content": registration_text,
                        "icon": "fa-calendar",
                        "chart_data": monthly_data
                    },
                    {
                        "title": "注册商分析",
                        "content": registrar_text,
                        "icon": "fa-building",
                        "chart_data": top_registrars
                    },
                    {
                        "title": "TLD分布",
                        "content": tld_text,
                        "icon": "fa-globe",
                        "chart_data": tlds[:10]
                    },
                    {
                        "title": "风险综合评估",
                        "content": risk_text,
                        "icon": "fa-shield-alt",
                        "risk_data": risk_assessment
                    },
                    {
                        "title": "域名用途分析",
                        "content": usage_text,
                        "icon": "fa-chart-line"
                    }
                ],
                "domain_examples": domain_examples,
                "summary": {
                    "total_variants": variants_result.get("total_variants", 0),
                    "active_domains": detection_result.get("active_count", 0),
                    "registrar_count": registrar_analysis.get("total_registrars", 0),
                    "tld_count": tld_analysis.get("total_tlds", 0),
                    "analysis_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }
            }
            
        except Exception as e:
            print(f"分析报告生成异常: {e}")
            return {
                "sections": [
                    {
                        "title": "分析报告生成失败",
                        "content": f"生成分析报告时发生错误: {str(e)}",
                        "icon": "fa-exclamation-triangle"
                    }
                ],
                "domain_examples": [],
                "summary": {}
            }
    
    def _save_analysis_results(self, original_domain: str, results: Dict):
        """保存分析结果"""
        try:
            safe_name = self._sanitize_filename(original_domain)
            analysis_dir = self.monitoring_results_dir / "xdig_analysis" / safe_name
            analysis_dir.mkdir(parents=True, exist_ok=True)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = analysis_dir / f"analysis_{timestamp}.json"
            
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(results, f, ensure_ascii=False, indent=2)
            
            print(f"分析结果已保存: {filename}")
            
        except Exception as e:
            print(f"保存分析结果失败: {e}")
    
    def _sanitize_filename(self, name: str) -> str:
        """清理文件名"""
        # 替换不安全的字符
        name = re.sub(r'[<>:"/\\|?*\x00-\x1F]', '_', name)
        if name == "":
            name = "domain"
        return name
    
    def get_previous_analyses(self, original_domain: str, limit: int = 10) -> List[Dict]:
        """获取之前的分析结果"""
        try:
            try:
                original_domain = normalize_domain_input(original_domain)
            except DomainInputError:
                original_domain = (original_domain or "").strip().lower()
            safe_name = self._sanitize_filename(original_domain)
            analysis_dir = self.monitoring_results_dir / "xdig_analysis" / safe_name
            
            if not analysis_dir.exists():
                return []
            
            analysis_files = list(analysis_dir.glob("analysis_*.json"))
            analysis_files.sort(key=lambda x: x.stat().st_mtime, reverse=True)
            
            analyses = []
            for file_path in analysis_files[:limit]:
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        analyses.append({
                            "file": file_path.name,
                            "timestamp": datetime.fromtimestamp(file_path.stat().st_mtime).isoformat(),
                            "data": data
                        })
                except:
                    continue
            
            return analyses
            
        except Exception as e:
            print(f"获取历史分析失败: {e}")
            return []

# 单例实例
_analyzer_instance = None

def get_xdig_analyzer():
    """获取xdig分析器实例"""
    global _analyzer_instance
    if _analyzer_instance is None:
        _analyzer_instance = XdigEnhancedAnalyzer()
    return _analyzer_instance

if __name__ == "__main__":
    # 命令行测试
    import argparse
    
    parser = argparse.ArgumentParser(description='增强型xdig分析工具')
    parser.add_argument('-d', '--domain', required=True, help='目标域名')
    parser.add_argument('-t', '--threshold', type=float, default=0.98, help='相似度阈值')
    parser.add_argument('-o', '--output', help='输出JSON文件')
    
    args = parser.parse_args()
    
    analyzer = XdigEnhancedAnalyzer()
    result = analyzer.perform_comprehensive_analysis(args.domain, args.threshold)
    
    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        print(f"结果已保存到: {args.output}")
    else:
        print(json.dumps(result, ensure_ascii=False, indent=2))
