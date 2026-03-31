#!/usr/bin/env python3
"""
数据处理管道 - 协调各模块执行完整的域名监控流程
包含数据库存储功能的第二阶段实现

融合解析记录、应用层响应和威胁情报进行多维特征分析和风险建模
实现重点域名主动化监控和预警
"""

import json
import time
import logging
import subprocess
import sys
import os
import platform
from typing import List, Optional, Dict, Any
from datetime import datetime
from pathlib import Path
import ipaddress

# 添加模块路径
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.domain_input import DomainInputError, normalize_domain_input

try:
    from modules.multidim_risk_engine import run_multidimensional_analysis, MultiDimRunConfig
    MULTIDIM_ENGINE_ENABLED = True
except Exception as e:
    logging.warning(f"多维风险引擎导入失败: {e}，将跳过多维分析")
    MULTIDIM_ENGINE_ENABLED = False

try:
    from modules.whois_enhanced import batch_query_whois_structured
    from modules.data_schemas import create_whois_result_from_enhanced
    WHOIS_ENRICH_ENABLED = True
except Exception as e:
    logging.warning(f"WHOIS增强模块导入失败: {e}，将跳过首轮WHOIS强制入库")
    WHOIS_ENRICH_ENABLED = False

# 第二阶段新增：数据库模块
try:
    from modules.database.connection import init_database
    from modules.database.dao import get_data_manager
    DATABASE_ENABLED = True
except ImportError as e:
    logging.warning(f"数据库模块导入失败: {e}，将仅使用文件存储")
    DATABASE_ENABLED = False

# 第三阶段新增：被动DNS和证书透明度模块
try:
    from modules.passive_dns.collector import get_passive_dns_collector
    from modules.certificate_transparency.monitor import get_ct_monitor
    PASSIVE_DNS_ENABLED = True
    CT_MONITOR_ENABLED = True
except ImportError as e:
    logging.warning(f"被动DNS/证书透明度模块导入失败: {e}，将跳过相关功能")
    PASSIVE_DNS_ENABLED = False
    CT_MONITOR_ENABLED = False

# 第一阶段新增：主动Web探测模块
try:
    from modules.active_probing import ActiveProbingService
    from modules.active_probing.visual_compare import perceptual_hash
    ACTIVE_PROBING_ENABLED = True
except ImportError as e:
    logging.warning(f"主动Web探测模块导入失败: {e}，将跳过相关功能")
    ACTIVE_PROBING_ENABLED = False

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)



class DomainMonitoringPipeline:
    """
    域名监控数据处理管道
    当前流程：域名变体生成 → xdig 迭代探测 → 稳定存活域名入库
    """
    
    def __init__(self, base_dir: str = "."):
        self.base_dir = Path(base_dir)
        self.results_dir = self.base_dir / "monitoring_results"
        self.results_dir.mkdir(exist_ok=True)
        self.database_ready = False
        
        # 各模块的输出文件路径
        self.domain_variants_file = self.base_dir / "domain_variants" / "example.com_puny_only.txt"
        self.xdig_results_file = None
        self.final_results_file = self.results_dir / "comprehensive_results.json"
        self.multidim_latest_file = self.results_dir / "multidimensional_analysis_latest.json"
        self.alerts_latest_file = self.results_dir / "alerts_latest.json"

        # 新增：被动DNS和证书透明度结果文件
        self.passive_dns_results_file = self.results_dir / "passive_dns_results.json"
        self.certificate_transparency_results_file = self.results_dir / "certificate_transparency_results.json"
        self.active_probing_results_file = self.results_dir / "active_probing_results.json"
        self.risk_modeling_results_file = self.results_dir / "risk_modeling_results.json"
        self.visualization_data_file = self.results_dir / "visualization_data.json"

        if DATABASE_ENABLED:
            try:
                init_database()
                self.database_ready = True
                logger.info("数据管道数据库初始化成功")
            except Exception as e:
                self.database_ready = False
                logger.warning(f"数据管道数据库初始化失败，将跳过入库: {e}")
        
        # 初始化被动DNS和证书透明度模块（如果可用）
        self.passive_dns_collector = None
        self.ct_monitor = None
        self.active_probing_service = None
        
        if PASSIVE_DNS_ENABLED and self.database_ready:
            try:
                from modules.database.connection import DatabaseSession
                with DatabaseSession() as session:
                    self.passive_dns_collector = get_passive_dns_collector(session)
                    logger.info("被动DNS收集器初始化成功")
            except Exception as e:
                logger.warning(f"被动DNS收集器初始化失败: {e}")
        
        if CT_MONITOR_ENABLED and self.database_ready:
            try:
                from modules.database.connection import DatabaseSession
                with DatabaseSession() as session:
                    self.ct_monitor = get_ct_monitor(session)
                    logger.info("证书透明度监控器初始化成功")
            except Exception as e:
                logger.warning(f"证书透明度监控器初始化失败: {e}")

        if ACTIVE_PROBING_ENABLED:
            try:
                probing_timeout = max(5, int(os.getenv("ACTIVE_PROBING_TIMEOUT", "15")))
                screenshot_dir = os.getenv("SCREENSHOT_DIR", str(self.results_dir / "screenshots"))
                self.active_probing_service = ActiveProbingService(
                    timeout=probing_timeout,
                    screenshot_dir=screenshot_dir
                )
                logger.info("主动Web探测服务初始化成功")
            except Exception as e:
                logger.warning(f"主动Web探测服务初始化失败: {e}")

    def step1_generate_domain_variants(self, target_domain: str) -> bool:
        """
        步骤1: 使用main.go生成域名变体
        """
        logger.info(f"步骤1: 生成域名变体 - {target_domain}")
        
        # 如果目标是IP地址，则跳过通过 main.go 生成域名变体，直接创建单行变体文件
        try:
            ipaddress.ip_address(target_domain)
            domain_output_dir = self.base_dir / "domain_variants" / target_domain.replace('.', '_')
            domain_output_dir.mkdir(parents=True, exist_ok=True)
            punycode_file = domain_output_dir / "puny_only.txt"
            punycode_file.write_text(str(target_domain) + "\n", encoding='utf-8')
            self.domain_variants_file = punycode_file
            logger.info("目标为IP，已跳过域名变体生成并使用单行IP文件")
            return True
        except ValueError:
            pass

        try:
            # 构建命令
            cmd = ["go", "run", "main.go", "-domain", target_domain]
            
            logger.info(f"执行命令: {' '.join(cmd)}")
            
            # 执行命令 - 使用正确的编码处理输出
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                cwd=self.base_dir,
                encoding='utf-8',
                errors='replace'  # 替换无法解码的字符
            )
            
            if result.returncode == 0:
                logger.info("域名变体生成成功")
                
                # 检查生成的punycode文件 - 根据新的目录结构
                domain_output_dir = self.base_dir / "domain_variants" / target_domain.replace('.', '_')
                punycode_file = domain_output_dir / "puny_only.txt"
                
                # 如果上述路径不存在，尝试直接域名作为目录名
                if not punycode_file.exists():
                    domain_output_dir = self.base_dir / "domain_variants" / target_domain
                    punycode_file = domain_output_dir / "puny_only.txt"
                
                if punycode_file.exists():
                    self.domain_variants_file = punycode_file
                    count = len(punycode_file.read_text(encoding='utf-8').strip().splitlines())
                    logger.info(f"生成 {count} 个域名变体")
                    return True
                else:
                    logger.warning(f"未找到punycode文件: {punycode_file}")
                    # 列出目录内容帮助调试
                    try:
                        if domain_output_dir.exists():
                            files = list(domain_output_dir.iterdir())
                            logger.info(f"目录内容: {[f.name for f in files]}")
                    except:
                        pass
                    return False
            else:
                logger.error(f"域名变体生成失败，返回码: {result.returncode}")
                if result.stdout:
                    logger.error(f"标准输出: {result.stdout[:500]}")
                if result.stderr:
                    logger.error(f"错误输出: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"执行域名变体生成时出错: {e}")
            return False
    
    def step2_run_xdig_scan(
            self,
            target_domain: str,
            domainfile: Optional[str] = None,
            rate: int = 100
    ) -> bool:
        """
        步骤2：运行 xdig DNS 探测（支持自定义 domainfile）
        """

        logger.info("步骤2: 运行 xdig DNS 探测")

        try:
            import shutil

            if platform.system() != "Linux":
                logger.error("xdig 原始发包模式仅支持 Linux")
                return False

            # ========= 1️⃣ 查找 xdig =========
            xdig_executable = self.base_dir / "xdig"
            if not xdig_executable.exists():
                path_exec = shutil.which("xdig")
                if path_exec:
                    xdig_executable = Path(path_exec)

            if not xdig_executable.exists():
                logger.error("未找到 xdig 可执行文件")
                return False

            xdig_executable.chmod(0o755)

            # ========= 2️⃣ 自动获取网络参数 =========
            route = subprocess.check_output("ip route | grep default", shell=True, text=True)
            iface = route.split("dev")[1].split()[0]
            gateway_ip = route.split("via")[1].split()[0]

            ip_info = subprocess.check_output(
                f"ip -4 addr show {iface} | grep inet",
                shell=True,
                text=True
            )
            src_ip = ip_info.split()[1].split("/")[0]

            src_mac = Path(f"/sys/class/net/{iface}/address").read_text().strip()

            neigh = subprocess.check_output(
                f"ip neigh | grep {gateway_ip}",
                shell=True,
                text=True
            )
            gtw_mac = neigh.split("lladdr")[1].split()[0]

            logger.info(f"网络参数: iface={iface}, ip={src_ip}")

            # ========= 3️⃣ 选择 domainfile =========
            if domainfile:
                domain_file = Path(domainfile)
            else:
                domain_file = self.domain_variants_file

            if not domain_file.exists():
                logger.error(f"domainfile 不存在: {domain_file}")
                return False

            # ========= 4️⃣ DNS文件 =========
            dns_file = self.base_dir / "dns.txt"
            if not dns_file.exists():
                logger.error("dns.txt 不存在")
                return False

            # ========= 5️⃣ 输出文件 =========
            output_file = self.base_dir / f"result_{target_domain}_{rate}.txt"
            self.xdig_results_file = output_file

            # ========= 6️⃣ 组装命令 =========
            cmd = [
                "sudo", str(xdig_executable),
                "-iface", iface,
                "-srcip", src_ip,
                "-srcmac", src_mac,
                "-gtwmac", gtw_mac,
                "-domainfile", str(domain_file),
                "-dnsfile", str(dns_file),
                "-rate", str(rate),
                "-type", "a",
                "-out", str(output_file)
            ]

            logger.info("执行命令:")
            logger.info(" ".join(cmd))

            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode != 0:
                logger.error(f"xdig 扫描失败: {result.stderr}")
                return False

            logger.info(f"xdig 输出文件: {output_file}")

            return True

        except Exception as e:
            logger.error(f"执行 xdig 出错: {e}")
            return False
    
    def extract_active_domains_from_xdig(self) -> List[str]:
        """
        从xdig结果中提取存活的域名列表
        """
        active_domains = []
        try:
            alive_lines = []
            # read xdig output and collect alive entries (last column == '1')
            with open(self.xdig_results_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    raw = line.strip()
                    if not raw:
                        continue
                    # last column marker is expected after a comma
                    if raw.endswith(',1'):
                        parts = raw.split(',')
                        domain = parts[0]
                        active_domains.append(domain)
                        alive_lines.append(raw)

            # persist alive lines to a separate file for debugging/inspection
            try:
                alive_file = self.results_dir / 'xdig_active_alive.txt'
                with open(alive_file, 'w', encoding='utf-8') as out:
                    for l in alive_lines:
                        out.write(l + "\n")
                logger.info(f"已保存 {len(alive_lines)} 条存活行到 {alive_file}")
            except Exception as wf_err:
                logger.warning(f"写入 xdig 存活文件失败: {wf_err}")

            logger.info(f"从xdig结果中提取了 {len(active_domains)} 个存活域名")
            return active_domains

        except Exception as e:
            logger.error(f"提取存活域名时出错: {e}")
            return []
    
    def step3_query_passive_dns(self, target_domain: str, active_domains: List[str]) -> Dict[str, Any]:
        """
        步骤3: 查询被动DNS数据
        融合解析记录进行多维特征分析
        
        Args:
            target_domain: 目标域名
            active_domains: 存活域名列表
            
        Returns:
            被动DNS查询结果
        """
        logger.info("步骤3: 查询被动DNS数据")
        
        if not PASSIVE_DNS_ENABLED or not self.passive_dns_collector:
            logger.warning("被动DNS模块不可用，跳过步骤3")
            return {
                'success': False,
                'error': '被动DNS模块不可用',
                'results': {}
            }
        
        try:
            results = {}
            total_records = 0
            
            # 查询目标域名的被动DNS历史
            logger.info(f"查询目标域名被动DNS: {target_domain}")
            target_pdns_result = self.passive_dns_collector.query_domain(target_domain)
            results[target_domain] = target_pdns_result
            total_records += target_pdns_result.get('total_records', 0)
            
            # 查询存活域名的被动DNS历史（限制数量）
            max_domains_to_query = int(os.getenv("PASSIVE_DNS_MAX_DOMAINS", "10"))
            domains_to_query = active_domains[:max_domains_to_query]
            
            for domain in domains_to_query:
                try:
                    logger.info(f"查询存活域名被动DNS: {domain}")
                    pdns_result = self.passive_dns_collector.query_domain(domain)
                    results[domain] = pdns_result
                    total_records += pdns_result.get('total_records', 0)
                    
                    # 获取解析历史
                    history_result = self.passive_dns_collector.get_domain_resolution_history(domain, lookback_days=30)
                    results[f"{domain}_history"] = history_result
                    
                except Exception as e:
                    logger.warning(f"查询域名 {domain} 的被动DNS时出错: {e}")
                    results[domain] = {'error': str(e)}
            
            # 保存结果到文件
            pdns_data = {
                'target_domain': target_domain,
                'timestamp': datetime.now().isoformat(),
                'total_domains_queried': len(results),
                'total_records': total_records,
                'results': results
            }
            
            with open(self.passive_dns_results_file, 'w', encoding='utf-8') as f:
                json.dump(pdns_data, f, ensure_ascii=False, indent=2)
            
            logger.info(f"被动DNS查询完成: 查询了 {len(results)} 个域名，共 {total_records} 条记录")
            
            return {
                'success': True,
                'results_file': str(self.passive_dns_results_file),
                'total_domains_queried': len(results),
                'total_records': total_records,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"步骤3被动DNS查询失败: {e}")
            return {
                'success': False,
                'error': str(e),
                'results': {}
            }
    
    def step4_query_certificate_transparency(self, target_domain: str, active_domains: List[str]) -> Dict[str, Any]:
        """
        步骤4: 查询证书透明度数据
        获取TLS证书信息进行风险分析
        
        Args:
            target_domain: 目标域名
            active_domains: 存活域名列表
            
        Returns:
            证书透明度查询结果
        """
        logger.info("步骤4: 查询证书透明度数据")
        
        if not CT_MONITOR_ENABLED or not self.ct_monitor:
            logger.warning("证书透明度模块不可用，跳过步骤4")
            return {
                'success': False,
                'error': '证书透明度模块不可用',
                'results': {}
            }
        
        try:
            results = {}
            total_certificates = 0
            
            # 查询目标域名的证书历史
            logger.info(f"查询目标域名证书透明度: {target_domain}")
            target_cert_result = self.ct_monitor.query_crtsh(target_domain)
            results[target_domain] = target_cert_result
            if target_cert_result.get('success'):
                total_certificates += target_cert_result.get('certificate_count', 0)
            
            # 查询存活域名的证书历史（限制数量）
            max_domains_to_query = int(os.getenv("CT_MAX_DOMAINS", "10"))
            domains_to_query = active_domains[:max_domains_to_query]
            
            for domain in domains_to_query:
                try:
                    logger.info(f"查询存活域名证书透明度: {domain}")
                    cert_result = self.ct_monitor.query_crtsh(domain)
                    results[domain] = cert_result
                    if cert_result.get('success'):
                        total_certificates += cert_result.get('certificate_count', 0)
                    
                    # 检测可疑证书
                    suspicious_result = self.ct_monitor.detect_suspicious_certificates(domain)
                    results[f"{domain}_suspicious"] = suspicious_result
                    
                except Exception as e:
                    logger.warning(f"查询域名 {domain} 的证书透明度时出错: {e}")
                    results[domain] = {'error': str(e)}
            
            # 保存结果到文件
            ct_data = {
                'target_domain': target_domain,
                'timestamp': datetime.now().isoformat(),
                'total_domains_queried': len(results),
                'total_certificates': total_certificates,
                'results': results
            }
            
            with open(self.certificate_transparency_results_file, 'w', encoding='utf-8') as f:
                json.dump(ct_data, f, ensure_ascii=False, indent=2)
            
            logger.info(f"证书透明度查询完成: 查询了 {len(results)} 个域名，共 {total_certificates} 个证书")
            
            return {
                'success': True,
                'results_file': str(self.certificate_transparency_results_file),
                'total_domains_queried': len(results),
                'total_certificates': total_certificates,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"步骤4证书透明度查询失败: {e}")
            return {
                'success': False,
                'error': str(e),
                'results': {}
            }

    def step4_5_run_active_probing(self, target_domain: str, active_domains: List[str]) -> Dict[str, Any]:
        """
        步骤4.5: 主动Web探测
        对目标域名和存活域名做页面探测，并将截图元数据入库 web_screenshots。
        """
        logger.info("步骤4.5: 运行主动Web探测")

        if not ACTIVE_PROBING_ENABLED or not self.active_probing_service:
            logger.warning("主动Web探测模块不可用，跳过步骤4.5")
            return {
                "success": False,
                "error": "主动Web探测模块不可用",
                "results": {},
            }

        try:
            max_domains_to_probe = max(1, int(os.getenv("ACTIVE_PROBING_MAX_DOMAINS", "10")))
            enable_screenshot = os.getenv("ACTIVE_PROBING_ENABLE_SCREENSHOT", "1").strip() not in ("0", "false", "False")
            reference_image = os.getenv("ACTIVE_PROBING_REFERENCE_IMAGE", "").strip() or None

            domains_to_probe = [target_domain] + [d for d in active_domains if d and d != target_domain]
            domains_to_probe = domains_to_probe[:max_domains_to_probe]

            probing_results: Dict[str, Any] = {}
            for domain in domains_to_probe:
                try:
                    probing_results[domain] = self.active_probing_service.probe_domain(
                        domain=domain,
                        reference_image=reference_image,
                        enable_screenshot=enable_screenshot,
                    )
                except Exception as probe_err:
                    probing_results[domain] = {
                        "success": False,
                        "domain": domain,
                        "error": str(probe_err),
                    }

            # 保存到数据库（仅保存有截图的记录）
            saved_count = 0
            if DATABASE_ENABLED and self.database_ready:
                try:
                    from modules.database.connection import DatabaseSession
                    from modules.database.dao import ScanDAO

                    with DatabaseSession() as session:
                        for domain, result in probing_results.items():
                            if not isinstance(result, dict) or not result.get("success"):
                                continue
                            screenshot_path = result.get("screenshot_path")
                            if not screenshot_path:
                                continue

                            similarity_data = result.get("visual_similarity")
                            ssim_score = None
                            if isinstance(similarity_data, dict):
                                ssim_score = similarity_data.get("similarity")

                            phash = None
                            try:
                                phash = perceptual_hash(screenshot_path)
                            except Exception:
                                phash = None

                            page_features = result.get("page_features", {}) if isinstance(result.get("page_features"), dict) else {}
                            ScanDAO.save_web_screenshot(
                                session,
                                {
                                    "domain": domain,
                                    "screenshot_path": screenshot_path,
                                    "perceptual_hash": phash,
                                    "ssim_score": ssim_score,
                                    "page_title": page_features.get("title"),
                                    "status_code": result.get("status_code"),
                                    "load_ms": result.get("response_ms"),
                                },
                            )
                            saved_count += 1
                        session.commit()
                except Exception as db_err:
                    logger.warning(f"主动探测结果写入web_screenshots失败: {db_err}")

            success_count = sum(1 for r in probing_results.values() if isinstance(r, dict) and r.get("success"))
            probing_data = {
                "target_domain": target_domain,
                "timestamp": datetime.now().isoformat(),
                "total_domains_probed": len(domains_to_probe),
                "success_count": success_count,
                "saved_to_db_count": saved_count,
                "results": probing_results,
            }

            with open(self.active_probing_results_file, "w", encoding="utf-8") as f:
                json.dump(probing_data, f, ensure_ascii=False, indent=2)

            logger.info(
                f"主动Web探测完成: probed={len(domains_to_probe)}, success={success_count}, saved={saved_count}"
            )
            return {
                "success": True,
                "results_file": str(self.active_probing_results_file),
                "total_domains_probed": len(domains_to_probe),
                "success_count": success_count,
                "saved_to_db_count": saved_count,
                "timestamp": datetime.now().isoformat(),
            }
        except Exception as e:
            logger.error(f"步骤4.5主动Web探测失败: {e}")
            return {
                "success": False,
                "error": str(e),
                "results": {},
            }
    
    def step5_risk_modeling(self, target_domain: str, stable_active_domains: List[str],
                          pdns_results: Dict[str, Any], ct_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        步骤5: 风险建模与告警决策
        基于多维特征进行风险建模
        
        Args:
            target_domain: 目标域名
            stable_active_domains: 稳定存活域名列表
            pdns_results: 被动DNS查询结果
            ct_results: 证书透明度查询结果
            
        Returns:
            风险建模结果
        """
        logger.info("步骤5: 风险建模与告警决策")
        
        try:
            # 收集所有特征数据
            risk_data = {
                'target_domain': target_domain,
                'timestamp': datetime.now().isoformat(),
                'stable_domain_count': len(stable_active_domains),
                'risk_analysis': {}
            }
            
            # 分析每个稳定存活域名的风险
            high_risk_domains = []
            medium_risk_domains = []
            low_risk_domains = []
            
            for domain in stable_active_domains[:50]:  # 限制分析数量
                domain_risk = {
                    'domain': domain,
                    'risk_score': 0,
                    'risk_factors': [],
                    'severity': 'low'
                }
                
                # 风险因子1: 域名相似度
                similarity_score = self._calculate_domain_similarity(target_domain, domain)
                if similarity_score > 0.8:
                    domain_risk['risk_score'] += 30
                    domain_risk['risk_factors'].append(f"域名相似度高: {similarity_score:.2f}")
                
                # 风险因子2: 被动DNS记录分析
                if pdns_results.get('success') and domain in pdns_results.get('results', {}):
                    pdns_data = pdns_results['results'][domain]
                    record_count = pdns_data.get('total_records', 0)
                    if record_count > 10:
                        domain_risk['risk_score'] += 20
                        domain_risk['risk_factors'].append(f"被动DNS记录多: {record_count}条")
                    
                    # 检查是否有历史恶意解析记录
                    if 'malware' in str(pdns_data).lower() or 'phishing' in str(pdns_data).lower():
                        domain_risk['risk_score'] += 40
                        domain_risk['risk_factors'].append("历史恶意解析记录")
                
                # 风险因子3: 证书透明度分析
                if ct_results.get('success') and domain in ct_results.get('results', {}):
                    ct_data = ct_results['results'][domain]
                    if ct_data.get('success'):
                        cert_count = ct_data.get('certificate_count', 0)
                        if cert_count == 0:
                            domain_risk['risk_score'] += 10
                            domain_risk['risk_factors'].append("无有效SSL证书")
                        
                        # 检查可疑证书
                        suspicious_key = f"{domain}_suspicious"
                        if suspicious_key in ct_results.get('results', {}):
                            suspicious_data = ct_results['results'][suspicious_key]
                            if suspicious_data.get('suspicious_certificates', 0) > 0:
                                domain_risk['risk_score'] += 30
                                domain_risk['risk_factors'].append("存在可疑证书")
                
                # 风险因子4: 注册时间分析（简化为域名长度）
                domain_length = len(domain)
                if domain_length < 10:
                    domain_risk['risk_score'] += 15
                    domain_risk['risk_factors'].append(f"域名过短: {domain_length}字符")
                
                # 风险因子5: 常见仿冒模式
                if self._is_suspicious_pattern(target_domain, domain):
                    domain_risk['risk_score'] += 25
                    domain_risk['risk_factors'].append("符合仿冒域名模式")
                
                # 确定风险等级
                if domain_risk['risk_score'] >= 70:
                    domain_risk['severity'] = 'high'
                    high_risk_domains.append(domain_risk)
                elif domain_risk['risk_score'] >= 40:
                    domain_risk['severity'] = 'medium'
                    medium_risk_domains.append(domain_risk)
                else:
                    low_risk_domains.append(domain_risk)
                
                risk_data['risk_analysis'][domain] = domain_risk
            
            # 统计信息
            risk_data['summary'] = {
                'total_domains_analyzed': len(risk_data['risk_analysis']),
                'high_risk_count': len(high_risk_domains),
                'medium_risk_count': len(medium_risk_domains),
                'low_risk_count': len(low_risk_domains),
                'high_risk_domains': [d['domain'] for d in high_risk_domains],
                'medium_risk_domains': [d['domain'] for d in medium_risk_domains]
            }
            
            # 告警规则
            alerts = []
            if len(high_risk_domains) > 0:
                alerts.append({
                    'severity': 'critical',
                    'message': f"发现 {len(high_risk_domains)} 个高风险仿冒域名",
                    'domains': [d['domain'] for d in high_risk_domains]
                })
            
            if len(medium_risk_domains) > 5:
                alerts.append({
                    'severity': 'warning',
                    'message': f"发现 {len(medium_risk_domains)} 个中风险域名，建议进一步调查",
                    'domains': [d['domain'] for d in medium_risk_domains[:5]]  # 只显示前5个
                })
            
            risk_data['alerts'] = alerts
            
            # 保存结果到文件
            with open(self.risk_modeling_results_file, 'w', encoding='utf-8') as f:
                json.dump(risk_data, f, ensure_ascii=False, indent=2)
            
            logger.info(f"风险建模完成: 分析了 {len(risk_data['risk_analysis'])} 个域名，"
                       f"高风险: {len(high_risk_domains)}, 中风险: {len(medium_risk_domains)}")
            
            return {
                'success': True,
                'results_file': str(self.risk_modeling_results_file),
                'summary': risk_data['summary'],
                'risk_analysis': risk_data.get('risk_analysis', {}),
                'alert_count': len(alerts),
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"步骤5风险建模失败: {e}")
            return {
                'success': False,
                'error': str(e),
                'results': {}
            }
    
    def _calculate_domain_similarity(self, domain1: str, domain2: str) -> float:
        """计算两个域名的相似度（简化版）"""
        # 移除协议和路径
        domain1_clean = domain1.replace('http://', '').replace('https://', '').split('/')[0]
        domain2_clean = domain2.replace('http://', '').replace('https://', '').split('/')[0]
        
        # 简单的编辑距离相似度
        from difflib import SequenceMatcher
        return SequenceMatcher(None, domain1_clean, domain2_clean).ratio()
    
    def _is_suspicious_pattern(self, target_domain: str, candidate_domain: str) -> bool:
        """检查域名是否符合常见仿冒模式"""
        target_parts = target_domain.split('.')
        candidate_parts = candidate_domain.split('.')
        
        if len(target_parts) < 2 or len(candidate_parts) < 2:
            return False
        
        target_base = '.'.join(target_parts[-2:])  # 获取二级域名
        candidate_base = '.'.join(candidate_parts[-2:])
        
        # 检查是否与目标域名使用相同的顶级域名
        if target_base != candidate_base:
            return False
        
        # 常见仿冒模式
        suspicious_patterns = [
            'login-', 'secure-', 'verify-', 'auth-', 'account-',
            'admin-', 'support-', 'service-', 'update-', 'security-'
        ]
        
        candidate_name = candidate_parts[0].lower()
        
        # 检查是否包含仿冒前缀
        for pattern in suspicious_patterns:
            if candidate_name.startswith(pattern):
                return True
        
        # 检查是否包含目标域名的一部分
        target_name = target_parts[0].lower()
        if target_name in candidate_name and candidate_name != target_name:
            return True
        
        # 检查常见拼写错误模式
        common_typos = {
            'o': '0', 'l': '1', 'i': '1', 'e': '3', 'a': '4',
            's': '5', 'g': '6', 't': '7', 'b': '8', 'g': '9'
        }
        
        # 简化的拼写错误检查
        for correct, wrong in common_typos.items():
            if correct in target_name and wrong in candidate_name:
                return True
        
        return False
    
    def step6_generate_visualization_data(self, target_domain: str, 
                                        stable_active_domains: List[str],
                                        pdns_results: Dict[str, Any],
                                        ct_results: Dict[str, Any],
                                        risk_results: Dict[str, Any],
                                        active_probing_results: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        步骤6: 生成可视化数据
        为平台化呈现准备数据
        
        Args:
            target_domain: 目标域名
            stable_active_domains: 稳定存活域名列表
            pdns_results: 被动DNS查询结果
            ct_results: 证书透明度查询结果
            risk_results: 风险建模结果
            
        Returns:
            可视化数据
        """
        logger.info("步骤6: 生成可视化数据")
        
        try:
            # 准备可视化数据结构
            viz_data = {
                'target_domain': target_domain,
                'timestamp': datetime.now().isoformat(),
                'overview': {
                    'total_candidate_domains': len(stable_active_domains),
                    'high_risk_count': risk_results.get('summary', {}).get('high_risk_count', 0),
                    'medium_risk_count': risk_results.get('summary', {}).get('medium_risk_count', 0),
                    'low_risk_count': risk_results.get('summary', {}).get('low_risk_count', 0),
                    'alert_count': risk_results.get('alert_count', 0)
                },
                'timeline_data': {
                    'detection_timeline': [
                        {
                            'time': datetime.now().isoformat(),
                            'event': '域名变体生成',
                            'count': len(stable_active_domains)
                        }
                    ]
                },
                'geographic_data': {
                    # 可以添加IP地理位置数据
                    'locations': []
                },
                'network_graph': {
                    'nodes': [],
                    'edges': []
                },
                'risk_distribution': risk_results.get('summary', {}),
                'alerts': risk_results.get('alerts', []),
                'data_sources': {
                    'passive_dns_available': pdns_results.get('success', False),
                    'certificate_transparency_available': ct_results.get('success', False),
                    'active_probing_available': (active_probing_results or {}).get('success', False),
                    'risk_modeling_available': risk_results.get('success', False)
                }
            }
            
            # 添加节点数据（域名）
            viz_data['network_graph']['nodes'].append({
                'id': target_domain,
                'label': target_domain,
                'type': 'target',
                'size': 20,
                'color': '#ff0000'
            })
            
            # 添加高风险域名节点
            high_risk_domains = risk_results.get('summary', {}).get('high_risk_domains', [])
            for i, domain in enumerate(high_risk_domains[:10]):  # 限制数量
                viz_data['network_graph']['nodes'].append({
                    'id': domain,
                    'label': domain,
                    'type': 'high_risk',
                    'size': 15,
                    'color': '#ff6b6b'
                })
                viz_data['network_graph']['edges'].append({
                    'source': target_domain,
                    'target': domain,
                    'type': 'suspicious',
                    'weight': 1.0
                })
            
            # 添加中风险域名节点
            medium_risk_domains = risk_results.get('summary', {}).get('medium_risk_domains', [])
            for i, domain in enumerate(medium_risk_domains[:10]):
                viz_data['network_graph']['nodes'].append({
                    'id': domain,
                    'label': domain,
                    'type': 'medium_risk',
                    'size': 10,
                    'color': '#ffd166'
                })
                viz_data['network_graph']['edges'].append({
                    'source': target_domain,
                    'target': domain,
                    'type': 'related',
                    'weight': 0.5
                })
            
            # 保存数据到文件
            with open(self.visualization_data_file, 'w', encoding='utf-8') as f:
                json.dump(viz_data, f, ensure_ascii=False, indent=2)
            
            logger.info(f"可视化数据生成完成: 包含 {len(viz_data['network_graph']['nodes'])} 个节点，"
                       f"{len(viz_data['network_graph']['edges'])} 条边")
            
            return {
                'success': True,
                'results_file': str(self.visualization_data_file),
                'node_count': len(viz_data['network_graph']['nodes']),
                'edge_count': len(viz_data['network_graph']['edges']),
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"步骤6可视化数据生成失败: {e}")
            return {
                'success': False,
                'error': str(e),
                'results': {}
            }
    
    def step6_save_stable_active_to_db(
        self,
        target_domain: str,
        stable_active_domains: List[str],
        executed_rounds: int,
        converged_round: Optional[int],
        min_hits: int,
        candidate_limit: int,
        candidate_source_file: str,
        candidate_domain_count: int,
        first_round_active_count: int,
        round_active_counts: List[int],
        risk_results: Optional[Dict[str, Any]] = None,
        convergence_reason: str = "",
    ) -> bool:
        """
        步骤6（简化版）:
        仅将 xdig 稳定存活域名写入数据库，不依赖 HTTP/WHOIS/威胁情报。
        """
        try:
            dedup_domains = sorted(set(d.strip().lower() for d in stable_active_domains if d and d.strip()))
            summary = {
                "saved": 0,
                "whois_queried": 0,
                "whois_success": 0,
                "whois_failed": 0,
                "risk_assessment_saved": 0,
            }
            whois_by_domain: Dict[str, Dict[str, Any]] = {}
            risk_by_domain: Dict[str, Dict[str, Any]] = {}

            risk_analysis_map = (risk_results or {}).get("risk_analysis", {})
            if isinstance(risk_analysis_map, dict):
                for domain_text, domain_risk in risk_analysis_map.items():
                    if not isinstance(domain_risk, dict):
                        continue
                    d = (domain_text or "").strip().lower()
                    if not d:
                        continue
                    score = float(domain_risk.get("risk_score", 0.0) or 0.0)
                    severity = (domain_risk.get("severity") or "unknown").strip().lower()
                    if severity not in {"critical", "high", "medium", "low"}:
                        severity = "unknown"
                    risk_by_domain[d] = {
                        "visual_similarity_score": 0.0,
                        "whois_risk_score": 0.0,
                        "http_risk_score": 0.0,
                        "threat_risk_score": 0.0,
                        "dns_risk_score": 5.0,
                        "weighted_total_score": round(max(0.0, min(100.0, score)), 2),
                        "risk_level": severity,
                        "risk_factors": domain_risk.get("risk_factors", []),
                        "confidence": 0.7,
                    }

            # 强制首轮进行WHOIS查询并准备入库，确保分析页注册时间/注册商图表可用
            whois_enabled = os.getenv("INITIAL_SCAN_FORCE_WHOIS", "1").strip().lower() not in ("0", "false", "no")
            if whois_enabled and WHOIS_ENRICH_ENABLED and dedup_domains:
                whois_workers = max(1, int(os.getenv("INITIAL_SCAN_WHOIS_WORKERS", "5")))
                whois_delay = max(0.0, float(os.getenv("INITIAL_SCAN_WHOIS_DELAY", "1.0")))
                whois_max_domains = max(0, int(os.getenv("INITIAL_SCAN_WHOIS_MAX_DOMAINS", "0")))
                whois_domains = dedup_domains[:whois_max_domains] if whois_max_domains > 0 else dedup_domains

                logger.info(
                    f"步骤6: 首轮WHOIS强制查询，domains={len(whois_domains)}, "
                    f"workers={whois_workers}, delay={whois_delay}s"
                )
                summary["whois_queried"] = len(whois_domains)

                try:
                    whois_results = batch_query_whois_structured(
                        whois_domains,
                        max_workers=whois_workers,
                        delay=whois_delay,
                    )
                    for item in whois_results:
                        if not isinstance(item, dict):
                            continue
                        d = (item.get("domain") or "").strip().lower()
                        if not d:
                            continue
                        if item.get("status") == "success":
                            try:
                                normalized = create_whois_result_from_enhanced(item).to_dict()
                                whois_by_domain[d] = normalized
                                summary["whois_success"] += 1
                            except Exception as convert_err:
                                logger.warning(f"WHOIS结果规范化失败 {d}: {convert_err}")
                                summary["whois_failed"] += 1
                        else:
                            summary["whois_failed"] += 1
                except Exception as whois_err:
                    logger.warning(f"步骤6 WHOIS批量查询失败: {whois_err}")
            elif whois_enabled and not WHOIS_ENRICH_ENABLED:
                logger.warning("首轮WHOIS强制入库已开启，但WHOIS模块不可用")

            if not DATABASE_ENABLED or not self.database_ready:
                logger.warning("数据库不可用，跳过稳定存活域名入库")
            else:
                data_manager = get_data_manager()
                for domain in dedup_domains:
                    try:
                        monitoring_data = {
                            "visual_similarity": 0.0,
                            "generation_method": "xdig_stable_probe",
                            "dns_result": {
                                "has_dns_record": True,
                                "resolved_ips": [],
                                "response_time_ms": 0.0,
                                "dns_server": "xdig_stable",
                            },
                        }
                        whois_result = whois_by_domain.get(domain)
                        if whois_result:
                            monitoring_data["whois_result"] = whois_result

                        risk_assessment = risk_by_domain.get(domain)
                        if not risk_assessment:
                            whois_score = float((whois_result or {}).get("whois_risk_score", 0.0) or 0.0)
                            fallback_score = max(0.0, min(100.0, 5.0 + whois_score))
                            if fallback_score >= 70:
                                fallback_level = "critical"
                            elif fallback_score >= 50:
                                fallback_level = "high"
                            elif fallback_score >= 25:
                                fallback_level = "medium"
                            elif fallback_score > 0:
                                fallback_level = "low"
                            else:
                                fallback_level = "unknown"
                            fallback_factors = ["dns_active"]
                            if whois_score > 0:
                                fallback_factors.append("whois_signal")
                            risk_assessment = {
                                "visual_similarity_score": 0.0,
                                "whois_risk_score": whois_score,
                                "http_risk_score": 0.0,
                                "threat_risk_score": 0.0,
                                "dns_risk_score": 5.0,
                                "weighted_total_score": round(fallback_score, 2),
                                "risk_level": fallback_level,
                                "risk_factors": fallback_factors,
                                "confidence": 0.5 if whois_score > 0 else 0.35,
                            }
                        monitoring_data["risk_assessment"] = risk_assessment
                        data_manager.save_complete_monitoring_result(
                            domain=domain,
                            original_target=target_domain,
                            monitoring_data=monitoring_data,
                        )
                        summary["saved"] += 1
                        summary["risk_assessment_saved"] += 1
                    except Exception as db_error:
                        logger.warning(f"稳定域名入库失败 {domain}: {db_error}")

            # 输出简化报告，便于前端/排障复用
            report = {
                "target_domain": target_domain,
                "mode": "xdig_stable_only",
                "rounds": executed_rounds,
                "executed_rounds": executed_rounds,
                "converged_round": converged_round,
                "min_hits": min_hits,
                "candidate_limit": candidate_limit,
                "candidate_source_file": candidate_source_file,
                "candidate_domain_count": candidate_domain_count,
                "first_round_active_count": first_round_active_count,
                "round_active_counts": round_active_counts,
                "convergence_reason": convergence_reason,
                "stable_active_count": len(stable_active_domains),
                "saved_count": summary["saved"],
                "whois_queried_count": summary["whois_queried"],
                "whois_success_count": summary["whois_success"],
                "whois_failed_count": summary["whois_failed"],
                "risk_assessment_saved_count": summary["risk_assessment_saved"],
                "stable_active_domains": sorted(set(stable_active_domains)),
                "timestamp": datetime.now().isoformat(),
            }
            with open(self.final_results_file, "w", encoding="utf-8") as f:
                json.dump(report, f, ensure_ascii=False, indent=2)

            logger.info(
                f"稳定存活域名入库完成: target={target_domain}, stable={len(stable_active_domains)}, saved={summary['saved']}"
            )
            return True
        except Exception as e:
            logger.error(f"稳定存活域名入库阶段失败: {e}")
            return False

    def step7_run_multidimensional_analysis(
        self,
        target_domain: str,
        stable_active_domains: List[str],
    ) -> bool:
        """
        步骤7:
        融合DNS/HTTP/WHOIS/威胁情报做多维特征建模，并生成告警结果。
        """
        enabled = os.getenv("MULTI_DIM_ANALYSIS_ENABLED", "1").strip() not in ("0", "false", "False")
        if not enabled:
            logger.info("MULTI_DIM_ANALYSIS_ENABLED=0，跳过多维分析")
            return True

        if not MULTIDIM_ENGINE_ENABLED:
            logger.warning("多维风险引擎不可用，跳过步骤7")
            return True

        domains = sorted(set(d.strip().lower() for d in stable_active_domains if d and d.strip()))
        if not domains:
            logger.info("稳定存活域名为空，跳过步骤7")
            return True

        try:
            max_domains = max(1, int(os.getenv("MULTI_DIM_MAX_DOMAINS", "50")))
            dns_timeout = max(1.0, float(os.getenv("MULTI_DIM_DNS_TIMEOUT", "3.0")))
            http_timeout = max(3, int(os.getenv("MULTI_DIM_HTTP_TIMEOUT", "10")))
            threat_workers = max(1, int(os.getenv("MULTI_DIM_THREAT_WORKERS", "3")))
            threat_delay = max(0.1, float(os.getenv("MULTI_DIM_THREAT_DELAY", "1.0")))

            cfg = MultiDimRunConfig(
                max_domains=max_domains,
                dns_timeout=dns_timeout,
                http_timeout=http_timeout,
                threat_workers=threat_workers,
                threat_delay_seconds=threat_delay,
            )
            result = run_multidimensional_analysis(
                target_domain=target_domain,
                domains=domains,
                output_dir=str(self.results_dir),
                config=cfg,
            )
            summary = result.get("summary", {})
            logger.info(
                "步骤7完成: analyzed=%s, alerts=%s",
                summary.get("analyzed_domain_count", 0),
                summary.get("risk_distribution", {}).get("critical", 0)
                + summary.get("risk_distribution", {}).get("high", 0),
            )
            self._append_multidim_summary_to_report(
                multidim_summary=summary,
                analysis_file=result.get("analysis_file", ""),
                alerts_file=result.get("alerts_file", ""),
            )
            return True
        except Exception as e:
            logger.error(f"步骤7多维分析失败: {e}")
            return False

    def _append_multidim_summary_to_report(
        self,
        multidim_summary: dict,
        analysis_file: str,
        alerts_file: str,
    ) -> None:
        """
        将多维分析摘要补充到综合报告，便于前端统一读取。
        """
        try:
            report = {}
            if self.final_results_file.exists():
                with open(self.final_results_file, "r", encoding="utf-8") as f:
                    loaded = json.load(f)
                    if isinstance(loaded, dict):
                        report = loaded
            report["multidimensional_analysis"] = {
                "summary": multidim_summary,
                "analysis_file": analysis_file,
                "alerts_file": alerts_file,
                "latest_analysis_file": str(self.multidim_latest_file),
                "latest_alerts_file": str(self.alerts_latest_file),
                "updated_at": datetime.now().isoformat(),
            }
            with open(self.final_results_file, "w", encoding="utf-8") as f:
                json.dump(report, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.warning(f"回写多维分析摘要失败: {e}")

    def run_full_pipeline(self, target_domain: str) -> bool:
        """
        运行完整的监控管道
        """
        try:
            target_domain = normalize_domain_input(target_domain)
        except DomainInputError as e:
            logger.error(f"目标域名输入无效: {e}")
            return False

        logger.info(f"开始运行域名监控管道 - 目标域名: {target_domain}")
        logger.info("运行模式: xdig 多轮计数判活（仅 DNS 存在性）")
        
        start_time = time.time()
        
        try:
            # 步骤1: 生成域名变体
            if not self.step1_generate_domain_variants(target_domain):
                logger.error("步骤1失败，停止管道执行")
                return False

            # 步骤2（多轮统计版）: 每轮都扫描同一候选集合，按命中次数判定稳定存活
            max_rounds = max(2, int(os.getenv("XDIG_STABLE_MAX_ROUNDS", "3")))
            min_hits = max(1, int(os.getenv("XDIG_STABLE_MIN_HITS", "2")))
            if min_hits > max_rounds:
                min_hits = max_rounds
            abs_delta_threshold = max(0, int(os.getenv("XDIG_STABLE_ABS_DELTA", "2")))
            rel_delta_threshold = max(0.0, float(os.getenv("XDIG_STABLE_REL_DELTA", "0.02")))
            scan_rate = max(10, int(os.getenv("XDIG_RATE", "100")))

            previous_active_count = None
            first_round_active_domains: List[str] = []
            round_active_counts: List[int] = []
            hit_counter: dict[str, int] = {}
            stable_active_domains: List[str] = []
            convergence_reason = "达到最大轮次，采用最后一轮结果"
            rounds_used = 0
            converged_round: Optional[int] = None
            candidate_limit = max(0, int(os.getenv("XDIG_CANDIDATE_LIMIT", "0")))
            scan_domain_file = self.domain_variants_file
            if candidate_limit > 0 and self.domain_variants_file.exists():
                limited_file = self.results_dir / f"{target_domain}_candidates_limit_{candidate_limit}.txt"
                kept = 0
                with open(self.domain_variants_file, "r", encoding="utf-8", errors="ignore") as src, \
                        open(limited_file, "w", encoding="utf-8") as dst:
                    for line in src:
                        line = line.strip()
                        if not line:
                            continue
                        dst.write(line + "\n")
                        kept += 1
                        if kept >= candidate_limit:
                            break
                scan_domain_file = limited_file
                logger.info(f"已启用候选域名限制: limit={candidate_limit}, 文件={scan_domain_file}")

            candidate_domain_count = 0
            if scan_domain_file.exists():
                with open(scan_domain_file, "r", encoding="utf-8", errors="ignore") as f:
                    candidate_domain_count = sum(1 for line in f if line.strip())
            logger.info(f"候选域名总数: {candidate_domain_count}, 来源文件: {scan_domain_file}")

            for round_idx in range(1, max_rounds + 1):
                rounds_used = round_idx
                logger.info(
                    f"xdig 多轮探测: 第 {round_idx}/{max_rounds} 轮, 输入文件={scan_domain_file}"
                )

                if not self.step2_run_xdig_scan(
                    target_domain=target_domain,
                    domainfile=str(scan_domain_file),
                    rate=scan_rate,
                ):
                    logger.error(f"第 {round_idx} 轮 xdig 探测失败")
                    return False

                active_domains = sorted(
                    set(d.strip().lower() for d in self.extract_active_domains_from_xdig() if d and d.strip())
                )
                active_count = len(active_domains)
                round_active_counts.append(active_count)
                logger.info(f"第 {round_idx} 轮存活数量: {active_count}")

                if round_idx == 1:
                    first_round_active_domains = active_domains

                for d in active_domains:
                    hit_counter[d] = hit_counter.get(d, 0) + 1

                if previous_active_count is not None:
                    abs_delta = abs(active_count - previous_active_count)
                    rel_delta = (abs_delta / previous_active_count) if previous_active_count > 0 else 0.0
                    logger.info(
                        f"第 {round_idx} 轮与上一轮变化: abs={abs_delta}, rel={rel_delta:.4f}, "
                        f"阈值(abs<={abs_delta_threshold} 或 rel<={rel_delta_threshold:.4f})"
                    )
                    if abs_delta <= abs_delta_threshold or rel_delta <= rel_delta_threshold:
                        convergence_reason = (
                            f"第{round_idx}轮收敛: 相邻轮次变化满足阈值(abs={abs_delta}, rel={rel_delta:.4f})"
                        )
                        logger.info(convergence_reason)
                        converged_round = round_idx
                        previous_active_count = active_count
                        break

                if active_count == 0:
                    convergence_reason = f"第{round_idx}轮存活数量为0，提前停止"
                    logger.warning(convergence_reason)
                    converged_round = round_idx
                    previous_active_count = active_count
                    break
                previous_active_count = active_count

            stable_active_domains = sorted([d for d, cnt in hit_counter.items() if cnt >= min_hits])
            first_round_active_count = len(first_round_active_domains)
            logger.info(
                f"稳定口径: rounds={rounds_used}, min_hits={min_hits}, "
                f"first_round_active={first_round_active_count}, stable_active={len(stable_active_domains)}"
            )

            # 步骤3: 查询被动DNS数据
            logger.info("步骤3: 查询被动DNS数据")
            pdns_results = self.step3_query_passive_dns(target_domain, stable_active_domains)
            if not pdns_results.get('success'):
                logger.warning(f"被动DNS查询部分失败: {pdns_results.get('error')}")
            
            # 步骤4: 查询证书透明度数据
            logger.info("步骤4: 查询证书透明度数据")
            ct_results = self.step4_query_certificate_transparency(target_domain, stable_active_domains)
            if not ct_results.get('success'):
                logger.warning(f"证书透明度查询部分失败: {ct_results.get('error')}")

            # 步骤4.5: 主动Web探测
            logger.info("步骤4.5: 主动Web探测")
            active_probing_results = self.step4_5_run_active_probing(target_domain, stable_active_domains)
            if not active_probing_results.get("success"):
                logger.warning(f"主动Web探测部分失败: {active_probing_results.get('error')}")
            
            # 步骤5: 风险建模与告警决策
            logger.info("步骤5: 风险建模与告警决策")
            risk_results = self.step5_risk_modeling(
                target_domain=target_domain,
                stable_active_domains=stable_active_domains,
                pdns_results=pdns_results,
                ct_results=ct_results
            )
            if not risk_results.get('success'):
                logger.warning(f"风险建模部分失败: {risk_results.get('error')}")
            
            # 步骤6: 生成可视化数据
            logger.info("步骤6: 生成可视化数据")
            viz_results = self.step6_generate_visualization_data(
                target_domain=target_domain,
                stable_active_domains=stable_active_domains,
                pdns_results=pdns_results,
                ct_results=ct_results,
                risk_results=risk_results,
                active_probing_results=active_probing_results
            )
            if not viz_results.get('success'):
                logger.warning(f"可视化数据生成部分失败: {viz_results.get('error')}")

            # 步骤7: 保存稳定存活集合到数据库
            if not self.step6_save_stable_active_to_db(
                target_domain=target_domain,
                stable_active_domains=stable_active_domains,
                executed_rounds=rounds_used,
                converged_round=converged_round,
                min_hits=min_hits,
                candidate_limit=candidate_limit,
                candidate_source_file=str(scan_domain_file),
                candidate_domain_count=candidate_domain_count,
                first_round_active_count=first_round_active_count,
                round_active_counts=round_active_counts,
                risk_results=risk_results,
                convergence_reason=convergence_reason,
            ):
                logger.error("步骤7失败")
                return False

            # 步骤8: 多维融合风险建模和告警
            if not self.step7_run_multidimensional_analysis(
                target_domain=target_domain,
                stable_active_domains=stable_active_domains,
            ):
                logger.warning("步骤8失败（不影响xdig稳定判活结果）")
            
            elapsed_time = time.time() - start_time
            logger.info(f"管道执行完成，总耗时: {elapsed_time:.2f} 秒")
            
            # 输出结果文件路径
            logger.info(f"结果文件:")
            logger.info(f"  - xdig结果: {self.xdig_results_file}")
            logger.info(f"  - 主动探测结果: {self.active_probing_results_file}")
            logger.info(f"  - 稳定存活报告: {self.final_results_file}")
            
            return True
            
        except Exception as e:
            logger.error(f"管道执行过程中出错: {e}")
            return False

def main():
    """
    命令行入口点
    """
    import argparse
    
    parser = argparse.ArgumentParser(description='域名监控数据处理管道')
    parser.add_argument('-d', '--domain', required=True, help='目标域名（例如: example.com）')
    parser.add_argument('-b', '--base-dir', default='.', help='项目基础目录（默认当前目录）')
    parser.add_argument('-v', '--verbose', action='store_true', help='详细输出')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # 创建并运行管道
    pipeline = DomainMonitoringPipeline(args.base_dir)
    success = pipeline.run_full_pipeline(args.domain)
    
    if success:
        print(f"\n✅ 监控管道执行成功!")
        print(f"   结果文件保存在: {pipeline.results_dir}")
        
        # 检查稳定存活报告
        if pipeline.final_results_file.exists():
            try:
                with open(pipeline.final_results_file, "r", encoding="utf-8") as f:
                    data = json.load(f)

                if isinstance(data, dict):
                    print(f"   执行轮次: {data.get('executed_rounds', data.get('rounds', 0))}")
                    print(f"   收敛轮次: {data.get('converged_round', '未提前收敛')}")
                    print(f"   候选域名总数: {data.get('candidate_domain_count', 0)}")
                    print(f"   候选限制: {data.get('candidate_limit', 0)}")
                    print(f"   稳定存活域名: {data.get('stable_active_count', 0)}")
                    print(f"   已写入数据库: {data.get('saved_count', 0)}")
                    print(f"   收敛原因: {data.get('convergence_reason', '')}")
                    multidim = data.get("multidimensional_analysis", {}).get("summary", {})
                    if isinstance(multidim, dict) and multidim:
                        print(f"   多维分析域名数: {multidim.get('analyzed_domain_count', 0)}")
                        print(f"   多维风险分布: {multidim.get('risk_distribution', {})}")
            except Exception:
                pass
    else:
        print(f"\n❌ 监控管道执行失败!")
        sys.exit(1)

if __name__ == "__main__":
    main()
  
