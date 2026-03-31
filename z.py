'''
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
import re
from typing import List, Optional, Dict, Any, Set
from datetime import datetime
from pathlib import Path
import ipaddress
import whois
import requests
import tldextract
from ipwhois import IPWhois
from bs4 import BeautifulSoup
import ssl
import socket
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# 添加模块路径
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.domain_input import DomainInputError, normalize_domain_input

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class PhishingDetectTool:
    """钓鱼域名检测工具类，实现报告中所有核心检测逻辑：
    1. Whois信息分析 2. IP归属/反向解析 3. SSL证书校验 4. 内容欺诈检测
    5. 关联域名分析 6. 官方白名单比对 7. 欺诈特征判定（拼写错误/虚假信息等）
    """
    def __init__(self, official_whitelist: Dict[str, Any]):
        """
        初始化官方白名单（核心，用于比对判定）
        :param official_whitelist: 官方域名/IP/NS/SSL等白名单配置，示例：
            {
                "domain": ["coscoshipping.com", "coscoshipping.cn"],  # 官方主域名
                "ns": ["vip3.alidns.com", "vip4.alidns.com"],        # 官方NS服务器
                "ip_country": ["CN"],                                # 官方IP所属国家
                "ssl_issuer": ["DigiCert", "Thawte"],                # 官方SSL颁发机构
                "brand": "COSCO SHIPPING"                            # 目标品牌名
            }
        """
        self.official = official_whitelist
        self.brand = self.official.get("brand", "")
        # 欺诈特征正则（报告中典型特征：拼写错误/不完整信息）
        self.re_bad_spell = re.compile(r"Uinited|Amercia|Recevied|Shiping", re.IGNORECASE)
        self.re_invalid_phone = re.compile(r"\+\d+-\d+-\s*\d{1,5}$")  # 位数不全的电话
        self.re_invalid_email = re.compile(r"@\w+(\.\w+)+")

    def get_whois_info(self, domain: str) -> Dict[str, Any]:
        """获取域名Whois信息（对齐报告3.1/3.2）"""
        try:
            w = whois.whois(domain)
            return {
                "domain": domain,
                "create_date": str(w.get("creation_date", "未知")),
                "expire_date": str(w.get("expiration_date", "未知")),
                "registrar": w.get("registrar", "未知"),
                "registrant": w.get("registrant_name", "隐藏（隐私保护）"),
                "status": w.get("status", "未知"),
                "is_hidden": True if "隐私保护" in str(w.get("registrant_name", "")) else False
            }
        except Exception as e:
            logger.warning(f"获取{domain} Whois失败: {e}")
            return {"domain": domain, "error": str(e)}

    def get_ip_info(self, domain: str) -> Dict[str, Any]:
        """获取域名IP+IP归属/反向解析（对齐报告2.1/2.3/5.2）"""
        try:
            ip = socket.gethostbyname(domain)
            # IP反向解析
            try:
                reverse_dns = socket.gethostbyaddr(ip)[0]
            except:
                reverse_dns = "未知"
            # IP归属地
            try:
                ip_whois = IPWhois(ip)
                ip_info = ip_whois.lookup_rdap()
                country = ip_info.get("asn_country_code", "未知")
                org = ip_info.get("asn_description", "未知")
            except:
                country = "未知"
                org = "未知"
            # NS服务器
            try:
                ns = socket.gethostbyname_ex(domain)[-1]
            except:
                ns = ["未知"]
            return {
                "domain": domain,
                "ip": ip,
                "reverse_dns": reverse_dns,
                "ip_country": country,
                "ip_org": org,
                "ns_server": ns,
                # 判定：是否非官方国家/廉价NS
                "is_foreign_ip": country not in self.official.get("ip_country", []),
                "is_cheap_ns": not any(ns in self.official.get("ns", []) for ns in ns)
            }
        except Exception as e:
            logger.warning(f"获取{domain} IP信息失败: {e}")
            return {"domain": domain, "error": str(e)}

    def get_ssl_cert(self, domain: str) -> Dict[str, Any]:
        """获取SSL证书信息并校验（对齐报告4.3/SSL对比）"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert_data = ssock.getpeercert()
                    # 解析证书颁发机构/有效期/主体
                    issuer = dict(x[0] for x in cert_data.get("issuer", []))
                    subject = dict(x[0] for x in cert_data.get("subject", []))
                    return {
                        "domain": domain,
                        "has_ssl": True,
                        "ssl_issuer": issuer.get("organizationName", "未知"),
                        "ssl_cn": subject.get("commonName", "未知"),
                        "ssl_start": cert_data.get("notBefore", "未知"),
                        "ssl_end": cert_data.get("notAfter", "未知"),
                        "is_free_ssl": True if "Let's Encrypt" in issuer.get("organizationName", "") else False,
                        "is_official_ssl": any(iss in issuer.get("organizationName", "") for iss in self.official.get("ssl_issuer", []))
                    }
        except Exception as e:
            logger.warning(f"获取{domain} SSL证书失败: {e}")
            return {"domain": domain, "has_ssl": False, "error": str(e)}

    def get_web_content(self, domain: str) -> Dict[str, Any]:
        """获取网页内容并检测欺诈特征（对齐报告4.1/4.2）"""
        try:
            urls = [f"https://{domain}", f"http://{domain}"]
            html = ""
            status_code = 0
            for url in urls:
                resp = requests.get(
                    url, timeout=5, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
                )
                if resp.status_code == 200:
                    html = resp.text[:20000]  # 限制长度
                    status_code = resp.status_code
                    break
            soup = BeautifulSoup(html, "html.parser")
            # 提取关键信息：联系地址/电话/邮箱/品牌名/业务描述
            contact_text = soup.get_text(strip=True)
            email = re.search(self.re_invalid_email, contact_text)
            phone = re.search(self.re_invalid_phone, contact_text)
            address = soup.find(text=re.compile(r"\d+.*Way|St|Ave.*\d{5}"))  # 匹配欧美地址
            brand_in_page = self.brand in contact_text
            # 欺诈特征检测
            bad_spell = bool(self.re_bad_spell.search(contact_text))
            invalid_phone = bool(phone)
            invalid_email = bool(email) and not any(off in email.group(0) for off in self.official.get("domain", []))
            business_desc = soup.find(text=re.compile(r"Since \d{4}|leading.*provider", re.IGNORECASE))
            return {
                "domain": domain,
                "status_code": status_code,
                "has_brand": brand_in_page,
                "contact_email": email.group(0) if email else "未知",
                "contact_phone": phone.group(0) if phone else "未知",
                "contact_address": str(address) if address else "未知",
                "has_bad_spell": bad_spell,  # 拼写错误（如Uinited）
                "has_invalid_phone": invalid_phone,  # 电话位数不全
                "has_invalid_email": invalid_email,  # 邮箱域名非官方
                "has_business_desc": bool(business_desc)
            }
        except Exception as e:
            logger.warning(f"获取{domain} 网页内容失败: {e}")
            return {"domain": domain, "error": str(e)}

    def check_associated_domain(self, domain: str, ip: str) -> List[str]:
        """检测同一IP下的关联域名（对齐报告5.3）"""
        try:
            # 简易版：通过反向解析+DNS查询（生产环境可对接被动DNS接口）
            associated_domains = []
            reverse_dns = socket.gethostbyaddr(ip)[0]
            # 提取主域并查询同域下的子域（生产环境替换为被动DNS查询）
            ext = tldextract.extract(reverse_dns)
            main_domain = f"{ext.domain}.{ext.suffix}"
            if main_domain != domain:
                associated_domains.append(main_domain)
            return associated_domains
        except Exception as e:
            logger.warning(f"检测{domain} 关联域名失败: {e}")
            return []

    def judge_phishing(self, all_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        核心：整合所有检测信息，按照报告规则判定是否为钓鱼域名
        风险等级：🔴高危（确认钓鱼）/🟡可疑/🟢正常
        """
        risk_score = 0
        risk_reason = []
        # 1. Whois特征：新注册/隐私保护/非官方注册商（报告3.1/3.2）
        if all_info.get("whois", {}).get("is_hidden", False):
            risk_score += 20
            risk_reason.append("Whois信息隐藏（隐私保护）")
        if "2023" in all_info.get("whois", {}).get("create_date", "") or "2024" in all_info.get("whois", {}).get("create_date", ""):
            risk_score += 15
            risk_reason.append("域名注册时间较新（近2年）")
        if all_info.get("whois", {}).get("registrar", "") not in ["Alibaba Cloud", "GoDaddy"]:  # 非官方注册商
            risk_score += 10
            risk_reason.append("域名注册商非官方合作商")

        # 2. IP/NS特征：非中国IP/廉价NS（报告2.3/5.1/5.2）
        if all_info.get("ip", {}).get("is_foreign_ip", False):
            risk_score += 20
            risk_reason.append("服务器IP位于非官方国家")
        if all_info.get("ip", {}).get("is_cheap_ns", False):
            risk_score += 15
            risk_reason.append("使用廉价第三方NS服务器")

        # 3. SSL特征：免费证书/非官方颁发机构（报告4.3）
        if all_info.get("ssl", {}).get("is_free_ssl", False):
            risk_score += 15
            risk_reason.append("使用Let's Encrypt免费SSL证书")
        if not all_info.get("ssl", {}).get("is_official_ssl", False) and all_info.get("ssl", {}).get("has_ssl", False):
            risk_score += 10
            risk_reason.append("SSL证书颁发机构非官方指定")

        # 4. 内容特征：欺诈信息（报告4.1）
        if all_info.get("content", {}).get("has_bad_spell", False):
            risk_score += 25
            risk_reason.append("网页存在明显拼写错误（如Uinited）")
        if all_info.get("content", {}).get("has_invalid_phone", False):
            risk_score += 20
            risk_reason.append("联系电话位数不全，存在欺诈特征")
        if all_info.get("content", {}).get("has_invalid_email", False):
            risk_score += 25
            risk_reason.append("联系邮箱域名与官方无关")

        # 5. 品牌特征：冒用品牌但信息矛盾
        if all_info.get("content", {}).get("has_brand", False) and len(risk_reason) > 2:
            risk_score += 30
            risk_reason.append("冒用官方品牌但存在多处信息矛盾")

        # 判定风险等级（对齐报告风险等级）
        if risk_score >= 80:
            risk_level = "🔴高危"
            is_phishing = True
        elif 40 <= risk_score < 80:
            risk_level = "🟡可疑"
            is_phishing = False
        else:
            risk_level = "🟢正常"
            is_phishing = False

        return {
            "is_phishing": is_phishing,
            "risk_level": risk_level,
            "risk_score": risk_score,
            "risk_reason": risk_reason,
            "associated_domains": all_info.get("associated_domains", [])
        }




class DomainMonitoringPipeline:
    """
    域名监控数据处理管道
    当前流程：域名变体生成 → xdig 迭代探测 → 稳定存活域名入库
    """
    
    def __init__(self, base_dir: str = "."):
        self.base_dir = Path(base_dir)
        # results directory
        self.results_dir = self.base_dir / "monitoring_results"
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self.database_ready = False
        # 初始化钓鱼检测工具（传入官方白名单）
        self.official_whitelist = official_whitelist or {}
        self.phish_tool = PhishingDetectTool(self.official_whitelist)
        
        # 各模块的输出文件路径
        #self.domain_variants_file = self.base_dir / "domain_variants" / "example.com_puny_only.txt"
        self.xdig_results_file = None
        #self.semantic_domains_file = self.results_dir / "semantic_phishing_domains.txt"
        self.semantic_domains_file = self.results_dir / "semantic_phishing_domains.txt"
        self.target_result_dir=None
        self.current_target = None
        #self.final_results_file = self.results_dir / "comprehensive_results.json"
        #self.multidim_latest_file = self.results_dir / "multidimensional_analysis_latest.json"
        #self.alerts_latest_file = self.results_dir / "alerts_latest.json"

        # 新增：被动DNS和证书透明度结果文件
        #self.passive_dns_results_file = self.results_dir / "passive_dns_results.json"
        #self.certificate_transparency_results_file = self.results_dir / "certificate_transparency_results.json"
        #self.active_probing_results_file = self.results_dir / "active_probing_results.json"
        #self.risk_modeling_results_file = self.results_dir / "risk_modeling_results.json"
        #self.visualization_data_file = self.results_dir / "visualization_data.json"
        
        # 初始化被动DNS和证书透明度模块（如果可用）
        #self.passive_dns_collector = None
        #self.ct_monitor = None
        #self.active_probing_service = None

    
        
        
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
        
    
    def step1_5_generate_semantic_phishing(self,target_domain:str)->bool:
        """
        步骤1.5：使用LLM生成语义钓鱼域名
        """
        logger.info("步骤1.5：生成语义钓鱼域名")

        try:
            dash_key=os.getenv("DASHSCOPE_API_KEY")
            serper_key=os.getenv("SERPER_API_KEY")

            if not dash_key:
                logger.warning("未配置DASHSCOPE_API_KEY,跳过语义生成")
                return True
            
            adapter=PhishingGeneratorAdapter(dash_key)

            domains=adapter.generate_for(target_domain,serper_key)

            if not domains:
                logger.warning("语义钓鱼生成结果为空")
                return True
            
            with open(self.semantic_domains_file,"w",encoding="utf-8") as f:
                for d in domains:
                    f.write(d.strip().lower()+"\n")

            logger.info(f"生成语义钓鱼域名数量：{len(domains)}")
            logger.info(f"保存路径：{self.semantic_domains_file}")

            return True
        except Exception as e:
            logger.warning(f"语义钓鱼生成失败：{e}")
            return True
        

    def merge_domain_sources(self)->bool:
        """
        合并域名变体+语义钓鱼域名
        """
        logger.info("合并域名候选池")

        try:
            if not self.domain_variants_file.exists():
                logger.error("域名变体文件不存在")
                return False
            
            domains=set()

            with open(self.domain_variants_file,"r",encoding="utf-8",errors="ignore") as f:
                for line in f:
                    d=line.strip().lower()
                    if d:
                        domains.add(d)

            if self.semantic_domains_file.exists():
                with open(self.semantic_domains_file,"r",encoding="utf-8") as f:
                    for line in f:
                        d=line.strip().lower()
                        if d:
                            domains.add(d)
                    
            merged_file=self.results_dir/"all_candiates.txt"

            with open(merged_file,"w",encoding="utf-8") as f:
                for d in sorted(domains):
                    f.write(d+"\n")
            
            logger.info(f"合并后域名数量：{len(domains)}")

            self.domain_variants_file=merged_file

            return True
        
        except Exception as e:
            logger.error(f"合并域名失败：{e}")
            return False
    


    def step2_run_xdig_scan(
            self,
            target_domain: str,
            domainfile: Optional[str] = None,
            rate: int = 500
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

            # Run xdig and stream its output so user can see progress in real time
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                cwd=self.base_dir,
                bufsize=1,
                universal_newlines=True,
            )

            try:
                # Stream lines as they arrive
                if proc.stdout is not None:
                    for line in proc.stdout:
                        line = line.rstrip('\n')
                        if line:
                            logger.info(line)
                rc = proc.wait()
            except KeyboardInterrupt:
                try:
                    proc.terminate()
                except Exception:
                    pass
                logger.warning("xdig 被用户中断")
                return False

            if rc != 0:
                logger.error(f"xdig 扫描失败，返回码: {rc}")
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
                        # only keep the domain name (strip trailing markers)
                        alive_lines.append(domain)

            # persist alive lines to a per-target file (timestamped to avoid overwriting)
            try:
                try:
                    stem = Path(self.xdig_results_file).stem
                    if stem.startswith('result_'):
                        target_name = stem[len('result_'):].rsplit('_', 1)[0]
                    else:
                        target_name = stem
                    target_name = str(target_name).replace(os.path.sep, '_')
                except Exception:
                    target_name = 'unknown_target'

                # 写入单个目标文件（覆盖旧文件），确保每个目标只保留一份最终列表
                alive_file = self.results_dir / f'xdig_active_alive_{target_name}.txt'

                with alive_file.open('w', encoding='utf-8') as out:
                    if alive_lines:
                        out.write('\n'.join(alive_lines))
                        out.write('\n')

                logger.info("已保存 %d 条存活行到 %s", len(alive_lines), alive_file)
            except Exception as wf_err:
                logger.warning("写入 xdig 存活文件失败: %s", wf_err)

            logger.info(f"从xdig结果中提取了 {len(active_domains)} 个存活域名")
            return active_domains

        except Exception as e:
            logger.error(f"提取存活域名时出错: {e}")
            return []

    def step3_http_probe(self,domains:List[str])->List[str]:
        """
        步骤3：对存活域名进行HTTP探测，返回响应正常的域名列表
        """
        logger.info("步骤3：HTTPX应用层探测")

        try:
            import shutil

            httpx_exec=shutil.which("httpx")
            if not httpx_exec:
                logger.error("未找到httpx,请先安装")
                return []
            
            input_file=self.results_dir/"httpx_input.txt"
            target_name=self.current_target.replace(".","_")
            #output_file=self.results_dir/f"httpx_alive_{target_name}.txt"
            output_file=self.target_result_dir/f"httpx_alive.txt"

            #写入待测域名
            with open(input_file,"w",encoding="utf-8") as f:
                for d in domains:
                    f.write(d+"\n")

            cmd=[
                httpx_exec,
                "-l",str(input_file),
                "-silent",
                "-status-code",
                "-title",
                "-tech-detect",
                "-follow-redirects",
                "-timeout","5",
                "-retries","1",
                "-o",str(output_file)
            ]

            logger.info("执行HTTPX探测：")
            logger.info("".join(cmd))

            result=subprocess.run(cmd,capture_output=True,text=True)

            if result.returncode!=0:
                logger.error("httpx执行失败")
                return []
            
            alive_domains=[]

            if output_file.exists():
                with open(output_file,"r",encoding="utf-8") as f:
                    for line in f:
                        parts=line.strip().split()
                        if parts:
                            url=parts[0]
                            alive_domains.append(url)

            logger.info(f"HTTPX存活网站数量：{len(alive_domains)}")

            return alive_domains
        
        except Exception as e:
            logger.error(f"httpx探测失败:{e}")
            return []

    def step4_full_dimension_detect(self,alive_domains:List[str])->List[Dict[str,Any]]:
        """步骤四：对HTTP存活域名执行全维度钓鱼检测"""
        logger.info(f"步骤四：全维度钓鱼检测-共检测{len(alive_domains)}个存活域名")
        detect_results=[]
        for domain in alive_domains:
            logger.info(f"开始检测域名：{domain}")
            #1.获取各维度信息
            whois_info=self.phish_tool.get_whois_info(domain)
            ip_info=self.phish_tool.get_ip_info(domain)
            ssl_info=self.phish_toolget_ssl_cert(domain)
            content_info=self.phish_tool.get_web_content(domain)
            #2.关联域名分析
            associated_domains=self.phish_tool.check_associated_domain(domain, ip_info.get("ip", ""))
            #3.整合信息判定钓鱼风险
            all_info={
                "domain": domain,
                "whois": whois_info,
                "ip": ip_info,
                "ssl": ssl_info,
                "content": content_info,
                "associated_domains": associated_domains,
                "detect_time":datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            #核心判定：是否为钓鱼域名
            phish_judge=self.phish_tool.judge_phishing(all_info)
            all_info.update(phish_judge)
            detect_results.append(all_info)
            logger.info(f"检测结果 - 域名: {domain}, 风险等级: {phish_judge['risk_level']}, 是否钓鱼: {phish_judge['is_phishing']}")

        #保存全维度检测结果
        detect_file=self.target_result_dir/"full_dimension_detect.json"
        with open(detect_file,"w",encoding="utf-8") as f:
            json.dump(detect_results,f,ensure_ascii=False,indent=2)
        logger.info(f"已保存全维度检测结果: {detect_file}")
        return detect_results

    def run_full_pipeline(self, target_domain: str) -> bool:
        """
        运行完整的监控管道
        """

        self.current_target=target_domain
        self.target_result_dir=self.results_dir/target_domain.replace(".","_")
        self.target_result_dir.mkdir(exist_ok=True)
        

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
            
            #步骤1.5：语义钓鱼域名生成
            self.step1_5_generate_semantic_phishing(target_domain)

            if not self.merge_domain_sources():
                logger.error("合并域名失败")
                return False

            

            # 步骤2（多轮统计版）: 每轮都扫描同一候选集合，按命中次数判定稳定存活
            max_rounds = max(2, int(os.getenv("XDIG_STABLE_MAX_ROUNDS", "3")))
            min_hits = max(1, int(os.getenv("XDIG_STABLE_MIN_HITS", "2")))
            if min_hits > max_rounds:
                min_hits = max_rounds
            abs_delta_threshold = max(0, int(os.getenv("XDIG_STABLE_ABS_DELTA", "2")))
            rel_delta_threshold = max(0.0, float(os.getenv("XDIG_STABLE_REL_DELTA", "0.02")))
            scan_rate = max(10, int(os.getenv("XDIG_RATE", "500")))

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

                # 将本轮的活跃候选写到临时文件，下一轮将对这些候选重新探测
                try:
                    round_active_file = self.results_dir / f"{target_domain}_xdig_round_{round_idx}_active.txt"
                    with open(round_active_file, "w", encoding="utf-8") as rf:
                        for d in active_domains:
                            rf.write(d + "\n")
                    logger.info(f"已将第{round_idx}轮活跃候选写入: {round_active_file}")
                    # 下一轮使用上一轮的活跃候选进行探测
                    scan_domain_file = round_active_file
                except Exception as wf_e:
                    logger.warning(f"写入轮次候选文件失败: {wf_e}")

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
            httpx_alive_sites=self.step3_http_probe(stable_active_domains)
            logger.info(f"HTTP可访问网站数量:{len(httpx_alive_sites)}")
            llm_results=self.step4_llm_phishing_detection(httpx_alive_sites)
            phishing_sites=[
                r for r in llm_results if r.get("is_phishing")
            ]
            logger.info(f"检测到疑似钓鱼网站:{len(phishing_sites)}")

            http_result_file=self.results_dir/"http_alive_sites.txt"
            with open(http_result_file,"w",encoding="utf-8") as f:
                for site in httpx_alive_sites:
                    f.write(site+"\n")

            logger.info(f"HTTPX存活站点已保存:{http_result_file}")




            first_round_active_count = len(first_round_active_domains)
            logger.info(
                f"稳定口径: rounds={rounds_used}, min_hits={min_hits}, "
                f"first_round_active={first_round_active_count}, stable_active={len(stable_active_domains)}"
            )

            
            elapsed_time = time.time() - start_time
            logger.info(f"管道执行完成，总耗时: {elapsed_time:.2f} 秒")
            
            # 输出结果文件路径
            logger.info(f"结果文件:")
            logger.info(f"  - xdig结果: {self.xdig_results_file}")
            #logger.info(f"  - 主动探测结果: {self.active_probing_results_file}")
            #logger.info(f"  - 稳定存活报告: {self.final_results_file}")
            
            return True

        except Exception as e:
            logger.error(f"管道执行过程中出错: {e}")
            return False
        


    def fetch_webpage_content(self,url:str)->str:
        """
        获取网页HTML内容（限制大小
        """

        try:
            import requests

            if not url.startswith("http"):
                url="http://"+url

            resp=requests.get(
                url,
                timeout=6,
                headers={"User-Agent":"Mozilla/5.0"}
            )

            if resp.status_code!=200:
                return ""
            
            html=resp.text[:15000]#限制长度
            return html

        except Exception:
            return ""
        

    def llm_detect_phishing(self, domain: str, html: str) -> Dict[str, Any]:
        """
        使用LLM判断页面是否为钓鱼域名
        """
        try:
            import dashscope
            from dashscope import Generation

            dashscope.api_key=os.getenv("DASHSCOPE_API_KEY")

            prompt=f"""
        你是一个网络安全专家，请判断下面网页是否是钓鱼网站。
        域名: {domain}
        网页HTML内容片段：
        {html[:5000]}

        请输出JSON格式：
        {{
"is_phishing": true/false,
"confidence": 0-100,
"brand_target": "可能伪造的品牌",
"reason": "简短分析"
}}
"""
            response=Generation.call(
                model="qwen-plus",
                prompt=prompt,
                max_tokens=300,
            )

            text=response.output.text

            import json
            result=json.loads(text)

            return result
        
        except Exception as e:
            logger.warning(f"LLM分析失败：{e}")
            return {}
        

    def step4_llm_phishing_detection(self, http_alive_sites: List[str]):
        """
        步骤4：LLM分析钓鱼页面
        """
        logger.info("步骤4: LLM页面钓鱼检测")

        results = []

        for site in http_alive_sites:

            html = self.fetch_webpage_content(site)

            if not html:
                continue

            analysis = self.llm_detect_phishing(site, html)

            if analysis:
                analysis["domain"] = site
                results.append(analysis)

                logger.info(
                    f"{site} -> phishing={analysis.get('is_phishing')} "
                    f"confidence={analysis.get('confidence')}"
                )

        output_file = self.target_result_dir / "llm_phishing_detection.json"

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)

        logger.info(f"LLM检测结果已保存: {output_file}")

        return results
        

        


# --------------- Adapter: reuse SemanticPhishingDomainGenerator ---------------
try:
    from semantic_phishing_generator import SemanticPhishingDomainGenerator
except Exception as e:
    logger.warning(f"无法导入 SemanticPhishingDomainGenerator: {e}")
    SemanticPhishingDomainGenerator = None


class PhishingGeneratorAdapter:
    """
    适配器：封装并复用 `SemanticPhishingDomainGenerator` 的功能
    使用示例:
        adapter = PhishingGeneratorAdapter(dashscope_api_key=None)
        domains = adapter.generate_for('paypal.com', serper_api_key)
    """

    def __init__(self, dashscope_api_key: str | None = None):
        if SemanticPhishingDomainGenerator is None:
            raise ImportError("SemanticPhishingDomainGenerator 未导入")
        self.generator = SemanticPhishingDomainGenerator(dashscope_api_key)

    def generate_for(self, domain: str, serper_api_key: str | None = None) -> List[str]:
        return self.generator.generate(domain, serper_api_key)

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
        print(f"   结果文件保存在: {pipeline.target_result_dir}")
        
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
                    #print(f"   已写入数据库: {data.get('saved_count', 0)}")
                    print(f"   收敛原因: {data.get('convergence_reason', '')}")
            except Exception:
                pass
    else:
        print(f"\n❌ 监控管道执行失败!")
        sys.exit(1)

if __name__ == "__main__":
    main()

   
        
#!/usr/bin/env python3


import json
import time
import logging
import subprocess
import sys
import os
import platform
import re
from typing import List, Optional, Dict, Any, Set
from datetime import datetime
from pathlib import Path
import ipaddress
import whois
import requests
import tldextract
from ipwhois import IPWhois
from bs4 import BeautifulSoup
import ssl
import socket
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# 添加模块路径
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ====================== 新增：钓鱼检测工具类（对齐报告分析维度）======================
class PhishingDetectTool:
    """钓鱼域名检测工具类，实现报告中所有核心检测逻辑：
    1. Whois信息分析 2. IP归属/反向解析 3. SSL证书校验 4. 内容欺诈检测
    5. 关联域名分析 6. 官方白名单比对 7. 欺诈特征判定（拼写错误/虚假信息等）
    """
    def __init__(self, official_whitelist: Dict[str, Any]):
        """
        初始化官方白名单（核心，用于比对判定）
        :param official_whitelist: 官方域名/IP/NS/SSL等白名单配置，示例：
            {
                "domain": ["coscoshipping.com", "coscoshipping.cn"],  # 官方主域名
                "ns": ["vip3.alidns.com", "vip4.alidns.com"],        # 官方NS服务器
                "ip_country": ["CN"],                                # 官方IP所属国家
                "ssl_issuer": ["DigiCert", "Thawte"],                # 官方SSL颁发机构
                "brand": "COSCO SHIPPING"                            # 目标品牌名
            }
        """
        self.official = official_whitelist
        self.brand = self.official.get("brand", "")
        # 欺诈特征正则（报告中典型特征：拼写错误/不完整信息）
        self.re_bad_spell = re.compile(r"Uinited|Amercia|Recevied|Shiping", re.IGNORECASE)
        self.re_invalid_phone = re.compile(r"\+\d+-\d+-\s*\d{1,5}$")  # 位数不全的电话
        self.re_invalid_email = re.compile(r"@\w+(\.\w+)+")

    def get_whois_info(self, domain: str) -> Dict[str, Any]:
        """获取域名Whois信息（对齐报告3.1/3.2）"""
        try:
            w = whois.whois(domain)
            return {
                "domain": domain,
                "create_date": str(w.get("creation_date", "未知")),
                "expire_date": str(w.get("expiration_date", "未知")),
                "registrar": w.get("registrar", "未知"),
                "registrant": w.get("registrant_name", "隐藏（隐私保护）"),
                "status": w.get("status", "未知"),
                "is_hidden": True if "隐私保护" in str(w.get("registrant_name", "")) else False
            }
        except Exception as e:
            logger.warning(f"获取{domain} Whois失败: {e}")
            return {"domain": domain, "error": str(e)}

    def get_ip_info(self, domain: str) -> Dict[str, Any]:
        """获取域名IP+IP归属/反向解析（对齐报告2.1/2.3/5.2）"""
        try:
            ip = socket.gethostbyname(domain)
            # IP反向解析
            try:
                reverse_dns = socket.gethostbyaddr(ip)[0]
            except:
                reverse_dns = "未知"
            # IP归属地
            try:
                ip_whois = IPWhois(ip)
                ip_info = ip_whois.lookup_rdap()
                country = ip_info.get("asn_country_code", "未知")
                org = ip_info.get("asn_description", "未知")
            except:
                country = "未知"
                org = "未知"
            # NS服务器
            try:
                ns = socket.gethostbyname_ex(domain)[-1]
            except:
                ns = ["未知"]
            return {
                "domain": domain,
                "ip": ip,
                "reverse_dns": reverse_dns,
                "ip_country": country,
                "ip_org": org,
                "ns_server": ns,
                # 判定：是否非官方国家/廉价NS
                "is_foreign_ip": country not in self.official.get("ip_country", []),
                "is_cheap_ns": not any(ns in self.official.get("ns", []) for ns in ns)
            }
        except Exception as e:
            logger.warning(f"获取{domain} IP信息失败: {e}")
            return {"domain": domain, "error": str(e)}

    def get_ssl_cert(self, domain: str) -> Dict[str, Any]:
        """获取SSL证书信息并校验（对齐报告4.3/SSL对比）"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert_data = ssock.getpeercert()
                    # 解析证书颁发机构/有效期/主体
                    issuer = dict(x[0] for x in cert_data.get("issuer", []))
                    subject = dict(x[0] for x in cert_data.get("subject", []))
                    return {
                        "domain": domain,
                        "has_ssl": True,
                        "ssl_issuer": issuer.get("organizationName", "未知"),
                        "ssl_cn": subject.get("commonName", "未知"),
                        "ssl_start": cert_data.get("notBefore", "未知"),
                        "ssl_end": cert_data.get("notAfter", "未知"),
                        "is_free_ssl": True if "Let's Encrypt" in issuer.get("organizationName", "") else False,
                        "is_official_ssl": any(iss in issuer.get("organizationName", "") for iss in self.official.get("ssl_issuer", []))
                    }
        except Exception as e:
            logger.warning(f"获取{domain} SSL证书失败: {e}")
            return {"domain": domain, "has_ssl": False, "error": str(e)}

    def get_web_content(self, domain: str) -> Dict[str, Any]:
        """获取网页内容并检测欺诈特征（对齐报告4.1/4.2）"""
        try:
            urls = [f"https://{domain}", f"http://{domain}"]
            html = ""
            status_code = 0
            for url in urls:
                resp = requests.get(
                    url, timeout=5, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
                )
                if resp.status_code == 200:
                    html = resp.text[:20000]  # 限制长度
                    status_code = resp.status_code
                    break
            soup = BeautifulSoup(html, "html.parser")
            # 提取关键信息：联系地址/电话/邮箱/品牌名/业务描述
            contact_text = soup.get_text(strip=True)
            email = re.search(self.re_invalid_email, contact_text)
            phone = re.search(self.re_invalid_phone, contact_text)
            address = soup.find(text=re.compile(r"\d+.*Way|St|Ave.*\d{5}"))  # 匹配欧美地址
            brand_in_page = self.brand in contact_text
            # 欺诈特征检测
            bad_spell = bool(self.re_bad_spell.search(contact_text))
            invalid_phone = bool(phone)
            invalid_email = bool(email) and not any(off in email.group(0) for off in self.official.get("domain", []))
            business_desc = soup.find(text=re.compile(r"Since \d{4}|leading.*provider", re.IGNORECASE))
            return {
                "domain": domain,
                "status_code": status_code,
                "has_brand": brand_in_page,
                "contact_email": email.group(0) if email else "未知",
                "contact_phone": phone.group(0) if phone else "未知",
                "contact_address": str(address) if address else "未知",
                "has_bad_spell": bad_spell,  # 拼写错误（如Uinited）
                "has_invalid_phone": invalid_phone,  # 电话位数不全
                "has_invalid_email": invalid_email,  # 邮箱域名非官方
                "has_business_desc": bool(business_desc)
            }
        except Exception as e:
            logger.warning(f"获取{domain} 网页内容失败: {e}")
            return {"domain": domain, "error": str(e)}

    def check_associated_domain(self, domain: str, ip: str) -> List[str]:
        """检测同一IP下的关联域名（对齐报告5.3）"""
        try:
            # 简易版：通过反向解析+DNS查询（生产环境可对接被动DNS接口）
            associated_domains = []
            reverse_dns = socket.gethostbyaddr(ip)[0]
            # 提取主域并查询同域下的子域（生产环境替换为被动DNS查询）
            ext = tldextract.extract(reverse_dns)
            main_domain = f"{ext.domain}.{ext.suffix}"
            if main_domain != domain:
                associated_domains.append(main_domain)
            return associated_domains
        except Exception as e:
            logger.warning(f"检测{domain} 关联域名失败: {e}")
            return []

    def judge_phishing(self, all_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        核心：整合所有检测信息，按照报告规则判定是否为钓鱼域名
        风险等级：🔴高危（确认钓鱼）/🟡可疑/🟢正常
        """
        risk_score = 0
        risk_reason = []
        # 1. Whois特征：新注册/隐私保护/非官方注册商（报告3.1/3.2）
        if all_info.get("whois", {}).get("is_hidden", False):
            risk_score += 20
            risk_reason.append("Whois信息隐藏（隐私保护）")
        if "2023" in all_info.get("whois", {}).get("create_date", "") or "2024" in all_info.get("whois", {}).get("create_date", ""):
            risk_score += 15
            risk_reason.append("域名注册时间较新（近2年）")
        if all_info.get("whois", {}).get("registrar", "") not in ["Alibaba Cloud", "GoDaddy"]:  # 非官方注册商
            risk_score += 10
            risk_reason.append("域名注册商非官方合作商")

        # 2. IP/NS特征：非中国IP/廉价NS（报告2.3/5.1/5.2）
        if all_info.get("ip", {}).get("is_foreign_ip", False):
            risk_score += 20
            risk_reason.append("服务器IP位于非官方国家")
        if all_info.get("ip", {}).get("is_cheap_ns", False):
            risk_score += 15
            risk_reason.append("使用廉价第三方NS服务器")

        # 3. SSL特征：免费证书/非官方颁发机构（报告4.3）
        if all_info.get("ssl", {}).get("is_free_ssl", False):
            risk_score += 15
            risk_reason.append("使用Let's Encrypt免费SSL证书")
        if not all_info.get("ssl", {}).get("is_official_ssl", False) and all_info.get("ssl", {}).get("has_ssl", False):
            risk_score += 10
            risk_reason.append("SSL证书颁发机构非官方指定")

        # 4. 内容特征：欺诈信息（报告4.1）
        if all_info.get("content", {}).get("has_bad_spell", False):
            risk_score += 25
            risk_reason.append("网页存在明显拼写错误（如Uinited）")
        if all_info.get("content", {}).get("has_invalid_phone", False):
            risk_score += 20
            risk_reason.append("联系电话位数不全，存在欺诈特征")
        if all_info.get("content", {}).get("has_invalid_email", False):
            risk_score += 25
            risk_reason.append("联系邮箱域名与官方无关")

        # 5. 品牌特征：冒用品牌但信息矛盾
        if all_info.get("content", {}).get("has_brand", False) and len(risk_reason) > 2:
            risk_score += 30
            risk_reason.append("冒用官方品牌但存在多处信息矛盾")

        # 判定风险等级（对齐报告风险等级）
        if risk_score >= 80:
            risk_level = "🔴高危"
            is_phishing = True
        elif 40 <= risk_score < 80:
            risk_level = "🟡可疑"
            is_phishing = False
        else:
            risk_level = "🟢正常"
            is_phishing = False

        return {
            "is_phishing": is_phishing,
            "risk_level": risk_level,
            "risk_score": risk_score,
            "risk_reason": risk_reason,
            "associated_domains": all_info.get("associated_domains", [])
        }

# ====================== 原有Pipeline类改造 ======================
class DomainMonitoringPipeline:
    """
    域名监控数据处理管道（改造后）
    完整流程：域名变体生成 → xdig迭代探测 → HTTP存活 → 全维度钓鱼检测 → LLM精准判读 → 结果标准化
    """
    def __init__(self, base_dir: str = ".", official_whitelist: Dict[str, Any] = None):
        self.base_dir = Path(base_dir)
        self.results_dir = self.base_dir / "monitoring_results"
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self.database_ready = False
        # 初始化钓鱼检测工具（传入官方白名单）
        self.official_whitelist = official_whitelist or {}
        self.phish_tool = PhishingDetectTool(self.official_whitelist)
        # 各模块路径
        self.semantic_domains_file = self.results_dir / "semantic_phishing_domains.txt"
        self.xdig_results_file = None
        self.current_target = None
        self.target_result_dir = None

    # --- 原有方法保留：step1_generate_domain_variants ---
    def step1_generate_domain_variants(self, target_domain: str) -> bool:
        logger.info(f"步骤1: 生成域名变体 - {target_domain}")
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
            cmd = ["go", "run", "main.go", "-domain", target_domain]
            logger.info(f"执行命令: {' '.join(cmd)}")
            result = subprocess.run(
                cmd, capture_output=True, text=True, cwd=self.base_dir,
                encoding='utf-8', errors='replace'
            )
            if result.returncode == 0:
                domain_output_dir = self.base_dir / "domain_variants" / target_domain.replace('.', '_')
                punycode_file = domain_output_dir / "puny_only.txt"
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
                    return False
            else:
                logger.error(f"域名变体生成失败，返回码: {result.returncode}")
                if result.stderr:
                    logger.error(f"错误输出: {result.stderr}")
                return False
        except Exception as e:
            logger.error(f"执行域名变体生成时出错: {e}")
            return False

    # --- 原有方法保留：step1_5_generate_semantic_phishing ---
    def step1_5_generate_semantic_phishing(self,target_domain:str)->bool:
        logger.info("步骤1.5：生成语义钓鱼域名")
        try:
            dash_key=os.getenv("DASHSCOPE_API_KEY")
            if not dash_key:
                logger.warning("未配置DASHSCOPE_API_KEY,跳过语义生成")
                return True
            try:
                from semantic_phishing_generator import SemanticPhishingDomainGenerator
                adapter = PhishingGeneratorAdapter(dash_key)
                domains=adapter.generate_for(target_domain,os.getenv("SERPER_API_KEY"))
                if domains:
                    with open(self.semantic_domains_file,"w",encoding="utf-8") as f:
                        for d in domains:
                            f.write(d.strip().lower()+"\n")
                    logger.info(f"生成语义钓鱼域名数量：{len(domains)}")
                else:
                    logger.warning("语义钓鱼生成结果为空")
                return True
            except ImportError:
                logger.warning("未找到SemanticPhishingDomainGenerator，跳过语义生成")
                return True
        except Exception as e:
            logger.warning(f"语义钓鱼生成失败：{e}")
            return True

    # --- 原有方法保留：merge_domain_sources ---
    def merge_domain_sources(self)->bool:
        logger.info("合并域名候选池")
        try:
            if not hasattr(self, 'domain_variants_file') or not self.domain_variants_file.exists():
                logger.error("域名变体文件不存在")
                return False
            domains=set()
            with open(self.domain_variants_file,"r",encoding="utf-8",errors="ignore") as f:
                for line in f:
                    d=line.strip().lower()
                    if d:
                        domains.add(d)
            if self.semantic_domains_file.exists():
                with open(self.semantic_domains_file,"r",encoding="utf-8") as f:
                    for line in f:
                        d=line.strip().lower()
                        if d:
                            domains.add(d)
            merged_file=self.results_dir/"all_candiates.txt"
            with open(merged_file,"w",encoding="utf-8") as f:
                for d in sorted(domains):
                    f.write(d+"\n")
            logger.info(f"合并后域名数量：{len(domains)}")
            self.domain_variants_file=merged_file
            return True
        except Exception as e:
            logger.error(f"合并域名失败：{e}")
            return False

    # --- 原有方法保留：step2_run_xdig_scan ---
    def step2_run_xdig_scan(self, target_domain: str, domainfile: Optional[str] = None, rate: int = 500) -> bool:
        logger.info("步骤2: 运行 xdig DNS 探测")
        try:
            import shutil
            if platform.system() != "Linux":
                logger.error("xdig 原始发包模式仅支持 Linux")
                return False
            xdig_executable = self.base_dir / "xdig"
            if not xdig_executable.exists():
                path_exec = shutil.which("xdig")
                if path_exec:
                    xdig_executable = Path(path_exec)
            if not xdig_executable.exists():
                logger.error("未找到 xdig 可执行文件")
                return False
            xdig_executable.chmod(0o755)
            # 获取网络参数
            route = subprocess.check_output("ip route | grep default", shell=True, text=True)
            iface = route.split("dev")[1].split()[0]
            gateway_ip = route.split("via")[1].split()[0]
            ip_info = subprocess.check_output(f"ip -4 addr show {iface} | grep inet", shell=True, text=True)
            src_ip = ip_info.split()[1].split("/")[0]
            src_mac = Path(f"/sys/class/net/{iface}/address").read_text().strip()
            neigh = subprocess.check_output(f"ip neigh | grep {gateway_ip}", shell=True, text=True)
            gtw_mac = neigh.split("lladdr")[1].split()[0]
            logger.info(f"网络参数: iface={iface}, ip={src_ip}")
            # 选择domainfile
            domain_file = Path(domainfile) if domainfile else self.domain_variants_file
            if not domain_file.exists():
                logger.error(f"domainfile 不存在: {domain_file}")
                return False
            dns_file = self.base_dir / "dns.txt"
            if not dns_file.exists():
                logger.error("dns.txt 不存在")
                return False
            # 输出文件
            output_file = self.base_dir / f"result_{target_domain}_{rate}.txt"
            self.xdig_results_file = output_file
            # 组装命令
            cmd = [
                "sudo", str(xdig_executable),
                "-iface", iface, "-srcip", src_ip, "-srcmac", src_mac, "-gtwmac", gtw_mac,
                "-domainfile", str(domain_file), "-dnsfile", str(dns_file),
                "-rate", str(rate), "-type", "a", "-out", str(output_file)
            ]
            logger.info(f"执行命令: {' '.join(cmd)}")
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, cwd=self.base_dir, bufsize=1, universal_newlines=True,
            )
            if proc.stdout is not None:
                for line in proc.stdout:
                    line = line.rstrip('\n')
                    if line:
                        logger.info(line)
            rc = proc.wait()
            if rc != 0:
                logger.error(f"xdig 扫描失败，返回码: {rc}")
                return False
            logger.info(f"xdig 输出文件: {output_file}")
            return True
        except Exception as e:
            logger.error(f"执行 xdig 出错: {e}")
            return False

    # --- 原有方法保留：extract_active_domains_from_xdig ---
    def extract_active_domains_from_xdig(self) -> List[str]:
        active_domains = []
        try:
            if not self.xdig_results_file or not self.xdig_results_file.exists():
                logger.error("xdig结果文件不存在")
                return []
            with open(self.xdig_results_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    raw = line.strip()
                    if raw and raw.endswith(',1'):
                        parts = raw.split(',')
                        domain = parts[0].strip()
                        if domain:
                            active_domains.append(domain)
            # 保存存活域名
            try:
                stem = Path(self.xdig_results_file).stem
                target_name = stem[len('result_'):].rsplit('_', 1)[0] if stem.startswith('result_') else 'unknown_target'
                alive_file = self.results_dir / f'xdig_active_alive_{target_name}.txt'
                with alive_file.open('w', encoding='utf-8') as out:
                    if active_domains:
                        out.write('\n'.join(active_domains))
                logger.info(f"已保存 {len(active_domains)} 条存活域名到 {alive_file}")
            except Exception as wf_err:
                logger.warning(f"写入 xdig 存活文件失败: {wf_err}")
            logger.info(f"从xdig结果中提取了 {len(active_domains)} 个存活域名")
            return list(set(active_domains))
        except Exception as e:
            logger.error(f"提取存活域名时出错: {e}")
            return []

    # --- 原有方法改造：step3_http_probe（修复拼写错误+优化结果）---
    def step3_http_probe(self,domains:List[str])->List[str]:
        logger.info("步骤3：HTTPX应用层探测")
        try:
            import shutil
            httpx_exec=shutil.which("httpx")
            if not httpx_exec:
                logger.error("未找到httpx,请先安装: pip install httpx")
                return []
            input_file=self.results_dir/"httpx_input.txt"
            output_file=self.target_result_dir/f"httpx_alive.txt"
            # 写入待测域名
            with open(input_file,"w",encoding="utf-8") as f:
                for d in domains:
                    f.write(d+"\n")
            cmd=[
                httpx_exec, "-l", str(input_file), "-silent", "-status-code",
                "-title", "-tech-detect", "-follow-redirects",
                "-timeout","5", "-retries","1", "-o", str(output_file)
            ]
            logger.info(f"执行HTTPX探测: {' '.join(cmd)}")
            result=subprocess.run(cmd,capture_output=True,text=True)
            if result.returncode!=0:
                logger.error(f"httpx执行失败: {result.stderr}")
                return []
            alive_domains=[]
            if output_file.exists():  # 修复原代码exits()拼写错误
                with open(output_file,"r",encoding="utf-8") as f:
                    for line in f:
                        parts=line.strip().split()
                        if parts and parts[0].startswith(('http', 'https')):
                            domain = parts[0].replace('https://', '').replace('http://', '').split('/')[0]
                            alive_domains.append(domain)
            alive_domains = list(set(alive_domains))
            logger.info(f"HTTPX存活网站数量：{len(alive_domains)}")
            return alive_domains
        except Exception as e:
            logger.error(f"httpx探测失败:{e}")
            return []

    # ====================== 新增：步骤4 全维度钓鱼检测（核心）======================
    def step4_full_dimension_detect(self, alive_domains: List[str]) -> List[Dict[str, Any]]:
        """步骤4：对HTTP存活域名执行全维度钓鱼检测（对齐报告所有分析点）"""
        logger.info(f"步骤4：全维度钓鱼检测 - 共检测 {len(alive_domains)} 个存活域名")
        detect_results = []
        for domain in alive_domains:
            logger.info(f"开始检测域名: {domain}")
            # 1. 获取各维度信息
            whois_info = self.phish_tool.get_whois_info(domain)
            ip_info = self.phish_tool.get_ip_info(domain)
            ssl_info = self.phish_tool.get_ssl_cert(domain)
            content_info = self.phish_tool.get_web_content(domain)
            # 2. 检测关联域名
            associated_domains = self.phish_tool.check_associated_domain(domain, ip_info.get("ip", ""))
            # 3. 整合所有信息
            all_info = {
                "domain": domain,
                "whois": whois_info,
                "ip": ip_info,
                "ssl": ssl_info,
                "content": content_info,
                "associated_domains": associated_domains,
                "detect_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            # 4. 核心判定：是否为钓鱼域名
            phish_judge = self.phish_tool.judge_phishing(all_info)
            all_info.update(phish_judge)
            detect_results.append(all_info)
            logger.info(f"{domain} 检测完成 - 风险等级: {all_info.get('risk_level')}, 是否钓鱼: {all_info.get('is_phishing')}")
        # 保存全维度检测结果
        detect_file = self.target_result_dir / "full_dimension_detect.json"
        with open(detect_file, "w", encoding="utf-8") as f:
            json.dump(detect_results, f, indent=2, ensure_ascii=False)
        logger.info(f"全维度检测结果已保存: {detect_file}")
        return detect_results

    # ====================== 改造：步骤5 LLM精准判读（基于全维度检测结果）======================
    def step5_llm_refine_judge(self, detect_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """步骤5：基于全维度检测结果，让LLM做精准二次判读（替代原简单LLM检测）"""
        logger.info("步骤5：LLM精准二次判读钓鱼域名")
        try:
            import dashscope
            from dashscope import Generation
            dash_key = os.getenv("DASHSCOPE_API_KEY")
            if not dash_key:
                logger.warning("未配置DASHSCOPE_API_KEY, 跳过LLM二次判读")
                return detect_results
            dashscope.api_key = dash_key
            refined_results = []
            for res in detect_results:
                # 构造精准prompt（包含所有检测维度，对齐报告分析逻辑）
                prompt = f"""
你是网络安全专家，负责基于全维度检测结果判定域名是否为钓鱼域名，严格参考COSCO钓鱼域名分析报告的判定规则。
检测域名：{res.get('domain')}
官方品牌：{self.official_whitelist.get('brand', '')}
官方白名单：{self.official_whitelist.get('domain', [])}
全维度检测结果：
1. Whois信息：{json.dumps(res.get('whois', {}), ensure_ascii=False)}
2. IP/NS信息：{json.dumps(res.get('ip', {}), ensure_ascii=False)}
3. SSL证书信息：{json.dumps(res.get('ssl', {}), ensure_ascii=False)}
4. 网页内容信息：{json.dumps(res.get('content', {}), ensure_ascii=False)}
5. 关联域名：{res.get('associated_domains', [])}
6. 初判结果：风险等级{res.get('risk_level')}，是否钓鱼{res.get('is_phishing')}，风险原因{res.get('risk_reason', [])}

请基于以上信息做二次精准判读，输出JSON格式（字段不可改）：
{{
"is_phishing": true/false,
"risk_level": "🔴高危"/"🟡可疑"/"🟢正常",
"confidence": 0-100,
"core_reason": "核心钓鱼/可疑/正常原因（不超过50字）",
"ioc_info": {{
    "domain": "检测域名",
    "ip": "对应IP",
    "associated_domains": "关联域名列表"
}}
}}
"""
                # 调用LLM
                response = Generation.call(
                    model="qwen-plus",
                    prompt=prompt,
                    max_tokens=500,
                    result_format="json"
                )
                llm_res = json.loads(response.output.text)
                # 整合LLM结果
                res["llm_refine"] = llm_res
                refined_results.append(res)
            # 保存LLM二次判读结果
            llm_file = self.target_result_dir / "llm_refine_judge.json"
            with open(llm_file, "w", encoding="utf-8") as f:
                json.dump(refined_results, f, indent=2, ensure_ascii=False)
            logger.info(f"LLM精准判读结果已保存: {llm_file}")
            return refined_results
        except Exception as e:
            logger.error(f"LLM二次判读失败: {e}")
            return detect_results

    # ====================== 新增：步骤6 生成IOC和检测报告（对齐报告输出）======================
    def step6_generate_report(self, refined_results: List[Dict[str, Any]]) -> None:
        """步骤6：生成钓鱼域名IOC清单和标准化检测报告（完全对齐COSCO分析报告格式）"""
        logger.info("步骤6：生成钓鱼域名IOC清单和标准化检测报告")
        # 1. 提取IOC信息（对齐报告10.1-10.5）
        ioc_data = {
            "domain_ioc": [res.get('domain') for res in refined_results if res.get('is_phishing')],
            "ip_ioc": [res.get('ip', {}).get('ip') for res in refined_results if res.get('is_phishing') and res.get('ip', {}).get('ip')],
            "ns_ioc": [ns for res in refined_results if res.get('is_phishing') for ns in res.get('ip', {}).get('ns_server', []) if ns != "未知"],
            "email_ioc": [res.get('content', {}).get('contact_email') for res in refined_results if res.get('is_phishing') and res.get('content', {}).get('contact_email') != "未知"],
            "address_ioc": [res.get('content', {}).get('contact_address') for res in refined_results if res.get('is_phishing') and res.get('content', {}).get('contact_address') != "未知"],
            "detect_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        # 去重
        for k in ioc_data:
            if isinstance(ioc_data[k], list):
                ioc_data[k] = list(set([x for x in ioc_data[k] if x]))
        # 保存IOC清单
        ioc_file = self.target_result_dir / "phishing_ioc.json"
        with open(ioc_file, "w", encoding="utf-8") as f:
            json.dump(ioc_data, f, indent=2, ensure_ascii=False)
        logger.info(f"钓鱼域名IOC清单已保存: {ioc_file}")

        # 2. 生成标准化检测报告（markdown格式，对齐报告结构）
        phishing_domains = [res for res in refined_results if res.get('is_phishing')]
        report_md = f"""# 钓鱼域名检测分析报告
报告编号: {self.current_target.upper()}-{datetime.now().strftime('%Y%m%d-%H%M%S')}
报告日期: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
检测目标: {self.current_target}
官方品牌: {self.official_whitelist.get('brand', '')}
高危钓鱼域名数量: {len(phishing_domains)}
可疑域名数量: {len([res for res in refined_results if res.get('risk_level') == '🟡可疑'])}

## 一、执行摘要
本次共检测 {len(refined_results)} 个存活域名，其中确认**{len(phishing_domains)}个高危钓鱼域名**，均采用Typosquatting（连字符/拼写错误）技术模仿官方域名，存在Whois隐藏、非官方IP/NS、免费SSL证书、网页虚假信息等典型欺诈特征。

## 二、高危钓鱼域名详情
"""
        # 逐个写入钓鱼域名详情
        for idx, res in enumerate(phishing_domains, 1):
            report_md += f"""### {idx}. 域名：{res.get('domain')}
- **风险等级**: {res.get('risk_level')}
- **是否钓鱼**: {res.get('is_phishing')}
- **LLM置信度**: {res.get('llm_refine', {}).get('confidence', 0)}%
- **核心原因**: {res.get('llm_refine', {}).get('core_reason', '; '.join(res.get('risk_reason', [])))}
- **对应IP**: {res.get('ip', {}).get('ip', '未知')}
- **IP归属**: {res.get('ip', {}).get('ip_country', '未知')}/{res.get('ip', {}).get('ip_org', '未知')}
- **NS服务器**: {', '.join(res.get('ip', {}).get('ns_server', ['未知']))}
- **SSL证书**: {res.get('ssl', {}).get('has_ssl', False) and '有（免费）' or '无'}
- **联系邮箱**: {res.get('content', {}).get('contact_email', '未知')}
- **联系电话**: {res.get('content', {}).get('contact_phone', '未知')}
- **关联域名**: {', '.join(res.get('associated_domains', ['无']))}
\n"""
        # 新增建议措施（对齐报告9.1/9.2）
        report_md += f"""## 三、建议措施
### 立即行动项（P0）
1. 将本次检测出的域名IOC加入防火墙/邮件网关/浏览器黑名单
2. 通知员工和客户，警惕来自钓鱼域名的邮件/链接
3. 向域名注册商举报钓鱼域名，申请注销
4. 监控关联域名，防止攻击者通过子域继续欺诈

### 长期防护建议（P1）
1. 部署DMARC/SPF/DKIM，防止官方域名被冒用
2. 注册防御性域名，抢注常见Typosquatting变体（连字符/拼写错误/字母替换）
3. 持续监控新注册的相似域名，做到早发现早处置
4. 定期开展员工安全意识培训，进行钓鱼演练

## 四、IOC清单
### 域名IOC
{chr(10).join([f"- {d}" for d in ioc_data.get('domain_ioc', [])]) or '无'}
### IP IOC
{chr(10).join([f"- {ip}" for ip in ioc_data.get('ip_ioc', [])]) or '无'}
### 联系邮箱IOC
{chr(10).join([f"- {e}" for e in ioc_data.get('email_ioc', [])]) or '无'}
"""
        # 保存markdown报告
        report_file = self.target_result_dir / "phishing_detect_report.md"
        with open(report_file, "w", encoding="utf-8") as f:
            f.write(report_md)
        logger.info(f"标准化检测报告已保存: {report_file}")

    # --- 原有方法改造：run_full_pipeline（整合新增步骤）---
    def run_full_pipeline(self, target_domain: str) -> bool:
        self.current_target = target_domain
        self.target_result_dir = self.results_dir / target_domain.replace(".", "_")
        self.target_result_dir.mkdir(exist_ok=True)
        start_time = time.time()
        try:
            logger.info(f"开始运行域名监控管道 - 目标域名: {target_domain}")
            logger.info("运行模式: 全维度钓鱼域名检测（对齐COSCO分析报告）")
            # 步骤1：生成域名变体
            if not self.step1_generate_domain_variants(target_domain):
                logger.error("步骤1失败，停止管道执行")
                return False
            # 步骤1.5：生成语义钓鱼域名
            self.step1_5_generate_semantic_phishing(target_domain)
            # 合并域名
            if not self.merge_domain_sources():
                logger.error("合并域名失败，停止管道执行")
                return False
            # 步骤2：xdig多轮DNS探测
            max_rounds = max(2, int(os.getenv("XDIG_STABLE_MAX_ROUNDS", "3")))
            min_hits = max(1, int(os.getenv("XDIG_STABLE_MIN_HITS", "2")))
            abs_delta_threshold = max(0, int(os.getenv("XDIG_STABLE_ABS_DELTA", "2")))
            rel_delta_threshold = max(0.0, float(os.getenv("XDIG_STABLE_REL_DELTA", "0.02")))
            scan_rate = max(10, int(os.getenv("XDIG_RATE", "500")))
            candidate_limit = max(0, int(os.getenv("XDIG_CANDIDATE_LIMIT", "0")))
            previous_active_count = None
            hit_counter: dict[str, int] = {}
            scan_domain_file = self.domain_variants_file
            # 候选域名限制
            if candidate_limit > 0 and scan_domain_file.exists():
                limited_file = self.results_dir / f"{target_domain}_candidates_limit_{candidate_limit}.txt"
                kept = 0
                with open(scan_domain_file, "r", encoding="utf-8", errors="ignore") as src, open(limited_file, "w", encoding="utf-8") as dst:
                    for line in src:
                        line = line.strip()
                        if line:
                            dst.write(line + "\n")
                            kept += 1
                            if kept >= candidate_limit:
                                break
                scan_domain_file = limited_file
                logger.info(f"已启用候选域名限制: limit={candidate_limit}")
            # 多轮xdig探测
            for round_idx in range(1, max_rounds + 1):
                logger.info(f"xdig 多轮探测: 第 {round_idx}/{max_rounds} 轮")
                if not self.step2_run_xdig_scan(target_domain=target_domain, domainfile=str(scan_domain_file), rate=scan_rate):
                    logger.error(f"第 {round_idx} 轮 xdig 探测失败")
                    return False
                active_domains = self.extract_active_domains_from_xdig()
                active_count = len(active_domains)
                logger.info(f"第 {round_idx} 轮存活数量: {active_count}")
                # 写入本轮活跃域名
                round_active_file = self.results_dir / f"{target_domain}_xdig_round_{round_idx}_active.txt"
                with open(round_active_file, "w", encoding="utf-8") as rf:
                    rf.write("\n".join(active_domains))
                scan_domain_file = round_active_file
                # 计数
                for d in active_domains:
                    hit_counter[d] = hit_counter.get(d, 0) + 1
                # 收敛判断
                if previous_active_count is not None:
                    abs_delta = abs(active_count - previous_active_count)
                    rel_delta = (abs_delta / previous_active_count) if previous_active_count > 0 else 0.0
                    if abs_delta <= abs_delta_threshold or rel_delta <= rel_delta_threshold:
                        logger.info(f"第{round_idx}轮收敛，停止多轮探测")
                        break
                if active_count == 0:
                    logger.warning(f"第{round_idx}轮存活数量为0，提前停止")
                    break
                previous_active_count = active_count
            # 提取稳定存活域名
            stable_active_domains = sorted([d for d, cnt in hit_counter.items() if cnt >= min_hits])
            if not stable_active_domains:
                logger.warning("无稳定存活域名，停止管道执行")
                return True
            logger.info(f"稳定存活域名数量: {len(stable_active_domains)}")
            # 步骤3：HTTP存活探测
            http_alive_domains = self.step3_http_probe(stable_active_domains)
            if not http_alive_domains:
                logger.warning("无HTTP存活域名，停止管道执行")
                return True
            # 步骤4：全维度钓鱼检测（核心新增）
            detect_results = self.step4_full_dimension_detect(http_alive_domains)
            # 步骤5：LLM精准二次判读（改造）
            refined_results = self.step5_llm_refine_judge(detect_results)
            # 步骤6：生成IOC和标准化报告（新增）
            self.step6_generate_report(refined_results)
            # 统计结果
            phishing_count = len([res for res in refined_results if res.get('is_phishing')])
            suspect_count = len([res for res in refined_results if res.get('risk_level') == '🟡可疑'])
            elapsed_time = time.time() - start_time
            logger.info(f"管道执行完成，总耗时: {elapsed_time:.2f} 秒")
            logger.info(f"最终检测结果 - 高危钓鱼域名: {phishing_count} 个, 可疑域名: {suspect_count} 个")
            logger.info(f"所有结果已保存至: {self.target_result_dir}")
            return True
        except Exception as e:
            logger.error(f"管道执行过程中出错: {e}", exc_info=True)
            return False

    # --- 原有方法保留：fetch_webpage_content/llm_detect_phishing（备用）---
    def fetch_webpage_content(self,url:str)->str:
        try:
            if not url.startswith("http"):
                url="http://"+url
            resp=requests.get(url, timeout=6, headers={"User-Agent":"Mozilla/5.0"})
            if resp.status_code!=200:
                return ""
            return resp.text[:15000]
        except Exception:
            return ""

    def llm_detect_phishing(self, domain: str, html: str) -> Dict[str, Any]:
        try:
            import dashscope
            from dashscope import Generation
            dashscope.api_key=os.getenv("DASHSCOPE_API_KEY")
            prompt=f"""你是网络安全专家，请判断下面网页是否是钓鱼网站。
域名: {domain}
网页HTML内容片段：{html[:5000]}
请输出JSON格式：{{"is_phishing": true/false,"confidence": 0-100,"brand_target": "可能伪造的品牌","reason": "简短分析"}}"""
            response=Generation.call(model="qwen-plus", prompt=prompt, max_tokens=300,)
            return json.loads(response.output.text)
        except Exception as e:
            logger.warning(f"LLM分析失败：{e}")
            return {}

# ====================== 原有适配器保留 ======================
try:
    from semantic_phishing_generator import SemanticPhishingDomainGenerator
except Exception as e:
    logger.warning(f"无法导入 SemanticPhishingDomainGenerator: {e}")
    SemanticPhishingDomainGenerator = None

class PhishingGeneratorAdapter:
    def __init__(self, dashscope_api_key: str | None = None):
        if SemanticPhishingDomainGenerator is None:
            raise ImportError("SemanticPhishingDomainGenerator 未导入")
        self.generator = SemanticPhishingDomainGenerator(dashscope_api_key)
    def generate_for(self, domain: str, serper_api_key: str | None = None) -> List[str]:
        return self.generator.generate(domain, serper_api_key)

# ====================== 改造主函数：传入官方白名单 ======================
def main():
    import argparse
    parser = argparse.ArgumentParser(description='域名监控数据处理管道（全维度钓鱼检测，对齐COSCO分析报告）')
    parser.add_argument('-d', '--domain', required=True, help='目标域名（例如: coscoshipping.com）')
    parser.add_argument('-b', '--base-dir', default='.', help='项目基础目录（默认当前目录）')
    parser.add_argument('-v', '--verbose', action='store_true', help='详细输出')
    args = parser.parse_args()
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    # ====================== 关键：配置目标品牌的官方白名单（根据实际需求修改）======================
    # 示例：COSCO SHIPPING 官方白名单（完全对齐报告中的官方信息）
    official_whitelist = {
        "brand": "COSCO SHIPPING",
        "domain": ["coscoshipping.com", "coscoshipping.cn", "coscoshipping.net"],
        "ns": ["vip3.alidns.com", "vip4.alidns.com"],
        "ip_country": ["CN"],
        "ssl_issuer": ["DigiCert", "Thawte", "奇安信"]
    }
    # 初始化管道并运行
    pipeline = DomainMonitoringPipeline(args.base_dir, official_whitelist=official_whitelist)
    success = pipeline.run_full_pipeline(args.domain)
    if success:
        print(f"\n✅ 监控管道执行成功!")
        print(f"   所有结果（含IOC/报告）保存在: {pipeline.target_result_dir}")
    else:
        print(f"\n❌ 监控管道执行失败!")
        sys.exit(1)

if __name__ == "__main__":
    main()

'''
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import time
import logging
import subprocess
import sys
import os
import platform
import re
import ipaddress
import socket
import ssl
from typing import List, Optional, Dict, Any, Set
from datetime import datetime, timezone
from pathlib import Path
from dataclasses import dataclass

import whois
import requests
import tldextract
from ipwhois import IPWhois
import dns.resolver
from bs4 import BeautifulSoup

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from modules.domain_input import DomainInputError, normalize_domain_input

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

try:
    from semantic_phishing_generator import (
        SemanticPhishingDomainGenerator,
        SemanticDomainRiskAnalyzer
    )
except Exception as e:
    logger.warning(f"导入 semantic_phishing_generator 失败，语义功能将不可用: {e}")
    SemanticPhishingDomainGenerator = None
    SemanticDomainRiskAnalyzer = None


@dataclass
class DomainAsset:
    fqdn: str
    subdomain: str
    domain: str
    suffix: str
    registered_domain: str


def parse_domain_asset(host: str) -> DomainAsset:
    host = (host or "").strip().lower()
    host = host.replace("https://", "").replace("http://", "")
    host = host.split("/")[0].strip(".")
    ext = tldextract.extract(host)
    registered = ".".join(part for part in [ext.domain, ext.suffix] if part)
    return DomainAsset(
        fqdn=host,
        subdomain=(ext.subdomain or "").lower(),
        domain=(ext.domain or "").lower(),
        suffix=(ext.suffix or "").lower(),
        registered_domain=registered.lower()
    )


def is_same_or_subdomain(candidate: str, root_domain: str) -> bool:
    candidate = (candidate or "").strip().lower().rstrip(".")
    root_domain = (root_domain or "").strip().lower().rstrip(".")
    return candidate == root_domain or candidate.endswith("." + root_domain)


def split_brand_tokens(domain_word: str) -> List[str]:
    """
    针对常见品牌串做优先切分。
    后续你可以继续扩展。
    """
    domain_word = (domain_word or "").strip().lower()

    known = {
        "coscoshipping": ["cosco", "shipping"],
        "alipayservice": ["alipay", "service"],
        "wechatpay": ["wechat", "pay"],
        "bankofchina": ["bank", "of", "china"],
        "chinamobile": ["china", "mobile"],
        "chinatelcom": ["china", "telcom"],
    }
    return known.get(domain_word, [domain_word])


def generate_brand_enhanced_variants(target_domain: str) -> Set[str]:
    """
    在原有 go 生成结果之外，额外补一层品牌切分规则，
    重点解决 coscoshipping.com -> cosco-shipping.com 这类问题。
    """
    asset = parse_domain_asset(target_domain)
    variants: Set[str] = set()

    if not asset.domain or not asset.suffix:
        return variants

    base = asset.domain
    suffix = asset.suffix

    variants.add(f"{base}.{suffix}")

    tokens = split_brand_tokens(base)
    if len(tokens) > 1:
        hyphen_name = "-".join(tokens)
        variants.add(f"{hyphen_name}.{suffix}")

        # 常见 TLD 扩展
        for tld in ["com", "net", "org", "cn", "co", "info"]:
            variants.add(f"{hyphen_name}.{tld}")

    # 删除连字符 / 添加连字符后的反向归一
    if "-" in base:
        variants.add(f"{base.replace('-', '')}.{suffix}")

    # 少量常见 typo
    if "shipping" in base:
        variants.add(f"{base.replace('shipping', 'shiping')}.{suffix}")
        variants.add(f"{base.replace('shipping', 'shippng')}.{suffix}")
        variants.add(f"{base.replace('shipping', 'shippinq')}.{suffix}")

    if "cosco" in base:
        variants.add(f"{base.replace('cosco', 'cosc0')}.{suffix}")
        variants.add(f"{base.replace('cosco', 'coscko')}.{suffix}")

    return {v.lower() for v in variants if v.strip()}


class PhishingDetectTool:
    def __init__(self, official_whitelist: Optional[Dict[str, Any]] = None):
        self.official = official_whitelist or {}
        self.brand = str(self.official.get("brand", "") or "").strip()

        self.official_domains = sorted(set(
            d.strip().lower()
            for d in self.official.get("domain", [])
            if isinstance(d, str) and d.strip()
        ))

        self.root_domains = sorted(set(
            d.strip().lower()
            for d in self.official.get("root_domains", [])
            if isinstance(d, str) and d.strip()
        ))

        self.known_fqdns = sorted(set(
            d.strip().lower()
            for d in self.official.get("known_fqdns", [])
            if isinstance(d, str) and d.strip()
        ))

        self.brand_tokens = sorted(set(
            t.strip().lower()
            for t in self.official.get("brand_tokens", [])
            if isinstance(t, str) and t.strip()
        ))

        # 兼容旧字段
        if not self.root_domains and self.official_domains:
            self.root_domains = sorted(set(
                parse_domain_asset(d).registered_domain for d in self.official_domains if d
            ))

        self.re_bad_spell = re.compile(
            r"Uinited|Amercia|Recevied|Shiping|Logn|Passwrod|Verifcation",
            re.IGNORECASE
        )
        self.re_email = re.compile(
            r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
        )
        self.re_phone = re.compile(
            r"\+?\d[\d\-\s()]{6,20}\d"
        )
        self.re_sensitive_words = re.compile(
            r"login|sign in|verify|verification|password|bank|payment|invoice|refund|tracking|confirm|account suspended",
            re.IGNORECASE
        )

    @staticmethod
    def _normalize_domain_like(value: str) -> str:
        value = (value or "").strip().lower()
        value = value.replace("https://", "").replace("http://", "")
        value = value.split("/")[0]
        return value.strip(".")

    @staticmethod
    def _safe_request(url: str, timeout: int = 5) -> Optional[requests.Response]:
        try:
            return requests.get(
                url,
                timeout=timeout,
                headers={"User-Agent": "Mozilla/5.0"},
                allow_redirects=True,
                verify=False,
            )
        except Exception:
            return None

    @staticmethod
    def _parse_creation_date(raw_date: Any) -> Optional[datetime]:
        if raw_date is None:
            return None
        if isinstance(raw_date, list) and raw_date:
            raw_date = raw_date[0]
        if isinstance(raw_date, datetime):
            if raw_date.tzinfo is None:
                return raw_date.replace(tzinfo=timezone.utc)
            return raw_date
        return None

    def _is_official_registered_domain(self, domain: str) -> bool:
        asset = parse_domain_asset(domain)
        return asset.registered_domain in self.root_domains

    def _is_official_full_domain(self, domain: str) -> bool:
        domain = self._normalize_domain_like(domain)
        return any(is_same_or_subdomain(domain, d) for d in self.root_domains + self.known_fqdns)

    def _email_matches_official(self, email_domain: str) -> bool:
        email_domain = (email_domain or "").strip().lower().rstrip(".")
        if not email_domain:
            return False
        for d in self.root_domains + self.known_fqdns + self.official_domains:
            if is_same_or_subdomain(email_domain, d) or is_same_or_subdomain(d, email_domain):
                return True
        return False

    def score_brand_impersonation(self, candidate_domain: str) -> Dict[str, Any]:
        """
        解决“外部独立域冒充官方品牌/子域体系”的问题。
        """
        candidate_domain = self._normalize_domain_like(candidate_domain)
        asset = parse_domain_asset(candidate_domain)

        score = 0
        reasons = []

        if not self._is_official_registered_domain(candidate_domain):
            score += 20
            reasons.append("候选域名不在官方根域名体系内")

        candidate_naked = asset.registered_domain.replace(".", "").replace("-", "")
        for root in self.root_domains:
            root_naked = root.replace(".", "").replace("-", "")
            if candidate_naked == root_naked and asset.registered_domain != root:
                score += 35
                reasons.append("与官方根域仅存在连字符/分隔符差异")
                break

        token_hits = [t for t in self.brand_tokens if t and t in candidate_domain]
        if token_hits:
            score += min(30, 10 * len(token_hits))
            reasons.append(f"命中品牌关键词: {token_hits}")

        # 若官方存在业务子域，如 boao.coscoshipping.com，而候选是外部相似独立域
        # 则进一步提升风险
        for fqdn in self.known_fqdns:
            official_asset = parse_domain_asset(fqdn)
            official_naked = official_asset.registered_domain.replace(".", "").replace("-", "")
            if candidate_naked == official_naked and asset.registered_domain != official_asset.registered_domain:
                score += 15
                reasons.append("与已知官方业务子域所属品牌根域高度相似")
                break

        return {
            "brand_score": min(score, 100),
            "brand_reasons": reasons,
            "brand_token_hits": token_hits,
            "candidate_registered_domain": asset.registered_domain,
            "candidate_fqdn": asset.fqdn,
        }

    def get_whois_info(self, domain: str) -> Dict[str, Any]:
        try:
            w = whois.whois(domain)
            creation_date = self._parse_creation_date(w.get("creation_date"))
            expire_date = w.get("expiration_date", "未知")
            registrar = w.get("registrar", "未知")
            registrant_name = w.get("registrant_name", "") or ""

            is_hidden = any(
                key in str(registrant_name).lower()
                for key in ["privacy", "redacted", "hidden", "protect", "隐私"]
            )

            age_days = None
            if creation_date:
                age_days = (datetime.now(timezone.utc) - creation_date).days

            return {
                "domain": domain,
                "create_date": str(creation_date) if creation_date else "未知",
                "expire_date": str(expire_date),
                "registrar": registrar,
                "registrant": registrant_name or "隐藏（隐私保护）",
                "status": w.get("status", "未知"),
                "is_hidden": is_hidden,
                "domain_age_days": age_days,
            }
        except Exception as e:
            logger.warning(f"获取 {domain} Whois 失败: {e}")
            return {"domain": domain, "error": str(e)}

    def get_ns_records(self, domain: str) -> List[str]:
        try:
            answers = dns.resolver.resolve(domain, "NS")
            return sorted([str(r.target).rstrip(".").lower() for r in answers])
        except Exception as e:
            logger.warning(f"获取 {domain} NS 记录失败: {e}")
            return []

    def get_ip_info(self, domain: str) -> Dict[str, Any]:
        try:
            ip = socket.gethostbyname(domain)

            try:
                reverse_dns = socket.gethostbyaddr(ip)[0]
            except Exception:
                reverse_dns = "未知"

            try:
                ip_whois = IPWhois(ip)
                ip_info = ip_whois.lookup_rdap()
                country = ip_info.get("asn_country_code", "未知")
                org = ip_info.get("asn_description", "未知")
            except Exception:
                country = "未知"
                org = "未知"

            try:
                resolved_ips = socket.gethostbyname_ex(domain)[-1]
            except Exception:
                resolved_ips = []

            ns_records = self.get_ns_records(domain)
            official_ns = [x.lower() for x in self.official.get("ns", []) if x]
            is_cheap_ns = False
            if ns_records and official_ns:
                is_cheap_ns = not any(ns in official_ns for ns in ns_records)

            return {
                "domain": domain,
                "ip": ip,
                "reverse_dns": reverse_dns,
                "ip_country": country,
                "ip_org": org,
                "resolved_ips": resolved_ips,
                "ns_server": ns_records,
                "is_foreign_ip": country not in self.official.get("ip_country", []),
                "is_cheap_ns": is_cheap_ns,
            }
        except Exception as e:
            logger.warning(f"获取 {domain} IP 信息失败: {e}")
            return {"domain": domain, "error": str(e)}

    def get_ssl_cert(self, domain: str) -> Dict[str, Any]:
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert_data = ssock.getpeercert()
                    issuer = dict(x[0] for x in cert_data.get("issuer", []))
                    subject = dict(x[0] for x in cert_data.get("subject", []))
                    issuer_org = issuer.get("organizationName", "未知")

                    return {
                        "domain": domain,
                        "has_ssl": True,
                        "ssl_issuer": issuer_org,
                        "ssl_cn": subject.get("commonName", "未知"),
                        "ssl_start": cert_data.get("notBefore", "未知"),
                        "ssl_end": cert_data.get("notAfter", "未知"),
                        "is_free_ssl": "Let's Encrypt" in issuer_org,
                        "is_official_ssl": any(
                            iss.lower() in issuer_org.lower()
                            for iss in self.official.get("ssl_issuer", [])
                        ),
                    }
        except Exception as e:
            logger.warning(f"获取 {domain} SSL 证书失败: {e}")
            return {"domain": domain, "has_ssl": False, "error": str(e)}

    def get_web_content(self, domain: str) -> Dict[str, Any]:
        try:
            domain = self._normalize_domain_like(domain)
            urls = [f"https://{domain}", f"http://{domain}"]

            html = ""
            status_code = 0
            final_url = ""

            for url in urls:
                resp = self._safe_request(url, timeout=6)
                if resp and resp.status_code < 500:
                    html = resp.text[:20000]
                    status_code = resp.status_code
                    final_url = resp.url
                    if html:
                        break

            soup = BeautifulSoup(html, "html.parser")
            contact_text = soup.get_text(" ", strip=True)[:15000]

            email_match = self.re_email.search(contact_text)
            phone_match = self.re_phone.search(contact_text)
            address_match = re.search(
                r"\d{1,6}\s+[A-Za-z0-9\s.,-]+(?:Street|St|Avenue|Ave|Road|Rd|Way|Boulevard|Blvd)\b.*?\d{4,6}",
                contact_text,
                re.IGNORECASE
            )

            email = email_match.group(0) if email_match else "未知"
            phone = phone_match.group(0) if phone_match else "未知"
            address = address_match.group(0) if address_match else "未知"

            has_brand = False
            lower_text = contact_text.lower()
            if self.brand and self.brand.lower() in lower_text:
                has_brand = True
            elif any(t in lower_text for t in self.brand_tokens if len(t) >= 4):
                has_brand = True

            has_bad_spell = bool(self.re_bad_spell.search(contact_text))
            has_sensitive_words = bool(self.re_sensitive_words.search(contact_text))

            invalid_phone = False
            if phone_match:
                digits = re.sub(r"\D", "", phone_match.group(0))
                if len(digits) < 7:
                    invalid_phone = True

            invalid_email = False
            if email_match:
                email_domain = email.split("@")[-1].lower()
                if not self._email_matches_official(email_domain):
                    invalid_email = True

            has_login_form = bool(
                soup.find("input", {"type": re.compile(r"password", re.IGNORECASE)})
                or soup.find("form")
            )

            title = soup.title.string.strip() if soup.title and soup.title.string else ""

            return {
                "domain": domain,
                "status_code": status_code,
                "final_url": final_url,
                "page_title": title,
                "has_brand": has_brand,
                "contact_email": email,
                "contact_phone": phone,
                "contact_address": address,
                "has_bad_spell": has_bad_spell,
                "has_invalid_phone": invalid_phone,
                "has_invalid_email": invalid_email,
                "has_sensitive_words": has_sensitive_words,
                "has_login_form": has_login_form,
                "html_excerpt": html[:5000],
            }
        except Exception as e:
            logger.warning(f"获取 {domain} 网页内容失败: {e}")
            return {"domain": domain, "error": str(e)}

    def check_associated_domain(self, domain: str, ip: str) -> List[str]:
        try:
            if not ip:
                return []
            associated_domains = []
            reverse_dns = socket.gethostbyaddr(ip)[0]
            ext = tldextract.extract(reverse_dns)
            main_domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
            if main_domain and main_domain != domain:
                associated_domains.append(main_domain)
            return associated_domains
        except Exception as e:
            logger.warning(f"检测 {domain} 关联域名失败: {e}")
            return []

    def judge_phishing(self, all_info: Dict[str, Any]) -> Dict[str, Any]:
        risk_score = 0
        risk_reason = []

        whois_info = all_info.get("whois", {})
        ip_info = all_info.get("ip", {})
        ssl_info = all_info.get("ssl", {})
        content_info = all_info.get("content", {})

        brand_eval = self.score_brand_impersonation(all_info.get("domain", ""))
        brand_score = int(brand_eval.get("brand_score", 0) or 0)
        brand_reasons = list(brand_eval.get("brand_reasons", []))

        # 品牌仿冒特征直接进入规则分
        if brand_score >= 60:
            risk_score += 30
            risk_reason.append("域名命名模式与官方品牌高度相似")
        elif brand_score >= 40:
            risk_score += 20
            risk_reason.append("域名命名模式疑似模仿官方品牌")
        elif brand_score >= 20:
            risk_score += 10
            risk_reason.append("域名包含官方品牌相关特征")

        risk_reason.extend(brand_reasons)

        if whois_info.get("is_hidden", False):
            risk_score += 20
            risk_reason.append("Whois 信息隐藏或隐私保护")

        domain_age_days = whois_info.get("domain_age_days")
        if isinstance(domain_age_days, int):
            if domain_age_days <= 180:
                risk_score += 25
                risk_reason.append("域名注册时间极新（<=180天）")
            elif domain_age_days <= 730:
                risk_score += 15
                risk_reason.append("域名注册时间较新（<=2年）")

        registrar = str(whois_info.get("registrar", "") or "")
        trusted_registrars = [r.lower() for r in self.official.get("trusted_registrar", ["Alibaba Cloud", "GoDaddy"])]
        if registrar and trusted_registrars and registrar.lower() not in trusted_registrars:
            risk_score += 10
            risk_reason.append("域名注册商不在信任名单中")

        if ip_info.get("is_foreign_ip", False):
            risk_score += 20
            risk_reason.append("服务器 IP 位于非官方国家/地区")

        if ip_info.get("is_cheap_ns", False):
            risk_score += 15
            risk_reason.append("NameServer 不在官方白名单中")

        if ssl_info.get("is_free_ssl", False):
            risk_score += 15
            risk_reason.append("使用免费 SSL 证书")

        if ssl_info.get("has_ssl", False) and not ssl_info.get("is_official_ssl", False):
            risk_score += 10
            risk_reason.append("SSL 颁发机构不在官方白名单中")

        if content_info.get("has_bad_spell", False):
            risk_score += 20
            risk_reason.append("页面存在明显拼写或文案异常")

        if content_info.get("has_invalid_phone", False):
            risk_score += 15
            risk_reason.append("联系电话格式异常")

        if content_info.get("has_invalid_email", False):
            risk_score += 25
            risk_reason.append("联系邮箱域名与官方体系不一致")

        if content_info.get("has_sensitive_words", False):
            risk_score += 12
            risk_reason.append("页面含登录/验证/支付等敏感诱导词")

        if content_info.get("has_login_form", False):
            risk_score += 18
            risk_reason.append("页面存在登录表单或密码输入框")

        if content_info.get("has_brand", False) and len(risk_reason) >= 2:
            risk_score += 20
            risk_reason.append("页面存在品牌借用且伴随多项异常特征")

        risk_score = min(100, risk_score)
        if risk_score >= 80:
            risk_level = "🔴高危"
            is_phishing = True
        elif risk_score >= 50:
            risk_level = "🟡可疑"
            is_phishing = False
        else:
            risk_level = "🟢低风险"
            is_phishing = False

        dedup = []
        seen = set()
        for r in risk_reason:
            if r not in seen:
                seen.add(r)
                dedup.append(r)

        return {
            "rule_score": risk_score,
            "rule_level": risk_level,
            "rule_is_phishing": is_phishing,
            "rule_reasons": dedup,
            "associated_domains": all_info.get("associated_domains", []),
            "brand_impersonation": brand_eval,
        }


class DomainMonitoringPipeline:
    def __init__(self, base_dir: str = ".", official_whitelist: Optional[Dict[str, Any]] = None):
        self.base_dir = Path(base_dir)
        self.results_dir = self.base_dir / "monitoring_results"
        self.results_dir.mkdir(parents=True, exist_ok=True)

        self.database_ready = False
        self.official_whitelist = official_whitelist or {}
        self.phish_tool = PhishingDetectTool(self.official_whitelist)

        self.xdig_results_file: Optional[Path] = None
        self.semantic_domains_file = self.results_dir / "semantic_phishing_domains.txt"
        self.final_results_file = self.results_dir / "comprehensive_results.json"

        self.target_result_dir: Optional[Path] = None
        self.current_target: Optional[str] = None
        self.domain_variants_file: Optional[Path] = None

    def step1_generate_domain_variants(self, target_domain: str) -> bool:
        logger.info(f"步骤1: 生成域名变体 - {target_domain}")

        try:
            ipaddress.ip_address(target_domain)
            domain_output_dir = self.base_dir / "domain_variants" / target_domain.replace(".", "_")
            domain_output_dir.mkdir(parents=True, exist_ok=True)
            punycode_file = domain_output_dir / "puny_only.txt"
            punycode_file.write_text(str(target_domain) + "\n", encoding="utf-8")
            self.domain_variants_file = punycode_file
            logger.info("目标为 IP，已跳过域名变体生成并使用单行 IP 文件")
            return True
        except ValueError:
            pass

        try:
            domains = set()

            # 原 go 生成
            cmd = ["go", "run", "main.go", "-domain", target_domain]
            logger.info(f"执行命令: {' '.join(cmd)}")

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=self.base_dir,
                encoding="utf-8",
                errors="replace"
            )

            if result.returncode != 0:
                logger.error(f"域名变体生成失败，返回码: {result.returncode}")
                if result.stdout:
                    logger.error(f"标准输出: {result.stdout[:500]}")
                if result.stderr:
                    logger.error(f"错误输出: {result.stderr[:500]}")
            else:
                domain_output_dir = self.base_dir / "domain_variants" / target_domain.replace(".", "_")
                punycode_file = domain_output_dir / "puny_only.txt"

                if not punycode_file.exists():
                    domain_output_dir = self.base_dir / "domain_variants" / target_domain
                    punycode_file = domain_output_dir / "puny_only.txt"

                if punycode_file.exists():
                    with open(punycode_file, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            d = line.strip().lower()
                            if d:
                                domains.add(d)

            # 增补品牌增强变体
            extra_variants = generate_brand_enhanced_variants(target_domain)
            domains.update(extra_variants)

            if not domains:
                logger.warning("未生成任何域名变体")
                return False

            domain_output_dir = self.base_dir / "domain_variants" / target_domain.replace(".", "_")
            domain_output_dir.mkdir(parents=True, exist_ok=True)
            merged_variant_file = domain_output_dir / "puny_only_enhanced.txt"
            with open(merged_variant_file, "w", encoding="utf-8") as f:
                for d in sorted(domains):
                    f.write(d + "\n")

            self.domain_variants_file = merged_variant_file
            logger.info(f"生成并增强后共 {len(domains)} 个域名变体")
            return True

        except Exception as e:
            logger.error(f"执行域名变体生成时出错: {e}")
            return False

    def step1_5_generate_semantic_phishing(self, target_domain: str) -> Dict[str, Any]:
        logger.info("步骤1.5：生成语义钓鱼域名（仅生成）")

        if SemanticPhishingDomainGenerator is None:
            logger.warning("语义生成模块不可用，跳过语义生成")
            return {"domains": [], "semantic_results": []}

        try:
            dash_key = os.getenv("DASHSCOPE_API_KEY")
            serper_key = os.getenv("SERPER_API_KEY")

            if not dash_key:
                logger.warning("未配置 DASHSCOPE_API_KEY，跳过语义生成")
                return {"domains": [], "semantic_results": []}

            generator = SemanticPhishingDomainGenerator(dash_key)
            domains = generator.generate(target_domain, serper_key)

            if not domains:
                logger.warning("语义钓鱼生成结果为空")
                return {"domains": [], "semantic_results": []}

            semantic_max_domains = max(0, int(os.getenv("SEMANTIC_MAX_DOMAINS", "0")))
            if semantic_max_domains > 0:
                domains = domains[:semantic_max_domains]
                logger.info(f"已启用语义候选上限：SEMANTIC_MAX_DOMAINS={semantic_max_domains}")

            with open(self.semantic_domains_file, "w", encoding="utf-8") as f:
                for d in domains:
                    d = d.strip().lower()
                    if d:
                        f.write(d + "\n")

            logger.info(f"生成语义钓鱼域名数量：{len(domains)}")
            return {"domains": domains, "semantic_results": []}

        except Exception as e:
            logger.warning(f"语义钓鱼生成失败：{e}")
            return {"domains": [], "semantic_results": []}

    def merge_domain_sources(self) -> bool:
        logger.info("合并域名候选池")
        try:
            if not self.domain_variants_file or not self.domain_variants_file.exists():
                logger.error("域名变体文件不存在")
                return False

            domains = set()
            with open(self.domain_variants_file, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    d = line.strip().lower()
                    if d:
                        domains.add(d)

            if self.semantic_domains_file.exists():
                with open(self.semantic_domains_file, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        d = line.strip().lower()
                        if d:
                            domains.add(d)

            merged_file = self.results_dir / "all_candidates.txt"
            with open(merged_file, "w", encoding="utf-8") as f:
                for d in sorted(domains):
                    f.write(d + "\n")

            logger.info(f"合并后域名数量：{len(domains)}")
            self.domain_variants_file = merged_file
            return True

        except Exception as e:
            logger.error(f"合并域名失败：{e}")
            return False

    def step2_run_xdig_scan(self, target_domain: str, domainfile: Optional[str] = None, rate: int = 500) -> bool:
        logger.info("步骤2: 运行 xdig DNS 探测")

        try:
            import shutil

            if platform.system() != "Linux":
                logger.error("xdig 原始发包模式仅支持 Linux")
                return False

            xdig_executable = self.base_dir / "xdig"
            if not xdig_executable.exists():
                path_exec = shutil.which("xdig")
                if path_exec:
                    xdig_executable = Path(path_exec)

            if not xdig_executable.exists():
                logger.error("未找到 xdig 可执行文件")
                return False

            xdig_executable.chmod(0o755)

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

            domain_file = Path(domainfile) if domainfile else self.domain_variants_file
            if not domain_file or not domain_file.exists():
                logger.error(f"domainfile 不存在: {domain_file}")
                return False

            dns_file = self.base_dir / "dns.txt"
            if not dns_file.exists():
                logger.error("dns.txt 不存在")
                return False

            output_file = self.base_dir / f"result_{target_domain}_{rate}.txt"
            self.xdig_results_file = output_file

            cmd = [
                "sudo", str(xdig_executable),
                "-iface", iface,
                "-srcip", src_ip,
                "-srcmac", src_mac,
                "-gtwmac", gtw_mac,
                "-domainfile", str(domain_file),
                "-dnsfile", str(dns_file),
                "-rate", str(rate),
                "-try", "2",
                "-wtgtime", "8",
                "-type", "a",
                "-out", str(output_file)
            ]

            logger.info("执行命令:")
            logger.info(" ".join(cmd))

            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                cwd=self.base_dir,
                bufsize=1,
                universal_newlines=True,
            )

            try:
                if proc.stdout is not None:
                    for line in proc.stdout:
                        line = line.rstrip("\n")
                        if line:
                            logger.info(line)
                rc = proc.wait()
            except KeyboardInterrupt:
                try:
                    proc.terminate()
                except Exception:
                    pass
                logger.warning("xdig 被用户中断")
                return False

            if rc != 0:
                logger.error(f"xdig 扫描失败，返回码: {rc}")
                return False

            logger.info(f"xdig 输出文件: {output_file}")
            return True

        except Exception as e:
            logger.error(f"执行 xdig 出错: {e}")
            return False

    def step2_5_semantic_analyze_active_domains(self, active_domains: List[str]) -> Dict[str, Dict[str, Any]]:
        logger.info("步骤2.5：对 DNS 稳定存在域名做 LLM 语义分析")

        if SemanticDomainRiskAnalyzer is None:
            logger.warning("语义分析模块不可用，跳过域名语义分析")
            return {}

        try:
            dash_key = os.getenv("DASHSCOPE_API_KEY")
            if not dash_key:
                logger.warning("未配置 DASHSCOPE_API_KEY，跳过域名语义分析")
                return {}

            if not active_domains:
                logger.warning("无 DNS 稳定存在域名，跳过域名语义分析")
                return {}

            semantic_analyzer = SemanticDomainRiskAnalyzer(
                dashscope_api_key=dash_key,
                official_whitelist=self.official_whitelist
            )

            analyze_targets = sorted(set(d.strip().lower() for d in active_domains if d and d.strip()))
            semantic_analyze_limit = max(0, int(os.getenv("SEMANTIC_ANALYZE_LIMIT", "0")))
            if semantic_analyze_limit > 0:
                analyze_targets = analyze_targets[:semantic_analyze_limit]

            logger.info(f"进入域名语义分析的 DNS 存在域名数量：{len(analyze_targets)}")

            semantic_results_list = semantic_analyzer.analyze_domains(analyze_targets)
            semantic_result_map: Dict[str, Dict[str, Any]] = {}
            for item in semantic_results_list:
                domain = str(item.get("domain", "")).strip().lower()
                if domain:
                    semantic_result_map[domain] = item

            output_file = self.target_result_dir / "semantic_analysis_active_domains.json"
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(list(semantic_result_map.values()), f, ensure_ascii=False, indent=2)

            logger.info(f"已保存域名语义分析结果到 {output_file}")
            return semantic_result_map

        except Exception as e:
            logger.warning(f"DNS 存在域名语义分析失败：{e}")
            return {}

    def extract_active_domains_from_xdig(self) -> List[str]:
        active_domains = []
        try:
            if not self.xdig_results_file or not self.xdig_results_file.exists():
                logger.error("xdig 结果文件不存在")
                return []

            alive_lines = []
            with open(self.xdig_results_file, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    raw = line.strip()
                    if not raw:
                        continue
                    if raw.endswith(",1"):
                        parts = raw.split(",")
                        domain = parts[0].strip().lower()
                        if domain:
                            active_domains.append(domain)
                            alive_lines.append(domain)

            try:
                stem = Path(self.xdig_results_file).stem
                if stem.startswith("result_"):
                    target_name = stem[len("result_"):].rsplit("_", 1)[0]
                else:
                    target_name = stem
                target_name = str(target_name).replace(os.path.sep, "_")

                alive_file = self.results_dir / f"xdig_active_alive_{target_name}.txt"
                with alive_file.open("w", encoding="utf-8") as out:
                    if alive_lines:
                        out.write("\n".join(sorted(set(alive_lines))) + "\n")
                logger.info("已保存 %d 条存活域名到 %s", len(alive_lines), alive_file)
            except Exception as wf_err:
                logger.warning("写入 xdig 存活文件失败: %s", wf_err)

            unique_domains = sorted(set(active_domains))
            logger.info(f"从 xdig 结果中提取了 {len(unique_domains)} 个存活域名")
            return unique_domains

        except Exception as e:
            logger.error(f"提取存活域名时出错: {e}")
            return []

    def step3_http_probe(self, domains: List[str]) -> List[str]:
        logger.info("步骤3：HTTPX 应用层探测")

        try:
            import shutil
            httpx_exec = shutil.which("httpx")
            if not httpx_exec:
                logger.error("未找到 httpx，请先安装")
                return []

            input_file = self.results_dir / "httpx_input.txt"
            output_file = self.target_result_dir / "httpx_alive.txt"

            with open(input_file, "w", encoding="utf-8") as f:
                for d in domains:
                    f.write(d + "\n")

            cmd = [
                httpx_exec,
                "-l", str(input_file),
                "-silent",
                "-status-code",
                "-title",
                "-tech-detect",
                "-follow-redirects",
                "-timeout", "5",
                "-retries", "1",
                "-o", str(output_file)
            ]

            logger.info("执行 HTTPX 探测：")
            logger.info(" ".join(cmd))

            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                logger.error(f"httpx 执行失败: {result.stderr}")
                return []

            alive_domains = []
            if output_file.exists():
                with open(output_file, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        parts = line.strip().split()
                        if parts:
                            url = parts[0]
                            clean_domain = self.phish_tool._normalize_domain_like(url)
                            if clean_domain:
                                alive_domains.append(clean_domain)

            alive_domains = sorted(set(alive_domains))
            logger.info(f"HTTPX 存活网站数量：{len(alive_domains)}")
            return alive_domains

        except Exception as e:
            logger.error(f"httpx 探测失败: {e}")
            return []

    def fetch_webpage_content(self, url: str) -> str:
        try:
            if not url.startswith("http"):
                url = "http://" + url

            resp = requests.get(
                url,
                timeout=6,
                headers={"User-Agent": "Mozilla/5.0"},
                verify=False,
                allow_redirects=True,
            )
            if resp.status_code >= 400:
                return ""
            return resp.text[:15000]

        except Exception:
            return ""

    def llm_detect_phishing(self, domain: str, html: str) -> Dict[str, Any]:
        try:
            import dashscope
            from dashscope import Generation

            dashscope.api_key = os.getenv("DASHSCOPE_API_KEY")
            if not dashscope.api_key:
                return {}

            prompt = f"""
你是一个网络安全专家，请判断下面网页是否是钓鱼网站。

待分析域名: {domain}
网页HTML内容片段:
{html[:5000]}

请严格输出 JSON，不要输出解释文字：
{{
  "is_phishing": true,
  "confidence": 0,
  "brand_target": "可能伪造的品牌或机构，如无则为空字符串",
  "page_type": "fake_login/fake_payment/logistics_notice/account_verification/normal/unknown",
  "reason": "简短分析原因"
}}
"""

            response = Generation.call(
                model="qwen-plus",
                prompt=prompt,
                max_tokens=300,
            )
            text = response.output.text.strip()

            try:
                result = json.loads(text)
            except Exception:
                match = re.search(r"\{.*\}", text, re.S)
                if not match:
                    return {}
                result = json.loads(match.group(0))

            return {
                "is_phishing": bool(result.get("is_phishing", False)),
                "confidence": int(result.get("confidence", 0) or 0),
                "brand_target": str(result.get("brand_target", "") or ""),
                "page_type": str(result.get("page_type", "unknown") or "unknown"),
                "reason": str(result.get("reason", "") or ""),
            }

        except Exception as e:
            logger.warning(f"LLM 分析失败：{e}")
            return {}

    def step4_full_dimension_detect(self, alive_domains: List[str]) -> List[Dict[str, Any]]:
        logger.info(f"步骤4：全维度规则检测 - 共检测 {len(alive_domains)} 个存活域名")
        detect_results = []

        for domain in alive_domains:
            logger.info(f"开始规则检测域名：{domain}")

            whois_info = self.phish_tool.get_whois_info(domain)
            ip_info = self.phish_tool.get_ip_info(domain)
            ssl_info = self.phish_tool.get_ssl_cert(domain)
            content_info = self.phish_tool.get_web_content(domain)
            associated_domains = self.phish_tool.check_associated_domain(domain, ip_info.get("ip", ""))

            all_info = {
                "domain": domain,
                "domain_asset": {
                    "fqdn": parse_domain_asset(domain).fqdn,
                    "subdomain": parse_domain_asset(domain).subdomain,
                    "domain": parse_domain_asset(domain).domain,
                    "suffix": parse_domain_asset(domain).suffix,
                    "registered_domain": parse_domain_asset(domain).registered_domain,
                },
                "whois": whois_info,
                "ip": ip_info,
                "ssl": ssl_info,
                "content": content_info,
                "associated_domains": associated_domains,
                "detect_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }

            rule_result = self.phish_tool.judge_phishing(all_info)
            all_info.update(rule_result)
            detect_results.append(all_info)

            logger.info(
                f"规则检测完成 - 域名: {domain}, 规则分: {rule_result['rule_score']}, 等级: {rule_result['rule_level']}"
            )

        detect_file = self.target_result_dir / "full_dimension_detect.json"
        with open(detect_file, "w", encoding="utf-8") as f:
            json.dump(detect_results, f, ensure_ascii=False, indent=2)

        logger.info(f"已保存全维度规则检测结果: {detect_file}")
        return detect_results

    def step5_llm_phishing_detection(self, alive_domains: List[str]) -> Dict[str, Dict[str, Any]]:
        logger.info("步骤5: LLM 页面钓鱼检测")
        result_map: Dict[str, Dict[str, Any]] = {}

        for domain in alive_domains:
            html = self.fetch_webpage_content(domain)
            if not html:
                logger.info(f"{domain} 页面内容为空，跳过 LLM 检测")
                continue

            analysis = self.llm_detect_phishing(domain, html)
            if analysis:
                analysis["domain"] = domain
                result_map[domain] = analysis
                logger.info(f"{domain} -> LLM phishing={analysis.get('is_phishing')} confidence={analysis.get('confidence')}")
        output_file = self.target_result_dir / "llm_phishing_detection.json"
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(list(result_map.values()), f, indent=2, ensure_ascii=False)

        logger.info(f"LLM 检测结果已保存: {output_file}")
        return result_map

    def fuse_rule_and_llm(self, rule_item: Dict[str, Any], llm_item: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        rule_score = int(rule_item.get("rule_score", 0) or 0)
        rule_reasons = list(rule_item.get("rule_reasons", []))

        llm_adjustment = 0
        synergy_bonus = 0
        llm_result = {}
        llm_reason = ""
        llm_confidence = 0
        llm_is_phishing = False
        llm_page_type = "unknown"

        if llm_item:
            llm_result = llm_item
            llm_is_phishing = bool(llm_item.get("is_phishing", False))
            llm_confidence = int(llm_item.get("confidence", 0) or 0)
            llm_reason = str(llm_item.get("reason", "") or "")
            llm_page_type = str(llm_item.get("page_type", "unknown") or "unknown")

            if llm_is_phishing:
                if llm_confidence >= 90:
                    llm_adjustment += 20
                elif llm_confidence >= 80:
                    llm_adjustment += 15
                elif llm_confidence >= 70:
                    llm_adjustment += 10
                elif llm_confidence >= 60:
                    llm_adjustment += 6
                else:
                    llm_adjustment += 3
            else:
                if llm_confidence >= 85:
                    llm_adjustment -= 10
                elif llm_confidence >= 70:
                    llm_adjustment -= 5

            high_risk_page_types = {"fake_login", "fake_payment", "account_verification"}
            medium_risk_page_types = {"logistics_notice"}

            if llm_page_type in high_risk_page_types:
                llm_adjustment += 8
            elif llm_page_type in medium_risk_page_types:
                llm_adjustment += 4

            if rule_score >= 60 and llm_is_phishing and llm_confidence >= 80:
                synergy_bonus += 10
            elif rule_score >= 45 and llm_is_phishing and llm_confidence >= 75:
                synergy_bonus += 6

        final_score = max(0, min(100, rule_score + llm_adjustment + synergy_bonus))
        if final_score >= 80:
            risk_level = "🔴高危"
            is_phishing = True
        elif final_score >= 50:
            risk_level = "🟡可疑"
            is_phishing = False
        else:
            risk_level = "🟢低风险"
            is_phishing = False

        final_reasons = list(rule_reasons)
        if llm_result:
            if llm_reason:
                final_reasons.append(f"LLM 语义分析：{llm_reason}")
            if llm_page_type and llm_page_type != "unknown":
                final_reasons.append(f"LLM 页面类型识别：{llm_page_type}")
            if synergy_bonus > 0:
                final_reasons.append("规则特征与页面语义特征同时指向钓鱼风险")

        dedup_reasons = []
        seen = set()
        for r in final_reasons:
            if r not in seen:
                seen.add(r)
                dedup_reasons.append(r)

        return {
            "rule_score": rule_score,
            "llm_adjustment": llm_adjustment,
            "synergy_bonus": synergy_bonus,
            "final_score": final_score,
            "risk_level": risk_level,
            "is_phishing": is_phishing,
            "final_reasons": dedup_reasons,
            "llm_refine": {
                "is_phishing": llm_is_phishing,
                "confidence": llm_confidence,
                "core_reason": llm_reason,
                "page_type": llm_page_type,
                "brand_target": llm_result.get("brand_target", "") if llm_result else "",
            }
        }

    def step6_fuse_rule_and_llm(self, rule_results: List[Dict[str, Any]], llm_result_map: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
        logger.info("步骤6：融合规则检测 + LLM 检测")
        fused_results = []

        for item in rule_results:
            domain = item.get("domain")
            llm_item = llm_result_map.get(domain)
            fused = self.fuse_rule_and_llm(item, llm_item)

            merged = dict(item)
            merged.update({
                "llm_result": llm_item or {},
                "rule_score": fused["rule_score"],
                "llm_adjustment": fused["llm_adjustment"],
                "synergy_bonus": fused["synergy_bonus"],
                "final_score": fused["final_score"],
                "risk_level": fused["risk_level"],
                "is_phishing": fused["is_phishing"],
                "risk_reason": fused["final_reasons"],
                "llm_refine": fused["llm_refine"],
            })
            fused_results.append(merged)

        output_file = self.target_result_dir / "fused_phishing_detection.json"
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(fused_results, f, ensure_ascii=False, indent=2)
        logger.info(f"融合检测结果已保存: {output_file}")
        return fused_results

    def apply_domain_semantic_adjustment(self, fused_results: List[Dict[str, Any]], semantic_result_map: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
        logger.info("步骤6.5：融合域名语义分析结果")
        adjusted_results = []

        for item in fused_results:
            domain = str(item.get("domain", "")).strip().lower()
            semantic_item = semantic_result_map.get(domain, {})

            semantic_score = int(semantic_item.get("semantic_risk_score", 0) or 0)
            semantic_reason = str(semantic_item.get("reason", "") or "")
            semantic_intent = str(semantic_item.get("attack_intent", "unknown") or "unknown")
            brand_abuse = bool(semantic_item.get("brand_abuse", False))

            semantic_adjustment = 0
            if semantic_score >= 90:
                semantic_adjustment += 15
            elif semantic_score >= 80:
                semantic_adjustment += 10
            elif semantic_score >= 70:
                semantic_adjustment += 6
            elif semantic_score >= 60:
                semantic_adjustment += 3

            if brand_abuse:
                semantic_adjustment += 5

            if semantic_intent in {"login", "verification", "payment"}:
                semantic_adjustment += 5
            elif semantic_intent in {"support", "tracking"}:
                semantic_adjustment += 2

            old_final_score = int(item.get("final_score", 0) or 0)
            new_final_score = max(0, min(100, old_final_score + semantic_adjustment))

            if new_final_score >= 80:
                new_risk_level = "🔴高危"
                new_is_phishing = True
            elif new_final_score >= 50:
                new_risk_level = "🟡可疑"
                new_is_phishing = False
            else:
                new_risk_level = "🟢低风险"
                new_is_phishing = False

            risk_reason = list(item.get("risk_reason", []) or [])
            if semantic_reason:
                risk_reason.append(f"域名语义分析：{semantic_reason}")
            if semantic_intent and semantic_intent != "unknown":
                risk_reason.append(f"域名攻击意图：{semantic_intent}")
            if semantic_adjustment > 0:
                risk_reason.append("域名命名模式与钓鱼语义特征匹配")

            dedup_reason = []
            seen = set()
            for r in risk_reason:
                if r not in seen:
                    seen.add(r)
                    dedup_reason.append(r)

            merged = dict(item)
            merged.update({
                "semantic_result": semantic_item,
                "semantic_adjustment": semantic_adjustment,
                "final_score": new_final_score,
                "risk_level": new_risk_level,
                "is_phishing": new_is_phishing,
                "risk_reason": dedup_reason,
            })
            adjusted_results.append(merged)

        output_file = self.target_result_dir / "fused_phishing_detection_with_domain_semantic.json"
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(adjusted_results, f, ensure_ascii=False, indent=2)

        logger.info(f"融合域名语义后的检测结果已保存：{output_file}")
        return adjusted_results

    def save_final_summary(self, target_domain: str, candidate_domain_count: int, rounds_used: int, converged_round: Optional[int], convergence_reason: str, stable_active_domains: List[str], http_alive_sites: List[str], fused_results: List[Dict[str, Any]], start_time: float) -> Dict[str, Any]:
        phishing_sites = [r for r in fused_results if r.get("is_phishing")]
        suspicious_sites = [r for r in fused_results if r.get("risk_level") == "🟡可疑"]

        summary = {
            "target_domain": target_domain,
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "elapsed_seconds": round(time.time() - start_time, 2),
            "executed_rounds": rounds_used,
            "converged_round": converged_round,
            "convergence_reason": convergence_reason,
            "candidate_domain_count": candidate_domain_count,
            "stable_active_count": len(stable_active_domains),
            "stable_active_domains": stable_active_domains,
            "http_alive_count": len(http_alive_sites),
            "http_alive_sites": http_alive_sites,
            "fused_result_count": len(fused_results),
            "phishing_count": len(phishing_sites),
            "suspicious_count": len(suspicious_sites),
            "results": fused_results,
        }

        self.final_results_file = self.target_result_dir / "comprehensive_results.json"
        with open(self.final_results_file, "w", encoding="utf-8") as f:
            json.dump(summary, f, ensure_ascii=False, indent=2)

        logger.info(f"最终汇总结果已保存: {self.final_results_file}")
        return summary

    def run_full_pipeline(self, target_domain: str) -> bool:
        self.current_target = target_domain
        self.target_result_dir = self.results_dir / target_domain.replace(".", "_")
        self.target_result_dir.mkdir(parents=True, exist_ok=True)

        try:
            target_domain = normalize_domain_input(target_domain)
        except DomainInputError as e:
            logger.error(f"目标域名输入无效: {e}")
            return False

        logger.info(f"开始运行域名监控管道 - 目标域名: {target_domain}")
        logger.info("运行模式: 先 DNS，后 LLM 域名语义分析 + 规则检测 + 页面 LLM 融合评分")

        start_time = time.time()

        try:
            if not self.step1_generate_domain_variants(target_domain):
                logger.error("步骤1失败，停止管道执行")
                return False

            self.step1_5_generate_semantic_phishing(target_domain)

            if not self.merge_domain_sources():
                logger.error("合并域名失败")
                return False

            max_rounds = max(2, int(os.getenv("XDIG_STABLE_MAX_ROUNDS", "3")))
            min_hits = max(1, int(os.getenv("XDIG_STABLE_MIN_HITS", "2")))
            if min_hits > max_rounds:
                min_hits = max_rounds

            abs_delta_threshold = max(0, int(os.getenv("XDIG_STABLE_ABS_DELTA", "2")))
            rel_delta_threshold = max(0.0, float(os.getenv("XDIG_STABLE_REL_DELTA", "0.02")))
            scan_rate = max(10, int(os.getenv("XDIG_RATE", "500")))
            candidate_limit = max(0, int(os.getenv("XDIG_CANDIDATE_LIMIT", "0")))

            previous_active_count = None
            round_active_counts: List[int] = []
            hit_counter: Dict[str, int] = {}
            round_active_domains_map: Dict[int, List[str]] = {}

            convergence_reason = "达到最大轮次，采用命中次数统计结果"
            rounds_used = 0
            converged_round: Optional[int] = None

            base_scan_file = self.domain_variants_file

            if candidate_limit > 0 and base_scan_file and base_scan_file.exists():
                limited_file = self.results_dir / f"{target_domain}_candidates_limit_{candidate_limit}.txt"
                kept = 0
                with open(base_scan_file, "r", encoding="utf-8", errors="ignore") as src, open(limited_file, "w", encoding="utf-8") as dst:
                    for line in src:
                        line = line.strip()
                        if not line:
                            continue
                        dst.write(line + "\n")
                        kept += 1
                        if kept >= candidate_limit:
                            break
                base_scan_file = limited_file
                logger.info(f"已启用候选域名限制: limit={candidate_limit}, 文件={base_scan_file}")

            candidate_domain_count = 0
            if base_scan_file and base_scan_file.exists():
                with open(base_scan_file, "r", encoding="utf-8", errors="ignore") as f:
                    candidate_domain_count = sum(1 for line in f if line.strip())

            logger.info(f"候选域名总数: {candidate_domain_count}, 来源文件: {base_scan_file}")

            for round_idx in range(1, max_rounds + 1):
                rounds_used = round_idx
                logger.info(f"xdig 多轮探测: 第 {round_idx}/{max_rounds} 轮, 输入文件={base_scan_file}")

                if not self.step2_run_xdig_scan(target_domain=target_domain, domainfile=str(base_scan_file), rate=scan_rate):
                    logger.error(f"第 {round_idx} 轮 xdig 探测失败")
                    return False

                active_domains = sorted(set(
                    d.strip().lower()
                    for d in self.extract_active_domains_from_xdig()
                    if d and d.strip()
                ))

                active_count = len(active_domains)
                round_active_counts.append(active_count)
                round_active_domains_map[round_idx] = active_domains
                logger.info(f"第 {round_idx} 轮存活数量: {active_count}")

                try:
                    round_active_file = self.results_dir / f"{target_domain}_xdig_round_{round_idx}_active.txt"
                    with open(round_active_file, "w", encoding="utf-8") as rf:
                        for d in active_domains:
                            rf.write(d + "\n")
                except Exception as wf_e:
                    logger.warning(f"写入轮次候选文件失败: {wf_e}")

                for d in active_domains:
                    hit_counter[d] = hit_counter.get(d, 0) + 1

                if previous_active_count is not None:
                    abs_delta = abs(active_count - previous_active_count)
                    rel_delta = (abs_delta / previous_active_count) if previous_active_count > 0 else 0.0
                    logger.info(
                        f"第 {round_idx} 轮与上一轮变化: abs={abs_delta}, rel={rel_delta:.4f}, 阈值(abs<={abs_delta_threshold} 或 rel<={rel_delta_threshold:.4f})"
                    )
                    if abs_delta <= abs_delta_threshold or rel_delta <= rel_delta_threshold:
                        convergence_reason = f"第{round_idx}轮收敛: 相邻轮次变化满足阈值(abs={abs_delta}, rel={rel_delta:.4f})"
                        converged_round = round_idx
                        logger.info(convergence_reason)
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
            logger.info(f"稳定存活域名数量：{len(stable_active_domains)}")

            try:
                hit_stat_file = self.target_result_dir / "xdig_hit_counter.json"
                hit_stat_data = {
                    "target_domain": target_domain,
                    "candidate_domain_count": candidate_domain_count,
                    "max_rounds": max_rounds,
                    "rounds_used": rounds_used,
                    "min_hits": min_hits,
                    "round_active_counts": round_active_counts,
                    "round_active_domains_map": round_active_domains_map,
                    "converged_round": converged_round,
                    "convergence_reason": convergence_reason,
                    "hit_counter": dict(sorted(hit_counter.items(), key=lambda x: (-x[1], x[0]))),
                    "stable_active_domains": stable_active_domains,
                }
                with open(hit_stat_file, "w", encoding="utf-8") as f:
                    json.dump(hit_stat_data, f, ensure_ascii=False, indent=2)
                logger.info(f"已保存 xdig 命中统计数据: {hit_stat_file}")
            except Exception as e:
                logger.warning(f"保存 xdig 命中统计数据失败: {e}")

            logger.info(f"稳定口径：rounds={rounds_used}, min_hits={min_hits}, stable_active={len(stable_active_domains)}")

            if not stable_active_domains:
                logger.warning("无稳定存活域名，停止管道执行")
                return True

            semantic_result_map = self.step2_5_semantic_analyze_active_domains(stable_active_domains)
            httpx_alive_sites = self.step3_http_probe(stable_active_domains)
            logger.info(f"HTTP 可访问网站数量：{len(httpx_alive_sites)}")

            http_result_file = self.target_result_dir / "http_alive_sites.txt"
            with open(http_result_file, "w", encoding="utf-8") as f:
                for site in httpx_alive_sites:
                    f.write(site + "\n")

            rule_results = self.step4_full_dimension_detect(httpx_alive_sites)
            llm_result_map = self.step5_llm_phishing_detection(httpx_alive_sites)
            fused_results = self.step6_fuse_rule_and_llm(rule_results, llm_result_map)
            fused_results = self.apply_domain_semantic_adjustment(fused_results, semantic_result_map)

            summary = self.save_final_summary(
                target_domain=target_domain,
                candidate_domain_count=candidate_domain_count,
                rounds_used=rounds_used,
                converged_round=converged_round,
                convergence_reason=convergence_reason,
                stable_active_domains=stable_active_domains,
                http_alive_sites=httpx_alive_sites,
                fused_results=fused_results,
                start_time=start_time,
            )

            logger.info(
                f"稳定口径: rounds={rounds_used}, min_hits={min_hits}, stable_active={len(stable_active_domains)}, http_alive={len(httpx_alive_sites)}, phishing={summary['phishing_count']}"
            )
            elapsed_time = time.time() - start_time
            logger.info(f"管道执行完成，总耗时: {elapsed_time:.2f} 秒")
            logger.info("结果文件:")
            logger.info(f"  - xdig结果: {self.xdig_results_file}")
            logger.info(f"  - 汇总结果: {self.final_results_file}")
            return True

        except Exception as e:
            logger.error(f"管道执行过程中出错: {e}", exc_info=True)
            return False


def build_default_official_whitelist(target_domain: str) -> Dict[str, Any]:
    """
    这里不再只是把 target_domain 自己塞进白名单，
    而是尽量构造“官方根域 + 已知业务子域 + 品牌词”。
    """
    target_domain = (target_domain or "").strip().lower()
    asset = parse_domain_asset(target_domain)

    root_domain = asset.registered_domain
    brand_guess = asset.domain.upper() if asset.domain else ""

    root_domains = [root_domain] if root_domain else []
    known_fqdns = []
    brand_tokens = []

    if asset.domain:
        brand_tokens.extend(split_brand_tokens(asset.domain))
        brand_tokens.append(asset.domain)

    # 针对你当前这个案例直接增强
    if root_domain == "coscoshipping.com":
        known_fqdns.extend([
            "boao.coscoshipping.com",
            "lines.coscoshipping.com",
            "synconhub.coscoshipping.com",
            "ebusiness.coscoshipping.com",
        ])
        brand_tokens.extend(["cosco", "shipping", "boao", "coscoshipping"])
        brand_guess = "COSCO SHIPPING"

    # 如果用户输入的本身是业务子域，也纳入官方已知 FQDN
    if target_domain and target_domain != root_domain:
        known_fqdns.append(target_domain)

    # 兼容旧字段 domain
    domain_field = sorted(set(root_domains + known_fqdns))

    return {
        "domain": domain_field,
        "root_domains": sorted(set(root_domains)),
        "known_fqdns": sorted(set(known_fqdns)),
        "brand_tokens": sorted(set(t.lower() for t in brand_tokens if t)),
        "ns": [],
        "ip_country": ["CN"],
        "ssl_issuer": ["DigiCert", "GlobalSign", "Sectigo", "GeoTrust", "Thawte"],
        "trusted_registrar": ["Alibaba Cloud", "GoDaddy", "Namecheap", "Dynadot"],
        "brand": brand_guess
    }


def main():
    import argparse

    parser = argparse.ArgumentParser(description="域名监控数据处理管道（规则 + LLM 融合版）")
    parser.add_argument("-d", "--domain", required=True, help="目标域名（例如: example.com）")
    parser.add_argument("-b", "--base-dir", default=".", help="项目基础目录（默认当前目录）")
    parser.add_argument("-v", "--verbose", action="store_true", help="详细输出")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    official_whitelist = build_default_official_whitelist(args.domain)
    pipeline = DomainMonitoringPipeline(base_dir=args.base_dir, official_whitelist=official_whitelist)
    success = pipeline.run_full_pipeline(args.domain)

    if success:
        print("\n✅ 监控管道执行成功!")
        print(f"   结果目录: {pipeline.target_result_dir}")

        if pipeline.final_results_file and pipeline.final_results_file.exists():
            try:
                with open(pipeline.final_results_file, "r", encoding="utf-8") as f:
                    data = json.load(f)

                print(f"   执行轮次: {data.get('executed_rounds', 0)}")
                print(f"   收敛轮次: {data.get('converged_round', '未提前收敛')}")
                print(f"   候选域名总数: {data.get('candidate_domain_count', 0)}")
                print(f"   稳定存活域名: {data.get('stable_active_count', 0)}")
                print(f"   HTTP存活站点: {data.get('http_alive_count', 0)}")
                print(f"   高危钓鱼站点: {data.get('phishing_count', 0)}")
                print(f"   可疑站点: {data.get('suspicious_count', 0)}")
                print(f"   收敛原因: {data.get('convergence_reason', '')}")
            except Exception as e:
                logger.warning(f"读取最终结果失败: {e}")
    else:
        print("\n❌ 监控管道执行失败!")
        sys.exit(1)


if __name__ == "__main__":
    main()
