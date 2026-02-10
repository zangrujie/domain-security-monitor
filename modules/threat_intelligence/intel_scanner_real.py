#!/usr/bin/env python3
"""
真实威胁情报扫描器 - 集成真实威胁情报API
支持VirusTotal、URLhaus等
"""

import os
import requests
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
import logging
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
from urllib.parse import urlparse

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 用户代理
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# 已知恶意域名列表（示例）
KNOWN_MALICIOUS_DOMAINS = {
    'malicious-example.com': {'reason': '已知恶意软件分发', 'source': '内部黑名单'},
    'phishing-sample.net': {'reason': '钓鱼网站', 'source': '内部黑名单'},
    'spam-domain.org': {'reason': '垃圾邮件源', 'source': '内部黑名单'}
}

# 已知高风险TLD
HIGH_RISK_TLDS = ['.top', '.xyz', '.club', '.win', '.bid', '.loan', '.date', '.tk', '.ml', '.ga', '.cf']

# API密钥从环境变量获取
VT_API_KEY = os.getenv('VT_API_KEY')
URLHAUS_API_KEY = None  # URLhaus无需API密钥

class ThreatIntelligenceScanner:
    """威胁情报扫描器类"""
    
    def __init__(self, max_workers: int = 3, rate_limit_delay: float = 1.0):
        """
        初始化威胁情报扫描器
        
        Args:
            max_workers: 最大并发工作线程数
            rate_limit_delay: API调用延迟（秒），用于遵守速率限制
        """
        self.max_workers = max_workers
        self.rate_limit_delay = rate_limit_delay
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': USER_AGENT})
        
        # 缓存最近检查结果（防止重复调用API）
        self.result_cache = {}
        self.cache_ttl = timedelta(hours=1)
        
        logger.info(f"初始化威胁情报扫描器，VT API密钥: {'已配置' if VT_API_KEY else '未配置'}")
    
    def check_virustotal(self, domain: str) -> Dict[str, Any]:
        """
        使用真实VirusTotal API检查域名
        
        文档: https://developers.virustotal.com/reference/domain-info
        
        Args:
            domain: 要检查的域名
            
        Returns:
            包含检查结果的字典
        """
        if not VT_API_KEY:
            logger.warning("VirusTotal API密钥未配置，使用模拟模式")
            return self.check_virustotal_simulated(domain)
        
        # 检查缓存
        cache_key = f"vt_{domain}"
        cached_result = self.result_cache.get(cache_key)
        if cached_result and datetime.now() - cached_result['timestamp'] < self.cache_ttl:
            logger.debug(f"从缓存返回VirusTotal检查结果: {domain}")
            return cached_result['result']
        
        try:
            url = f"https://www.virustotal.com/api/v3/domains/{domain}"
            headers = {
                'x-apikey': VT_API_KEY,
                'Accept': 'application/json'
            }
            
            # 遵守速率限制
            time.sleep(self.rate_limit_delay)
            
            response = self.session.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                attributes = data.get('data', {}).get('attributes', {})
                
                # 解析分析结果
                last_analysis_stats = attributes.get('last_analysis_stats', {})
                reputation = attributes.get('reputation', 0)
                categories = attributes.get('categories', {})
                
                result = {
                    'source': 'virustotal',
                    'reputation_score': reputation,
                    'malicious_detections': last_analysis_stats.get('malicious', 0),
                    'suspicious_detections': last_analysis_stats.get('suspicious', 0),
                    'total_engines': sum(last_analysis_stats.values()),
                    'last_analysis_date': attributes.get('last_analysis_date'),
                    'categories': list(categories.values()),
                    'whois': attributes.get('whois'),
                    'registrar': attributes.get('registrar'),
                    'status': 'found',
                    'api_call_success': True
                }
                
            elif response.status_code == 404:
                # 域名未找到
                result = {
                    'source': 'virustotal',
                    'reputation_score': 0,
                    'malicious_detections': 0,
                    'suspicious_detections': 0,
                    'total_engines': 0,
                    'last_analysis_date': None,
                    'categories': [],
                    'status': 'not_found',
                    'api_call_success': True
                }
                
            elif response.status_code == 401:
                logger.error("VirusTotal API密钥无效")
                result = {
                    'source': 'virustotal',
                    'reputation_score': 0,
                    'malicious_detections': 0,
                    'suspicious_detections': 0,
                    'total_engines': 0,
                    'last_analysis_date': None,
                    'categories': [],
                    'status': 'api_key_invalid',
                    'error': 'API密钥无效',
                    'api_call_success': False
                }
                
            elif response.status_code == 429:
                logger.warning("VirusTotal API速率限制")
                result = {
                    'source': 'virustotal',
                    'reputation_score': 0,
                    'malicious_detections': 0,
                    'suspicious_detections': 0,
                    'total_engines': 0,
                    'last_analysis_date': None,
                    'categories': [],
                    'status': 'rate_limited',
                    'error': 'API速率限制',
                    'api_call_success': False
                }
                
            else:
                logger.error(f"VirusTotal API错误: {response.status_code}")
                result = {
                    'source': 'virustotal',
                    'reputation_score': 0,
                    'malicious_detections': 0,
                    'suspicious_detections': 0,
                    'total_engines': 0,
                    'last_analysis_date': None,
                    'categories': [],
                    'status': f'api_error_{response.status_code}',
                    'error': f'API错误 {response.status_code}',
                    'api_call_success': False
                }
                
        except requests.exceptions.Timeout:
            logger.error(f"VirusTotal API请求超时: {domain}")
            result = {
                'source': 'virustotal',
                'reputation_score': 0,
                'malicious_detections': 0,
                'suspicious_detections': 0,
                'total_engines': 0,
                'last_analysis_date': None,
                'categories': [],
                'status': 'timeout',
                'error': '请求超时',
                'api_call_success': False
            }
            
        except Exception as e:
            logger.error(f"VirusTotal检查异常 {domain}: {e}")
            result = {
                'source': 'virustotal',
                'reputation_score': 0,
                'malicious_detections': 0,
                'suspicious_detections': 0,
                'total_engines': 0,
                'last_analysis_date': None,
                'categories': [],
                'status': 'error',
                'error': str(e),
                'api_call_success': False
            }
        
        # 缓存结果
        self.result_cache[cache_key] = {
            'timestamp': datetime.now(),
            'result': result
        }
        
        return result
    
    def check_virustotal_simulated(self, domain: str) -> Dict[str, Any]:
        """
        模拟VirusTotal域名检查（备用方案）
        """
        # 模拟检查逻辑
        time.sleep(0.1)
        
        # 基于域名特征的简单模拟
        domain_hash = hashlib.md5(domain.encode()).hexdigest()
        hash_int = int(domain_hash[:8], 16)
        
        # 模拟检测结果
        simulated_score = (hash_int % 100) / 100.0
        
        # 模拟恶意软件检测
        malware_detections = hash_int % 10 if simulated_score > 0.3 else 0
        
        return {
            'source': 'virustotal_simulated',
            'reputation_score': round(1.0 - simulated_score, 2),
            'malicious_detections': malware_detections,
            'suspicious_detections': max(0, malware_detections - 2),
            'total_engines': 90,
            'last_analysis_date': datetime.now().isoformat(),
            'categories': ['simulated'] if simulated_score > 0.5 else [],
            'status': 'simulated_no_api_key',
            'note': '实际使用需要配置VirusTotal API密钥',
            'api_call_success': True
        }
    
    def check_urlhaus(self, domain: str) -> Dict[str, Any]:
        """
        检查URLhaus恶意URL数据库（公开API）
        """
        # 检查缓存
        cache_key = f"urlhaus_{domain}"
        cached_result = self.result_cache.get(cache_key)
        if cached_result and datetime.now() - cached_result['timestamp'] < self.cache_ttl:
            logger.debug(f"从缓存返回URLhaus检查结果: {domain}")
            return cached_result['result']
        
        try:
            url = f"https://urlhaus-api.abuse.ch/v1/host/{domain}/"
            headers = {
                'Accept': 'application/json'
            }
            
            # URLhaus不需要延迟，但避免过频调用
            time.sleep(0.5)
            
            response = self.session.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('query_status') == 'ok':
                    result = {
                        'source': 'urlhaus',
                        'malicious': True,
                        'threats': data.get('urls', []),
                        'threat_count': len(data.get('urls', [])),
                        'first_seen': data.get('firstseen'),
                        'last_online': data.get('last_online'),
                        'status': 'found',
                        'api_call_success': True
                    }
                else:
                    result = {
                        'source': 'urlhaus',
                        'malicious': False,
                        'status': 'not_found',
                        'query_status': data.get('query_status'),
                        'api_call_success': True
                    }
            else:
                result = {
                    'source': 'urlhaus',
                    'malicious': False,
                    'status': f'api_error_{response.status_code}',
                    'error': 'API请求失败',
                    'api_call_success': False
                }
                
        except Exception as e:
            logger.debug(f"URLhaus检查失败 {domain}: {e}")
            result = {
                'source': 'urlhaus',
                'malicious': False,
                'status': 'error',
                'error': str(e),
                'api_call_success': False
            }
        
        # 缓存结果
        self.result_cache[cache_key] = {
            'timestamp': datetime.now(),
            'result': result
        }
        
        return result
    
    def check_phishtank_simulated(self, domain: str) -> Dict[str, Any]:
        """
        模拟PhishTank检查
        """
        # 简单的基于关键词的模拟检查
        phishing_keywords = ['login', 'secure', 'verify', 'account', 'bank', 'paypal', 'auth', 'signin']
        
        has_phishing_keyword = any(keyword in domain.lower() for keyword in phishing_keywords)
        
        # 检查已知恶意列表
        is_known_phishing = domain in KNOWN_MALICIOUS_DOMAINS
        
        return {
            'source': 'phishtank_simulated',
            'phishing_suspected': has_phishing_keyword or is_known_phishing,
            'known_phishing': is_known_phishing,
            'matched_keywords': [k for k in phishing_keywords if k in domain.lower()],
            'status': 'simulated',
            'note': '实际使用需要PhishTank API或数据库',
            'api_call_success': True
        }
    
    def check_tld_risk(self, domain: str) -> Dict[str, Any]:
        """
        检查TLD（顶级域名）风险
        """
        tld_risk = 'low'
        matched_tld = None
        
        for risky_tld in HIGH_RISK_TLDS:
            if domain.endswith(risky_tld):
                tld_risk = 'high'
                matched_tld = risky_tld
                break
        
        return {
            'source': 'tld_analysis',
            'risk_level': tld_risk,
            'matched_tld': matched_tld,
            'high_risk_tlds': HIGH_RISK_TLDS,
            'status': 'analyzed',
            'api_call_success': True
        }
    
    def check_domain_age_simulated(self, domain: str) -> Dict[str, Any]:
        """
        模拟域名年龄分析
        """
        # 简单模拟：基于域名长度的"年龄"推测
        domain_length = len(domain.split('.')[0])
        
        if domain_length <= 5:
            age_estimate = 'old'
        elif domain_length <= 8:
            age_estimate = 'medium'
        else:
            age_estimate = 'new'
        
        return {
            'source': 'domain_age_simulated',
            'estimated_age': age_estimate,
            'domain_length': domain_length,
            'status': 'simulated',
            'note': '实际年龄需要WHOIS查询',
            'api_call_success': True
        }
    
    def check_internal_blacklist(self, domain: str) -> Dict[str, Any]:
        """
        检查内部黑名单
        """
        if domain in KNOWN_MALICIOUS_DOMAINS:
            return {
                'source': 'internal_blacklist',
                'listed': True,
                'reason': KNOWN_MALICIOUS_DOMAINS[domain]['reason'],
                'source_detail': KNOWN_MALICIOUS_DOMAINS[domain]['source'],
                'status': 'found',
                'api_call_success': True
            }
        else:
            return {
                'source': 'internal_blacklist',
                'listed': False,
                'status': 'not_found',
                'api_call_success': True
            }
    
    def calculate_threat_risk_score(self, threat_results: Dict[str, Any]) -> float:
        """
        计算威胁情报风险评分（0-100，越高风险越高）
        """
        risk_factors = []
        
        # 1. VirusTotal检测（40分）
        vt_result = threat_results.get('virustotal', {})
        if vt_result.get('api_call_success', False):
            if vt_result.get('status') == 'found':
                reputation = vt_result.get('reputation_score', 0)
                if reputation < -100:
                    risk_factors.append(40)
                elif reputation < 0:
                    risk_factors.append(25)
                
                malicious = vt_result.get('malicious_detections', 0)
                suspicious = vt_result.get('suspicious_detections', 0)
                
                if malicious >= 5:
                    risk_factors.append(35)
                elif malicious >= 1:
                    risk_factors.append(20)
                
                if suspicious >= 5:
                    risk_factors.append(15)
        elif vt_result.get('status') == 'simulated_no_api_key':
            # 模拟模式下的评分
            rep_score = vt_result.get('reputation_score', 0.5)
            if rep_score < 0.3:
                risk_factors.append(30)
            elif rep_score < 0.6:
                risk_factors.append(15)
            
            malicious_detections = vt_result.get('malicious_detections', 0)
            if malicious_detections >= 5:
                risk_factors.append(30)
            elif malicious_detections >= 1:
                risk_factors.append(15)
        
        # 2. URLhaus检测（35分）
        urlhaus_result = threat_results.get('urlhaus', {})
        if urlhaus_result.get('api_call_success', False) and urlhaus_result.get('malicious'):
            risk_factors.append(35)
        
        # 3. PhishTank检测（30分）
        phishtank_result = threat_results.get('phishtank', {})
        if phishtank_result.get('api_call_success', True):
            if phishtank_result.get('known_phishing'):
                risk_factors.append(30)
            elif phishtank_result.get('phishing_suspected'):
                risk_factors.append(20)
        
        # 4. TLD风险（25分）
        tld_result = threat_results.get('tld_analysis', {})
        if tld_result.get('api_call_success', True) and tld_result.get('risk_level') == 'high':
            risk_factors.append(25)
        
        # 5. 域名年龄风险（15分）
        age_result = threat_results.get('domain_age', {})
        if age_result.get('api_call_success', True) and age_result.get('estimated_age') == 'new':
            risk_factors.append(15)
        
        # 6. 内部黑名单（40分）
        blacklist_result = threat_results.get('internal_blacklist', {})
        if blacklist_result.get('api_call_success', True) and blacklist_result.get('listed'):
            risk_factors.append(40)
        
        # 计算总分（威胁情报权重20%）
        total_risk = min(100, sum(risk_factors))
        weighted_risk = total_risk * 0.20  # 威胁情报权重20%
        
        return round(weighted_risk, 2)
    
    def check_domain_reputation(self, domain: str) -> Dict[str, Any]:
        """
        检查单个域名的多源威胁情报
        """
        start_time = time.time()
        
        threat_results = {}
        
        try:
            # 1. 检查内部黑名单
            threat_results['internal_blacklist'] = self.check_internal_blacklist(domain)
            
            # 2. VirusTotal检查
            threat_results['virustotal'] = self.check_virustotal(domain)
            
            # 3. URLhaus检查
            threat_results['urlhaus'] = self.check_urlhaus(domain)
            
            # 4. PhishTank检查
            threat_results['phishtank'] = self.check_phishtank_simulated(domain)
            
            # 5. TLD风险分析
            threat_results['tld_analysis'] = self.check_tld_risk(domain)
            
            # 6. 域名年龄分析
            threat_results['domain_age'] = self.check_domain_age_simulated(domain)
            
            # 计算综合风险评分
            threat_risk_score = self.calculate_threat_risk_score(threat_results)
            
            # 确定API调用成功率
            api_success_count = sum(1 for r in threat_results.values() if r.get('api_call_success', False))
            api_total_count = len(threat_results)
            api_success_rate = api_success_count / api_total_count if api_total_count > 0 else 0
            
            result = {
                'domain': domain,
                'check_timestamp': datetime.now().isoformat(),
                'check_duration_seconds': round(time.time() - start_time, 2),
                'threat_sources_checked': list(threat_results.keys()),
                'threat_results': threat_results,
                'threat_risk_score': threat_risk_score,
                'risk_level': 'high' if threat_risk_score > 15 else 'medium' if threat_risk_score > 8 else 'low',
                'api_success_rate': round(api_success_rate, 2),
                'has_real_api_data': any(r.get('status') not in ['simulated', 'simulated_no_api_key'] 
                                        for r in threat_results.values() if r.get('api_call_success', False))
            }
            
            logger.info(f"威胁情报检查完成: {domain}, 风险评分: {threat_risk_score}, API成功率: {api_success_rate:.0%}")
            return result
            
        except Exception as e:
            logger.error(f"威胁情报检查失败 {domain}: {e}")
            return {
                'domain': domain,
                'check_timestamp': datetime.now().isoformat(),
                'check_duration_seconds': round(time.time() - start_time, 2),
                'error': str(e),
                'threat_risk_score': 0.0,
                'risk_level': 'unknown',
                'api_success_rate': 0.0,
                'has_real_api_data': False
            }
    
    def check_multiple_domains(self, domains: List[str]) -> List[Dict[str, Any]]:
        """
        批量检查多个域名的威胁情报
        """
        results = []
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_domain = {}
            
            for domain in domains:
                future = executor.submit(self.check_domain_reputation, domain)
                future_to_domain[future] = domain
            
            # 收集结果
            for future in as_completed(future_to_domain):
                domain = future_to_domain[future]
                try:
                    result = future.result(timeout=30)
                    results.append(result)
                except Exception as e:
                    logger.error(f"处理域名 {domain} 时出错: {e}")
                    results.append({
                        'domain': domain,
                        'check_timestamp': datetime.now().isoformat(),
                        'error': str(e),
                        'threat_risk_score': 0.0,
                        'risk_level': 'unknown',
                        'api_success_rate': 0.0,
                        'has_real_api_data': False
                    })
        
        # 按风险评分排序
        results.sort(key=lambda x: x.get('threat_risk_score', 0), reverse=True)
        
        return results
    
    def scan_file(self, input_file: str, output_file: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        从文件读取域名并批量检查威胁情报
        """
        # 读取域名列表
        domains = []
        try:
            with open(input_file, 'r', encoding='utf-8') as f:
                for line in f:
                    domain = line.strip()
                    if domain and not domain.startswith('#'):
                        domains.append(domain)
        except Exception as e:
            logger.error(f"读取文件 {input_file} 失败: {e}")
            return []
        
        logger.info(f"从 {input_file} 读取了 {len(domains)} 个域名")
        
        # 批量检查
        results = self.check_multiple_domains(domains)
        
        # 保存结果
        if output_file:
            try:
                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(results, f, ensure_ascii=False, indent=2)
                logger.info(f"威胁情报结果已保存到 {output_file}")
            except Exception as e:
                logger.error(f"保存威胁情报结果到 {output_file} 失败: {e}")
        
        # 打印统计信息
        high_risk = sum(1 for r in results if r.get('risk_level') == 'high')
        medium_risk = sum(1 for r in results if r.get('risk_level') == 'medium')
        real_api_data = sum(1 for r in results if r.get('has_real_api_data', False))
        
        logger.info(f"威胁情报检查完成: 高风险 {high_risk}, 中风险 {medium_risk}, 真实API数据 {real_api_data}, 总计 {len(results)}")
        
        return results

def main():
    """
    命令行入口点
    """
    import argparse
    
    parser = argparse.ArgumentParser(description='真实威胁情报检查工具')
    parser.add_argument('-i', '--input', required=True, help='输入文件（每行一个域名）')
    parser.add_argument('-o', '--output', help='输出JSON文件')
    parser.add_argument('-w', '--workers', type=int, default=3, help='并发工作线程数（默认3）')
    parser.add_argument('-d', '--delay', type=float, default=1.0, help='API调用延迟（秒，默认1.0）')
    parser.add_argument('-v', '--verbose', action='store_true', help='详细输出')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # 创建扫描器
    scanner = ThreatIntelligenceScanner(max_workers=args.workers, rate_limit_delay=args.delay)
    
    # 运行检查
    results = scanner.scan_file(args.input, args.output)
    
    # 打印高风险域名
    high_risk_domains = [r for r in results if r.get('risk_level') == 'high']
    if high_risk_domains:
        print("\n高风险域名:")
        for result in high_risk_domains[:10]:
            domain = result['domain']
            score = result.get('threat_risk_score', 0)
            api_success = result.get('api_success_rate', 0)
            real_data = "✓" if result.get('has_real_api_data') else "✗"
            print(f"  {domain}: 威胁评分 {score}, API成功率: {api_success:.0%}, 真实数据: {real_data}")

if __name__ == "__main__":
    main()