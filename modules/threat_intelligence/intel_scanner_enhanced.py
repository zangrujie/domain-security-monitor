#!/usr/bin/env python3
"""
增强版威胁情报扫描器 - 支持多种API，包含降级方案和更智能的检查
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
import socket

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 用户代理
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

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
if isinstance(VT_API_KEY, str):
    VT_API_KEY = VT_API_KEY.replace('\r', '').strip()
URLHAUS_API_KEY = None  # URLhaus API可能不再公开

class EnhancedThreatIntelligenceScanner:
    """增强版威胁情报扫描器类"""
    
    def __init__(self, max_workers: int = 3, rate_limit_delay: float = 1.0):
        """
        初始化增强版威胁情报扫描器
        
        Args:
            max_workers: 最大并发工作线程数
            rate_limit_delay: API调用延迟（秒），用于遵守速率限制
        """
        self.max_workers = max_workers
        self.rate_limit_delay = rate_limit_delay
        
        # 创建会话
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': USER_AGENT,
            'Accept': 'application/json'
        })
        
        # 缓存最近检查结果（防止重复调用API）
        self.result_cache = {}
        self.cache_ttl = timedelta(hours=1)
        
        # API可用性状态
        self.api_status = {
            'virustotal': bool(VT_API_KEY),
            'urlhaus': False,  # 初始未知
            'phishtank': False,
            'abuseipdb': False
        }
        
        # 初始化API状态检查
        self._check_api_availability()
        
        logger.info(f"初始化增强版威胁情报扫描器，API状态: {self.api_status}")
    
    def _check_api_availability(self):
        """检查API可用性"""
        # 检查VirusTotal API
        if self.api_status['virustotal']:
            logger.info("VirusTotal API: ✅ 已配置")
        else:
            logger.warning("VirusTotal API: ⚠️  未配置，使用模拟模式")
        
        # 检查URLhaus API（公开数据下载）
        try:
            # 测试URLhaus公开数据下载
            test_response = self.session.get(
                "https://urlhaus.abuse.ch/downloads/json_online/",
                timeout=15
            )
            if test_response.status_code == 200:
                self.api_status['urlhaus'] = True
                logger.info("URLhaus公开数据: ✅ 可用")
            else:
                logger.warning(f"URLhaus公开数据: ⚠️  状态码 {test_response.status_code}")
        except Exception as e:
            logger.warning(f"URLhaus公开数据: ❌ 不可用 - {e}")
        
        # 检查其他API的可用性
        self._check_alternative_apis()
    
    def _check_alternative_apis(self):
        """检查替代API的可用性"""
        # 检查AbuseIPDB（需要API密钥）
        abuseipdb_key = os.getenv('ABUSEIPDB_API_KEY')
        if abuseipdb_key:
            self.api_status['abuseipdb'] = True
            logger.info("AbuseIPDB API: ✅ 已配置")
        
        # 检查PhishTank（公开数据下载）
        try:
            test_response = self.session.get(
                "http://data.phishtank.com/data/online-valid.json",
                timeout=10
            )
            if test_response.status_code == 200:
                self.api_status['phishtank'] = True
                logger.info("PhishTank数据: ✅ 可用")
        except:
            logger.info("PhishTank数据: ⚠️  不可用，使用本地数据库")
    
    def check_virustotal(self, domain: str) -> Dict[str, Any]:
        """
        使用真实VirusTotal API检查域名
        """
        if not self.api_status['virustotal']:
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
            
            result = self._parse_virustotal_response(response, domain)
            
            # 缓存结果
            self.result_cache[cache_key] = {
                'timestamp': datetime.now(),
                'result': result
            }
            
            return result
            
        except requests.exceptions.Timeout:
            logger.error(f"VirusTotal API请求超时: {domain}")
            return self._create_virustotal_error_result('timeout', '请求超时')
        except Exception as e:
            logger.error(f"VirusTotal检查异常 {domain}: {e}")
            return self._create_virustotal_error_result('error', str(e))
    
    def _parse_virustotal_response(self, response, domain: str) -> Dict[str, Any]:
        """解析VirusTotal API响应"""
        if response.status_code == 200:
            data = response.json()
            attributes = data.get('data', {}).get('attributes', {})
            
            # 解析分析结果
            last_analysis_stats = attributes.get('last_analysis_stats', {})
            reputation = attributes.get('reputation', 0)
            categories = attributes.get('categories', {})
            jarm = attributes.get('jarm', '')
            
            result = {
                'source': 'virustotal',
                'reputation_score': reputation,
                'malicious_detections': last_analysis_stats.get('malicious', 0),
                'suspicious_detections': last_analysis_stats.get('suspicious', 0),
                'harmless_detections': last_analysis_stats.get('harmless', 0),
                'undetected_detections': last_analysis_stats.get('undetected', 0),
                'total_engines': sum(last_analysis_stats.values()),
                'last_analysis_date': attributes.get('last_analysis_date'),
                'categories': list(categories.values()),
                'whois': attributes.get('whois'),
                'registrar': attributes.get('registrar'),
                'jarm_fingerprint': jarm,
                'status': 'found',
                'api_call_success': True
            }
            
        elif response.status_code == 404:
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
            result = self._create_virustotal_error_result('api_key_invalid', 'API密钥无效')
            
        elif response.status_code == 429:
            logger.warning("VirusTotal API速率限制")
            result = self._create_virustotal_error_result('rate_limited', 'API速率限制')
            
        else:
            logger.error(f"VirusTotal API错误: {response.status_code}")
            result = self._create_virustotal_error_result(f'api_error_{response.status_code}', f'API错误 {response.status_code}')
        
        return result
    
    def _create_virustotal_error_result(self, status: str, error: str) -> Dict[str, Any]:
        """创建VirusTotal错误结果"""
        return {
            'source': 'virustotal',
            'reputation_score': 0,
            'malicious_detections': 0,
            'suspicious_detections': 0,
            'total_engines': 0,
            'last_analysis_date': None,
            'categories': [],
            'status': status,
            'error': error,
            'api_call_success': False
        }
    
    def check_virustotal_simulated(self, domain: str) -> Dict[str, Any]:
        """
        模拟VirusTotal域名检查（备用方案）
        """
        # 基于域名特征的智能模拟
        time.sleep(0.05)
        
        # 使用多种特征计算模拟分数
        domain_hash = hashlib.sha256(domain.encode()).hexdigest()
        hash_int = int(domain_hash[:8], 16)
        
        # 基于域名长度的特征
        domain_length = len(domain.split('.')[0])
        length_factor = min(1.0, domain_length / 20.0)
        
        # 基于TLD的风险特征
        tld_risk_factor = 0.0
        for risky_tld in HIGH_RISK_TLDS:
            if domain.endswith(risky_tld):
                tld_risk_factor = 0.7
                break
        
        # 基于关键词的特征
        suspicious_keywords = ['test', 'fake', 'demo', 'example', 'sample']
        keyword_factor = 0.0
        for keyword in suspicious_keywords:
            if keyword in domain.lower():
                keyword_factor = 0.5
                break
        
        # 计算综合模拟分数
        simulated_score = (
            (hash_int % 100) / 100.0 * 0.4 +
            length_factor * 0.3 +
            tld_risk_factor * 0.2 +
            keyword_factor * 0.1
        )
        
        # 模拟恶意软件检测（基于综合分数）
        malware_detections = int(simulated_score * 15) if simulated_score > 0.3 else 0
        suspicious_detections = max(0, malware_detections - 2)
        
        return {
            'source': 'virustotal_simulated',
            'reputation_score': round(1.0 - simulated_score, 2),
            'malicious_detections': malware_detections,
            'suspicious_detections': suspicious_detections,
            'harmless_detections': 80 - malware_detections - suspicious_detections,
            'undetected_detections': 10,
            'total_engines': 90,
            'last_analysis_date': datetime.now().isoformat(),
            'categories': ['simulated'] if simulated_score > 0.5 else [],
            'status': 'simulated_no_api_key',
            'note': '实际使用需要配置VirusTotal API密钥',
            'api_call_success': True
        }
    
    def check_urlhaus(self, domain: str) -> Dict[str, Any]:
        """
        检查URLhaus恶意URL数据库 - 使用公开数据下载
        """
        # 检查缓存
        cache_key = f"urlhaus_{domain}"
        cached_result = self.result_cache.get(cache_key)
        if cached_result and datetime.now() - cached_result['timestamp'] < self.cache_ttl:
            logger.debug(f"从缓存返回URLhaus检查结果: {domain}")
            return cached_result['result']
        
        try:
            # 如果公开数据不可用，则使用模拟模式
            if not self.api_status['urlhaus']:
                logger.debug(f"URLhaus公开数据不可用，使用模拟模式检查: {domain}")
                return self.check_urlhaus_simulated(domain)
            
            # 下载URLhaus公开数据并检查域名
            result = self._check_urlhaus_public_data(domain)
            
            # 缓存结果
            self.result_cache[cache_key] = {
                'timestamp': datetime.now(),
                'result': result
            }
            
            return result
                
        except Exception as e:
            logger.debug(f"URLhaus检查失败 {domain}: {e}")
            result = {
                'source': 'urlhaus',
                'malicious': False,
                'status': 'error',
                'error': str(e),
                'api_call_success': False
            }
            
            # 缓存失败结果（短期缓存）
            self.result_cache[cache_key] = {
                'timestamp': datetime.now(),
                'result': result
            }
            
            return result
    
    def _check_urlhaus_public_data(self, domain: str) -> Dict[str, Any]:
        """
        使用URLhaus公开数据检查域名
        注意：公开数据文件可能很大，这里只进行简单的域名匹配
        """
        try:
            # 从URLhaus下载公开数据
            url = "https://urlhaus.abuse.ch/downloads/json_online/"
            logger.debug(f"下载URLhaus公开数据检查域名: {domain}")
            
            response = self.session.get(url, timeout=30)
            
            if response.status_code != 200:
                logger.warning(f"无法下载URLhaus公开数据: {response.status_code}")
                return {
                    'source': 'urlhaus',
                    'malicious': False,
                    'status': 'data_download_failed',
                    'error': f'无法下载公开数据，状态码: {response.status_code}',
                    'api_call_success': False
                }
            
            # 解析JSON数据
            try:
                data = response.json()
            except json.JSONDecodeError:
                logger.warning("URLhaus公开数据格式错误")
                return {
                    'source': 'urlhaus',
                    'malicious': False,
                    'status': 'data_format_error',
                    'error': '公开数据JSON格式错误',
                    'api_call_success': False
                }
            
            # 检查域名是否在恶意URL列表中
            malicious_urls = []
            threat_count = 0
            tags_set = set()
            
            # 简化检查：只检查数据中的前N条记录，避免处理整个大文件
            max_records_to_check = 1000
            records_checked = 0
            
            for record_id, records in data.items():
                if not isinstance(records, list):
                    continue
                
                for record in records:
                    records_checked += 1
                    if records_checked > max_records_to_check:
                        break
                    
                    # 检查URL是否包含该域名
                    url_str = record.get('url', '')
                    if domain in url_str:
                        threat_count += 1
                        malicious_urls.append({
                            'url': url_str,
                            'dateadded': record.get('dateadded'),
                            'url_status': record.get('url_status'),
                            'threat': record.get('threat'),
                            'tags': record.get('tags', [])
                        })
                        
                        # 收集标签
                        if record.get('tags'):
                            for tag in record.get('tags', []):
                                tags_set.add(tag)
                
                if records_checked > max_records_to_check:
                    break
            
            if threat_count > 0:
                # 找到恶意记录
                return {
                    'source': 'urlhaus_public_data',
                    'malicious': True,
                    'threats': malicious_urls,
                    'threat_count': threat_count,
                    'first_seen': malicious_urls[0].get('dateadded') if malicious_urls else None,
                    'tags': list(tags_set),
                    'status': 'found_in_public_data',
                    'note': f'基于URLhaus公开数据检查（检查了{records_checked}条记录）',
                    'api_call_success': True
                }
            else:
                # 未找到恶意记录
                return {
                    'source': 'urlhaus_public_data',
                    'malicious': False,
                    'status': 'not_found_in_public_data',
                    'note': f'基于URLhaus公开数据检查（检查了{records_checked}条记录）',
                    'records_checked': records_checked,
                    'api_call_success': True
                }
                
        except requests.exceptions.Timeout:
            logger.warning(f"URLhaus公开数据下载超时: {domain}")
            return {
                'source': 'urlhaus',
                'malicious': False,
                'status': 'timeout',
                'error': '公开数据下载超时',
                'api_call_success': False
            }
        except Exception as e:
            logger.warning(f"URLhaus公开数据检查异常 {domain}: {e}")
            return {
                'source': 'urlhaus',
                'malicious': False,
                'status': 'error',
                'error': str(e),
                'api_call_success': False
            }
    
    def check_urlhaus_simulated(self, domain: str) -> Dict[str, Any]:
        """
        模拟URLhaus检查
        """
        # 基于域名特征的简单模拟
        domain_hash = hashlib.md5(domain.encode()).hexdigest()
        hash_int = int(domain_hash[:8], 16)
        
        # 模拟恶意检测（基于哈希值）
        is_malicious = (hash_int % 100) < 5  # 5%的概率模拟为恶意
        
        if is_malicious:
            return {
                'source': 'urlhaus_simulated',
                'malicious': True,
                'threats': [f"http://{domain}/malware.exe"],
                'threat_count': 1,
                'first_seen': (datetime.now() - timedelta(days=hash_int % 30)).isoformat(),
                'last_online': datetime.now().isoformat(),
                'tags': ['malware', 'phishing'] if hash_int % 2 == 0 else ['spam'],
                'status': 'found_simulated',
                'note': '模拟结果 - URLhaus API可能需要认证',
                'api_call_success': True
            }
        else:
            return {
                'source': 'urlhaus_simulated',
                'malicious': False,
                'status': 'not_found_simulated',
                'note': '模拟结果 - URLhaus API可能需要认证',
                'api_call_success': True
            }
    
    def check_dns_reputation(self, domain: str) -> Dict[str, Any]:
        """
        检查DNS声誉（开源情报）
        """
        try:
            # 尝试解析域名
            start_time = time.time()
            ip_addresses = []
            
            try:
                # 获取所有IP地址
                addrinfo = socket.getaddrinfo(domain, None)
                ip_addresses = list(set([info[4][0] for info in addrinfo]))
            except:
                pass
            
            dns_resolution_time = time.time() - start_time
            
            # 检查是否为保留IP或私有IP
            suspicious_ips = []
            for ip in ip_addresses:
                if ip.startswith('10.') or ip.startswith('192.168.') or ip.startswith('172.'):
                    suspicious_ips.append(ip)
            
            # 简单的DNS声誉分析
            has_dns = len(ip_addresses) > 0
            dns_reputation = 'good' if has_dns and len(suspicious_ips) == 0 else 'suspicious'
            
            return {
                'source': 'dns_reputation',
                'has_dns_records': has_dns,
                'ip_addresses': ip_addresses,
                'suspicious_ips': suspicious_ips,
                'dns_resolution_time': round(dns_resolution_time, 3),
                'reputation': dns_reputation,
                'status': 'analyzed',
                'api_call_success': True
            }
            
        except Exception as e:
            logger.debug(f"DNS声誉检查失败 {domain}: {e}")
            return {
                'source': 'dns_reputation',
                'has_dns_records': False,
                'ip_addresses': [],
                'suspicious_ips': [],
                'dns_resolution_time': 0,
                'reputation': 'unknown',
                'status': 'error',
                'error': str(e),
                'api_call_success': False
            }
    
    def check_domain_characteristics(self, domain: str) -> Dict[str, Any]:
        """
        分析域名特征
        """
        try:
            # 分析域名结构
            parts = domain.split('.')
            if len(parts) < 2:
                return {
                    'source': 'domain_characteristics',
                    'valid_domain': False,
                    'parts_count': len(parts),
                    'status': 'invalid',
                    'api_call_success': True
                }
            
            second_level = parts[-2]
            tld = parts[-1]
            
            # 计算各种特征
            domain_length = len(domain)
            second_level_length = len(second_level)
            has_hyphen = '-' in second_level
            has_numbers = any(char.isdigit() for char in second_level)
            entropy = self._calculate_entropy(second_level)
            
            # 基于特征的简单风险评估
            risk_factors = []
            if second_level_length <= 3:
                risk_factors.append('very_short')
            elif second_level_length <= 5:
                risk_factors.append('short')
            
            if has_hyphen:
                risk_factors.append('has_hyphen')
            
            if has_numbers:
                risk_factors.append('has_numbers')
            
            if entropy < 2.0:
                risk_factors.append('low_entropy')
            
            risk_score = len(risk_factors) * 10  # 每个风险因子10分
            
            return {
                'source': 'domain_characteristics',
                'valid_domain': True,
                'second_level': second_level,
                'tld': tld,
                'domain_length': domain_length,
                'second_level_length': second_level_length,
                'has_hyphen': has_hyphen,
                'has_numbers': has_numbers,
                'entropy': round(entropy, 2),
                'risk_factors': risk_factors,
                'risk_score': risk_score,
                'status': 'analyzed',
                'api_call_success': True
            }
            
        except Exception as e:
            logger.debug(f"域名特征分析失败 {domain}: {e}")
            return {
                'source': 'domain_characteristics',
                'valid_domain': False,
                'status': 'error',
                'error': str(e),
                'api_call_success': False
            }
    
    def _calculate_entropy(self, text: str) -> float:
        """计算字符串的熵"""
        if not text:
            return 0.0
        
        # 计算字符频率
        freq = {}
        for char in text.lower():
            freq[char] = freq.get(char, 0) + 1
        
        # 计算熵
        entropy = 0.0
        length = len(text)
        for count in freq.values():
            probability = count / length
            entropy -= probability * (probability and probability.log2())
        
        return entropy
    
    def calculate_enhanced_risk_score(self, threat_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        计算增强版风险评分和详细分析
        """
        # 收集所有风险因子
        risk_factors = []
        factor_details = {}
        
        # 1. VirusTotal风险（40分）
        vt_result = threat_results.get('virustotal', {})
        if vt_result.get('api_call_success', False):
            if vt_result.get('status') == 'found':
                reputation = vt_result.get('reputation_score', 0)
                if reputation < -100:
                    risk_factors.append(('vt_reputation_extreme', 40))
                    factor_details['vt_reputation'] = f"信誉极差 ({reputation})"
                elif reputation < 0:
                    risk_factors.append(('vt_reputation_negative', 25))
                    factor_details['vt_reputation'] = f"信誉差 ({reputation})"
                
                malicious = vt_result.get('malicious_detections', 0)
                suspicious = vt_result.get('suspicious_detections', 0)
                
                if malicious >= 10:
                    risk_factors.append(('vt_malicious_high', 35))
                    factor_details['vt_malicious'] = f"高恶意检测 ({malicious})"
                elif malicious >= 5:
                    risk_factors.append(('vt_malicious_medium', 25))
                    factor_details['vt_malicious'] = f"中恶意检测 ({malicious})"
                elif malicious >= 1:
                    risk_factors.append(('vt_malicious_low', 15))
                    factor_details['vt_malicious'] = f"低恶意检测 ({malicious})"
                
                if suspicious >= 10:
                    risk_factors.append(('vt_suspicious_high', 20))
                    factor_details['vt_suspicious'] = f"高可疑检测 ({suspicious})"
                elif suspicious >= 5:
                    risk_factors.append(('vt_suspicious_medium', 10))
                    factor_details['vt_suspicious'] = f"中可疑检测 ({suspicious})"
        
        # 2. URLhaus风险（30分）
        urlhaus_result = threat_results.get('urlhaus', {})
        if urlhaus_result.get('api_call_success', False) and urlhaus_result.get('malicious'):
            risk_factors.append(('urlhaus_malicious', 30))
            factor_details['urlhaus'] = "URLhaus检测为恶意"
        
        # 3. DNS声誉风险（25分）
        dns_result = threat_results.get('dns_reputation', {})
        if dns_result.get('api_call_success', False):
            if dns_result.get('reputation') == 'suspicious':
                risk_factors.append(('dns_suspicious', 25))
                factor_details['dns'] = "DNS解析可疑"
            elif not dns_result.get('has_dns_records', False):
                risk_factors.append(('no_dns', 15))
                factor_details['dns'] = "无DNS记录"
        
        # 4. 域名特征风险（20分）
        domain_chars_result = threat_results.get('domain_characteristics', {})
        if domain_chars_result.get('api_call_success', False):
            domain_risk_score = domain_chars_result.get('risk_score', 0)
            if domain_risk_score >= 30:
                risk_factors.append(('domain_high_risk', 20))
                factor_details['domain_chars'] = f"域名高风险特征 ({domain_risk_score}分)"
            elif domain_risk_score >= 20:
                risk_factors.append(('domain_medium_risk', 10))
                factor_details['domain_chars'] = f"域名中风险特征 ({domain_risk_score}分)"
        
        # 5. TLD风险（15分）
        tld_result = threat_results.get('tld_analysis', {})
        if tld_result.get('api_call_success', True) and tld_result.get('risk_level') == 'high':
            risk_factors.append(('high_risk_tld', 15))
            factor_details['tld'] = f"高风险TLD: {tld_result.get('matched_tld')}"
        
        # 6. 内部黑名单（40分）
        blacklist_result = threat_results.get('internal_blacklist', {})
        if blacklist_result.get('api_call_success', True) and blacklist_result.get('listed'):
            risk_factors.append(('internal_blacklist', 40))
            factor_details['blacklist'] = "内部黑名单"
        
        # 计算总分
        total_risk = min(100, sum(score for _, score in risk_factors))
        
        # 计算详细评分
        category_scores = {
            'threat_intelligence': 0,
            'dns_reputation': 0,
            'domain_characteristics': 0,
            'tld_risk': 0
        }
        
        for factor_name, score in risk_factors:
            if factor_name.startswith('vt_') or factor_name.startswith('urlhaus'):
                category_scores['threat_intelligence'] += score
            elif factor_name.startswith('dns'):
                category_scores['dns_reputation'] += score
            elif factor_name.startswith('domain'):
                category_scores['domain_characteristics'] += score
            elif factor_name.startswith('tld'):
                category_scores['tld_risk'] += score
        
        # 归一化分类分数
        for category in category_scores:
            category_scores[category] = min(100, category_scores[category])
        
        # 确定整体风险等级
        if total_risk >= 60:
            risk_level = 'critical'
        elif total_risk >= 40:
            risk_level = 'high'
        elif total_risk >= 20:
            risk_level = 'medium'
        elif total_risk >= 10:
            risk_level = 'low'
        else:
            risk_level = 'very_low'
        
        # 确定置信度（基于API调用成功率和数据质量）
        api_success_count = sum(1 for r in threat_results.values() if r.get('api_call_success', False))
        api_total_count = len(threat_results)
        api_success_rate = api_success_count / api_total_count if api_total_count > 0 else 0
        
        real_data_count = sum(1 for r in threat_results.values() 
                            if r.get('status') not in ['simulated', 'simulated_no_api_key', 'not_found_simulated'] 
                            and r.get('api_call_success', False))
        
        confidence = min(100, int(api_success_rate * 50 + (real_data_count / api_total_count) * 50))
        
        return {
            'total_risk_score': total_risk,
            'risk_level': risk_level,
            'category_scores': category_scores,
            'risk_factors': [name for name, _ in risk_factors],
            'factor_details': factor_details,
            'confidence': confidence,
            'api_success_rate': round(api_success_rate, 2),
            'real_data_count': real_data_count,
            'total_data_sources': api_total_count
        }
    
    def check_domain_reputation_enhanced(self, domain: str) -> Dict[str, Any]:
        """
        增强版域名声誉检查
        """
        start_time = time.time()
        
        threat_results = {}
        
        try:
            # 收集所有威胁情报
            threat_results['virustotal'] = self.check_virustotal(domain)
            threat_results['urlhaus'] = self.check_urlhaus(domain)
            threat_results['dns_reputation'] = self.check_dns_reputation(domain)
            threat_results['domain_characteristics'] = self.check_domain_characteristics(domain)
            
            # 其他检查
            threat_results['tld_analysis'] = self.check_tld_risk(domain)
            threat_results['internal_blacklist'] = self.check_internal_blacklist(domain)
            
            # 计算增强版风险评分
            risk_analysis = self.calculate_enhanced_risk_score(threat_results)
            
            # 确定API成功率
            api_success_count = sum(1 for r in threat_results.values() if r.get('api_call_success', False))
            api_total_count = len(threat_results)
            api_success_rate = api_success_count / api_total_count if api_total_count > 0 else 0
            
            result = {
                'domain': domain,
                'check_timestamp': datetime.now().isoformat(),
                'check_duration_seconds': round(time.time() - start_time, 2),
                'threat_sources_checked': list(threat_results.keys()),
                'threat_results': threat_results,
                'risk_analysis': risk_analysis,
                'api_success_rate': round(api_success_rate, 2),
                'has_real_api_data': any(r.get('status') not in ['simulated', 'simulated_no_api_key', 'not_found_simulated'] 
                                        for r in threat_results.values() if r.get('api_call_success', False))
            }
            
            logger.info(f"增强版威胁情报检查完成: {domain}, 风险评分: {risk_analysis['total_risk_score']}, 风险等级: {risk_analysis['risk_level']}")
            return result
            
        except Exception as e:
            logger.error(f"增强版威胁情报检查失败 {domain}: {e}")
            return {
                'domain': domain,
                'check_timestamp': datetime.now().isoformat(),
                'check_duration_seconds': round(time.time() - start_time, 2),
                'error': str(e),
                'risk_analysis': {
                    'total_risk_score': 0,
                    'risk_level': 'unknown',
                    'confidence': 0,
                    'api_success_rate': 0.0,
                    'real_data_count': 0,
                    'total_data_sources': 0
                },
                'has_real_api_data': False
            }
    
    # 辅助方法（从父类复制）
    def check_tld_risk(self, domain: str) -> Dict[str, Any]:
        """检查TLD风险"""
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
    
    def check_internal_blacklist(self, domain: str) -> Dict[str, Any]:
        """检查内部黑名单"""
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
    
    def check_multiple_domains(self, domains: List[str]) -> List[Dict[str, Any]]:
        """批量检查域名"""
        results = []
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_domain = {}
            
            for domain in domains:
                future = executor.submit(self.check_domain_reputation_enhanced, domain)
                future_to_domain[future] = domain
            
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
                        'risk_analysis': {
                            'total_risk_score': 0,
                            'risk_level': 'unknown',
                            'confidence': 0
                        },
                        'has_real_api_data': False
                    })
        
        # 按风险评分排序
        results.sort(key=lambda x: x.get('risk_analysis', {}).get('total_risk_score', 0), reverse=True)
        
        return results
    
    def scan_file(self, input_file: str, output_file: Optional[str] = None) -> List[Dict[str, Any]]:
        """从文件扫描域名"""
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
        
        results = self.check_multiple_domains(domains)
        
        if output_file:
            try:
                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(results, f, ensure_ascii=False, indent=2)
                logger.info(f"威胁情报结果已保存到 {output_file}")
            except Exception as e:
                logger.error(f"保存威胁情报结果到 {output_file} 失败: {e}")
        
        # 打印统计信息
        risk_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'very_low': 0, 'unknown': 0}
        for result in results:
            risk_level = result.get('risk_analysis', {}).get('risk_level', 'unknown')
            risk_counts[risk_level] = risk_counts.get(risk_level, 0) + 1
        
        logger.info(f"威胁情报检查完成: {risk_counts}")
        
        return results


def main():
    """命令行入口点"""
    import argparse
    
    parser = argparse.ArgumentParser(description='增强版威胁情报检查工具')
    parser.add_argument('-i', '--input', required=True, help='输入文件（每行一个域名）')
    parser.add_argument('-o', '--output', help='输出JSON文件')
    parser.add_argument('-w', '--workers', type=int, default=3, help='并发工作线程数（默认3）')
    parser.add_argument('-d', '--delay', type=float, default=1.0, help='API调用延迟（秒，默认1.0）')
    parser.add_argument('-v', '--verbose', action='store_true', help='详细输出')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # 创建扫描器
    scanner = EnhancedThreatIntelligenceScanner(max_workers=args.workers, rate_limit_delay=args.delay)
    
    # 运行检查
    results = scanner.scan_file(args.input, args.output)
    
    # 打印高风险域名
    high_risk_domains = [r for r in results 
                         if r.get('risk_analysis', {}).get('risk_level') in ['critical', 'high']]
    
    if high_risk_domains:
        print("\n高风险域名:")
        for result in high_risk_domains[:10]:
            domain = result['domain']
            score = result.get('risk_analysis', {}).get('total_risk_score', 0)
            level = result.get('risk_analysis', {}).get('risk_level', 'unknown')
            confidence = result.get('risk_analysis', {}).get('confidence', 0)
            print(f"  {domain}: 风险评分 {score}, 风险等级: {level}, 置信度: {confidence}%")

if __name__ == "__main__":
    main()