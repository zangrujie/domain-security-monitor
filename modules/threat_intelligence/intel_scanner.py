#!/usr/bin/env python3
"""
威胁情报扫描器 - 集成多源威胁情报检查
注意：实际使用需要配置相应的API密钥
"""

import requests
import json
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import logging
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
import re

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
HIGH_RISK_TLDS = ['.top', '.xyz', '.club', '.win', '.bid', '.loan', '.date']

def check_virustotal_simulated(domain: str) -> Dict:
    """
    模拟VirusTotal域名检查（实际使用需要API密钥）
    """
    # 注意：这是模拟版本，实际使用时需要替换为真正的API调用
    # 示例：https://developers.virustotal.com/reference/domain-info
    
    # 模拟检查逻辑
    time.sleep(0.1)  # 模拟API延迟
    
    # 基于域名特征的简单模拟
    domain_hash = hashlib.md5(domain.encode()).hexdigest()
    hash_int = int(domain_hash[:8], 16)
    
    # 模拟检测结果
    simulated_score = (hash_int % 100) / 100.0  # 0-1之间的分数
    
    # 模拟恶意软件检测
    malware_detections = hash_int % 10 if simulated_score > 0.3 else 0
    
    return {
        'source': 'virustotal_simulated',
        'reputation_score': round(1.0 - simulated_score, 2),  # 信誉分（越高越好）
        'malicious_detections': malware_detections,
        'total_engines': 90,
        'last_analysis_date': datetime.now().isoformat(),
        'categories': ['simulated'] if simulated_score > 0.5 else [],
        'status': 'simulated_no_api_key',
        'note': '实际使用需要配置VirusTotal API密钥'
    }

def check_urlhaus(domain: str) -> Dict:
    """
    检查URLhaus恶意URL数据库（公开API）
    """
    try:
        url = f"https://urlhaus-api.abuse.ch/v1/host/{domain}/"
        headers = {
            'User-Agent': USER_AGENT,
            'Accept': 'application/json'
        }
        
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            if data.get('query_status') == 'ok':
                return {
                    'source': 'urlhaus',
                    'malicious': True,
                    'threats': data.get('urls', []),
                    'first_seen': data.get('firstseen'),
                    'last_online': data.get('last_online'),
                    'status': 'found'
                }
            else:
                return {
                    'source': 'urlhaus',
                    'malicious': False,
                    'status': 'not_found',
                    'query_status': data.get('query_status')
                }
        else:
            return {
                'source': 'urlhaus',
                'malicious': False,
                'status': f'api_error_{response.status_code}',
                'error': 'API请求失败'
            }
            
    except Exception as e:
        logger.debug(f"URLhaus检查失败 {domain}: {e}")
        return {
            'source': 'urlhaus',
            'malicious': False,
            'status': 'error',
            'error': str(e)
        }

def check_phishtank_simulated(domain: str) -> Dict:
    """
    模拟PhishTank检查（实际需要API或下载数据库）
    """
    # 注意：实际使用可以集成PhishTank API或下载其数据库
    
    # 简单的基于关键词的模拟检查
    phishing_keywords = ['login', 'secure', 'verify', 'account', 'bank', 'paypal']
    
    has_phishing_keyword = any(keyword in domain.lower() for keyword in phishing_keywords)
    
    # 检查已知恶意列表
    is_known_phishing = domain in KNOWN_MALICIOUS_DOMAINS
    
    return {
        'source': 'phishtank_simulated',
        'phishing_suspected': has_phishing_keyword or is_known_phishing,
        'known_phishing': is_known_phishing,
        'matched_keywords': [k for k in phishing_keywords if k in domain.lower()],
        'status': 'simulated',
        'note': '实际使用需要PhishTank API或数据库'
    }

def check_tld_risk(domain: str) -> Dict:
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
        'status': 'analyzed'
    }

def check_domain_age_simulated(domain: str) -> Dict:
    """
    模拟域名年龄分析（实际需要WHOIS数据）
    """
    # 简单模拟：基于域名长度的"年龄"推测
    # 短域名通常更老，长域名可能更新
    
    domain_length = len(domain.split('.')[0])  # 只考虑二级域名部分
    
    if domain_length <= 5:
        age_estimate = 'old'  # 可能较老
    elif domain_length <= 8:
        age_estimate = 'medium'
    else:
        age_estimate = 'new'  # 可能较新
    
    return {
        'source': 'domain_age_simulated',
        'estimated_age': age_estimate,
        'domain_length': domain_length,
        'status': 'simulated',
        'note': '实际年龄需要WHOIS查询'
    }

def calculate_threat_risk_score(threat_results: Dict) -> float:
    """
    计算威胁情报风险评分（0-100，越高风险越高）
    权重分配：威胁情报20%（临时权重）
    """
    risk_factors = []
    
    # 1. VirusTotal信誉（40分）
    vt_result = threat_results.get('virustotal', {})
    if vt_result.get('status') == 'simulated_no_api_key':
        # 模拟模式下，基于模拟分数
        rep_score = vt_result.get('reputation_score', 0.5)
        if rep_score < 0.3:
            risk_factors.append(40)  # 信誉极差
        elif rep_score < 0.6:
            risk_factors.append(20)  # 信誉较差
        
        malicious_detections = vt_result.get('malicious_detections', 0)
        if malicious_detections >= 5:
            risk_factors.append(35)
        elif malicious_detections >= 1:
            risk_factors.append(15)
    
    # 2. URLhaus检测（30分）
    urlhaus_result = threat_results.get('urlhaus', {})
    if urlhaus_result.get('malicious'):
        risk_factors.append(30)
    
    # 3. PhishTank检测（30分）
    phishtank_result = threat_results.get('phishtank', {})
    if phishtank_result.get('phishing_suspected'):
        risk_factors.append(20)
    if phishtank_result.get('known_phishing'):
        risk_factors.append(30)
    
    # 4. TLD风险（25分）
    tld_result = threat_results.get('tld_analysis', {})
    if tld_result.get('risk_level') == 'high':
        risk_factors.append(25)
    
    # 5. 域名年龄风险（15分）
    age_result = threat_results.get('domain_age', {})
    if age_result.get('estimated_age') == 'new':
        risk_factors.append(15)
    
    # 6. 内部黑名单（40分）
    if threat_results.get('internal_blacklist', {}).get('listed'):
        risk_factors.append(40)
    
    # 计算总分（威胁情报20%权重）
    total_risk = min(100, sum(risk_factors))
    weighted_risk = total_risk * 0.20  # 威胁情报权重20%
    
    return round(weighted_risk, 2)

def check_domain_reputation(domain: str) -> Dict:
    """
    检查单个域名的多源威胁情报
    """
    start_time = time.time()
    
    threat_results = {}
    
    try:
        # 1. 检查内部黑名单
        if domain in KNOWN_MALICIOUS_DOMAINS:
            threat_results['internal_blacklist'] = {
                'listed': True,
                'reason': KNOWN_MALICIOUS_DOMAINS[domain]['reason'],
                'source': KNOWN_MALICIOUS_DOMAINS[domain]['source']
            }
        else:
            threat_results['internal_blacklist'] = {'listed': False}
        
        # 2. 模拟VirusTotal检查
        threat_results['virustotal'] = check_virustotal_simulated(domain)
        
        # 3. URLhaus检查
        threat_results['urlhaus'] = check_urlhaus(domain)
        
        # 4. 模拟PhishTank检查
        threat_results['phishtank'] = check_phishtank_simulated(domain)
        
        # 5. TLD风险分析
        threat_results['tld_analysis'] = check_tld_risk(domain)
        
        # 6. 域名年龄分析
        threat_results['domain_age'] = check_domain_age_simulated(domain)
        
        # 计算综合风险评分
        threat_risk_score = calculate_threat_risk_score(threat_results)
        
        result = {
            'domain': domain,
            'check_timestamp': datetime.now().isoformat(),
            'check_duration_seconds': round(time.time() - start_time, 2),
            'threat_sources_checked': list(threat_results.keys()),
            'threat_results': threat_results,
            'threat_risk_score': threat_risk_score,
            'risk_level': 'high' if threat_risk_score > 15 else 'medium' if threat_risk_score > 8 else 'low'
        }
        
        logger.info(f"威胁情报检查完成: {domain}, 风险评分: {threat_risk_score}")
        return result
        
    except Exception as e:
        logger.error(f"威胁情报检查失败 {domain}: {e}")
        return {
            'domain': domain,
            'check_timestamp': datetime.now().isoformat(),
            'check_duration_seconds': round(time.time() - start_time, 2),
            'error': str(e),
            'threat_risk_score': 0.0,
            'risk_level': 'unknown'
        }

def check_multiple_sources(domains: List[str], max_workers: int = 3) -> List[Dict]:
    """
    批量检查多个域名的威胁情报
    """
    results = []
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_domain = {}
        
        for domain in domains:
            future = executor.submit(check_domain_reputation, domain)
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
                    'risk_level': 'unknown'
                })
    
    # 按风险评分排序
    results.sort(key=lambda x: x.get('threat_risk_score', 0), reverse=True)
    
    return results

def scan_file(input_file: str, output_file: Optional[str] = None,
              max_workers: int = 3) -> List[Dict]:
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
    results = check_multiple_sources(domains, max_workers)
    
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
    
    logger.info(f"威胁情报检查完成: 高风险 {high_risk}, 中风险 {medium_risk}, 总计 {len(results)}")
    
    return results

def main():
    """
    命令行入口点
    """
    import argparse
    from typing import Optional
    
    parser = argparse.ArgumentParser(description='威胁情报检查工具')
    parser.add_argument('-i', '--input', required=True, help='输入文件（每行一个域名）')
    parser.add_argument('-o', '--output', help='输出JSON文件')
    parser.add_argument('-w', '--workers', type=int, default=3, help='并发工作线程数（默认3）')
    parser.add_argument('-v', '--verbose', action='store_true', help='详细输出')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # 运行检查
    results = scan_file(args.input, args.output, args.workers)
    
    # 打印高风险域名
    high_risk_domains = [r for r in results if r.get('risk_level') == 'high']
    if high_risk_domains:
        print("\n高风险域名:")
        for result in high_risk_domains[:10]:  # 只显示前10个
            domain = result['domain']
            score = result.get('threat_risk_score', 0)
            sources = result.get('threat_sources_checked', [])
            print(f"  {domain}: 威胁评分 {score}, 检查源: {len(sources)}个")

if __name__ == "__main__":
    main()