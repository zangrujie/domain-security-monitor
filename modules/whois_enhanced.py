#!/usr/bin/env python3
"""
增强版WHOIS查询模块 - 输出结构化JSON格式
"""

import whois
import json
import time
from datetime import datetime
from typing import Dict, List, Optional, Any
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
import re

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def extract_whois_fields(whois_data: Any) -> Dict[str, Any]:
    """
    从whois查询结果中提取关键字段并结构化
    """
    result = {
        'domain': getattr(whois_data, 'domain_name', ''),
        'registrar': getattr(whois_data, 'registrar', ''),
        'creation_date': None,
        'expiration_date': None,
        'updated_date': None,
        'name_servers': [],
        'status': [],
        'emails': [],
        'registrant': {},
        'admin': {},
        'tech': {},
        'raw_text': getattr(whois_data, 'text', '')
    }
    
    # 处理日期字段
    date_fields = ['creation_date', 'expiration_date', 'updated_date']
    for field in date_fields:
        value = getattr(whois_data, field, None)
        if value:
            if isinstance(value, list):
                value = value[0] if value else None
            if value:
                result[field] = value.isoformat() if hasattr(value, 'isoformat') else str(value)
    
    # 处理名称服务器
    ns = getattr(whois_data, 'name_servers', [])
    if ns:
        if isinstance(ns, list):
            result['name_servers'] = [str(s).lower() for s in ns if s]
        else:
            result['name_servers'] = [str(ns).lower()]
    
    # 处理状态
    status = getattr(whois_data, 'status', [])
    if status:
        if isinstance(status, list):
            result['status'] = [str(s).lower() for s in status if s]
        else:
            result['status'] = [str(status).lower()]
    
    # 处理邮箱
    emails = getattr(whois_data, 'emails', [])
    if emails:
        if isinstance(emails, list):
            result['emails'] = [str(e).lower() for e in emails if e and '@' in str(e)]
        else:
            if '@' in str(emails):
                result['emails'] = [str(emails).lower()]
    
    # 提取联系人信息
    contact_fields = ['registrant', 'admin', 'tech']
    for field in contact_fields:
        contact = getattr(whois_data, field, None)
        if contact:
            if isinstance(contact, str):
                result[field] = {'raw': contact}
            elif hasattr(contact, '__dict__'):
                # 尝试提取常见字段
                contact_dict = {}
                for attr in ['name', 'organization', 'street', 'city', 'state', 
                           'postal_code', 'country', 'phone', 'fax', 'email']:
                    val = getattr(contact, attr, None)
                    if val:
                        contact_dict[attr] = str(val)
                result[field] = contact_dict
            else:
                result[field] = {'raw': str(contact)}
    
    return result

def calculate_whois_risk_score(whois_info: Dict) -> float:
    """
    计算WHOIS风险评分（0-100，越高风险越高）
    权重分配：注册异常20%（临时权重）
    """
    risk_factors = []
    
    # 1. 新注册域名（30分）
    creation_date = whois_info.get('creation_date')
    if creation_date:
        try:
            if isinstance(creation_date, str):
                # 尝试解析日期
                from dateutil import parser
                created = parser.parse(creation_date)
                days_old = (datetime.now() - created).days
                if days_old < 30:
                    risk_factors.append(30)  # 30天内注册
                elif days_old < 90:
                    risk_factors.append(15)  # 90天内注册
        except:
            pass
    
    # 2. WHOIS隐私保护（25分）
    statuses = whois_info.get('status', [])
    if any('privacy' in s or 'proxy' in s or 'redacted' in s for s in statuses):
        risk_factors.append(25)
    
    # 3. 注册商风险（20分）
    registrar = whois_info.get('registrar', '').lower()
    # 已知高风险注册商列表（示例）
    risky_registrars = ['privacy', 'proxy', 'anonymous', 'hide']
    if any(r in registrar for r in risky_registrars):
        risk_factors.append(20)
    
    # 4. 邮箱异常（25分）
    emails = whois_info.get('emails', [])
    if emails:
        # 检查临时邮箱
        temp_email_domains = ['temp-mail', 'guerrillamail', 'mailinator', '10minutemail']
        for email in emails:
            if any(domain in email for domain in temp_email_domains):
                risk_factors.append(25)
                break
    
    # 5. 名称服务器异常（20分）
    name_servers = whois_info.get('name_servers', [])
    if len(name_servers) == 0:
        risk_factors.append(20)  # 无名称服务器
    elif len(name_servers) > 5:
        risk_factors.append(10)  # 过多名称服务器
    
    # 计算总分（注册异常20%权重）
    total_risk = min(100, sum(risk_factors))
    weighted_risk = total_risk * 0.20  # 注册异常权重20%
    
    return round(weighted_risk, 2)

def query_domain_whois_structured(domain: str, timeout: int = 10) -> Dict:
    """
    查询单个域名的WHOIS信息，返回结构化结果
    """
    start_time = time.time()
    
    try:
        # 查询WHOIS
        w = whois.whois(domain)
        
        # 提取结构化信息
        whois_info = extract_whois_fields(w)
        
        # 计算风险评分
        whois_risk_score = calculate_whois_risk_score(whois_info)
        
        result = {
            'domain': domain,
            'query_timestamp': datetime.now().isoformat(),
            'query_duration_seconds': round(time.time() - start_time, 2),
            'status': 'success',
            'whois_info': whois_info,
            'whois_risk_score': whois_risk_score,
            'risk_level': 'high' if whois_risk_score > 15 else 'medium' if whois_risk_score > 8 else 'low'
        }
        
        logger.info(f"WHOIS查询成功: {domain}, 风险评分: {whois_risk_score}")
        return result
        
    except Exception as e:
        logger.error(f"WHOIS查询失败 {domain}: {e}")
        return {
            'domain': domain,
            'query_timestamp': datetime.now().isoformat(),
            'query_duration_seconds': round(time.time() - start_time, 2),
            'status': 'error',
            'error': str(e),
            'whois_risk_score': 0.0,
            'risk_level': 'unknown'
        }

def batch_query_whois_structured(domains: List[str], max_workers: int = 5, 
                                delay: float = 2.0) -> List[Dict]:
    """
    批量查询WHOIS信息
    """
    results = []
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_domain = {}
        
        for i, domain in enumerate(domains):
            # 添加延迟以避免请求过于频繁
            if i > 0:
                time.sleep(delay)
            
            future = executor.submit(query_domain_whois_structured, domain)
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
                    'query_timestamp': datetime.now().isoformat(),
                    'status': 'error',
                    'error': str(e),
                    'whois_risk_score': 0.0,
                    'risk_level': 'unknown'
                })
    
    # 按风险评分排序
    results.sort(key=lambda x: x.get('whois_risk_score', 0), reverse=True)
    
    return results

def query_whois_file(input_file: str, output_file: Optional[str] = None,
                     max_workers: int = 5, delay: float = 2.0) -> List[Dict]:
    """
    从文件读取域名并批量查询WHOIS
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
    
    # 批量查询
    results = batch_query_whois_structured(domains, max_workers, delay)
    
    # 保存结果
    if output_file:
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(results, f, ensure_ascii=False, indent=2)
            logger.info(f"WHOIS结果已保存到 {output_file}")
        except Exception as e:
            logger.error(f"保存WHOIS结果到 {output_file} 失败: {e}")
    
    # 打印统计信息
    success_count = sum(1 for r in results if r.get('status') == 'success')
    high_risk = sum(1 for r in results if r.get('risk_level') == 'high')
    medium_risk = sum(1 for r in results if r.get('risk_level') == 'medium')
    
    logger.info(f"WHOIS查询完成: 成功 {success_count}/{len(domains)}, "
                f"高风险 {high_risk}, 中风险 {medium_risk}")
    
    return results

def main():
    """
    命令行入口点
    """
    import argparse
    from typing import Optional
    
    parser = argparse.ArgumentParser(description='增强版WHOIS查询工具 - 输出结构化JSON')
    parser.add_argument('-i', '--input', required=True, help='输入文件（每行一个域名）')
    parser.add_argument('-o', '--output', help='输出JSON文件')
    parser.add_argument('-w', '--workers', type=int, default=5, help='并发工作线程数（默认5）')
    parser.add_argument('-d', '--delay', type=float, default=2.0, help='查询间隔秒数（默认2.0）')
    parser.add_argument('-v', '--verbose', action='store_true', help='详细输出')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # 运行查询
    results = query_whois_file(args.input, args.output, args.workers, args.delay)
    
    # 打印高风险域名
    high_risk_domains = [r for r in results if r.get('risk_level') == 'high']
    if high_risk_domains:
        print("\n高风险域名:")
        for result in high_risk_domains[:10]:  # 只显示前10个
            domain = result['domain']
            score = result.get('whois_risk_score', 0)
            registrar = result.get('whois_info', {}).get('registrar', 'N/A')
            print(f"  {domain}: 风险评分 {score}, 注册商: {registrar}")

if __name__ == "__main__":
    main()