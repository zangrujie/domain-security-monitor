#!/usr/bin/env python3
"""
HTTP扫描器核心模块
独立HTTP/HTTPS应用层扫描，不依赖xdig修改
"""

import asyncio
import aiohttp
import ssl
import socket
import json
import time
from typing import List, Dict, Optional, Tuple
from urllib.parse import urlparse, urljoin
from datetime import datetime, timedelta
import logging
from bs4 import BeautifulSoup
import re

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# 用户代理
DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

# 可疑关键词（用于检测钓鱼页面）
SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'signon', 'account', 'verify', 'authentication',
    'password', 'credential', 'bank', 'paypal', 'alipay', 'wechat',
    'security', 'update', 'confirm', 'validation', 'authorize'
]

# 已知登录表单字段
LOGIN_FORM_FIELDS = ['username', 'user', 'email', 'password', 'pass', 'login', 'signin']


async def get_ssl_certificate_info(hostname: str, port: int = 443) -> Optional[Dict]:
    """
    获取SSL证书信息
    """
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                
                # 解析证书信息
                cert_info = {
                    'valid': True,
                    'subject': {},
                    'issuer': {},
                    'not_before': None,
                    'not_after': None,
                    'serial_number': None
                }
                
                # 提取主题和颁发者
                for field, value in cert.get('subject', []):
                    cert_info['subject'][field] = value
                
                for field, value in cert.get('issuer', []):
                    cert_info['issuer'][field] = value
                
                # 提取有效期
                cert_info['not_before'] = cert.get('notBefore')
                cert_info['not_after'] = cert.get('notAfter')
                
                # 检查是否过期
                if cert_info['not_after']:
                    expiry_date = datetime.strptime(cert_info['not_after'], '%b %d %H:%M:%S %Y %Z')
                    if expiry_date < datetime.now():
                        cert_info['valid'] = False
                    elif expiry_date < datetime.now() + timedelta(days=30):
                        cert_info['expiring_soon'] = True
                
                return cert_info
    except Exception as e:
        logger.debug(f"SSL证书检查失败 {hostname}: {e}")
        return None


def analyze_page_content(html: str, domain: str) -> Dict:
    """
    分析页面内容，检测可疑特征
    """
    try:
        soup = BeautifulSoup(html, 'html.parser')
        
        # 提取页面标题
        title = soup.title.string if soup.title else ""
        
        # 检查登录表单
        has_login_form = False
        form_fields = []
        forms = soup.find_all('form')
        for form in forms:
            inputs = form.find_all('input')
            field_names = [inp.get('name', '').lower() for inp in inputs if inp.get('name')]
            for field in field_names:
                if any(login_field in field for login_field in LOGIN_FORM_FIELDS):
                    has_login_form = True
                    form_fields = field_names
                    break
        
        # 检查可疑关键词
        text_content = soup.get_text().lower()
        found_keywords = []
        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword.lower() in text_content:
                found_keywords.append(keyword)
        
        # 检查重定向
        redirect_meta = soup.find('meta', attrs={'http-equiv': 'refresh'})
        has_redirect = redirect_meta is not None
        
        # 检查外部资源
        external_resources = []
        for tag in soup.find_all(['script', 'img', 'link']):
            src = tag.get('src') or tag.get('href')
            if src:
                parsed_src = urlparse(src)
                if parsed_src.netloc and parsed_src.netloc != domain:
                    external_resources.append(src)
        
        return {
            'title': title,
            'has_login_form': has_login_form,
            'form_fields': form_fields[:5],  # 只保留前5个字段
            'found_keywords': found_keywords,
            'has_redirect': has_redirect,
            'external_resources_count': len(external_resources),
            'page_size_bytes': len(html)
        }
    except Exception as e:
        logger.debug(f"页面分析失败 {domain}: {e}")
        return {
            'title': '',
            'has_login_form': False,
            'form_fields': [],
            'found_keywords': [],
            'has_redirect': False,
            'external_resources_count': 0,
            'page_size_bytes': len(html) if html else 0
        }


async def probe_http_protocol(domain: str, session: aiohttp.ClientSession, 
                             timeout: int = 10) -> Dict:
    """
    探测单个域名的HTTP和HTTPS协议
    """
    results = {
        'http': None,
        'https': None,
        'preferred': None
    }
    
    protocols = [
        ('http', f'http://{domain}'),
        ('https', f'https://{domain}')
    ]
    
    for proto, url in protocols:
        try:
            async with session.get(url, timeout=timeout, allow_redirects=True, 
                                  ssl=False if proto == 'http' else None) as response:
                response_text = await response.text()
                
                # 收集响应头
                headers = {}
                for key, value in response.headers.items():
                    if key.lower() in ['server', 'x-powered-by', 'content-type', 
                                      'content-length', 'set-cookie', 'location']:
                        headers[key] = value
                
                proto_result = {
                    'status': response.status,
                    'final_url': str(response.url),
                    'headers': headers,
                    'redirect_count': len(response.history),
                    'page_analysis': analyze_page_content(response_text, domain)
                }
                
                results[proto] = proto_result
                
                # 如果是HTTPS且成功，检查SSL证书
                if proto == 'https' and response.status < 400:
                    cert_info = await get_ssl_certificate_info(domain)
                    if cert_info:
                        proto_result['ssl_certificate'] = cert_info
                
                logger.info(f"{proto.upper()} {domain}: {response.status}")
                
        except asyncio.TimeoutError:
            logger.debug(f"{proto.upper()} {domain}: 超时")
            results[proto] = {'status': 'timeout', 'error': '请求超时'}
        except aiohttp.ClientConnectorError as e:
            logger.debug(f"{proto.upper()} {domain}: 连接错误 - {e}")
            results[proto] = {'status': 'connection_error', 'error': str(e)}
        except Exception as e:
            logger.debug(f"{proto.upper()} {domain}: 错误 - {e}")
            results[proto] = {'status': 'error', 'error': str(e)}
    
    # 确定首选协议
    if results['https'] and results['https'].get('status') in [200, 301, 302]:
        results['preferred'] = 'https'
    elif results['http'] and results['http'].get('status') in [200, 301, 302]:
        results['preferred'] = 'http'
    else:
        results['preferred'] = 'none'
    
    return results


def calculate_risk_score(scan_result: Dict) -> float:
    """
    计算HTTP层风险评分（0-100，越高风险越高）
    权重分配：应用层风险35%（临时权重）
    """
    risk_factors = []
    
    # 1. HTTP状态异常（20分）
    http_status = scan_result.get('http', {}).get('status')
    https_status = scan_result.get('https', {}).get('status')
    
    if https_status not in [200, 301, 302] and http_status not in [200, 301, 302]:
        risk_factors.append(20)  # 两种协议都不可用
    elif https_status not in [200, 301, 302] and http_status in [200, 301, 302]:
        risk_factors.append(15)  # 只有HTTP可用（不安全）
    
    # 2. SSL证书问题（30分）
    cert_info = scan_result.get('https', {}).get('ssl_certificate')
    if cert_info:
        if not cert_info.get('valid', True):
            risk_factors.append(30)  # 证书无效
        elif cert_info.get('expiring_soon', False):
            risk_factors.append(10)  # 证书即将过期
    elif scan_result.get('https', {}).get('status') == 200:
        risk_factors.append(25)  # HTTPS成功但没有证书信息（异常）
    
    # 3. 页面特征风险（50分）
    page_analysis = scan_result.get('preferred') and scan_result.get(scan_result['preferred'], {}).get('page_analysis', {})
    if page_analysis:
        # 登录表单（高风险）
        if page_analysis.get('has_login_form', False):
            risk_factors.append(30)
        
        # 发现多个可疑关键词
        keywords = page_analysis.get('found_keywords', [])
        if len(keywords) >= 3:
            risk_factors.append(20)
        elif len(keywords) >= 1:
            risk_factors.append(10)
        
        # 重定向
        if page_analysis.get('has_redirect', False):
            risk_factors.append(15)
        
        # 大量外部资源
        if page_analysis.get('external_resources_count', 0) > 5:
            risk_factors.append(10)
    
    # 计算总分（应用层风险35%权重，所以实际分数要乘以0.35）
    total_risk = min(100, sum(risk_factors))
    weighted_risk = total_risk * 0.35  # 应用层权重35%
    
    return round(weighted_risk, 2)


async def scan_domain(domain: str, timeout: int = 10) -> Dict:
    """
    扫描单个域名
    """
    start_time = time.time()
    
    # 配置HTTP会话
    connector = aiohttp.TCPConnector(limit_per_host=2, ssl=False)
    headers = {
        'User-Agent': DEFAULT_USER_AGENT,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1'
    }
    
    async with aiohttp.ClientSession(connector=connector, headers=headers) as session:
        http_results = await probe_http_protocol(domain, session, timeout)
    
    # 计算风险评分
    http_risk_score = calculate_risk_score(http_results)
    
    result = {
        'domain': domain,
        'scan_timestamp': datetime.now().isoformat(),
        'scan_duration_seconds': round(time.time() - start_time, 2),
        'http_results': http_results,
        'http_risk_score': http_risk_score,
        'risk_level': 'high' if http_risk_score > 20 else 'medium' if http_risk_score > 10 else 'low'
    }
    
    return result


async def scan_batch(domains: List[str], concurrency: int = 5, 
                     timeout: int = 10) -> List[Dict]:
    """
    批量扫描域名列表
    """
    semaphore = asyncio.Semaphore(concurrency)
    
    async def scan_with_semaphore(domain: str) -> Dict:
        async with semaphore:
            try:
                return await scan_domain(domain, timeout)
            except Exception as e:
                logger.error(f"扫描域名 {domain} 时出错: {e}")
                return {
                    'domain': domain,
                    'scan_timestamp': datetime.now().isoformat(),
                    'error': str(e),
                    'http_risk_score': 0.0,
                    'risk_level': 'unknown'
                }
    
    tasks = [scan_with_semaphore(domain) for domain in domains]
    results = await asyncio.gather(*tasks)
    
    # 按风险评分排序
    results.sort(key=lambda x: x.get('http_risk_score', 0), reverse=True)
    
    return results


def scan_file(input_file: str, output_file: Optional[str] = None, 
              concurrency: int = 5, timeout: int = 10) -> List[Dict]:
    """
    从文件读取域名并扫描
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
    
    # 运行扫描
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    results = loop.run_until_complete(scan_batch(domains, concurrency, timeout))
    loop.close()
    
    # 保存结果
    if output_file:
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(results, f, ensure_ascii=False, indent=2)
            logger.info(f"结果已保存到 {output_file}")
        except Exception as e:
            logger.error(f"保存结果到 {output_file} 失败: {e}")
    
    # 打印统计信息
    high_risk = sum(1 for r in results if r.get('risk_level') == 'high')
    medium_risk = sum(1 for r in results if r.get('risk_level') == 'medium')
    
    logger.info(f"扫描完成: 高风险 {high_risk}, 中风险 {medium_risk}, 总计 {len(results)}")
    
    return results


def main():
    """
    命令行入口点
    """
    import argparse
    
    parser = argparse.ArgumentParser(description='HTTP/HTTPS应用层扫描器')
    parser.add_argument('-i', '--input', required=True, help='输入文件（每行一个域名）')
    parser.add_argument('-o', '--output', help='输出JSON文件')
    parser.add_argument('-c', '--concurrency', type=int, default=5, help='并发数（默认5）')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='超时时间秒（默认10）')
    parser.add_argument('-v', '--verbose', action='store_true', help='详细输出')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # 运行扫描
    results = scan_file(args.input, args.output, args.concurrency, args.timeout)
    
    # 打印高风险域名
    high_risk_domains = [r for r in results if r.get('risk_level') == 'high']
    if high_risk_domains:
        print("\n高风险域名:")
        for result in high_risk_domains[:10]:  # 只显示前10个
            domain = result['domain']
            score = result.get('http_risk_score', 0)
            print(f"  {domain}: 风险评分 {score}")


if __name__ == "__main__":
    main()