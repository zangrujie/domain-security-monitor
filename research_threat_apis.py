#!/usr/bin/env python3
"""
研究可用的威胁情报API
测试各种免费/开源威胁情报API的可用性和认证要求
"""

import requests
import json
import time
from datetime import datetime

# 用户代理
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

# 创建会话
session = requests.Session()
session.headers.update({'User-Agent': USER_AGENT, 'Accept': 'application/json'})

def test_api(url, method='GET', headers=None, params=None, test_domain="google.com", description=""):
    """测试API连接"""
    print(f"\n测试: {description}")
    print(f"URL: {url}")
    
    try:
        start_time = time.time()
        
        if method == 'GET':
            response = session.get(url, headers=headers, params=params, timeout=10)
        elif method == 'POST':
            response = session.post(url, headers=headers, json=params, timeout=10)
        else:
            print(f"  不支持的方法: {method}")
            return
        
        elapsed = time.time() - start_time
        
        print(f"  状态码: {response.status_code}")
        print(f"  响应时间: {elapsed:.2f}s")
        
        if response.status_code == 200:
            try:
                data = response.json()
                print(f"  成功! 响应示例: {str(data)[:200]}")
                return True
            except:
                print(f"  成功! 响应内容: {response.text[:200]}")
                return True
        elif response.status_code == 401:
            print(f"  需要认证 (401)")
            print(f"  响应: {response.text[:200]}")
            return False
        elif response.status_code == 403:
            print(f"  禁止访问 (403)")
            return False
        elif response.status_code == 429:
            print(f"  速率限制 (429)")
            return False
        else:
            print(f"  错误: {response.status_code}")
            print(f"  响应: {response.text[:200]}")
            return False
            
    except requests.exceptions.Timeout:
        print(f"  超时")
        return False
    except Exception as e:
        print(f"  异常: {e}")
        return False

def test_urlhaus_apis():
    """测试URLhaus相关API"""
    print("\n" + "="*60)
    print("测试URLhaus APIs")
    print("="*60)
    
    # 测试URLhaus状态端点
    test_api(
        url="https://urlhaus-api.abuse.ch/v1/status/",
        description="URLhaus状态检查"
    )
    
    # 测试URLhaus域名检查（无认证）
    test_api(
        url=f"https://urlhaus-api.abuse.ch/v1/host/google.com/",
        description="URLhaus域名检查（无认证）"
    )
    
    # 测试不同的URLhaus端点
    test_api(
        url="https://urlhaus.abuse.ch/downloads/json_online/",
        description="URLhaus JSON数据下载"
    )
    
    test_api(
        url="https://urlhaus.abuse.ch/downloads/csv_online/",
        description="URLhaus CSV数据下载"
    )

def test_virustotal_apis():
    """测试VirusTotal APIs"""
    print("\n" + "="*60)
    print("测试VirusTotal APIs")
    print("="*60)
    
    # VirusTotal公开数据检查
    test_api(
        url="https://www.virustotal.com/api/v3/domains/google.com",
        headers={'x-apikey': 'test-key'},  # 使用测试密钥
        description="VirusTotal域名检查（带API密钥头）"
    )
    
    # 检查VirusTotal文档
    test_api(
        url="https://www.virustotal.com/api/v3/docs",
        description="VirusTotal API文档"
    )

def test_alternative_apis():
    """测试替代威胁情报APIs"""
    print("\n" + "="*60)
    print("测试替代威胁情报APIs")
    print("="*60)
    
    # AbuseIPDB（需要API密钥）
    test_api(
        url="https://api.abuseipdb.com/api/v2/check",
        params={'ipAddress': '8.8.8.8', 'maxAgeInDays': 90},
        headers={'Key': 'test-key', 'Accept': 'application/json'},
        description="AbuseIPDB IP检查"
    )
    
    # PhishTank数据源
    test_api(
        url="http://data.phishtank.com/data/online-valid.json",
        description="PhishTank在线钓鱼数据"
    )
    
    # AlienVault OTX（需要API密钥）
    test_api(
        url="https://otx.alienvault.com/api/v1/indicators/domain/google.com",
        description="AlienVault OTX域名情报"
    )
    
    # ThreatCrowd
    test_api(
        url="https://www.threatcrowd.org/searchApi/v2/domain/report/",
        params={'domain': 'google.com'},
        description="ThreatCrowd域名报告"
    )
    
    # ThreatMiner
    test_api(
        url="https://api.threatminer.org/v2/domain.php",
        params={'q': 'google.com', 'rt': 1},
        description="ThreatMiner域名查询"
    )

def test_open_source_intel():
    """测试开源情报源"""
    print("\n" + "="*60)
    print("测试开源情报源")
    print("="*60)
    
    # CIRCL Passive DNS
    test_api(
        url="https://www.circl.lu/pdns/query/google.com",
        description="CIRCL Passive DNS查询"
    )
    
    # DNS火炬（DNS火炬数据库）
    test_api(
        url="https://api.dnstwist.report/v1/scan/google.com",
        description="DNS火炬域名扫描"
    )
    
    # Shodan（需要API密钥）
    test_api(
        url="https://api.shodan.io/shodan/host/search",
        params={'query': 'domain:google.com'},
        description="Shodan主机搜索"
    )
    
    # GreyNoise（需要API密钥）
    test_api(
        url="https://api.greynoise.io/v3/community/google.com",
        headers={'key': 'test-key'},
        description="GreyNoise社区API"
    )

def test_local_dns_and_whois():
    """测试本地DNS和WHOIS检查"""
    print("\n" + "="*60)
    print("测试本地DNS和WHOIS检查")
    print("="*60)
    
    import socket
    import dns.resolver
    
    # 测试DNS解析
    try:
        print("\n测试DNS解析:")
        start_time = time.time()
        ip_addresses = socket.getaddrinfo("google.com", None)
        ips = list(set([info[4][0] for info in ip_addresses]))
        elapsed = time.time() - start_time
        
        print(f"  DNS解析时间: {elapsed:.3f}s")
        print(f"  解析到的IP地址: {ips}")
        print(f"  成功解析: {len(ips) > 0}")
    except Exception as e:
        print(f"  DNS解析失败: {e}")
    
    # 测试WHOIS（使用python-whois）
    try:
        import whois
        print("\n测试WHOIS查询:")
        start_time = time.time()
        domain_info = whois.whois("google.com")
        elapsed = time.time() - start_time
        
        print(f"  WHOIS查询时间: {elapsed:.3f}s")
        print(f"  注册商: {domain_info.registrar}")
        print(f"  创建日期: {domain_info.creation_date}")
        print(f"  成功获取WHOIS信息")
    except Exception as e:
        print(f"  WHOIS查询失败: {e}")

def research_urlhaus_authentication():
    """研究URLhaus认证方式"""
    print("\n" + "="*60)
    print("研究URLhaus认证方式")
    print("="*60)
    
    # 检查URLhaus网站获取认证信息
    print("\nURLhaus API认证信息研究:")
    
    # 测试可能的认证方式
    auth_methods = [
        {'headers': {'Authorization': 'Bearer test'}, 'desc': 'Bearer令牌'},
        {'headers': {'X-API-Key': 'test'}, 'desc': 'X-API-Key头'},
        {'headers': {'api-key': 'test'}, 'desc': 'api-key头'},
        {'headers': {'key': 'test'}, 'desc': 'key头'},
    ]
    
    for auth in auth_methods:
        print(f"\n测试认证方式: {auth['desc']}")
        test_api(
            url="https://urlhaus-api.abuse.ch/v1/status/",
            headers=auth['headers'],
            description=f"URLhaus状态检查 ({auth['desc']})"
        )

def generate_recommendations():
    """生成API推荐和建议"""
    print("\n" + "="*60)
    print("威胁情报API推荐和建议")
    print("="*60)
    
    recommendations = """
## 威胁情报API配置建议

### 1. VirusTotal API (推荐)
- **状态**: 需要API密钥（免费版可用）
- **限制**: 免费版4 requests/minute, 500 requests/day
- **获取方式**: 
  1. 注册: https://www.virustotal.com/gui/join-us
  2. 获取API密钥: https://www.virustotal.com/gui/user/{用户名}/apikey
  3. 设置环境变量: set VT_API_KEY=your_api_key_here
- **优势**: 数据质量高，覆盖范围广

### 2. URLhaus API (目前需要认证)
- **状态**: 需要认证（可能不再提供公开访问）
- **问题**: 目前返回401错误，需要API密钥或特殊访问权限
- **替代方案**: 使用模拟算法或寻找其他数据源

### 3. 开源情报替代方案

#### a) PhishTank数据 (推荐)
- **URL**: http://data.phishtank.com/data/online-valid.json
- **状态**: 公开可用
- **类型**: 钓鱼网站数据库
- **使用**: 定期下载并本地化检查

#### b) ThreatCrowd API (推荐)
- **URL**: https://www.threatcrowd.org/searchApi/v2/domain/report/
- **状态**: 公开可用
- **限制**: 可能有速率限制
- **数据**: 域名关联的恶意软件、IP、邮件等

#### c) CIRCL Passive DNS
- **URL**: https://www.circl.lu/pdns/query/{domain}
- **状态**: 公开可用
- **数据**: 被动DNS查询结果

#### d) DNS火炬 API
- **URL**: https://api.dnstwist.report/v1/scan/{domain}
- **状态**: 公开可用
- **数据**: 域名变体、TYPO扫描

### 4. 本地分析方案

#### a) DNS声誉分析
- 检查DNS解析状态
- 识别私有IP和保留IP
- 分析DNS解析时间

#### b) 域名特征分析
- 域名长度和结构
- 熵值计算（信息复杂度）
- 风险因子识别（短域名、带数字、带短横线等）

#### c) TLD风险分析
- 识别高风险TLD（.top, .xyz, .club, .win等）
- 基于TLD的简单风险评估

### 5. 实施建议

1. **优先级**:
   - 配置VirusTotal API（最重要的威胁情报源）
   - 集成PhishTank数据（第二优先级）
   - 添加ThreatCrowd作为补充

2. **降级方案**:
   - 当API不可用时使用智能模拟算法
   - 基于域名特征的模拟检查
   - 缓存机制减少重复调用

3. **配置管理**:
   - 创建.env.template配置文件
   - 支持多个API密钥配置
   - 添加API可用性自动检测

4. **性能优化**:
   - 并发处理多个域名
   - 缓存API结果（1小时TTL）
   - 添加速率限制和延迟控制

### 6. 代码更新建议

1. 增强威胁情报扫描器支持多个数据源
2. 添加API密钥配置管理
3. 实现智能降级和模拟算法
4. 添加详细的日志和监控
5. 创建API可用性检查模块
"""
    
    print(recommendations)
    
    # 创建配置文件模板
    env_template = """
# 威胁情报API配置
VT_API_KEY=your_virustotal_api_key_here
# ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
# URLHAUS_API_KEY=your_urlhaus_api_key_here
# OTX_API_KEY=your_otx_api_key_here
# SHODAN_API_KEY=your_shodan_api_key_here

# 数据库配置
DB_HOST=localhost
DB_PORT=5432
DB_NAME=domain_security
DB_USER=postgres
DB_PASSWORD=123

# 扫描配置
MAX_WORKERS=3
RATE_LIMIT_DELAY=1.0
CACHE_TTL_HOURS=1
"""
    
    print("\n配置文件模板 (.env.template):")
    print(env_template)

def main():
    """主测试函数"""
    print("威胁情报API可用性研究")
    print("="*60)
    print(f"测试时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*60)
    
    # 运行测试
    test_urlhaus_apis()
    test_virustotal_apis()
    test_alternative_apis()
    test_open_source_intel()
    test_local_dns_and_whois()
    research_urlhaus_authentication()
    
    # 生成推荐
    generate_recommendations()
    
    print("\n" + "="*60)
    print("研究完成")
    print("="*60)

if __name__ == "__main__":
    main()