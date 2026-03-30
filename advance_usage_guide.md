# 高级使用指南：威胁情报API配置与批量处理

## 第一部分：威胁情报API配置指南

### 🚀 立即操作：配置VirusTotal API

#### 步骤1：获取VirusTotal API密钥
1. **访问注册页面**：打开 [VirusTotal 注册页面](https://www.virustotal.com/gui/join-us)
2. **创建账户**：
   - 输入邮箱地址
   - 设置密码
   - 完成人机验证
3. **验证邮箱**：查收验证邮件并点击确认链接
4. **获取API密钥**：
   - 登录VirusTotal
   - 访问API密钥页面：`https://www.virustotal.com/gui/user/[您的用户名]/apikey`
   - 复制API密钥（长字符串，如`abc123def456...`）

#### 步骤2：配置环境变量
编辑 `.env` 文件，添加您的VirusTotal API密钥：

```env
# PostgreSQL数据库连接配置
DB_USER=postgres
DB_PASSWORD=123
DB_HOST=localhost
DB_PORT=5432
DB_NAME=domain_security

# 威胁情报API密钥配置
VT_API_KEY=1f5e342d0b68bf33c9903322a7072f51df6cca1becdd1d6404c5aab60a371843  # ← 替换为您的真实API密钥
# URLHAUS_API_KEY=not_required  # URLhaus无需API密钥
```

#### 步骤3：测试API配置
运行测试脚本验证API配置：

```powershell
# 激活虚拟环境
.\myenv\Scripts\activate

# 创建并运行API测试脚本
python -c "
import os
from modules.threat_intelligence.intel_scanner import check_domain_reputation

# 测试单个域名的威胁情报检查
result = check_domain_reputation('example.com')
print(f'测试域名: example.com')
print(f'威胁评分: {result.get(\"threat_risk_score\", 0)}')
print(f'风险等级: {result.get(\"risk_level\", \"unknown\")}')
print(f'检查源: {result.get(\"threat_sources_checked\", [])}')
"

# 检查API是否正常工作
if result.get('threat_results', {}).get('virustotal', {}).get('status') == 'simulated_no_api_key':
    print('⚠️ 警告: 仍在使用模拟模式，请确认VT_API_KEY配置正确')
else:
    print('✅ VirusTotal API配置成功！')
```

### 📊 API使用统计与限制

| API服务 | 免费版限制 | 建议用法 | 费率 |
|---------|-----------|----------|------|
| **VirusTotal** | 4请求/分钟，500请求/天 | 优先检查高风险域名 | 免费 |
| **URLhaus** | 无限制（但需合理使用） | 所有域名检查 | 免费 |
| **PhishTank** | 100请求/小时（需注册） | 可选的钓鱼检测 | 免费 |

### 🔧 高级配置：多API密钥轮换

如果您需要处理大量域名，可以配置多个API密钥轮换使用：

```python
# 在 .env 文件中配置多个API密钥
VT_API_KEY_1=your_key_1
VT_API_KEY_2=your_key_2
VT_API_KEY_3=your_key_3

# 使用密钥轮换策略
API_KEYS = [
    os.getenv('VT_API_KEY_1'),
    os.getenv('VT_API_KEY_2'),
    os.getenv('VT_API_KEY_3')
]
```

---

## 第二部分：批量处理操作指南

### 📁 批量域名处理工作流

#### 方案1：单个目标域名批量分析
```powershell
# 1. 准备目标域名列表
echo "google.com" > targets.txt
echo "facebook.com" >> targets.txt
echo "github.com" >> targets.txt
echo "microsoft.com" >> targets.txt

# 2. 批量运行数据管道
foreach ($domain in (Get-Content targets.txt)) {
    Write-Host "分析域名: $domain"
    python -m modules.data_pipeline -d $domain
}
```

#### 方案2：从文件读取域名列表批量处理
```powershell
# 1. 创建批量处理脚本 batch_process.py
python -c "
import subprocess
import sys

targets = ['google.com', 'facebook.com', 'github.com', 'microsoft.com', 'amazon.com']

for target in targets:
    print(f'🚀 开始分析: {target}')
    cmd = f'python -m modules.data_pipeline -d {target}'
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    
    if result.returncode == 0:
        print(f'✅ {target} 分析完成')
    else:
        print(f'❌ {target} 分析失败: {result.stderr[:100]}')
    
    print('---' * 20)
"
```

### ⚙️ 批量处理优化策略

#### 策略1：分批处理（避免API限制）
```python
# batch_optimized.py
import subprocess
import time

def batch_process_domains(domains, batch_size=5, delay_minutes=2):
    """
    分批处理域名，避免API限制
    """
    for i in range(0, len(domains), batch_size):
        batch = domains[i:i+batch_size]
        print(f"批次 {i//batch_size + 1}: 处理 {len(batch)} 个域名")
        
        for domain in batch:
            print(f"  正在分析: {domain}")
            cmd = f"python -m modules.data_pipeline -d {domain}"
            subprocess.run(cmd, shell=True)
        
        # 添加延迟，避免API限制
        if i + batch_size < len(domains):
            print(f"等待 {delay_minutes} 分钟...")
            time.sleep(delay_minutes * 60)
    
    print("所有批次处理完成！")

# 使用示例
domains = ['example1.com', 'example2.com', 'example3.com', 'example4.com', 'example5.com']
batch_process_domains(domains, batch_size=3, delay_minutes=1)
```

#### 策略2：并行处理（高效利用资源）
```python
# parallel_process.py
import concurrent.futures
import subprocess

def process_domain(domain):
    """处理单个域名"""
    try:
        cmd = f"python -m modules.data_pipeline -d {domain}"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
        
        if result.returncode == 0:
            return {"domain": domain, "status": "success", "output": result.stdout[:200]}
        else:
            return {"domain": domain, "status": "failed", "error": result.stderr[:200]}
    
    except subprocess.TimeoutExpired:
        return {"domain": domain, "status": "timeout", "error": "处理超时"}
    except Exception as e:
        return {"domain": domain, "status": "error", "error": str(e)}

def parallel_batch_process(domains, max_workers=2):
    """并行批量处理域名"""
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_domain = {executor.submit(process_domain, domain): domain for domain in domains}
        
        results = []
        for future in concurrent.futures.as_completed(future_to_domain):
            domain = future_to_domain[future]
            try:
                result = future.result()
                results.append(result)
                print(f"{domain}: {result['status']}")
            except Exception as e:
                print(f"{domain}: 处理异常 - {e}")
                results.append({"domain": domain, "status": "exception", "error": str(e)})
    
    # 统计结果
    success_count = sum(1 for r in results if r["status"] == "success")
    print(f"\n✅ 成功: {success_count}/{len(domains)}")
    print(f"❌ 失败: {len(domains) - success_count}/{len(domains)}")
    
    return results
```

### 📊 批量处理结果汇总

#### 结果分析脚本
```python
# analyze_results.py
import json
import os
from datetime import datetime

def analyze_batch_results(results_dir="domain_variants"):
    """
    分析批量处理结果
    """
    summary = {
        "total_targets": 0,
        "total_variants": 0,
        "high_risk_variants": 0,
        "domains_by_risk": {},
        "processing_stats": {}
    }
    
    # 遍历所有目标域名目录
    for target in os.listdir(results_dir):
        target_path = os.path.join(results_dir, target)
        if os.path.isdir(target_path):
            summary["total_targets"] += 1
            
            # 检查高风险域名文件
            high_risk_file = os.path.join(target_path, "high_risk.txt")
            if os.path.exists(high_risk_file):
                with open(high_risk_file, 'r') as f:
                    high_risk_domains = [line.strip() for line in f if line.strip()]
                    summary["high_risk_variants"] += len(high_risk_domains)
                    summary["domains_by_risk"][target] = len(high_risk_domains)
            
            # 检查所有变体文件
            all_variants_file = os.path.join(target_path, "all_variants.txt")
            if os.path.exists(all_variants_file):
                with open(all_variants_file, 'r') as f:
                    all_variants = [line.strip() for line in f if line.strip()]
                    summary["total_variants"] += len(all_variants)
    
    # 生成报告
    report = f"""
批量处理结果分析报告
生成时间: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

📊 总体统计
├── 目标域名总数: {summary['total_targets']}
├── 生成变体总数: {summary['total_variants']}
└── 高风险变体数: {summary['high_risk_variants']}

🎯 各目标域名风险分布
"""
    
    for target, risk_count in summary["domains_by_risk"].items():
        report += f"├── {target}: {risk_count} 个高风险变体\n"
    
    report += f"""
📈 风险率: {summary['high_risk_variants']/max(summary['total_variants'], 1)*100:.1f}%

💡 建议
1. 重点关注高风险变体: {summary['high_risk_variants']} 个域名需要进一步调查
2. 考虑实施防护措施: 监控高风险域名活动
3. 定期重新扫描: 威胁态势可能随时间变化
"""
    
    # 保存报告
    report_file = "batch_analysis_report.txt"
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(report)
    
    print(f"✅ 分析报告已保存到: {report_file}")
    return summary
```

### 🚀 一键自动化脚本

#### 完整批量处理自动化脚本
```powershell
# run_batch_analysis.ps1
<#
.SYNOPSIS
批量域名安全分析自动化脚本

.DESCRIPTION
自动读取目标域名列表，运行完整的安全分析流程，
包括域名变体生成、DNS探测、HTTP扫描、WHOIS查询和威胁情报检查。

.PARAMETER InputFile
包含目标域名的文本文件（每行一个域名）

.PARAMETER OutputDir
输出目录，默认为当前目录下的"batch_results"

.PARAMETER MaxWorkers
最大并发工作数，默认为2

.EXAMPLE
.\run_batch_analysis.ps1 -InputFile "targets.txt"
.\run_batch_analysis.ps1 -InputFile "targets.txt" -MaxWorkers 4
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$InputFile,
    
    [string]$OutputDir = "batch_results",
    
    [int]$MaxWorkers = 2
)

# 创建输出目录
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir | Out-Null
    Write-Host "创建输出目录: $OutputDir"
}

# 读取目标域名
$targets = Get-Content $InputFile | Where-Object { $_ -match '^\w+' }
Write-Host "读取到 $($targets.Count) 个目标域名"

# 批量处理
$results = @()
$counter = 1

foreach ($target in $targets) {
    Write-Host "`n[$counter/$($targets.Count)] 处理: $target"
    
    # 运行数据管道
    $startTime = Get-Date
    $outputFile = Join-Path $OutputDir "$target-results.json"
    
    try {
        # 执行分析
        python -m modules.data_pipeline -d $target
        
        # 收集结果信息
        $endTime = Get-Date
        $duration = $endTime - $startTime
        
        $result = @{
            Domain = $target
            Status = "Success"
            StartTime = $startTime
            EndTime = $endTime
            Duration = $duration.TotalSeconds
            OutputDir = "domain_variants/$target"
        }
        
        $results += $result
        Write-Host "✅ 完成: $target (耗时: $($duration.TotalSeconds.ToString('F1'))秒)"
        
    } catch {
        $result = @{
            Domain = $target
            Status = "Failed"
            Error = $_.Exception.Message
            StartTime = $startTime
            EndTime = Get-Date
        }
        
        $results += $result
        Write-Host "❌ 失败: $target - $($_.Exception.Message)"
    }
    
    $counter++
    
    # 添加延迟避免API限制
    if ($counter -le $targets.Count) {
        Write-Host "等待10秒避免API限制..."
        Start-Sleep -Seconds 10
    }
}

# 生成汇总报告
$summary = @"
批量域名安全分析报告
生成时间: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

📊 处理统计
├── 总目标数: $($targets.Count)
├── 成功数: $($results | Where-Object { $_.Status -eq 'Success' } | Measure-Object).Count
├── 失败数: $($results | Where-Object { $_.Status -eq 'Failed' } | Measure-Object).Count
└── 成功率: $(($results | Where-Object { $_.Status -eq 'Success' } | Measure-Object).Count / [math]::Max($targets.Count, 1) * 100)%


📁 输出文件位置
├── 域名变体: domain_variants/<域名>/
├── 监控结果: monitoring_results/
└── 数据库: PostgreSQL domain_security 数据库


🔍 后续操作建议
1. 查看高风险域名: 检查各目标目录下的 high_risk.txt
2. 数据库查询: 运行 'python test_database.py' 验证数据存储
3. 重新扫描: 定期运行批量分析监控新威胁

📋 详细结果
"@

# 添加每个域名的详细结果
foreach ($result in $results) {
    if ($result.Status -eq "Success") {
        $summary += "`n✅ $($result.Domain): 成功 ($($result.Duration.ToString('F1'))秒)"
    } else {
        $summary += "`n❌ $($result.Domain): 失败 - $($result.Error)"
    }
}

# 保存报告
$summary | Out-File -FilePath (Join-Path $OutputDir "batch_summary.txt") -Encoding UTF8
Write-Host "`n✅ 批量处理完成！报告已保存到: $(Join-Path $OutputDir "batch_summary.txt")"
```

### 🎯 实际应用场景

#### 场景1：企业域名监控
```powershell
# 企业核心域名保护
$enterpriseDomains = @(
    "company.com",
    "company.cn",
    "company.com.cn",
    "company.net",
    "company.org"
)

# 创建监控列表
$enterpriseDomains | Out-File "enterprise_targets.txt"

# 运行批量监控
.\run_batch_analysis.ps1 -InputFile "enterprise_targets.txt" -MaxWorkers 3
```

#### 场景2：品牌保护
```powershell
# 品牌关键词监控
$brandKeywords = @(
    "mybrand",
    "ourbrand", 
    "brandofficial",
    "brandsupport"
)

# 生成域名变体并监控
foreach ($keyword in $brandKeywords) {
    Write-Host "监控品牌关键词: $keyword"
    
    # 为每个关键词创建变体
    python -c "
import subprocess
subprocess.run(['go', 'run', 'main.go', '-domain', '$keyword.com'])
"
    
    # 运行安全分析
    python -m modules.data_pipeline -d "$keyword.com"
}
```

### ⚡ 性能优化提示

1. **数据库索引优化**：
   ```sql
   -- 在PostgreSQL中创建性能优化索引
   CREATE INDEX idx_domains_domain ON domains(domain);
   CREATE INDEX idx_risk_assessments_score ON risk_assessments(weighted_total_score DESC);
   CREATE INDEX idx_threat_intel_score ON threat_intelligence(threat_risk_score DESC);
   ```

2. **内存管理**：
   - 批量处理时限制并发数（MaxWorkers）
   - 定期清理临时文件
   - 监控PostgreSQL内存使用

3. **网络优化**：
   - 使用本地DNS缓存
   - 配置HTTP连接池
   - 设置合理的超时时间

### 🔧 故障排除

#### 常见问题1：API限制错误
**症状**：VirusTotal返回"429 Too Many Requests"
**解决**：
```python
# 在.env中添加延迟配置
API_RATE_LIMIT_DELAY=15  # 秒
```

#### 常见问题2：数据库连接超时
**症状**：数据库连接错误或超时
**解决**：
```powershell
# 重启PostgreSQL服务
net stop postgresql-x64-16
net start postgresql-x64-16

# 验证数据库连接
python test_db_simple.py
```

#### 常见问题3：内存不足
**症状**：处理大量域名时内存耗尽
**解决**：
```powershell
# 减少并发数
.\run_batch_analysis.ps1 -InputFile "targets.txt" -MaxWorkers 1

# 分批处理
$batches = Get-Content "targets.txt" | Select-Object -First 10
# 处理第一批
$batches | Out-File "batch1.txt"
.\run_batch_analysis.ps1 -InputFile "batch1.txt"
```

---

## 📞 技术支持

如果遇到问题，请检查：

1. **日志文件**：查看程序输出的日志信息
2. **数据库状态**：运行 `python test_database.py` 验证数据库连接
3. **API配置**：确认 `.env` 文件中的API密钥正确
4. **系统资源**：确保有足够的内存和磁盘空间

**关键成功指标**：
- ✅ PostgreSQL服务正常运行
- ✅ VirusTotal API配置正确
- ✅ 数据管道能完整执行
- ✅ 高风险域名被正确识别

**立即开始**：
1. 配置VirusTotal API密钥
2. 创建目标域名列表
3. 运行批量分析脚本
4. 查看分析报告并采取相应防护措施

Happy Security Monitoring! 🔒