# 威胁情报API配置指南

## 概述

要使用真实的威胁情报API（而不是模拟版本），您需要配置相应的API密钥。本指南将帮助您获取和配置以下API密钥：

1. **VirusTotal API** - 全面的恶意软件和域名信誉检查
2. **URLhaus API** - 恶意URL数据库（无需密钥）
3. **PhishTank API** - 钓鱼网站数据库（可选）

## 快速配置

### 1. VirusTotal API 密钥获取

VirusTotal提供免费的API密钥，但有限制：
- **免费版限制**: 4次请求/分钟，500次请求/天
- **获取步骤**:
  1. 访问 [VirusTotal 注册页面](https://www.virustotal.com/gui/join-us)
  2. 创建账户并验证邮箱
  3. 登录后访问 [API密钥页面](https://www.virustotal.com/gui/user/[您的用户名]/apikey)
  4. 复制API密钥

### 2. 配置API密钥

编辑 `.env` 文件，添加以下配置：

```env
# 威胁情报API密钥
VT_API_KEY=your_virustotal_api_key_here
# URLHAUS_API_KEY=not_required  # URLhaus无需API密钥
# PISHTANK_API_KEY=your_phishtank_api_key_here  # 可选
```

## 详细配置说明

### VirusTotal API 集成

#### 免费版功能限制：
- 域名信誉查询：支持
- 文件扫描：支持（4文件/分钟）
- URL扫描：支持
- 实时扫描：不支持

#### API调用示例：
```python
import requests

VT_API_KEY = os.getenv('VT_API_KEY')
domain = "example.com"

# 域名信息查询
url = f"https://www.virustotal.com/api/v3/domains/{domain}"
headers = {"x-apikey": VT_API_KEY}

response = requests.get(url, headers=headers)
if response.status_code == 200:
    data = response.json()
    # 处理结果
```

#### 速率限制处理：
系统会自动处理VirusTotal的速率限制（4请求/分钟），添加适当的延迟。

### URLhaus API (更新)

URLhaus API现在需要认证，但系统已经集成替代方案：

#### 1. URLhaus公开数据下载
系统使用URLhaus的公开数据文件进行域名检查：
- **无需API密钥**
- **数据源**: https://urlhaus.abuse.ch/downloads/json_online/
- **更新频率**: 实时更新
- **数据大小**: 较大（建议限制检查记录数）

#### 2. 认证API（需要密钥）
如果您有URLhaus API密钥，可以配置使用官方API：
- **状态**: 需要认证（401错误）
- **获取方式**: 可能需要申请或使用其他威胁情报平台
- **配置**: 在 `.env` 文件中设置 `URLHAUS_API_KEY`

#### 系统降级方案：
- 如果公开数据不可用，自动使用模拟模式
- 基于域名特征的智能模拟算法
- 缓存机制减少重复查询

#### 当前实现：
增强版威胁情报扫描器自动检测URLhaus公开数据可用性：
1. 首先尝试下载公开数据文件
2. 如果成功，检查域名是否在恶意URL列表中
3. 如果失败，使用模拟模式作为降级方案

### PhishTank API（可选）

PhishTank提供钓鱼网站数据库：
- 需要注册获取API密钥
- 免费但有限制
- 数据每日更新

#### 获取步骤：
1. 访问 [PhishTank](https://phishtank.org/)
2. 注册账户
3. 在用户面板获取API密钥

## 测试API配置

运行测试脚本来验证API配置：

```bash
# 激活虚拟环境
.\myenv\Scripts\activate

# 测试威胁情报API配置
python test_threat_intel_apis.py
```

## 故障排除

### 常见问题

#### 1. VirusTotal API密钥无效
- 确保已正确复制完整的API密钥
- 检查账户是否已验证邮箱
- 确认API密钥权限

#### 2. 速率限制错误
- VirusTotal免费版：4请求/分钟
- 系统会自动添加延迟，但批量扫描时可能需要手动调整
- 建议分批处理域名列表

#### 3. 网络连接问题
- 确保可以访问VirusTotal和URLhaus API
- 检查防火墙设置
- 验证网络代理配置（如有）

#### 4. API响应格式变化
- 如果API响应格式变化，可能需要更新解析代码
- 检查API文档获取最新格式

### 调试模式

启用详细日志以调试API问题：

```bash
# 设置环境变量启用调试
set THREAT_INTEL_DEBUG=1

# 运行威胁情报检查
python -m modules.threat_intelligence.intel_scanner -i domains.txt -o results.json -v
```

## 备选方案

如果无法获取API密钥，可以使用以下备选方案：

### 1. 本地黑名单数据库
创建和维护自己的恶意域名黑名单：

```python
# 在 .env 文件中配置
USE_LOCAL_BLACKLIST=true
BLACKLIST_FILE=local_blacklist.txt
```

### 2. 社区威胁情报源
使用公开的威胁情报源：
- [Malware Domain List](https://www.malwaredomainlist.com/)
- [OpenPhish](https://openphish.com/)
- [威胁情报共享平台](https://otx.alienvault.com/)

### 3. 增强模拟模式
改进当前的模拟模式，使用更复杂的启发式检测。

## 性能优化建议

### 1. 批量处理
- 尽量批量处理域名，减少API调用次数
- 使用缓存避免重复查询相同域名

### 2. 智能调度
- 根据API限制智能调度查询
- 优先处理高风险域名

### 3. 结果缓存
- 缓存查询结果，减少重复API调用
- 设置合理的缓存过期时间

## 安全注意事项

### 1. API密钥保护
- 不要将API密钥提交到版本控制系统
- 使用环境变量或配置文件存储密钥
- 定期轮换API密钥

### 2. 数据隐私
- 威胁情报查询可能涉及敏感域名
- 确保符合数据保护法规
- 匿名化查询数据（如需要）

### 3. 使用合规
- 仅用于授权的安全测试
- 遵守API服务条款
- 尊重速率限制

## 下一步操作

1. **获取VirusTotal API密钥**（立即开始）
2. **配置 `.env` 文件**（添加VT_API_KEY）
3. **测试API连接**（运行测试脚本）
4. **开始真实威胁情报扫描**

完成配置后，系统将使用真实API进行威胁情报检查，显著提高检测准确性。