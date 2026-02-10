# 域名安全分析工具使用指南

## 项目概述

本项目是一个完整的域名安全分析工具链，用于检测和识别潜在的钓鱼域名、伪造域名等安全威胁。工具链包含以下组件：

1. **域名变体生成器** (Go语言) - 生成视觉相似的域名变体
2. **DNS扫描器** (Go语言) - 高速扫描域名存活状态  
3. **WHOIS分析器** (Python) - 查询域名注册信息
4. **一键扫描脚本** (PowerShell) - 自动化整个工作流程

## 快速开始

### 方法一：使用一键扫描脚本（最简单）

```powershell
# 以管理员身份运行PowerShell
.\run_scan.ps1 -TargetDomain example.com
```

这个脚本会自动：
1. 生成 `example.com` 的变体域名
2. 扫描哪些变体域名是存活的（有DNS记录）
3. 查询存活域名的WHOIS信息

### 方法二：分步执行

#### 第1步：生成域名变体

```bash
# 编译程序（如果还没编译）
go build -o domain_gen.exe main.go

# 使用单个域名
.\domain_gen.exe -domain example.com

# 或使用域名列表文件
.\domain_gen.exe -file domains.txt -threshold 0.95

# 参数说明：
# -domain: 单个目标域名
# -file: 包含域名列表的文件（每行一个）
# -threshold: 视觉相似度阈值(0.0-1.0)，默认0.98
```

生成的文件会保存在 `domain_variants/` 目录下：
- `example.com_puny_only.txt` - 纯Punycode列表，供DNS扫描使用
- `example.com_high_risk.txt` - 高风险变体（相似度≥阈值）
- `example.com_all.txt` - 所有生成的变体
- `example.com_keyboard.txt` - 键盘替换生成的变体

#### 第2步：DNS扫描（检查域名存活状态）

```bash
# 确保已安装Npcap（Windows）或libpcap（Linux）
# xdig.exe 已预编译，可直接使用

.\xdig.exe -f domain_variants/example.com_puny_only.txt -o active_domains.txt -rate 500

# 参数说明：
# -f: 输入文件（域名列表）
# -o: 输出文件（存活域名列表）
# -rate: 查询速率（每秒查询数），默认1000
# -type: 查询类型（A/NS），默认A
# -try: 重复查询次数，默认1
```

#### 第3步：WHOIS查询（分析域名注册信息）

```bash
# 激活Python虚拟环境（如果有）
.\myenv\Scripts\activate

# 运行WHOIS查询
python sea_whois_sco.py active_domains.txt whois_results.txt

# 或者直接使用默认参数
python sea_whois_sco.py
```

## 详细功能说明

### 1. 域名变体生成技术

工具使用以下技术生成域名变体：

1. **相似字符替换** - 使用视觉相似的Unicode字符（如l→1，o→0，a→а）
2. **键盘相邻替换** - 替换为键盘上相邻的字符（如s→a/d/w/x）
3. **字符插入** - 在任意位置插入额外字符
4. **字符删除** - 删除任意字符
5. **连字符插入** - 在字符间插入连字符
6. **重复字符** - 重复任意字符
7. **字典词拼接** - 添加常见词汇（login、secure、auth等）
8. **相邻交换** - 交换相邻字符位置
9. **m→rn替换** - 视觉相似的m和rn替换

### 2. 视觉相似度计算

工具计算每个变体与原域名的视觉相似度：
- 使用预计算的字符相似度表（`dis_character/`目录）
- 考虑字符匹配和位置惩罚
- 可配置相似度阈值（-threshold参数）

### 3. DNS扫描特性

xdig工具的特点：
- 支持多个DNS服务器轮询
- 使用原始套接字（raw socket）高速发送查询
- 自动检测网络接口和网关信息
- 支持进度显示和交互式状态查看（按Enter查看进度）

### 4. WHOIS分析

- 批量查询域名注册信息
- 包含注册人、注册商、创建日期、过期日期等
- 支持延时控制避免被限制

## 环境配置要求

### Windows环境
1. **Go语言** - 编译和运行main.go
2. **Npcap** - 用于xdig的原始套接字支持（已包含SDK）
3. **Python 3** - 运行WHOIS查询脚本
4. **PowerShell 5.1+** - 运行一键脚本

### 依赖安装
```bash
# Python依赖
pip install -r requirements.txt

# Go依赖（自动下载）
go mod download
```

## 常见问题

### Q1: xdig运行时提示找不到网络接口
A: 确保以管理员身份运行，或手动指定网络参数：
```bash
.\xdig.exe -iface "以太网" -srcip 192.168.1.100 -srcmac "xx:xx:xx:xx:xx:xx" -gtwmac "xx:xx:xx:xx:xx:xx"
```

### Q2: 生成的变体域名太多怎么办？
A: 调整相似度阈值：
```bash
.\domain_gen.exe -domain example.com -threshold 0.99  # 只生成极高相似度的
```

### Q3: DNS扫描速度太慢/太快
A: 调整查询速率：
```bash
.\xdig.exe -f domains.txt -o result.txt -rate 200  # 降低到200QPS
.\xdig.exe -f domains.txt -o result.txt -rate 2000 # 增加到2000QPS
```

### Q4: WHOIS查询失败
A: 可能是查询频率过高，增加延迟：
```python
# 修改sea_whois_sco.py中的delay参数
batch_query_whois(input_filename, output_filename, delay=5)  # 增加到5秒
```

## 输出文件说明

### domain_gen.exe 输出：
```
domain_variants/example.com/
├── puny_only.txt        # 纯Punycode列表（供xdig使用）
├── all_variants.txt     # 所有变体及相似度
├── high_risk.txt        # 高风险变体（≥阈值）
└── keyboard_variants.txt # 键盘替换变体
```

### xdig.exe 输出：
```
result-*.txt  # 存活域名列表，格式：域名,状态(0=不存在,1=存在)
```

### sea_whois_sco.py 输出：
```
domain_whois_*.txt  # WHOIS查询结果，包含完整的注册信息
```

## 进阶用法

### 批量处理多个域名
```bash
# 创建domains.txt文件
echo example.com >> domains.txt
echo google.com >> domains.txt
echo github.com >> domains.txt

# 批量生成变体
.\domain_gen.exe -file domains.txt

# 批量扫描（需要合并puny_only文件）
```

### 自定义字典词
编辑 `main.go` 中的 `dictWords` 变量，添加或修改常用的钓鱼关键词。

### 扩展相似字符表
在 `dis_character/` 目录中添加更多字符的相似度数据。

## 注意事项

1. **法律合规** - 仅用于授权的安全测试
2. **频率控制** - 避免对DNS服务器造成过大压力
3. **隐私保护** - WHOIS查询可能涉及个人信息
4. **网络权限** - 需要管理员权限进行原始套接字操作

## 故障排除

### 编译错误
```bash
# 清理并重新编译
go clean
go build -o domain_gen.exe main.go
```

### Python模块错误
```bash
# 重新安装依赖
pip install --upgrade -r requirements.txt
```

### 网络权限问题
以管理员身份运行所有命令。