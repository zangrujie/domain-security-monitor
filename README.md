# 域名监控与钓鱼检测管道（基于 z.py）

本仓库包含用于域名变体生成、DNS 主动探测（xdig）、HTTP 层探测和全维度钓鱼判定的轻量化数据处理管道。此 README 针对 `z.py`——项目的命令行监控脚本，说明如何在 Linux 环境下快速运行最小化流程并获取检测结果。

**说明**: `z.py` 实现了完整管道：域名变体生成（Go 工具/增强规则）→ xdig 多轮 DNS 探测（仅 Linux 原始报文模式）→ httpx 应用层探测 → 规则化全维度检测 → 可选 LLM 精准判读 → 输出 IOC 与报告。

**保留建议文件**:
- `z.py` — 主脚本（命令行入口）
- `modules/domain_input.py` — 域名输入校验
- `semantic_phishing_generator.py` — 可选的语义钓鱼域名生成器（需 API key）
- `requirements.txt` — Python 依赖
- `.env.example` — 推荐的环境变量示例

**先决条件（推荐 Linux）**:
- Python 3.8+
- 在虚拟环境中安装依赖: `pip install -r requirements.txt`
- 可选但建议：Go 环境（用于 `go run main.go` 生成域名变体）
- 对于高效的 DNS 原始报文探测（xdig）：需要 Linux + `xdig` 可执行文件 + `dns.txt`（上游 DNS 列表） + sudo 权限 + libpcap
- HTTP 探测工具：`httpx`（可通过 `pip` 或 `apt`/`brew` 安装）
- 可选 LLM 功能：配置 `DASHSCOPE_API_KEY`（dashscope）与 `SERPER_API_KEY`（语义搜索），否则相关步骤会被跳过

环境变量示例（见 `.env.example`）:

```
# DASHSCOPE_API_KEY=your_dashscope_key
# SERPER_API_KEY=your_serper_key
# XDIG_RATE=500
# XDIG_STABLE_MAX_ROUNDS=3
# XDIG_STABLE_MIN_HITS=2
```

快速开始（Linux）:

1. 创建并激活虚拟环境，安装依赖：

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

2. 准备 `xdig` 与 `dns.txt`（如需使用 xdig 原始发包模式）：
- 将 `xdig` 放在项目根目录或确保可通过 PATH 找到
- 编辑 `dns.txt`，填入备用上游 DNS 服务器（每行一个）

3. 运行示例（最小化运行 — 会生成 `monitoring_results/<target>/` 结果目录）：

```bash
python z.py -d example.com -b .
```

常用选项：
- `-d, --domain` : 目标域名（必需）
- `-b, --base-dir` : 项目基础目录（默认 `.`）
- `-v, --verbose` : 打开详细日志

输出与结果说明：
- `monitoring_results/<target>/`：所有针对该目标的中间与最终产物
	- `all_candidates.txt` / `puny_only_enhanced.txt`：合并候选域名
	- `result_<target>_<rate>.txt`：xdig 原始探测输出（若使用 xdig）
	- `xdig_active_alive_<target>.txt`：xdig 提取的存活域名
	- `httpx_alive.txt`：httpx 探测出的 HTTP 可访问域名
	- `full_dimension_detect.json`：规则化全维度检测结果
	- `phishing_ioc.json`：提取的 IOC 清单
	- `phishing_detect_report.md`：自动生成的检测报告（Markdown）

注意事项与排错：
- `xdig` 的原始发包模式仅支持 Linux；在 Windows/非 Linux 下，脚本会跳过原始发包并提示错误。
- 若未安装 `httpx` 或 `xdig`，对应步骤会失败或被跳过；可先运行到生成候选域名与合并步骤来调试。
- 若使用 LLM（dashscope），请确保 `DASHSCOPE_API_KEY` 可用；无 API 时会跳过 LLM 步骤。
- 对于频繁网络探测，请遵守目标网络/服务的使用条款与法律合规性。


