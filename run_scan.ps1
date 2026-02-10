# Windows 版一键扫描脚本
# 注意：需要管理员权限运行（xdig需要原始套接字）
param (
    [string]$TargetDomain,
    [float]$Threshold = 0.98,
    [int]$Rate = 500
)

if (-not $TargetDomain) {
    Write-Host "使用方法: .\run_scan.ps1 -TargetDomain example.com [-Threshold 0.98] [-Rate 500]" -ForegroundColor Red
    Write-Host "注意：需要以管理员身份运行PowerShell！" -ForegroundColor Yellow
    exit
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "域名安全分析工具 - 一键扫描" -ForegroundColor Cyan
Write-Host "目标域名: $TargetDomain" -ForegroundColor Cyan
Write-Host "相似度阈值: $Threshold" -ForegroundColor Cyan
Write-Host "DNS扫描速率: $Rate QPS" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# 阶段 1: 生成域名变体
Write-Host "[*] 阶段 1: 生成域名变体..." -ForegroundColor Green
if (Test-Path "domain_gen.exe") {
    .\domain_gen.exe -domain $TargetDomain -threshold $Threshold
} else {
    Write-Host "未找到 domain_gen.exe，尝试编译..." -ForegroundColor Yellow
    go build -o domain_gen.exe main.go
    .\domain_gen.exe -domain $TargetDomain -threshold $Threshold
}

# 查找生成的punycode文件
$DomainDir = "domain_variants/$TargetDomain"
$VariantFile = "$DomainDir/puny_only.txt"

if (-not (Test-Path $VariantFile)) {
    Write-Host "错误: 未找到生成的变体文件 $VariantFile" -ForegroundColor Red
    exit 1
}

Write-Host "成功生成变体文件: $VariantFile" -ForegroundColor Green

# 阶段 2: DNS扫描（需要管理员权限）
Write-Host "[*] 阶段 2: DNS扫描存活域名..." -ForegroundColor Green
Write-Host "注意: 此阶段需要管理员权限访问原始套接字" -ForegroundColor Yellow

$ScanResult = "active_domains_${TargetDomain}.txt"

if (Test-Path "xdig_windows.exe") {
    Write-Host "使用 xdig_windows.exe 进行扫描..." -ForegroundColor Green
    .\xdig_windows.exe -f $VariantFile -o $ScanResult -rate $Rate -wtgtime 10
} elseif (Test-Path "xdig.exe") {
    Write-Host "使用 xdig.exe 进行扫描..." -ForegroundColor Green
    .\xdig.exe -f $VariantFile -o $ScanResult -rate $Rate -wtgtime 10
} else {
    Write-Host "未找到 xdig 可执行文件，尝试编译..." -ForegroundColor Yellow
    go build -o xdig_windows.exe xdig.go
    .\xdig_windows.exe -f $VariantFile -o $ScanResult -rate $Rate -wtgtime 10
}

# 阶段 3: WHOIS分析
if (Test-Path $ScanResult) {
    $WhoisResult = "whois_results_${TargetDomain}.txt"
    Write-Host "[*] 阶段 3: WHOIS查询..." -ForegroundColor Green
    
    # 检查Python环境
    if (Test-Path "myenv\Scripts\activate") {
        Write-Host "激活Python虚拟环境..." -ForegroundColor Green
        & myenv\Scripts\activate
    } elseif (Test-Path ".venv\Scripts\activate") {
        Write-Host "激活Python虚拟环境..." -ForegroundColor Green
        & .venv\Scripts\activate
    }
    
    # 运行WHOIS查询
    Write-Host "执行WHOIS查询，结果保存到: $WhoisResult" -ForegroundColor Green
    python sea_whois_sco.py $ScanResult $WhoisResult
} else {
    Write-Host "警告: 未找到存活域名结果文件 $ScanResult，跳过WHOIS查询" -ForegroundColor Yellow
}

# 输出总结
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "[+] 任务完成！" -ForegroundColor Green
Write-Host "生成的文件：" -ForegroundColor Cyan
Write-Host "  1. 域名变体目录: $DomainDir" -ForegroundColor White
Write-Host "  2. DNS扫描结果: $ScanResult" -ForegroundColor White
if (Test-Path $WhoisResult) {
    Write-Host "  3. WHOIS查询结果: $WhoisResult" -ForegroundColor White
}
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "注意: 详细使用说明请查看 USAGE_GUIDE.md" -ForegroundColor Yellow
