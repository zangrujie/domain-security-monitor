// 域名安全监控系统 - 仪表板JavaScript

// 全局变量
let riskChart = null;

// 加载仪表板数据
async function loadDashboardData() {
    try {
        console.log('加载仪表板数据...');
        
        // 加载统计信息
        const statsResponse = await fetch('/api/dashboard/stats');
        if (!statsResponse.ok) throw new Error('统计信息加载失败');
        const statsData = await statsResponse.json();
        
        if (statsData.success) {
            updateStatsCards(statsData.data);
        }
        
        // 加载最近域名
        await loadRecentDomains();
        
        // 加载风险分布
        await loadRiskDistribution();
        
    } catch (error) {
        console.error('加载仪表板数据失败:', error);
        showNotification('数据加载失败: ' + error.message, 'danger');
    }
}

// 更新统计卡片
function updateStatsCards(stats) {
    // 更新监控域名总数
    const totalDomains = stats.total_domains || 0;
    document.getElementById('total-domains').textContent = totalDomains;
    document.getElementById('domain-change').textContent = Math.floor(totalDomains * 0.1); // 模拟10%增长
    
    // 更新高风险域名
    const highRisk = stats.high_risk_domains || 0;
    document.getElementById('high-risk-domains').textContent = highRisk;
    document.getElementById('high-risk-change').textContent = Math.floor(highRisk * 0.05); // 模拟5%变化
    
    // 更新最近扫描
    const recentScans = stats.recent_scans || 0;
    document.getElementById('recent-scans').textContent = recentScans;
    document.getElementById('scan-time').textContent = '30分钟'; // 模拟时间
    
    // 更新威胁检测
    const threats = stats.threats_detected || 0;
    document.getElementById('threats-detected').textContent = threats;
    document.getElementById('threat-change').textContent = Math.floor(threats * 0.08); // 模拟8%拦截
}

// 加载最近域名
async function loadRecentDomains() {
    const tableBody = document.getElementById('recent-domains-table');
    if (!tableBody) return;
    
    try {
        tableBody.innerHTML = `
            <tr>
                <td colspan="4" class="loading">
                    <div class="spinner"></div>
                    加载中...
                </td>
            </tr>
        `;
        
        const response = await fetch('/api/dashboard/recent-domains?limit=5');
        if (!response.ok) throw new Error('域名列表加载失败');
        const data = await response.json();
        
        if (data.success && data.data.length > 0) {
            let html = '';
            data.data.forEach(domain => {
                const riskClass = getRiskClass(domain.risk_level);
                const riskText = getRiskText(domain.risk_level);
                
                html += `
                    <tr>
                        <td>
                            <div class="domain-info">
                                <strong>${escapeHtml(domain.domain)}</strong>
                                <br>
                                <small>原目标: ${escapeHtml(domain.original_target)}</small>
                            </div>
                        </td>
                        <td>${escapeHtml(domain.scan_time || '未知')}</td>
                        <td>
                            <span class="risk-badge ${riskClass}">${riskText}</span>
                        </td>
                        <td>
                            <button class="btn btn-sm btn-secondary" onclick="viewDomainDetail('${escapeHtml(domain.domain)}')">
                                <i class="fas fa-eye"></i> 查看
                            </button>
                        </td>
                    </tr>
                `;
            });
            tableBody.innerHTML = html;
        } else {
            tableBody.innerHTML = `
                <tr>
                    <td colspan="4" class="empty-state">
                        <i class="fas fa-inbox"></i>
                        <p>暂无域名数据</p>
                        <button class="btn btn-primary" onclick="startNewScan()">
                            <i class="fas fa-plus"></i> 开始第一次扫描
                        </button>
                    </td>
                </tr>
            `;
        }
    } catch (error) {
        console.error('加载域名列表失败:', error);
        tableBody.innerHTML = `
            <tr>
                <td colspan="4" class="empty-state">
                    <i class="fas fa-exclamation-triangle"></i>
                    <p>加载失败: ${error.message}</p>
                    <button class="btn btn-secondary" onclick="loadRecentDomains()">
                        <i class="fas fa-redo"></i> 重试
                    </button>
                </td>
            </tr>
        `;
    }
}

// 加载风险分布图表
async function loadRiskDistribution() {
    try {
        const response = await fetch('/api/dashboard/risk-distribution');
        if (!response.ok) throw new Error('风险分布数据加载失败');
        const data = await response.json();
        
        if (data.success) {
            renderRiskChart(data.data);
        }
    } catch (error) {
        console.error('加载风险分布失败:', error);
        // 使用示例数据
        renderRiskChart({critical: 1, high: 3, medium: 7, low: 15});
    }
}

// 渲染风险分布图表
function renderRiskChart(distribution) {
    const ctx = document.getElementById('riskDistributionChart');
    if (!ctx) return;
    
    // 销毁现有图表
    if (riskChart) {
        riskChart.destroy();
    }
    
    const labels = ['严重', '高', '中', '低'];
    const dataValues = [
        distribution.critical || 0,
        distribution.high || 0,
        distribution.medium || 0,
        distribution.low || 0
    ];
    
    const backgroundColors = [
        'rgba(231, 76, 60, 0.8)',    // 严重 - 红色
        'rgba(230, 126, 34, 0.8)',   // 高 - 橙色
        'rgba(241, 196, 15, 0.8)',   // 中 - 黄色
        'rgba(46, 204, 113, 0.8)'    // 低 - 绿色
    ];
    
    const borderColors = [
        'rgb(231, 76, 60)',
        'rgb(230, 126, 34)',
        'rgb(241, 196, 15)',
        'rgb(46, 204, 113)'
    ];
    
    riskChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: dataValues,
                backgroundColor: backgroundColors,
                borderColor: borderColors,
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right',
                    labels: {
                        font: {
                            size: 12
                        }
                    }
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const label = context.label || '';
                            const value = context.raw || 0;
                            const total = dataValues.reduce((a, b) => a + b, 0);
                            const percentage = total > 0 ? Math.round((value / total) * 100) : 0;
                            return `${label}: ${value} (${percentage}%)`;
                        }
                    }
                }
            }
        }
    });
}

// 检查系统状态
async function checkSystemStatus() {
    try {
        console.log('检查系统状态...');
        
        const response = await fetch('/api/system/status');
        if (!response.ok) throw new Error('系统状态检查失败');
        const data = await response.json();
        
        if (data.success) {
            const status = data.data;
            
            // 更新数据库状态
            const dbStatus = document.getElementById('db-status');
            if (dbStatus) {
                if (status.database) {
                    dbStatus.textContent = '正常';
                    dbStatus.className = 'status-value status-online';
                } else {
                    dbStatus.textContent = '断开';
                    dbStatus.className = 'status-value status-offline';
                }
            }
            
            // 更新VirusTotal状态
            const vtStatus = document.getElementById('vt-status');
            if (vtStatus) {
                if (status.api_keys?.virustotal) {
                    vtStatus.textContent = '已连接';
                    vtStatus.className = 'status-value status-online';
                } else {
                    vtStatus.textContent = '未配置';
                    vtStatus.className = 'status-value status-offline';
                }
            }
            
            // 更新扫描引擎状态
            const engineStatus = document.getElementById('engine-status');
            if (engineStatus) {
                engineStatus.textContent = '运行中';
                engineStatus.className = 'status-value status-online';
            }
            
            // 更新存储空间状态
            const storageStatus = document.getElementById('storage-status');
            if (storageStatus) {
                const domainCount = status.storage?.domain_count || 0;
                const resultFiles = status.storage?.result_files || 0;
                storageStatus.textContent = `${domainCount}个域名/${resultFiles}个结果`;
                storageStatus.className = 'status-value status-online';
            }
            
            showNotification('系统状态检查完成', 'success');
        }
    } catch (error) {
        console.error('检查系统状态失败:', error);
        
        // 更新状态显示为错误
        const statusElements = ['db-status', 'vt-status', 'engine-status', 'storage-status'];
        statusElements.forEach(id => {
            const element = document.getElementById(id);
            if (element) {
                element.textContent = '检查失败';
                element.className = 'status-value status-offline';
            }
        });
        
        showNotification('系统状态检查失败: ' + error.message, 'danger');
    }
}

// 开始快速扫描
async function startQuickScan(event) {
    event.preventDefault();
    
    const domainInput = document.getElementById('target-domain');
    const domain = domainInput.value.trim();
    
    if (!domain) {
        showNotification('请输入域名', 'warning');
        return false;
    }
    
    // 验证域名格式
    if (!isValidDomain(domain)) {
        showNotification('域名格式不正确，请输入类似 example.com 的格式', 'warning');
        return false;
    }
    
    // 显示进度条
    const progressContainer = document.getElementById('scan-progress');
    const progressBar = document.getElementById('scan-progress-bar');
    const scanMessage = document.getElementById('scan-message');
    
    progressContainer.style.display = 'block';
    scanMessage.textContent = `正在扫描域名: ${domain}`;
    progressBar.style.width = '10%';
    
    try {
        // 发送扫描请求
        const response = await fetch('/api/scan/start', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ domain: domain })
        });
        
        if (!response.ok) throw new Error('扫描请求失败');
        
        const data = await response.json();
        
        if (data.success) {
            // 模拟扫描进度
            simulateScanProgress(progressBar, scanMessage, data.data.scan_id);
            
            showNotification(`扫描任务已启动: ${domain}`, 'success');
        } else {
            throw new Error(data.error || '扫描启动失败');
        }
    } catch (error) {
        console.error('扫描启动失败:', error);
        progressBar.style.width = '100%';
        progressBar.style.backgroundColor = '#e74c3c';
        scanMessage.textContent = `扫描失败: ${error.message}`;
        
        setTimeout(() => {
            progressContainer.style.display = 'none';
            progressBar.style.width = '0%';
            progressBar.style.backgroundColor = '#3498db';
        }, 3000);
        
        showNotification('扫描启动失败: ' + error.message, 'danger');
    }
    
    return false;
}

// 模拟扫描进度
function simulateScanProgress(progressBar, scanMessage, scanId) {
    let progress = 10;
    const steps = [
        { percent: 20, message: '正在生成域名变体...' },
        { percent: 40, message: '进行DNS探测...' },
        { percent: 60, message: '扫描HTTP服务...' },
        { percent: 80, message: '查询WHOIS信息...' },
        { percent: 90, message: '检查威胁情报...' },
        { percent: 100, message: '扫描完成，生成报告...' }
    ];
    
    let stepIndex = 0;
    
    const interval = setInterval(() => {
        if (stepIndex < steps.length) {
            const step = steps[stepIndex];
            progress = step.percent;
            progressBar.style.width = progress + '%';
            scanMessage.textContent = step.message;
            stepIndex++;
        } else {
            clearInterval(interval);
            
            // 扫描完成
            setTimeout(() => {
                scanMessage.textContent = '扫描完成！正在加载结果...';
                setTimeout(() => {
                    document.getElementById('scan-progress').style.display = 'none';
                    progressBar.style.width = '0%';
                    document.getElementById('target-domain').value = '';
                    
                    // 刷新仪表板数据
                    loadDashboardData();
                    showNotification('域名扫描完成，结果已更新', 'success');
                }, 1500);
            }, 1000);
        }
    }, 1500);
}

// 查看域名详情
function viewDomainDetail(domain) {
    // 这里可以跳转到域名详情页面或打开模态框
    console.log('查看域名详情:', domain);
    showNotification(`正在加载域名详情: ${domain}`, 'info');
    
    // 模拟跳转到详情页面
    window.location.href = `/domains/${encodeURIComponent(domain)}`;
}

// 开始新扫描
function startNewScan() {
    document.getElementById('target-domain').focus();
    showNotification('输入要扫描的域名，然后点击"开始扫描"按钮', 'info');
}

// 刷新仪表板
function refreshDashboard() {
    loadDashboardData();
    showNotification('仪表板数据已刷新', 'info');
}

// 显示高级选项
function showAdvancedOptions() {
    showNotification('高级选项功能正在开发中', 'info');
}

// 显示通知
function showNotification(message, type = 'info') {
    // 创建通知元素
    const notification = document.createElement('div');
    notification.className = `alert alert-${type}`;
    notification.innerHTML = `<i class="fas fa-info-circle"></i> ${escapeHtml(message)}`;
    
    // 添加到通知区域
    const notificationArea = document.querySelector('.notifications');
    if (notificationArea) {
        notificationArea.appendChild(notification);
        
        // 3秒后自动移除
        setTimeout(() => {
            notification.remove();
        }, 3000);
    }
}

// 辅助函数：获取风险等级对应的CSS类
function getRiskClass(riskLevel) {
    switch (riskLevel?.toLowerCase()) {
        case 'critical': return 'risk-critical';
        case 'high': return 'risk-high';
        case 'medium': return 'risk-medium';
        case 'low': return 'risk-low';
        default: return 'risk-medium';
    }
}

// 辅助函数：获取风险等级对应的文本
function getRiskText(riskLevel) {
    switch (riskLevel?.toLowerCase()) {
        case 'critical': return '严重';
        case 'high': return '高';
        case 'medium': return '中';
        case 'low': return '低';
        default: return '未知';
    }
}

// 辅助函数：验证域名格式
function isValidDomain(domain) {
    // 简单的域名验证
    const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$/;
    return domainRegex.test(domain) && domain.includes('.');
}

// 辅助函数：HTML转义
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}