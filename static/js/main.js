// 通用JavaScript函数库 - 域名安全监控系统

// 全局变量
window.DomainSecurityMonitor = {
    config: {
        apiBaseUrl: '/api',
        refreshInterval: 30000 // 30秒
    },
    currentScans: {}
};

// 初始化应用
function initApp() {
    console.log('域名安全监控系统初始化');
    
    // 加载系统状态
    if (typeof checkSystemStatus === 'function') {
        checkSystemStatus();
    }
    
    // 设置页面标题
    document.title = '域名安全监控系统';
    
    // 初始化工具提示
    initTooltips();
    
    // 初始化事件监听器
    initEventListeners();
}

// 初始化工具提示
function initTooltips() {
    // 如果有jQuery UI tooltip则使用，否则使用原生实现
    if (typeof $ !== 'undefined' && $.ui && $.ui.tooltip) {
        $('[title]').tooltip();
    }
}

// 初始化事件监听器
function initEventListeners() {
    // 搜索表单
    const searchForm = document.querySelector('.search-form');
    if (searchForm) {
        searchForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const searchInput = this.querySelector('input[type="search"]');
            if (searchInput && searchInput.value.trim()) {
                const query = searchInput.value.trim();
                window.location.href = `/search?q=${encodeURIComponent(query)}`;
            }
        });
    }
    
    // 侧边栏菜单
    const navLinks = document.querySelectorAll('.nav-link');
    navLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            // 高亮当前活动菜单项
            navLinks.forEach(l => l.classList.remove('active'));
            this.classList.add('active');
        });
    });
}

// 显示加载指示器
function showLoading(container) {
    if (!container) {
        container = document.body;
    }
    
    const loadingDiv = document.createElement('div');
    loadingDiv.className = 'loading-overlay';
    loadingDiv.innerHTML = `
        <div class="loading-spinner">
            <div class="spinner-border text-primary" role="status">
                <span class="visually-hidden">加载中...</span>
            </div>
            <p class="mt-2">加载中...</p>
        </div>
    `;
    
    container.style.position = 'relative';
    container.appendChild(loadingDiv);
    
    return loadingDiv;
}

// 隐藏加载指示器
function hideLoading(loadingDiv) {
    if (loadingDiv && loadingDiv.parentNode) {
        loadingDiv.parentNode.style.position = '';
        loadingDiv.parentNode.removeChild(loadingDiv);
    }
}

// 格式化时间
function formatTime(timestamp) {
    if (!timestamp) return '未知';
    
    const date = new Date(timestamp);
    const now = new Date();
    const diffMs = now - date;
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);
    
    if (diffMins < 1) {
        return '刚刚';
    } else if (diffMins < 60) {
        return `${diffMins}分钟前`;
    } else if (diffHours < 24) {
        return `${diffHours}小时前`;
    } else if (diffDays < 7) {
        return `${diffDays}天前`;
    } else {
        return date.toLocaleDateString('zh-CN');
    }
}

// 格式化文件大小
function formatFileSize(bytes) {
    if (bytes === 0) return '0 B';
    
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// 复制到剪贴板
function copyToClipboard(text, successMessage = '已复制到剪贴板') {
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text)
            .then(() => {
                showNotification(successMessage, 'success');
            })
            .catch(err => {
                console.error('复制失败:', err);
                fallbackCopyToClipboard(text, successMessage);
            });
    } else {
        fallbackCopyToClipboard(text, successMessage);
    }
}

// 回退复制方法
function fallbackCopyToClipboard(text, successMessage) {
    const textArea = document.createElement('textarea');
    textArea.value = text;
    textArea.style.position = 'fixed';
    textArea.style.left = '-999999px';
    textArea.style.top = '-999999px';
    document.body.appendChild(textArea);
    textArea.focus();
    textArea.select();
    
    try {
        const successful = document.execCommand('copy');
        if (successful) {
            showNotification(successMessage, 'success');
        } else {
            showNotification('复制失败', 'danger');
        }
    } catch (err) {
        console.error('复制失败:', err);
        showNotification('复制失败: ' + err.message, 'danger');
    }
    
    document.body.removeChild(textArea);
}

// 导出数据
function exportData(data, filename, type = 'application/json') {
    const blob = new Blob([data], { type: type });
    const url = URL.createObjectURL(blob);
    
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.style.display = 'none';
    
    document.body.appendChild(a);
    a.click();
    
    setTimeout(() => {
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }, 100);
}

// 验证域名格式
function isValidDomain(domain) {
    if (!domain || typeof domain !== 'string') return false;
    
    // 移除前后空格
    domain = domain.trim();
    
    // 简单验证：至少包含一个点，并且点不在开头或结尾
    if (domain.length < 4 || domain.length > 253) return false;
    if (domain.startsWith('.') || domain.endsWith('.')) return false;
    if (!domain.includes('.')) return false;
    
    // 更严格的验证（可选）
    const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](\.[a-zA-Z]{2,})+$/;
    return domainRegex.test(domain);
}

// 生成随机ID
function generateId(prefix = 'id') {
    return `${prefix}_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
}

// 防抖函数
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// 节流函数
function throttle(func, limit) {
    let inThrottle;
    return function() {
        const args = arguments;
        const context = this;
        if (!inThrottle) {
            func.apply(context, args);
            inThrottle = true;
            setTimeout(() => inThrottle = false, limit);
        }
    };
}

// 页面加载完成后初始化
document.addEventListener('DOMContentLoaded', function() {
    // 检查是否需要自动刷新
    const autoRefresh = sessionStorage.getItem('autoRefresh');
    if (autoRefresh === 'true') {
        const interval = setInterval(() => {
            if (typeof refreshDashboard === 'function') {
                refreshDashboard();
            }
        }, DomainSecurityMonitor.config.refreshInterval);
        
        // 存储interval ID以便清除
        sessionStorage.setItem('refreshIntervalId', interval);
    }
    
    // 初始化应用
    initApp();
});

// 页面卸载前清理
window.addEventListener('beforeunload', function() {
    const intervalId = sessionStorage.getItem('refreshIntervalId');
    if (intervalId) {
        clearInterval(intervalId);
        sessionStorage.removeItem('refreshIntervalId');
    }
});

// 全局帮助函数：转义HTML
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// 全局帮助函数：显示通知（如果dashboard.js中的函数不存在）
if (typeof showNotification === 'undefined') {
    window.showNotification = function(message, type = 'info') {
        console.log(`[${type}] ${message}`);
        
        // 尝试使用现有通知系统
        const notificationArea = document.querySelector('.notifications');
        if (notificationArea) {
            const notification = document.createElement('div');
            notification.className = `alert alert-${type}`;
            notification.innerHTML = `<i class="fas fa-info-circle"></i> ${escapeHtml(message)}`;
            notification.style.marginBottom = '10px';
            notification.style.padding = '10px 15px';
            notification.style.borderRadius = '4px';
            notification.style.animation = 'slideIn 0.3s ease';
            
            notificationArea.appendChild(notification);
            
            // 3秒后自动移除
            setTimeout(() => {
                notification.style.animation = 'slideOut 0.3s ease';
                setTimeout(() => {
                    if (notification.parentNode) {
                        notification.parentNode.removeChild(notification);
                    }
                }, 300);
            }, 3000);
        }
    };
}