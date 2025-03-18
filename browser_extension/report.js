document.addEventListener('DOMContentLoaded', () => {
  // 安全地获取DOM元素
  function safeGetElement(id) {
    const element = document.getElementById(id);
    if (!element) {
      console.warn(`找不到ID为${id}的元素`);
      // 返回一个带有常用方法的空对象，避免空引用错误
      return {
        value: '',
        innerHTML: '',
        textContent: '',
        style: {},
        classList: {
          add: () => {},
          remove: () => {},
          toggle: () => {},
          contains: () => false
        },
        appendChild: () => {},
        addEventListener: () => {},
        disabled: false
      };
    }
    return element;
  }
  
  // 安全地添加事件监听器
  function safeAddEventListener(element, event, callback) {
    if (element && typeof element.addEventListener === 'function') {
      element.addEventListener(event, callback);
    } else {
      console.warn(`无法为不存在的元素添加${event}事件监听器`);
    }
  }

  // 安全地发送消息
  function safeSendMessage(message, callback) {
    try {
      if (chrome && chrome.runtime && chrome.runtime.sendMessage) {
        chrome.runtime.sendMessage(message, callback || function() {});
      } else {
        console.warn('chrome.runtime.sendMessage 不可用');
        if (callback) callback({error: 'chrome.runtime.sendMessage 不可用'});
      }
    } catch (error) {
      console.error('发送消息时出错:', error);
      if (callback) callback({error: error.message});
    }
  }

  // DOM元素
  const vulnerabilitiesContainer = safeGetElement('vulnerabilities-container');
  const filterType = safeGetElement('filter-type');
  const filterDomain = safeGetElement('filter-domain');
  const exportButton = safeGetElement('export-report');
  const clearButton = safeGetElement('clear-data');
  const prevButton = safeGetElement('prev-page');
  const nextButton = safeGetElement('next-page');
  const currentPageSpan = safeGetElement('current-page');
  
  // 统计元素
  const totalSitesElem = safeGetElement('total-sites');
  const totalVulnerabilitiesElem = safeGetElement('total-vulnerabilities');
  const xssCountElem = safeGetElement('xss-count');
  const sqliCountElem = safeGetElement('sqli-count');
  const csrfCountElem = safeGetElement('csrf-count');
  
  // 状态变量
  let allVulnerabilities = [];
  let filteredVulnerabilities = [];
  let currentPage = 1;
  const itemsPerPage = 10;
  let domains = new Set();
  
  // 初始化加载数据
  loadVulnerabilities();
  
  // 注册事件监听
  safeAddEventListener(filterType, 'change', filterVulnerabilities);
  safeAddEventListener(filterDomain, 'change', filterVulnerabilities);
  safeAddEventListener(exportButton, 'click', exportReport);
  
  // 添加CSV导出按钮
  const exportCSVButton = document.createElement('button');
  exportCSVButton.id = 'export-csv';
  exportCSVButton.className = 'secondary';
  exportCSVButton.textContent = '导出CSV';
  
  // 将按钮插入到导出报告按钮旁边
  if (exportButton && exportButton.parentNode) {
    exportButton.parentNode.insertBefore(exportCSVButton, exportButton.nextSibling);
  }
  
  // 为CSV导出按钮添加事件监听
  safeAddEventListener(exportCSVButton, 'click', exportAsCSV);
  
  safeAddEventListener(clearButton, 'click', clearData);
  safeAddEventListener(prevButton, 'click', () => navigatePage(-1));
  safeAddEventListener(nextButton, 'click', () => navigatePage(1));
  
  // 加载漏洞数据
  function loadVulnerabilities() {
    chrome.storage.local.get('vulnerabilities', (result) => {
      if (result.vulnerabilities && result.vulnerabilities.length > 0) {
        allVulnerabilities = result.vulnerabilities;
        extractDomains();
        updateFilters();
        filterVulnerabilities();
        updateStatistics();
      } else {
        showNoResults();
      }
    });
  }
  
  // 提取所有域名
  function extractDomains() {
    domains = new Set();
    
    allVulnerabilities.forEach(vuln => {
      try {
        const url = new URL(vuln.details.location);
        domains.add(url.hostname);
      } catch (e) {
        // 忽略无效URL
      }
    });
    
    // 更新域名过滤器
    if (filterDomain) {
      filterDomain.innerHTML = '<option value="all">所有站点</option>';
      domains.forEach(domain => {
        const option = document.createElement('option');
        option.value = domain;
        option.textContent = domain;
        filterDomain.appendChild(option);
      });
    } else {
      console.warn('找不到域名过滤器元素');
    }
  }
  
  // 根据过滤条件筛选漏洞
  function filterVulnerabilities() {
    const typeFilter = filterType.value;
    const domainFilter = filterDomain.value;
    
    filteredVulnerabilities = allVulnerabilities.filter(vuln => {
      let matchesType = typeFilter === 'all' || vuln.type === typeFilter;
      
      let matchesDomain = true;
      if (domainFilter !== 'all') {
        try {
          const url = new URL(vuln.details.location);
          matchesDomain = url.hostname === domainFilter;
        } catch (e) {
          matchesDomain = false;
        }
      }
      
      return matchesType && matchesDomain;
    });
    
    // 重置到第一页
    currentPage = 1;
    displayVulnerabilities();
    updatePagination();
  }
  
  // 显示漏洞列表
  function displayVulnerabilities() {
    if (filteredVulnerabilities.length === 0) {
      showNoResults();
      return;
    }
    
    // 计算当前页的数据
    const startIndex = (currentPage - 1) * itemsPerPage;
    const endIndex = Math.min(startIndex + itemsPerPage, filteredVulnerabilities.length);
    const currentPageItems = filteredVulnerabilities.slice(startIndex, endIndex);
    
    if (!vulnerabilitiesContainer) {
      console.warn('找不到漏洞容器元素');
      return;
    }
    
    vulnerabilitiesContainer.innerHTML = '';
    
    currentPageItems.forEach(vuln => {
      const vulnerabilityElement = document.createElement('div');
      vulnerabilityElement.className = 'vulnerability';
      
      // 获取简短的URL
      let shortUrl = '';
      try {
        const url = new URL(vuln.details.location);
        shortUrl = url.hostname + url.pathname.substring(0, 20) + (url.pathname.length > 20 ? '...' : '');
      } catch (e) {
        shortUrl = vuln.details.location.substring(0, 30) + '...';
      }
      
      vulnerabilityElement.innerHTML = `
        <h3>${vuln.type}</h3>
        <div class="vulnerability-details">
          <div class="label">URL:</div>
          <div><a href="${vuln.details.location}" target="_blank">${shortUrl}</a></div>
          
          <div class="label">证据:</div>
          <div>${vuln.details.evidence}</div>
        </div>
        <div class="evidence">${formatEvidence(vuln.details.evidence)}</div>
        <div class="timestamp">发现时间: ${new Date(vuln.timestamp).toLocaleString()}</div>
      `;
      
      vulnerabilitiesContainer.appendChild(vulnerabilityElement);
    });
  }
  
  // 格式化证据文本
  function formatEvidence(evidence) {
    if (!evidence) return '无详细信息';
    
    // 转义HTML
    return evidence
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }
  
  // 显示无结果提示
  function showNoResults() {
    if (vulnerabilitiesContainer) {
      vulnerabilitiesContainer.innerHTML = '<div class="no-results">暂无漏洞数据</div>';
    } else {
      console.warn('找不到漏洞容器元素');
    }
    updatePagination();
  }
  
  // 更新分页控件
  function updatePagination() {
    const totalPages = Math.ceil(filteredVulnerabilities.length / itemsPerPage);
    
    currentPageSpan.textContent = `第 ${currentPage} 页 / 共 ${totalPages} 页`;
    
    prevButton.disabled = currentPage <= 1;
    nextButton.disabled = currentPage >= totalPages;
    
    const paginationElement = document.querySelector('.pagination');
    if (paginationElement) {
      paginationElement.style.display = totalPages <= 1 ? 'none' : 'flex';
    } else {
      console.warn('找不到分页元素');
    }
  }
  
  // 翻页
  function navigatePage(direction) {
    const totalPages = Math.ceil(filteredVulnerabilities.length / itemsPerPage);
    const newPage = currentPage + direction;
    
    if (newPage >= 1 && newPage <= totalPages) {
      currentPage = newPage;
      displayVulnerabilities();
      updatePagination();
    }
  }
  
  // 更新过滤器
  function updateFilters() {
    // 具体实现：更新过滤器选项
  }
  
  // 更新统计信息
  function updateStatistics() {
    // 计算网站数量
    const siteCount = domains.size;
    totalSitesElem.textContent = siteCount;
    
    // 总漏洞数
    totalVulnerabilitiesElem.textContent = allVulnerabilities.length;
    
    // 各类型漏洞数
    const xssCount = allVulnerabilities.filter(v => v.type === 'XSS').length;
    const sqliCount = allVulnerabilities.filter(v => v.type === 'SQL Injection').length;
    const csrfCount = allVulnerabilities.filter(v => v.type === 'CSRF').length;
    
    xssCountElem.textContent = xssCount;
    sqliCountElem.textContent = sqliCount;
    csrfCountElem.textContent = csrfCount;
    
    // 各严重程度漏洞数
    const criticalCount = allVulnerabilities.filter(v => 
      v.details && v.details.severity && v.details.severity.toLowerCase() === 'critical').length;
    const highCount = allVulnerabilities.filter(v => 
      v.details && v.details.severity && v.details.severity.toLowerCase() === 'high').length;
    const mediumCount = allVulnerabilities.filter(v => 
      v.details && v.details.severity && v.details.severity.toLowerCase() === 'medium').length;
    const lowCount = allVulnerabilities.filter(v => 
      v.details && v.details.severity && v.details.severity.toLowerCase() === 'low').length;
    
    // 更新仪表盘上的严重程度计数
    const criticalCountElem = safeGetElement('critical-count');
    const highCountElem = safeGetElement('high-count');
    const mediumCountElem = safeGetElement('medium-count');
    const lowCountElem = safeGetElement('low-count');
    
    criticalCountElem.textContent = criticalCount;
    highCountElem.textContent = highCount;
    mediumCountElem.textContent = mediumCount;
    lowCountElem.textContent = lowCount;
    
    // 生成图表
    drawVulnerabilityChart();
    drawSeverityChart();
    drawDomainDistributionChart();
    drawRecentActivityChart();
  }
  
  // 绘制漏洞类型统计图表
  function drawVulnerabilityChart() {
    // 获取所有漏洞类型及其数量
    const vulnTypes = {};
    allVulnerabilities.forEach(vuln => {
      if (!vulnTypes[vuln.type]) {
        vulnTypes[vuln.type] = 0;
      }
      vulnTypes[vuln.type]++;
    });
    
    // 获取图表容器
    const chartContainer = safeGetElement('vulnerability-type-chart');
    if (!chartContainer) return;
    
    // 清空容器
    chartContainer.innerHTML = '';
    
    // 如果没有漏洞，显示无数据
    if (Object.keys(vulnTypes).length === 0) {
      chartContainer.innerHTML = '<div class="no-data">暂无数据</div>';
      return;
    }
    
    // 创建Canvas元素
    const canvas = document.createElement('canvas');
    canvas.width = chartContainer.clientWidth;
    canvas.height = chartContainer.clientHeight;
    chartContainer.appendChild(canvas);
    
    // 获取绘图上下文
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    
    // 定义颜色
    const colors = [
      '#e74c3c', '#3498db', '#2ecc71', '#f39c12', '#9b59b6',
      '#1abc9c', '#d35400', '#34495e', '#7f8c8d', '#c0392b'
    ];
    
    // 定义饼图参数
    const centerX = canvas.width / 2;
    const centerY = canvas.height / 2;
    const radius = Math.min(centerX, centerY) * 0.8;
    
    // 计算总数
    const total = Object.values(vulnTypes).reduce((sum, count) => sum + count, 0);
    
    // 绘制饼图
    let startAngle = 0;
    let colorIndex = 0;
    
    // 创建图例容器
    const legend = document.createElement('div');
    legend.className = 'chart-legend';
    chartContainer.appendChild(legend);
    
    for (const [type, count] of Object.entries(vulnTypes)) {
      const angle = (count / total) * Math.PI * 2;
      
      // 绘制扇形
      ctx.beginPath();
      ctx.moveTo(centerX, centerY);
      ctx.arc(centerX, centerY, radius, startAngle, startAngle + angle);
      ctx.closePath();
      
      // 填充颜色
      ctx.fillStyle = colors[colorIndex % colors.length];
      ctx.fill();
      
      // 绘制边框
      ctx.strokeStyle = 'white';
      ctx.lineWidth = 2;
      ctx.stroke();
      
      // 添加图例项
      const legendItem = document.createElement('div');
      legendItem.className = 'legend-item';
      legendItem.innerHTML = `
        <span class="color-box" style="background-color: ${colors[colorIndex % colors.length]}"></span>
        <span class="type">${type}</span>
        <span class="count">${count} (${Math.round((count / total) * 100)}%)</span>
      `;
      legend.appendChild(legendItem);
      
      // 更新角度和颜色索引
      startAngle += angle;
      colorIndex++;
    }
    
    // 添加CSS样式
    const style = document.createElement('style');
    style.textContent = `
      .chart-legend {
        margin-top: 15px;
        display: flex;
        flex-wrap: wrap;
        gap: 10px;
      }
      .legend-item {
        display: flex;
        align-items: center;
        margin-right: 15px;
        margin-bottom: 5px;
      }
      .color-box {
        width: 12px;
        height: 12px;
        margin-right: 5px;
        border-radius: 2px;
      }
      .type {
        margin-right: 5px;
        font-weight: bold;
      }
      .count {
        color: #666;
      }
      .no-data {
        display: flex;
        align-items: center;
        justify-content: center;
        height: 100%;
        color: #999;
        font-style: italic;
      }
    `;
    document.head.appendChild(style);
  }
  
  // 绘制漏洞严重程度分布图表
  function drawSeverityChart() {
    // 获取各严重程度漏洞数量
    const severityCounts = {
      '严重': allVulnerabilities.filter(v => 
        v.details && v.details.severity && v.details.severity.toLowerCase() === 'critical').length,
      '高危': allVulnerabilities.filter(v => 
        v.details && v.details.severity && v.details.severity.toLowerCase() === 'high').length,
      '中危': allVulnerabilities.filter(v => 
        v.details && v.details.severity && v.details.severity.toLowerCase() === 'medium').length,
      '低危': allVulnerabilities.filter(v => 
        v.details && v.details.severity && v.details.severity.toLowerCase() === 'low').length
    };
    
    // 获取图表容器
    const chartContainer = safeGetElement('severity-chart');
    if (!chartContainer) return;
    
    // 清空容器
    chartContainer.innerHTML = '';
    
    // 如果没有漏洞，显示无数据
    if (Object.values(severityCounts).reduce((sum, count) => sum + count, 0) === 0) {
      chartContainer.innerHTML = '<div class="no-data">暂无数据</div>';
      return;
    }
    
    // 创建Canvas元素
    const canvas = document.createElement('canvas');
    canvas.width = chartContainer.clientWidth;
    canvas.height = chartContainer.clientHeight;
    chartContainer.appendChild(canvas);
    
    // 获取绘图上下文
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    
    // 定义颜色
    const colors = {
      '严重': '#9c27b0',
      '高危': '#e74c3c',
      '中危': '#f39c12',
      '低危': '#3498db'
    };
    
    // 定义饼图参数
    const centerX = canvas.width / 2;
    const centerY = canvas.height / 2;
    const radius = Math.min(centerX, centerY) * 0.8;
    
    // 计算总数
    const total = Object.values(severityCounts).reduce((sum, count) => sum + count, 0);
    
    // 绘制饼图
    let startAngle = 0;
    
    // 创建图例容器
    const legend = document.createElement('div');
    legend.className = 'chart-legend';
    chartContainer.appendChild(legend);
    
    for (const [severity, count] of Object.entries(severityCounts)) {
      // 跳过计数为0的严重程度
      if (count === 0) continue;
      
      const angle = (count / total) * Math.PI * 2;
      
      // 绘制扇形
      ctx.beginPath();
      ctx.moveTo(centerX, centerY);
      ctx.arc(centerX, centerY, radius, startAngle, startAngle + angle);
      ctx.closePath();
      
      // 填充颜色
      ctx.fillStyle = colors[severity];
      ctx.fill();
      
      // 绘制边框
      ctx.strokeStyle = 'white';
      ctx.lineWidth = 2;
      ctx.stroke();
      
      // 添加图例项
      const legendItem = document.createElement('div');
      legendItem.className = 'legend-item';
      legendItem.innerHTML = `
        <span class="color-box" style="background-color: ${colors[severity]}"></span>
        <span class="type">${severity}</span>
        <span class="count">${count} (${Math.round((count / total) * 100)}%)</span>
      `;
      legend.appendChild(legendItem);
      
      // 更新角度
      startAngle += angle;
    }
  }
  
  // 绘制站点漏洞分布图表
  function drawDomainDistributionChart() {
    // 获取图表容器
    const chartContainer = safeGetElement('domain-distribution-chart');
    if (!chartContainer) return;
    
    // 清空容器
    chartContainer.innerHTML = '';
    
    // 如果没有漏洞，显示无数据
    if (allVulnerabilities.length === 0 || domains.size === 0) {
      chartContainer.innerHTML = '<div class="no-data">暂无数据</div>';
      return;
    }
    
    // 按域名分组漏洞
    const domainVulnCounts = {};
    allVulnerabilities.forEach(vuln => {
      try {
        const url = new URL(vuln.details.location);
        const domain = url.hostname;
        
        if (!domainVulnCounts[domain]) {
          domainVulnCounts[domain] = 0;
        }
        
        domainVulnCounts[domain]++;
      } catch (e) {
        // 忽略无效URL
      }
    });
    
    // 创建Canvas元素
    const canvas = document.createElement('canvas');
    canvas.width = chartContainer.clientWidth;
    canvas.height = chartContainer.clientHeight;
    chartContainer.appendChild(canvas);
    
    // 获取绘图上下文
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    
    // 定义颜色
    const colors = [
      '#e74c3c', '#3498db', '#2ecc71', '#f39c12', '#9b59b6',
      '#1abc9c', '#d35400', '#34495e', '#7f8c8d', '#c0392b'
    ];
    
    // 排序域名（按漏洞数量降序）
    const sortedDomains = Object.keys(domainVulnCounts).sort((a, b) => 
      domainVulnCounts[b] - domainVulnCounts[a]
    );
    
    // 限制最多显示前8个域名
    const displayDomains = sortedDomains.slice(0, 8);
    
    // 计算图表尺寸
    const barHeight = 25;
    const barSpacing = 10;
    const maxBarWidth = canvas.width - 150; // 留出右侧空间显示计数
    const maxCount = Math.max(...Object.values(domainVulnCounts));
    
    // 绘制柱状图
    displayDomains.forEach((domain, index) => {
      const count = domainVulnCounts[domain];
      const barWidth = (count / maxCount) * maxBarWidth;
      const y = index * (barHeight + barSpacing) + 20;
      
      // 绘制域名
      ctx.fillStyle = '#333';
      ctx.font = '12px Arial';
      ctx.textAlign = 'left';
      ctx.fillText(domain.length > 20 ? domain.substring(0, 17) + '...' : domain, 0, y);
      
      // 绘制柱状
      ctx.fillStyle = colors[index % colors.length];
      ctx.fillRect(0, y + 5, barWidth, barHeight);
      
      // 绘制计数
      ctx.fillStyle = '#333';
      ctx.textAlign = 'left';
      ctx.fillText(count.toString(), barWidth + 5, y + barHeight/2 + 5);
    });
    
    // 如果域名太多，添加提示
    if (sortedDomains.length > displayDomains.length) {
      ctx.fillStyle = '#666';
      ctx.font = '12px Arial';
      ctx.textAlign = 'center';
      ctx.fillText(`还有 ${sortedDomains.length - displayDomains.length} 个站点未显示`, canvas.width/2, canvas.height - 10);
    }
  }
  
  // 绘制最近检测活动图表
  function drawRecentActivityChart() {
    // 获取图表容器
    const chartContainer = safeGetElement('recent-activity-chart');
    if (!chartContainer) return;
    
    // 清空容器
    chartContainer.innerHTML = '';
    
    // 如果没有漏洞，显示无数据
    if (allVulnerabilities.length === 0) {
      chartContainer.innerHTML = '<div class="no-data">暂无数据</div>';
      return;
    }
    
    // 按日期对漏洞进行分组
    const vulnsByDate = {};
    
    // 获取最近7天的日期
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    
    const dates = [];
    for (let i = 6; i >= 0; i--) {
      const date = new Date(today);
      date.setDate(date.getDate() - i);
      const dateStr = date.toISOString().split('T')[0];
      dates.push(dateStr);
      vulnsByDate[dateStr] = 0;
    }
    
    // 统计每天的漏洞数量
    allVulnerabilities.forEach(vuln => {
      if (vuln.timestamp) {
        const vulnDate = new Date(vuln.timestamp);
        const dateStr = vulnDate.toISOString().split('T')[0];
        
        // 检查是否在最近7天内
        if (vulnsByDate.hasOwnProperty(dateStr)) {
          vulnsByDate[dateStr]++;
        }
      }
    });
    
    // 创建Canvas元素
    const canvas = document.createElement('canvas');
    canvas.width = chartContainer.clientWidth;
    canvas.height = chartContainer.clientHeight;
    chartContainer.appendChild(canvas);
    
    // 获取绘图上下文
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    
    // 图表尺寸
    const chartWidth = canvas.width - 60;
    const chartHeight = canvas.height - 60;
    const leftPadding = 40;
    const bottomPadding = 40;
    
    // 获取最大值
    const maxVulns = Math.max(...Object.values(vulnsByDate), 1);
    
    // 设置刻度
    const yStep = chartHeight / 5;
    const xStep = chartWidth / (dates.length - 1);
    
    // 绘制Y轴
    ctx.beginPath();
    ctx.moveTo(leftPadding, 20);
    ctx.lineTo(leftPadding, 20 + chartHeight);
    ctx.strokeStyle = '#999';
    ctx.stroke();
    
    // 绘制Y轴刻度
    for (let i = 0; i <= 5; i++) {
      const y = 20 + chartHeight - i * yStep;
      const value = Math.round(maxVulns * i / 5);
      
      ctx.beginPath();
      ctx.moveTo(leftPadding - 5, y);
      ctx.lineTo(leftPadding, y);
      ctx.strokeStyle = '#999';
      ctx.stroke();
      
      ctx.fillStyle = '#666';
      ctx.font = '10px Arial';
      ctx.textAlign = 'right';
      ctx.fillText(value.toString(), leftPadding - 8, y + 3);
    }
    
    // 绘制X轴
    ctx.beginPath();
    ctx.moveTo(leftPadding, 20 + chartHeight);
    ctx.lineTo(leftPadding + chartWidth, 20 + chartHeight);
    ctx.strokeStyle = '#999';
    ctx.stroke();
    
    // 绘制X轴刻度和日期
    dates.forEach((dateStr, index) => {
      const x = leftPadding + index * xStep;
      
      ctx.beginPath();
      ctx.moveTo(x, 20 + chartHeight);
      ctx.lineTo(x, 20 + chartHeight + 5);
      ctx.strokeStyle = '#999';
      ctx.stroke();
      
      // 格式化日期为简短格式（如"3/15"）
      const date = new Date(dateStr);
      const formattedDate = `${date.getMonth() + 1}/${date.getDate()}`;
      
      ctx.fillStyle = '#666';
      ctx.font = '10px Arial';
      ctx.textAlign = 'center';
      ctx.fillText(formattedDate, x, 20 + chartHeight + 18);
    });
    
    // 绘制数据点和连线
    ctx.beginPath();
    
    dates.forEach((dateStr, index) => {
      const value = vulnsByDate[dateStr];
      const x = leftPadding + index * xStep;
      const y = 20 + chartHeight - (value / maxVulns) * chartHeight;
      
      if (index === 0) {
        ctx.moveTo(x, y);
      } else {
        ctx.lineTo(x, y);
      }
      
      // 绘制数据点
      ctx.fillStyle = '#3498db';
      ctx.beginPath();
      ctx.arc(x, y, 4, 0, Math.PI * 2);
      ctx.fill();
      
      // 显示值
      ctx.fillStyle = '#333';
      ctx.font = '11px Arial';
      ctx.textAlign = 'center';
      ctx.fillText(value.toString(), x, y - 10);
    });
    
    // 绘制连线
    ctx.strokeStyle = '#3498db';
    ctx.lineWidth = 2;
    ctx.stroke();
    
    // 添加标题
    ctx.fillStyle = '#333';
    ctx.font = 'bold 12px Arial';
    ctx.textAlign = 'center';
    ctx.fillText('最近7天漏洞发现趋势', canvas.width / 2, 15);
  }
  
  // 导出报告
  function exportReport() {
    safeSendMessage(
      { action: 'generateReport' },
      (response) => {
        if (response && response.report) {
          // 创建下载链接
          const blob = new Blob([response.report], { type: 'text/markdown' });
          const url = URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = `漏洞报告_${new Date().toISOString().split('T')[0]}.md`;
          document.body.appendChild(a);
          a.click();
          
          // 清理
          setTimeout(() => {
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
          }, 100);
        } else {
          alert('生成报告失败');
        }
      }
    );
  }
});