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
  
  // 颜色常量定义
  const CHART_COLORS = {
    // 漏洞类型颜色
    vulnerabilityTypes: {
      'XSS': '#FF6384',
      'SQL Injection': '#36A2EB',
      'CSRF': '#FFCE56',
      'Information Leak': '#4BC0C0',
      'HTTP Header': '#9966FF',
      'Other': '#FF9F40',
      'default': '#C9C9C9'
    },
    // 严重程度颜色
    severityLevels: {
      'critical': '#9c27b0',
      'high': '#e74c3c',
      'medium': '#f39c12',
      'low': '#3498db',
      'info': '#7f8c8d'
    },
    // 图表通用配置
    chartConfig: {
      fontFamily: "'Microsoft YaHei', Arial, sans-serif",
      titleFontSize: 14,
      labelFontSize: 12,
      valueFontSize: 11
    }
  };
  
  // 绘制漏洞类型统计图表
  function drawVulnerabilityChart() {
    // 获取漏洞类型分布的数据
    const vulnerabilityTypes = {};
    let totalVulnerabilities = 0;

    // 计算各类型漏洞数量
    allVulnerabilities.forEach(vulnerability => {
      const type = vulnerability.type || 'Other';
      vulnerabilityTypes[type] = (vulnerabilityTypes[type] || 0) + 1;
      totalVulnerabilities++;
    });

    // 获取图表容器
    const chartContainer = safeGetElement('vulnerability-type-chart');
    if (!chartContainer) return;
    
    // 清空容器
    chartContainer.innerHTML = '';
    
    // 如果没有漏洞数据，显示提示信息
    if (totalVulnerabilities === 0) {
      chartContainer.innerHTML = '<div class="no-data">暂无漏洞数据</div>';
      return;
    }
    
    // 创建Canvas元素
    const canvas = document.createElement('canvas');
    canvas.width = chartContainer.clientWidth;
    canvas.height = 250;
    chartContainer.appendChild(canvas);
    
    // 获取绘图上下文
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    
    // 准备饼图数据
    const data = [];
    const labels = [];
    const percentages = [];
    
    for (const type in vulnerabilityTypes) {
      const count = vulnerabilityTypes[type];
      const percentage = (count / totalVulnerabilities) * 100;
      
      data.push(count);
      labels.push(type);
      percentages.push(percentage.toFixed(1));
    }
    
    // 绘制饼图
    const centerX = canvas.width / 2;
    const centerY = canvas.height / 2 - 10; // 向上偏移一点，为图例留出空间
    const radius = Math.min(centerX, centerY) * 0.8;
    
    let startAngle = 0;
    
    // 创建图例容器
    const legendDiv = document.createElement('div');
    legendDiv.style.display = 'flex';
    legendDiv.style.flexWrap = 'wrap';
    legendDiv.style.justifyContent = 'center';
    legendDiv.style.gap = '10px';
    legendDiv.style.marginTop = '15px';
    legendDiv.style.fontSize = CHART_COLORS.chartConfig.labelFontSize + 'px';
    
    // 绘制饼图扇区和创建图例
    data.forEach((value, index) => {
      const sliceAngle = (value / totalVulnerabilities) * 2 * Math.PI;
      const endAngle = startAngle + sliceAngle;
      
      // 绘制扇区
      ctx.beginPath();
      ctx.moveTo(centerX, centerY);
      ctx.arc(centerX, centerY, radius, startAngle, endAngle);
      ctx.closePath();
      
      // 设置扇区颜色和描边
      ctx.fillStyle = CHART_COLORS.vulnerabilityTypes[labels[index]] || CHART_COLORS.vulnerabilityTypes['default'];
      ctx.strokeStyle = 'white';
      ctx.lineWidth = 2;
      ctx.fill();
      ctx.stroke();
      
      // 创建图例项
      const legendItem = document.createElement('div');
      legendItem.style.display = 'flex';
      legendItem.style.alignItems = 'center';
      legendItem.style.padding = '3px 8px';
      legendItem.style.backgroundColor = 'rgba(255, 255, 255, 0.7)';
      legendItem.style.borderRadius = '4px';
      legendItem.style.boxShadow = '0 1px 3px rgba(0,0,0,0.1)';
      
      // 创建颜色方块
      const colorBox = document.createElement('span');
      colorBox.style.display = 'inline-block';
      colorBox.style.width = '12px';
      colorBox.style.height = '12px';
      colorBox.style.backgroundColor = CHART_COLORS.vulnerabilityTypes[labels[index]] || CHART_COLORS.vulnerabilityTypes['default'];
      colorBox.style.marginRight = '5px';
      colorBox.style.borderRadius = '2px';
      
      // 创建标签文本
      const labelText = document.createElement('span');
      labelText.textContent = `${labels[index]}: ${value} (${percentages[index]}%)`;
      
      // 组装图例项
      legendItem.appendChild(colorBox);
      legendItem.appendChild(labelText);
      legendDiv.appendChild(legendItem);
      
      // 更新起始角度
      startAngle = endAngle;
    });
    
    // 添加图例到容器
    chartContainer.appendChild(legendDiv);
  }
  
  // 绘制漏洞严重程度分布图表
  function drawSeverityChart() {
    // 获取漏洞严重程度分布的数据
    const severityCounts = {
      'critical': 0,
      'high': 0,
      'medium': 0,
      'low': 0,
      'info': 0
    };
    
    let totalVulnerabilities = 0;

    // 计算各严重程度漏洞数量
    allVulnerabilities.forEach(vulnerability => {
      const severity = vulnerability.severity?.toLowerCase() || 'info';
      if (severityCounts.hasOwnProperty(severity)) {
        severityCounts[severity]++;
        totalVulnerabilities++;
      } else {
        severityCounts['info']++;
        totalVulnerabilities++;
      }
    });

    // 获取图表容器
    const chartContainer = safeGetElement('severity-chart');
    if (!chartContainer) return;
    
    // 清空容器
    chartContainer.innerHTML = '';
    
    // 如果没有漏洞数据，显示提示信息
    if (totalVulnerabilities === 0) {
      chartContainer.innerHTML = '<div class="no-data">暂无漏洞数据</div>';
      return;
    }
    
    // 创建Canvas元素
    const canvas = document.createElement('canvas');
    canvas.width = chartContainer.clientWidth;
    canvas.height = 250;
    chartContainer.appendChild(canvas);
    
    // 获取绘图上下文
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    
    // 准备饼图数据
    const data = [];
    const labels = [];
    const percentages = [];
    
    const severityNames = {
      'critical': '严重',
      'high': '高危',
      'medium': '中危',
      'low': '低危',
      'info': '信息'
    };
    
    for (const severity in severityCounts) {
      const count = severityCounts[severity];
      if (count === 0) continue; // 跳过没有数据的严重程度
      
      const percentage = (count / totalVulnerabilities) * 100;
      
      data.push(count);
      labels.push(severityNames[severity] || severity);
      percentages.push(percentage.toFixed(1));
    }
    
    // 绘制饼图
    const centerX = canvas.width / 2;
    const centerY = canvas.height / 2 - 10; // 向上偏移一点，为图例留出空间
    const radius = Math.min(centerX, centerY) * 0.8;
    
    let startAngle = 0;
    
    // 创建图例容器
    const legendDiv = document.createElement('div');
    legendDiv.style.display = 'flex';
    legendDiv.style.flexWrap = 'wrap';
    legendDiv.style.justifyContent = 'center';
    legendDiv.style.gap = '10px';
    legendDiv.style.marginTop = '15px';
    legendDiv.style.fontSize = CHART_COLORS.chartConfig.labelFontSize + 'px';
    
    // 绘制饼图扇区和创建图例
    data.forEach((value, index) => {
      const sliceAngle = (value / totalVulnerabilities) * 2 * Math.PI;
      const endAngle = startAngle + sliceAngle;
      
      // 绘制扇区
      ctx.beginPath();
      ctx.moveTo(centerX, centerY);
      ctx.arc(centerX, centerY, radius, startAngle, endAngle);
      ctx.closePath();
      
      // 设置扇区颜色和描边
      ctx.fillStyle = CHART_COLORS.severityLevels[severity] || CHART_COLORS.vulnerabilityTypes['default'];
      ctx.strokeStyle = 'white';
      ctx.lineWidth = 2;
      ctx.fill();
      ctx.stroke();
      
      // 创建图例项
      const legendItem = document.createElement('div');
      legendItem.style.display = 'flex';
      legendItem.style.alignItems = 'center';
      legendItem.style.padding = '3px 8px';
      legendItem.style.backgroundColor = 'rgba(255, 255, 255, 0.7)';
      legendItem.style.borderRadius = '4px';
      legendItem.style.boxShadow = '0 1px 3px rgba(0,0,0,0.1)';
      
      // 创建颜色方块
      const colorBox = document.createElement('span');
      colorBox.style.display = 'inline-block';
      colorBox.style.width = '12px';
      colorBox.style.height = '12px';
      colorBox.style.backgroundColor = CHART_COLORS.severityLevels[severity] || CHART_COLORS.vulnerabilityTypes['default'];
      colorBox.style.marginRight = '5px';
      colorBox.style.borderRadius = '2px';
      
      // 创建标签文本
      const labelText = document.createElement('span');
      labelText.textContent = `${labels[index]}: ${value} (${percentages[index]}%)`;
      
      // 组装图例项
      legendItem.appendChild(colorBox);
      legendItem.appendChild(labelText);
      legendDiv.appendChild(legendItem);
      
      // 更新起始角度
      startAngle = endAngle;
    });
    
    // 添加图例到容器
    chartContainer.appendChild(legendDiv);
  }
  
  // 绘制站点漏洞分布图表
  function drawDomainDistributionChart() {
    // 获取域名分布数据
    const domainCounts = {};
    allVulnerabilities.forEach(vulnerability => {
      try {
        const hostname = new URL(vulnerability.details.location).hostname;
        domainCounts[hostname] = (domainCounts[hostname] || 0) + 1;
      } catch (e) {
        // 处理无效URL的情况
        const fallbackDomain = vulnerability.details.location || '未知域名';
        domainCounts[fallbackDomain] = (domainCounts[fallbackDomain] || 0) + 1;
      }
    });
    
    // 获取图表容器
    const chartContainer = safeGetElement('domain-distribution-chart');
    if (!chartContainer) return;
    
    // 清空容器
    chartContainer.innerHTML = '';
    
    // 检查是否有数据
    if (Object.keys(domainCounts).length === 0) {
      chartContainer.innerHTML = '<div class="no-data">暂无域名数据</div>';
      return;
    }
    
    // 按漏洞数量排序并限制显示数量
    const maxDomainsToShow = 8;
    const sortedDomains = Object.entries(domainCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, maxDomainsToShow);
    
    // 创建Canvas元素
    const canvas = document.createElement('canvas');
    canvas.width = chartContainer.clientWidth;
    canvas.height = 250;
    chartContainer.appendChild(canvas);
    
    // 获取绘图上下文
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    
    // 设置图表尺寸和边距
    const padding = { left: 170, right: 40, top: 30, bottom: 40 };
    const chartWidth = canvas.width - padding.left - padding.right;
    const chartHeight = canvas.height - padding.top - padding.bottom;
    
    // 计算条形图参数
    const barHeight = Math.min(25, chartHeight / sortedDomains.length - 5);
    const maxValue = Math.max(...sortedDomains.map(d => d[1]));
    
    // 绘制X轴
    ctx.beginPath();
    ctx.strokeStyle = '#ccc';
    ctx.lineWidth = 1;
    ctx.moveTo(padding.left, canvas.height - padding.bottom);
    ctx.lineTo(canvas.width - padding.right, canvas.height - padding.bottom);
    ctx.stroke();
    
    // 绘制X轴刻度和网格线
    const xSteps = 5;
    ctx.beginPath();
    ctx.strokeStyle = '#eee';
    ctx.textAlign = 'center';
    ctx.fillStyle = '#666';
    ctx.font = `${CHART_COLORS.chartConfig.labelFontSize}px ${CHART_COLORS.chartConfig.fontFamily}`;
    
    for (let i = 0; i <= xSteps; i++) {
      const value = Math.round((i / xSteps) * maxValue);
      const x = padding.left + (i / xSteps) * chartWidth;
      
      // 绘制网格线
      ctx.moveTo(x, padding.top);
      ctx.lineTo(x, canvas.height - padding.bottom);
      
      // 绘制X轴刻度
      ctx.fillText(value.toString(), x, canvas.height - padding.bottom + 15);
    }
    ctx.stroke();
    
    // 绘制条形图和域名标签
    sortedDomains.forEach((domain, index) => {
      const [domainName, count] = domain;
      const barWidth = (count / maxValue) * chartWidth;
      const y = padding.top + index * (barHeight + 5);
      
      // 截断过长的域名
      let displayName = domainName;
      const maxNameLength = 20;
      if (displayName.length > maxNameLength) {
        displayName = displayName.substring(0, maxNameLength) + '...';
      }
      
      // 绘制域名标签
      ctx.fillStyle = '#333';
      ctx.textAlign = 'right';
      ctx.font = `${CHART_COLORS.chartConfig.labelFontSize}px ${CHART_COLORS.chartConfig.fontFamily}`;
      ctx.fillText(displayName, padding.left - 10, y + barHeight / 2 + 4);
      
      // 绘制条形
      ctx.fillStyle = getBarColor(index);
      roundRect(ctx, padding.left, y, barWidth, barHeight, 4, true);
      
      // 绘制数值标签
      ctx.fillStyle = '#fff';
      ctx.textAlign = 'right';
      ctx.font = `bold ${CHART_COLORS.chartConfig.valueFontSize}px ${CHART_COLORS.chartConfig.fontFamily}`;
      if (barWidth > 40) { // 如果条形足够宽，在条形内显示数值
        ctx.fillText(count.toString(), padding.left + barWidth - 10, y + barHeight / 2 + 4);
      } else { // 否则在条形外显示数值
        ctx.fillStyle = '#333';
        ctx.textAlign = 'left';
        ctx.fillText(count.toString(), padding.left + barWidth + 5, y + barHeight / 2 + 4);
      }
    });
    
    // 显示剩余域名数量提示
    const remainingDomains = Object.keys(domainCounts).length - maxDomainsToShow;
    if (remainingDomains > 0) {
      ctx.fillStyle = '#7f8c8d';
      ctx.textAlign = 'right';
      ctx.font = `italic ${CHART_COLORS.chartConfig.labelFontSize}px ${CHART_COLORS.chartConfig.fontFamily}`;
      ctx.fillText(`还有 ${remainingDomains} 个站点未显示`, canvas.width - padding.right, canvas.height - 10);
    }
    
    // 辅助函数：为条形生成颜色
    function getBarColor(index) {
      const colors = [
        '#4285f4', '#ea4335', '#fbbc05', '#34a853', 
        '#5e35b1', '#00acc1', '#43a047', '#fb8c00'
      ];
      return colors[index % colors.length];
    }
    
    // 辅助函数：绘制圆角矩形
    function roundRect(ctx, x, y, width, height, radius, fill) {
      if (typeof radius === 'number') {
        radius = {tl: radius, tr: radius, br: radius, bl: radius};
      } else {
        radius = {...{tl: 0, tr: 0, br: 0, bl: 0}, ...radius};
      }
      ctx.beginPath();
      ctx.moveTo(x + radius.tl, y);
      ctx.lineTo(x + width - radius.tr, y);
      ctx.quadraticCurveTo(x + width, y, x + width, y + radius.tr);
      ctx.lineTo(x + width, y + height - radius.br);
      ctx.quadraticCurveTo(x + width, y + height, x + width - radius.br, y + height);
      ctx.lineTo(x + radius.bl, y + height);
      ctx.quadraticCurveTo(x, y + height, x, y + height - radius.bl);
      ctx.lineTo(x, y + radius.tl);
      ctx.quadraticCurveTo(x, y, x + radius.tl, y);
      ctx.closePath();
      if (fill) {
        ctx.fill();
      } else {
        ctx.stroke();
      }
    }
  }
  
  // 绘制最近检测活动图表
  function drawRecentActivityChart() {
    // 获取最近7天的漏洞检测数据
    const today = new Date();
    const dates = [];
    const dateCounts = {};
    
    // 生成最近7天的日期
    for (let i = 6; i >= 0; i--) {
      const date = new Date(today);
      date.setDate(today.getDate() - i);
      const dateString = `${date.getMonth() + 1}/${date.getDate()}`;
      dates.push(dateString);
      dateCounts[dateString] = 0;
    }
    
    // 统计每天的漏洞数量
    allVulnerabilities.forEach(vulnerability => {
      if (vulnerability.timestamp) {
        const vulnDate = new Date(vulnerability.timestamp);
        // 只统计最近7天的数据
        const diffDays = Math.floor((today - vulnDate) / (24 * 60 * 60 * 1000));
        if (diffDays >= 0 && diffDays < 7) {
          const dateString = `${vulnDate.getMonth() + 1}/${vulnDate.getDate()}`;
          dateCounts[dateString] = (dateCounts[dateString] || 0) + 1;
        }
      }
    });
    
    // 获取图表容器
    const chartContainer = safeGetElement('recent-activity-chart');
    if (!chartContainer) return;
    
    // 清空容器
    chartContainer.innerHTML = '';
    
    // 创建Canvas元素
    const canvas = document.createElement('canvas');
    canvas.width = chartContainer.clientWidth;
    canvas.height = 250;
    chartContainer.appendChild(canvas);
    
    // 获取绘图上下文
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    
    // 准备图表数据
    const data = dates.map(date => dateCounts[date] || 0);
    const maxValue = Math.max(...data, 10); // 至少为10，避免图表过于扁平
    
    // 设置图表尺寸和边距
    const padding = 40;
    const chartWidth = canvas.width - padding * 2;
    const chartHeight = canvas.height - padding * 2;
    
    // 绘制坐标轴
    ctx.beginPath();
    ctx.strokeStyle = '#ccc';
    ctx.lineWidth = 1;
    
    // X轴
    ctx.moveTo(padding, canvas.height - padding);
    ctx.lineTo(canvas.width - padding, canvas.height - padding);
    
    // Y轴
    ctx.moveTo(padding, padding);
    ctx.lineTo(padding, canvas.height - padding);
    ctx.stroke();
    
    // 绘制网格线和Y轴刻度
    const ySteps = 5;
    ctx.beginPath();
    ctx.strokeStyle = '#eee';
    ctx.fillStyle = '#666';
    ctx.textAlign = 'right';
    ctx.font = `${CHART_COLORS.chartConfig.labelFontSize}px ${CHART_COLORS.chartConfig.fontFamily}`;
    
    for (let i = 0; i <= ySteps; i++) {
      const y = canvas.height - padding - (i / ySteps) * chartHeight;
      const value = Math.round((i / ySteps) * maxValue);
      
      // 绘制网格线
      ctx.moveTo(padding, y);
      ctx.lineTo(canvas.width - padding, y);
      
      // 绘制Y轴刻度
      ctx.fillText(value.toString(), padding - 5, y + 4);
    }
    ctx.stroke();
    
    // 绘制X轴刻度和标签
    ctx.textAlign = 'center';
    dates.forEach((date, index) => {
      const x = padding + (index / (dates.length - 1)) * chartWidth;
      
      // 绘制X轴刻度
      ctx.beginPath();
      ctx.moveTo(x, canvas.height - padding);
      ctx.lineTo(x, canvas.height - padding + 5);
      ctx.stroke();
      
      // 绘制X轴标签
      ctx.fillText(date, x, canvas.height - padding + 20);
    });
    
    // 绘制数据点和折线
    ctx.beginPath();
    ctx.strokeStyle = '#4285f4';
    ctx.lineWidth = 2;
    
    // 绘制折线
    data.forEach((value, index) => {
      const x = padding + (index / (data.length - 1)) * chartWidth;
      const y = canvas.height - padding - (value / maxValue) * chartHeight;
      
      if (index === 0) {
        ctx.moveTo(x, y);
      } else {
        ctx.lineTo(x, y);
      }
    });
    ctx.stroke();
    
    // 绘制数据点
    data.forEach((value, index) => {
      const x = padding + (index / (data.length - 1)) * chartWidth;
      const y = canvas.height - padding - (value / maxValue) * chartHeight;
      
      // 绘制数据点
      ctx.beginPath();
      ctx.fillStyle = '#4285f4';
      ctx.arc(x, y, 4, 0, 2 * Math.PI);
      ctx.fill();
      
      // 绘制白色边框
      ctx.beginPath();
      ctx.strokeStyle = 'white';
      ctx.lineWidth = 2;
      ctx.arc(x, y, 4, 0, 2 * Math.PI);
      ctx.stroke();
      
      // 绘制数据标签
      if (value > 0) {
        ctx.fillStyle = '#333';
        ctx.textAlign = 'center';
        ctx.font = `bold ${CHART_COLORS.chartConfig.valueFontSize}px ${CHART_COLORS.chartConfig.fontFamily}`;
        ctx.fillText(value.toString(), x, y - 15);
      }
    });
    
    // 添加图表标题
    ctx.fillStyle = '#2c3e50';
    ctx.textAlign = 'center';
    ctx.font = `bold ${CHART_COLORS.chartConfig.titleFontSize}px ${CHART_COLORS.chartConfig.fontFamily}`;
    ctx.fillText('最近7天漏洞发现趋势', canvas.width / 2, 20);
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