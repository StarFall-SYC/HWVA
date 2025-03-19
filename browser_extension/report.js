document.addEventListener('DOMContentLoaded', () => {
  // 全局错误处理
  window.addEventListener('error', (e) => {
    console.error('捕获到全局错误:', e.message);
    // 只显示严重错误，避免用户困扰
    if (!e.message.includes('找不到') && !e.message.includes('不存在')) {
      showErrorMessage('发生错误: ' + e.message);
    }
    // 防止错误向上冒泡
    e.stopPropagation();
    // 阻止默认行为，避免更多错误
    e.preventDefault();
    return true; // 表示已处理错误
  });

  // 处理CSP错误
  window.addEventListener('securitypolicyviolation', (e) => {
    console.warn('捕获到CSP违规:', e.blockedURI, '类型:', e.violatedDirective);
    
    // 记录错误详情，方便调试
    console.warn('CSP错误详情:', {
      'Blocked URI': e.blockedURI,
      'Violated Directive': e.violatedDirective,
      'Original Policy': e.originalPolicy,
      'Disposition': e.disposition,
      'Line Number': e.lineNumber,
      'Column Number': e.columnNumber,
      'Source File': e.sourceFile
    });
    
    // 防止因CSP错误而导致页面功能中断
    if (e.blockedURI.includes('javascript:') || e.violatedDirective.includes('script-src')) {
      console.warn('检测到JavaScript URI CSP错误 - 将使用替代方法');
      
      // 如果是通过javascript: URL进行的导航，尝试使用更安全的方式
      if (document.activeElement && document.activeElement.tagName === 'A') {
        e.preventDefault();
        // 使用安全的方式替代javascript: URL
        const safeNavigationHandler = () => {
          showErrorMessage('由于安全策略，已阻止javascript: URL执行', 'warning');
          return false;
        };
        
        // 移除原始的href属性，使用事件监听器替代
        const link = document.activeElement;
        const originalHref = link.getAttribute('href');
        if (originalHref && originalHref.startsWith('javascript:')) {
          link.removeAttribute('href');
          link.addEventListener('click', safeNavigationHandler);
        }
      }
    }
  });

  // 创建一个MutationObserver来处理DOM变化，修复任何javascript: URL
  const fixJavaScriptURLs = () => {
    const links = document.querySelectorAll('a[href^="javascript:"]');
    links.forEach(link => {
      const originalHref = link.getAttribute('href');
      // 移除javascript: URL
      link.removeAttribute('href');
      // 添加一个安全的处理方式
      link.addEventListener('click', (e) => {
        e.preventDefault();
        console.warn('已阻止javascript: URL执行:', originalHref);
        showErrorMessage('由于安全策略，已阻止javascript: URL执行', 'warning');
        return false;
      });
    });
  };

  // 创建并启动观察者
  const observer = new MutationObserver((mutations) => {
    fixJavaScriptURLs();
  });
  
  // 配置观察选项
  observer.observe(document.body, {
    childList: true,
    subtree: true,
    attributes: true,
    attributeFilter: ['href']
  });

  // 初始检查
  fixJavaScriptURLs();

  // 颜色常量定义 - 移到文件顶部，确保在任何函数调用前就被定义
  const CHART_COLORS = {
    // 漏洞类型颜色
    vulnerabilityTypes: {
      'XSS': '#FF6384',
      'SQL注入': '#36A2EB',
      'CSRF': '#FFCE56',
      '敏感信息泄露': '#4BC0C0',
      '不安全的HTTP头部': '#9966FF',
      '不安全的CORS配置': '#8BC34A',
      '开放重定向': '#FF9800',
      'SSRF漏洞': '#E91E63',
      '其他': '#FF9F40',
      'default': '#C9C9C9'
    },
    // 严重程度颜色
    severityLevels: {
      'Critical': '#9c27b0',
      'High': '#e74c3c',
      'Medium': '#f39c12',
      'Low': '#3498db',
      'Info': '#7f8c8d',
      'default': '#C9C9C9'
    },
    // 图表配置
    chartConfig: {
      fontFamily: "'Microsoft YaHei', Arial, sans-serif",
      titleFontSize: 18,
      labelFontSize: 12,
      valueFontSize: 14,
      borderWidth: 2,
      animationDuration: 1000
    }
  };

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
  const vulnerabilitiesContainer = safeGetElement('vulnerabilities-list');
  const filterType = safeGetElement('type-filter');
  const filterDomain = safeGetElement('domain-filter');
  const exportButton = safeGetElement('export-report');
  const clearButton = safeGetElement('clear-data');
  const prevButton = safeGetElement('prev-page');
  const nextButton = safeGetElement('next-page');
  const currentPageSpan = safeGetElement('current-page-num');
  
  // 统计元素
  const totalSitesElem = safeGetElement('total-sites');
  const totalVulnerabilitiesElem = safeGetElement('total-vulnerabilities');
  const criticalCountElem = safeGetElement('critical-vulnerabilities');
  const highCountElem = safeGetElement('high-vulnerabilities');
  
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
    try {
    chrome.storage.local.get('vulnerabilities', (result) => {
        try {
          allVulnerabilities = [];
          
          if (!result || !result.vulnerabilities) {
            console.log('未找到漏洞数据或数据为空');
            showNoResults();
            refreshAllCharts(); // 刷新所有图表，显示无数据状态
            return;
          }
          
          // 确保统计信息对象存在并正确初始化
          if (!result.vulnerabilities.statistics) {
            result.vulnerabilities.statistics = { 
              domains: new Set(),
              totalCount: 0,
              severityCounts: {
                critical: 0,
                high: 0,
                medium: 0,
                low: 0,
                info: 0
              }
            };
          } else if (!result.vulnerabilities.statistics.domains) {
            // 如果domains不存在，创建一个空集合
            result.vulnerabilities.statistics.domains = new Set();
          } else if (Array.isArray(result.vulnerabilities.statistics.domains)) {
            // 如果domains是数组，转换为Set
            result.vulnerabilities.statistics.domains = new Set(result.vulnerabilities.statistics.domains);
          }
          
          // 处理新格式漏洞数据
          if (result.vulnerabilities.byDomain) {
            // 从byDomain对象中提取所有漏洞
            Object.keys(result.vulnerabilities.byDomain).forEach(domain => {
              const vulns = result.vulnerabilities.byDomain[domain];
              if (Array.isArray(vulns) && vulns.length > 0) {
                allVulnerabilities = allVulnerabilities.concat(vulns);
                
                // 同时更新domains集合
                try {
                  result.vulnerabilities.statistics.domains.add(domain);
                } catch (domainError) {
                  console.error('添加域名到统计数据时出错:', domainError);
                }
              }
            });
          } 
          // 处理旧格式（数组格式）
          else if (Array.isArray(result.vulnerabilities)) {
        allVulnerabilities = result.vulnerabilities;
            
            // 从数组中提取域名
            allVulnerabilities.forEach(vuln => {
              try {
                if (vuln.details && vuln.details.location) {
                  const url = new URL(vuln.details.location);
                  result.vulnerabilities.statistics.domains.add(url.hostname);
                }
              } catch (urlError) {
                console.error('解析URL时出错:', urlError);
              }
            });
          }
          
          // 检查是否有漏洞
          if (allVulnerabilities.length === 0) {
            console.log('提取后的漏洞数组为空');
            showNoResults();
            refreshAllCharts();
            return;
          }
          
          // 更新statistics中的总计数
          if (result.vulnerabilities.statistics) {
            result.vulnerabilities.statistics.totalCount = allVulnerabilities.length;
          }
          
          // 处理提取的漏洞
          try {
            // 从漏洞列表中提取域名
        extractDomains();
            // 更新页面上的过滤器
        updateFilters();
            // 更新过滤后的漏洞数组，但不显示
            filteredVulnerabilities = [...allVulnerabilities];
            // 更新统计信息
        updateStatistics();
            
            // 更新站点分析页面
            updateDomainAnalysis();
            
            // 提取所有漏洞URL的域名，确保我们有域名数据
            const extractedDomains = new Set();
            allVulnerabilities.forEach(vuln => {
              try {
                if (vuln && vuln.details && vuln.details.location) {
                  const url = new URL(vuln.details.location);
                  extractedDomains.add(url.hostname);
                }
              } catch (e) {
                // 忽略无效URL
                console.warn('域名提取错误:', e.message);
              }
            });
            console.log('提取到的域名数量:', extractedDomains.size, '域名列表:', Array.from(extractedDomains));
            
            // 刷新所有图表
            refreshAllCharts();
          } catch (processingError) {
            console.error('处理漏洞数据时出错:', processingError);
            showErrorMessage('处理漏洞数据时出错: ' + (processingError.message || '未知错误'));
          }
          
        } catch (error) {
          console.error('处理漏洞数据时出错:', error);
          showErrorMessage('加载漏洞数据时出错: ' + (error.message || '未知错误'));
        showNoResults();
          refreshAllCharts();
        }
      });
    } catch (error) {
      console.error('调用chrome.storage.local.get时出错:', error);
      showErrorMessage('加载漏洞数据时出错: ' + (error.message || '未知错误'));
      showNoResults();
      refreshAllCharts();
    }
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
      // 清空现有选项
      while (filterDomain.firstChild) {
        filterDomain.removeChild(filterDomain.firstChild);
      }
      
      // 添加"所有站点"选项
      const allOption = document.createElement('option');
      allOption.value = 'all';
      allOption.textContent = '所有站点';
      filterDomain.appendChild(allOption);
      
      // 为每个域名添加选项
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
    
    // 记录过滤结果
    console.log(`过滤后的漏洞数量: ${filteredVulnerabilities.length}`);
  }
  
  // 安全处理链接行为
  function handleLinkSafely(link, callback) {
    // 移除href属性，使用事件监听器替代
    if (link && link.tagName === 'A') {
      // 保存原始href以便记录
      const originalHref = link.getAttribute('href');
      
      // 如果是javascript:URL则移除
      if (originalHref && originalHref.toLowerCase().startsWith('javascript:')) {
        // 保存URL，但移除href属性
        link.dataset.originalHref = originalHref;
        link.removeAttribute('href');
        
        // 添加样式以保持链接外观
        link.style.cursor = 'pointer';
        link.style.textDecoration = 'underline';
        link.style.color = 'var(--primary-color, #4285f4)';
        
        // 添加安全的点击处理程序
        link.addEventListener('click', (e) => {
          e.preventDefault();
          if (typeof callback === 'function') {
            return callback(e);
          } else {
            console.warn('已阻止javascript: URL执行:', originalHref);
            showErrorMessage('已阻止执行不安全的链接', 'warning');
            return false;
          }
        });
        
        return true; // 表示已处理
      }
    }
    return false; // 表示未处理
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
      let fullUrl = '';
      try {
        const url = new URL(vuln.details.location);
        shortUrl = url.hostname + url.pathname.substring(0, 20) + (url.pathname.length > 20 ? '...' : '');
        fullUrl = url.toString();
      } catch (e) {
        shortUrl = vuln.details.location.substring(0, 30) + '...';
        fullUrl = vuln.details.location || '#';
      }
      
      // 使用DOM API创建元素，而不是使用innerHTML
      // 这样可以避免CSP限制和潜在的安全问题
      const titleElement = document.createElement('h3');
      titleElement.textContent = vuln.type;
      vulnerabilityElement.appendChild(titleElement);
      
      // 创建漏洞详情div
      const detailsDiv = document.createElement('div');
      detailsDiv.className = 'vulnerability-details';
      
      // URL标签
      const urlLabelDiv = document.createElement('div');
      urlLabelDiv.className = 'label';
      urlLabelDiv.textContent = 'URL:';
      detailsDiv.appendChild(urlLabelDiv);
      
      // URL值
      const urlValueDiv = document.createElement('div');
      const urlLink = document.createElement('a');
      urlLink.href = fullUrl;
      urlLink.textContent = shortUrl;
      urlLink.target = '_blank';
      urlValueDiv.appendChild(urlLink);
      detailsDiv.appendChild(urlValueDiv);
      
      // 证据标签
      const evidenceLabelDiv = document.createElement('div');
      evidenceLabelDiv.className = 'label';
      evidenceLabelDiv.textContent = '证据:';
      detailsDiv.appendChild(evidenceLabelDiv);
      
      // 证据值
      const evidenceValueDiv = document.createElement('div');
      evidenceValueDiv.textContent = vuln.details.evidence || '无详细信息';
      detailsDiv.appendChild(evidenceValueDiv);
      
      vulnerabilityElement.appendChild(detailsDiv);
      
      // 证据详情
      const evidenceDiv = document.createElement('div');
      evidenceDiv.className = 'evidence';
      // 使用textContent而不是innerHTML来避免潜在的XSS
      const formattedEvidence = formatEvidence(vuln.details.evidence);
      
      // 如果证据包含HTML，我们需要安全地显示它
      if (formattedEvidence.includes('&lt;') || formattedEvidence.includes('&gt;')) {
        // 使用pre标签显示HTML代码
        const preElement = document.createElement('pre');
        preElement.style.whiteSpace = 'pre-wrap';
        preElement.style.wordBreak = 'break-all';
        preElement.style.backgroundColor = '#f5f5f5';
        preElement.style.padding = '8px';
        preElement.style.borderRadius = '4px';
        preElement.textContent = vuln.details.evidence || '无详细信息';
        evidenceDiv.appendChild(preElement);
      } else {
        // 普通文本
        evidenceDiv.textContent = vuln.details.evidence || '无详细信息';
      }
      
      vulnerabilityElement.appendChild(evidenceDiv);
      
      // 时间戳
      const timestampDiv = document.createElement('div');
      timestampDiv.className = 'timestamp';
      timestampDiv.textContent = '发现时间: ' + new Date(vuln.timestamp).toLocaleString();
      vulnerabilityElement.appendChild(timestampDiv);
      
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
      // 清空容器
      while (vulnerabilitiesContainer.firstChild) {
        vulnerabilitiesContainer.removeChild(vulnerabilitiesContainer.firstChild);
      }
      
      // 创建并添加"无结果"元素
      const noResultsDiv = document.createElement('div');
      noResultsDiv.className = 'no-results';
      noResultsDiv.textContent = '暂无漏洞数据';
      vulnerabilitiesContainer.appendChild(noResultsDiv);
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
    // 更新过滤器选项，但不再显示漏洞列表
    // 这个函数现在只用于导出功能前的过滤
    console.log('更新过滤条件，准备导出数据');
    
    // 更新过滤后的漏洞数组，用于导出
    const typeFilter = safeGetElement('type-filter');
    const domainFilter = safeGetElement('domain-filter');
    
    if (!typeFilter || !domainFilter) return;
    
    const typeValue = typeFilter.value;
    const domainValue = domainFilter.value;
    
    // 根据过滤条件筛选漏洞
    filteredVulnerabilities = allVulnerabilities.filter(vuln => {
      let matchesType = typeValue === '' || vuln.type === typeValue;
      
      let matchesDomain = true;
      if (domainValue !== '') {
        try {
          const url = new URL(vuln.details.location);
          matchesDomain = url.hostname === domainValue;
        } catch (e) {
          matchesDomain = false;
        }
      }
      
      return matchesType && matchesDomain;
    });
    
    console.log(`过滤后的漏洞数量: ${filteredVulnerabilities.length}`);
  }
  
  // 更新统计信息
  function updateStatistics() {
    // 计算网站数量
    const siteCount = domains.size;
    totalSitesElem.textContent = siteCount;
    
    // 总漏洞数
    totalVulnerabilitiesElem.textContent = allVulnerabilities.length;
    
    // 各严重程度漏洞数
    const criticalCount = allVulnerabilities.filter(v => 
      v.details && v.details.severity && v.details.severity.toLowerCase() === 'critical').length;
    const highCount = allVulnerabilities.filter(v => 
      v.details && v.details.severity && v.details.severity.toLowerCase() === 'high').length;
    
    // 更新仪表盘上的严重程度计数
    criticalCountElem.textContent = criticalCount;
    highCountElem.textContent = highCount;
    
    // 生成图表
    drawVulnerabilityChart();
    drawSeverityChart();
    drawDomainDistributionChart();
    drawRecentActivityChart();
  }
  
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
    
    // 保留工具栏，清空其余内容
    const toolbarElement = chartContainer.querySelector('.chart-toolbar');
    
    // 清空容器内容
    while (chartContainer.firstChild) {
      chartContainer.removeChild(chartContainer.firstChild);
    }
    
    // 先添加回工具栏
    if (toolbarElement) {
      chartContainer.appendChild(toolbarElement);
    }
    
    // 如果没有漏洞数据，显示提示信息
    if (totalVulnerabilities === 0) {
      const noDataDiv = document.createElement('div');
      noDataDiv.className = 'no-data';
      noDataDiv.textContent = '暂无漏洞数据';
      chartContainer.appendChild(noDataDiv);
      return;
    }
    
    // 创建图表包装器，用于控制图表大小
    const chartWrapper = document.createElement('div');
    chartWrapper.style.display = 'flex';
    chartWrapper.style.flexDirection = 'column';
    chartWrapper.style.alignItems = 'center';
    chartWrapper.style.justifyContent = 'center';
    chartWrapper.style.maxWidth = '100%';
    chartWrapper.style.height = '220px'; // 减小高度避免溢出
    chartContainer.appendChild(chartWrapper);
    
    // 创建Canvas元素
    const canvas = document.createElement('canvas');
    // 调整canvas尺寸以适应容器
    canvas.width = Math.min(chartContainer.clientWidth - 20, 300);
    canvas.height = 180;
    chartWrapper.appendChild(canvas);
    
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
    
    // 绘制饼图（带动画）
    const centerX = canvas.width / 2;
    const centerY = canvas.height / 2;
    const radius = Math.min(centerX, centerY) * 0.7; // 减小半径，留出更多空间
    
    // 创建图例容器
    const legendDiv = document.createElement('div');
    legendDiv.style.display = 'flex';
    legendDiv.style.flexWrap = 'wrap';
    legendDiv.style.justifyContent = 'center';
    legendDiv.style.gap = '5px'; // 减小间距
    legendDiv.style.marginTop = '10px';
    legendDiv.style.width = '100%';
    legendDiv.style.fontSize = '10px'; // 减小字体
    legendDiv.style.overflow = 'auto'; // 添加滚动
    legendDiv.style.maxHeight = '70px'; // 限制最大高度
    
    // 创建图例项
    data.forEach((value, index) => {
      // 创建图例项
      const legendItem = document.createElement('div');
      legendItem.style.display = 'flex';
      legendItem.style.alignItems = 'center';
      legendItem.style.padding = '2px 5px'; // 减小内边距
      legendItem.style.backgroundColor = 'rgba(255, 255, 255, 0.7)';
      legendItem.style.borderRadius = '3px';
      legendItem.style.boxShadow = '0 1px 2px rgba(0,0,0,0.1)';
      legendItem.style.opacity = '0';
      legendItem.style.transition = 'opacity 0.5s ease';
      legendItem.style.margin = '2px'; // 添加外边距
      
      // 创建颜色方块
      const colorBox = document.createElement('span');
      colorBox.style.display = 'inline-block';
      colorBox.style.width = '8px'; // 减小颜色方块
      colorBox.style.height = '8px';
      colorBox.style.backgroundColor = CHART_COLORS.vulnerabilityTypes[labels[index]] || CHART_COLORS.vulnerabilityTypes['default'];
      colorBox.style.marginRight = '4px';
      colorBox.style.borderRadius = '2px';
      
      // 创建标签文本（截断过长文本）
      const labelText = document.createElement('span');
      const displayLabel = labels[index].length > 15 ? labels[index].substring(0, 12) + '...' : labels[index];
      labelText.textContent = `${displayLabel}: ${value} (${percentages[index]}%)`;
      labelText.title = `${labels[index]}: ${value} (${percentages[index]}%)`; // 添加完整提示
      
      // 组装图例项
      legendItem.appendChild(colorBox);
      legendItem.appendChild(labelText);
      legendDiv.appendChild(legendItem);
      
      // 延迟显示图例项（按顺序淡入）
      setTimeout(() => {
        legendItem.style.opacity = '1';
      }, 500 + index * 100);
    });
    
    // 添加图例到容器
    chartWrapper.appendChild(legendDiv);
    
    // 绘制动画
    let animationProgress = 0;
    const animationDuration = 1000; // 动画持续时间（毫秒）
    let lastFrameTime = 0;
    
    function animate(currentTime) {
      if (!lastFrameTime) lastFrameTime = currentTime;
      const deltaTime = currentTime - lastFrameTime;
      lastFrameTime = currentTime;
      
      // 更新动画进度
      animationProgress += deltaTime / animationDuration;
      if (animationProgress > 1) animationProgress = 1;
      
      // 清除画布
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      
      // 绘制饼图
      let startAngle = 0;
      
      data.forEach((value, index) => {
        const sliceAngle = (value / totalVulnerabilities) * 2 * Math.PI;
        // 计算当前动画帧的终止角度
        const endAngle = startAngle + sliceAngle * animationProgress;
        
        // 绘制扇区
        ctx.beginPath();
        ctx.moveTo(centerX, centerY);
        ctx.arc(centerX, centerY, radius, startAngle, endAngle);
        ctx.closePath();
        
        // 设置扇区颜色和描边
        ctx.fillStyle = CHART_COLORS.vulnerabilityTypes[labels[index]] || CHART_COLORS.vulnerabilityTypes['default'];
        ctx.strokeStyle = 'white';
        ctx.lineWidth = 1; // 减小线宽
        ctx.fill();
        ctx.stroke();
        
        // 更新下一个扇区的起始角度
        startAngle = startAngle + sliceAngle;
      });
      
      // 如果动画未完成，继续请求下一帧
      if (animationProgress < 1) {
        requestAnimationFrame(animate);
      }
    }
    
    // 启动动画
    requestAnimationFrame(animate);
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
    
    // 保留工具栏，清空其余内容
    const toolbarElement = chartContainer.querySelector('.chart-toolbar');
    
    // 清空容器内容
    while (chartContainer.firstChild) {
      chartContainer.removeChild(chartContainer.firstChild);
    }
    
    // 先添加回工具栏
    if (toolbarElement) {
      chartContainer.appendChild(toolbarElement);
    }
    
    // 如果没有漏洞数据，显示提示信息
    if (totalVulnerabilities === 0) {
      const noDataDiv = document.createElement('div');
      noDataDiv.className = 'no-data';
      noDataDiv.textContent = '暂无漏洞数据';
      chartContainer.appendChild(noDataDiv);
      return;
    }
    
    // 创建图表包装器，用于控制图表大小
    const chartWrapper = document.createElement('div');
    chartWrapper.style.display = 'flex';
    chartWrapper.style.flexDirection = 'column';
    chartWrapper.style.alignItems = 'center';
    chartWrapper.style.justifyContent = 'center';
    chartWrapper.style.maxWidth = '100%';
    chartWrapper.style.height = '220px'; // 减小高度避免溢出
    chartContainer.appendChild(chartWrapper);
    
    // 创建Canvas元素
    const canvas = document.createElement('canvas');
    // 调整canvas尺寸以适应容器
    canvas.width = Math.min(chartContainer.clientWidth - 20, 300);
    canvas.height = 180;
    chartWrapper.appendChild(canvas);
    
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
    const centerY = canvas.height / 2;
    const radius = Math.min(centerX, centerY) * 0.7; // 减小半径，留出更多空间
    
    let startAngle = 0;
    
    // 创建图例容器
    const legendDiv = document.createElement('div');
    legendDiv.style.display = 'flex';
    legendDiv.style.flexWrap = 'wrap';
    legendDiv.style.justifyContent = 'center';
    legendDiv.style.gap = '5px'; // 减小间距
    legendDiv.style.marginTop = '10px';
    legendDiv.style.width = '100%';
    legendDiv.style.fontSize = '10px'; // 减小字体
    
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
      ctx.fillStyle = CHART_COLORS.severityLevels[labels[index]] || CHART_COLORS.vulnerabilityTypes['default'];
      ctx.strokeStyle = 'white';
      ctx.lineWidth = 1;
      ctx.fill();
      ctx.stroke();
      
      // 创建图例项
      const legendItem = document.createElement('div');
      legendItem.style.display = 'flex';
      legendItem.style.alignItems = 'center';
      legendItem.style.padding = '2px 5px'; // 减小内边距
      legendItem.style.backgroundColor = 'rgba(255, 255, 255, 0.7)';
      legendItem.style.borderRadius = '3px';
      legendItem.style.boxShadow = '0 1px 2px rgba(0,0,0,0.1)';
      legendItem.style.margin = '2px'; // 添加外边距
      
      // 创建颜色方块
      const colorBox = document.createElement('span');
      colorBox.style.display = 'inline-block';
      colorBox.style.width = '8px'; // 减小颜色方块
      colorBox.style.height = '8px';
      colorBox.style.backgroundColor = CHART_COLORS.severityLevels[labels[index]] || CHART_COLORS.vulnerabilityTypes['default'];
      colorBox.style.marginRight = '4px';
      colorBox.style.borderRadius = '2px';
      
      // 创建标签文本
      const labelText = document.createElement('span');
      // 将严重程度首字母大写
      const severityLabel = labels[index].charAt(0).toUpperCase() + labels[index].slice(1);
      labelText.textContent = `${severityLabel}: ${value} (${percentages[index]}%)`;
      
      // 组装图例项
      legendItem.appendChild(colorBox);
      legendItem.appendChild(labelText);
      legendDiv.appendChild(legendItem);
      
      // 更新起始角度
      startAngle = endAngle;
    });
    
    // 添加图例到容器
    chartWrapper.appendChild(legendDiv);
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
    
    // 保留工具栏，清空其余内容
    const toolbarElement = chartContainer.querySelector('.chart-toolbar');
    
    // 清空容器内容
    while (chartContainer.firstChild) {
      chartContainer.removeChild(chartContainer.firstChild);
    }
    
    // 先添加回工具栏
    if (toolbarElement) {
      chartContainer.appendChild(toolbarElement);
    }
    
    // 检查是否有数据
    if (Object.keys(domainCounts).length === 0) {
      const noDataDiv = document.createElement('div');
      noDataDiv.className = 'no-data';
      noDataDiv.textContent = '暂无域名数据';
      chartContainer.appendChild(noDataDiv);
      return;
    }
    
    // 创建图表包装器，用于控制图表大小
    const chartWrapper = document.createElement('div');
    chartWrapper.style.display = 'flex';
    chartWrapper.style.flexDirection = 'column';
    chartWrapper.style.alignItems = 'center';
    chartWrapper.style.maxWidth = '100%';
    chartWrapper.style.height = '220px'; // 减少高度
    chartWrapper.style.overflowY = 'auto'; // 添加纵向滚动
    chartContainer.appendChild(chartWrapper);
    
    // 按漏洞数量排序并限制显示数量
    const maxDomainsToShow = 5; // 减少显示的域名数量
    const sortedDomains = Object.entries(domainCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, maxDomainsToShow);
    
    // 创建Canvas元素
    const canvas = document.createElement('canvas');
    canvas.width = Math.min(chartContainer.clientWidth - 20, 350);
    canvas.height = 180;
    chartWrapper.appendChild(canvas);
    
    // 获取绘图上下文
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    
    // 设置图表尺寸和边距
    const padding = { left: 120, right: 30, top: 20, bottom: 30 }; // 减少左边距
    const chartWidth = canvas.width - padding.left - padding.right;
    const chartHeight = canvas.height - padding.top - padding.bottom;
    
    // 计算条形图参数
    const barHeight = Math.min(20, chartHeight / sortedDomains.length - 5);
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
    ctx.font = '8px Arial'; // 减小刻度字体大小
    
    for (let i = 0; i <= xSteps; i++) {
      const value = Math.round((i / xSteps) * maxValue);
      const x = padding.left + (i / xSteps) * chartWidth;
      
      // 绘制网格线
      ctx.moveTo(x, padding.top);
      ctx.lineTo(x, canvas.height - padding.bottom);
      
      // 绘制X轴刻度
      ctx.fillText(value.toString(), x, canvas.height - padding.bottom + 12);
    }
    ctx.stroke();
    
    // 绘制条形图和域名标签
    sortedDomains.forEach((domain, index) => {
      const [domainName, count] = domain;
      const barWidth = (count / maxValue) * chartWidth;
      const y = padding.top + index * (barHeight + 5);
      
      // 截断过长的域名
      let displayName = domainName;
      const maxNameLength = 15; // 减少最大长度
      if (displayName.length > maxNameLength) {
        displayName = displayName.substring(0, maxNameLength) + '...';
      }
      
      // 绘制域名标签
      ctx.fillStyle = '#333';
      ctx.textAlign = 'right';
      ctx.font = '9px Arial'; // 减小标签字体大小
      ctx.fillText(displayName, padding.left - 5, y + barHeight / 2 + 3);
      
      // 绘制条形
      ctx.fillStyle = getBarColor(index);
      roundRect(ctx, padding.left, y, barWidth, barHeight, 2, true); // 减小圆角
      
      // 绘制数值标签
      ctx.fillStyle = '#fff';
      ctx.textAlign = 'right';
      ctx.font = 'bold 9px Arial'; // 减小数值字体大小
      if (barWidth > 25) { // 如果条形足够宽，在条形内显示数值
        ctx.fillText(count.toString(), padding.left + barWidth - 5, y + barHeight / 2 + 3);
      } else { // 否则在条形外显示数值
        ctx.fillStyle = '#333';
        ctx.textAlign = 'left';
        ctx.fillText(count.toString(), padding.left + barWidth + 3, y + barHeight / 2 + 3);
      }
    });
    
    // 显示剩余域名数量提示
    const remainingDomains = Object.keys(domainCounts).length - maxDomainsToShow;
    if (remainingDomains > 0) {
      ctx.fillStyle = '#7f8c8d';
      ctx.textAlign = 'right';
      ctx.font = 'italic 8px Arial'; // 减小提示字体
      ctx.fillText(`还有 ${remainingDomains} 个站点未显示`, canvas.width - padding.right, canvas.height - 5);
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
    
    // 保留工具栏，清空其余内容
    const toolbarElement = chartContainer.querySelector('.chart-toolbar');
    
    // 清空容器内容
    while (chartContainer.firstChild) {
      chartContainer.removeChild(chartContainer.firstChild);
    }
    
    // 先添加回工具栏
    if (toolbarElement) {
      chartContainer.appendChild(toolbarElement);
    }
    
    // 如果没有漏洞数据，显示提示信息
    if (Object.keys(dateCounts).length === 0) {
      const noDataDiv = document.createElement('div');
      noDataDiv.className = 'no-data';
      noDataDiv.textContent = '暂无活动数据';
      chartContainer.appendChild(noDataDiv);
      return;
    }
    
    // 创建图表包装器，用于控制图表大小
    const chartWrapper = document.createElement('div');
    chartWrapper.style.display = 'flex';
    chartWrapper.style.flexDirection = 'column';
    chartWrapper.style.alignItems = 'center';
    chartWrapper.style.maxWidth = '100%';
    chartWrapper.style.height = '220px'; // 减少高度
    chartContainer.appendChild(chartWrapper);
    
    // 创建Canvas元素
    const canvas = document.createElement('canvas');
    canvas.width = Math.min(chartContainer.clientWidth - 20, 350);
    canvas.height = 180;
    chartWrapper.appendChild(canvas);
    
    // 获取绘图上下文
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    
    // 准备图表数据
    const data = dates.map(date => dateCounts[date] || 0);
    const maxValue = Math.max(...data, 5); // 至少为5，避免图表过于扁平
    
    // 设置图表尺寸和边距
    const padding = 30;
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
    ctx.font = '8px Arial'; // 减小刻度字体
    
    for (let i = 0; i <= ySteps; i++) {
      const y = canvas.height - padding - (i / ySteps) * chartHeight;
      const value = Math.round((i / ySteps) * maxValue);
      
      // 绘制网格线
      ctx.moveTo(padding, y);
      ctx.lineTo(canvas.width - padding, y);
      
      // 绘制Y轴刻度
      ctx.fillText(value.toString(), padding - 3, y + 3);
    }
    ctx.stroke();
    
    // 绘制X轴刻度和标签
    ctx.textAlign = 'center';
    ctx.font = '8px Arial'; // 减小刻度字体
    
    dates.forEach((date, index) => {
      const x = padding + (index / (dates.length - 1)) * chartWidth;
      
      // 绘制X轴刻度
      ctx.beginPath();
      ctx.moveTo(x, canvas.height - padding);
      ctx.lineTo(x, canvas.height - padding + 3); // 减小刻度线长度
      ctx.stroke();
      
      // 绘制X轴标签
      ctx.fillText(date, x, canvas.height - padding + 12); // 减小标签距离
    });
    
    // 绘制数据点和折线
    ctx.beginPath();
    ctx.strokeStyle = '#4285f4';
    ctx.lineWidth = 1.5; // 减小线宽
    
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
      ctx.arc(x, y, 3, 0, 2 * Math.PI); // 减小数据点尺寸
      ctx.fill();
      
      // 绘制白色边框
      ctx.beginPath();
      ctx.strokeStyle = 'white';
      ctx.lineWidth = 1;
      ctx.arc(x, y, 3, 0, 2 * Math.PI); // 减小数据点尺寸
      ctx.stroke();
      
      // 绘制数据标签
      if (value > 0) {
        ctx.fillStyle = '#333';
        ctx.textAlign = 'center';
        ctx.font = 'bold 9px Arial'; // 减小标签字体大小
        ctx.fillText(value.toString(), x, y - 10); // 减小标签与点的距离
      }
    });
  }
  
  // 全屏查看图表
  function openChartFullscreen(chartType) {
    // 创建全屏遮罩
    const fullscreenOverlay = document.createElement('div');
    fullscreenOverlay.className = 'fullscreen-overlay';
    fullscreenOverlay.style.position = 'fixed';
    fullscreenOverlay.style.top = '0';
    fullscreenOverlay.style.left = '0';
    fullscreenOverlay.style.width = '100%';
    fullscreenOverlay.style.height = '100%';
    fullscreenOverlay.style.backgroundColor = 'rgba(255, 255, 255, 0.95)';
    fullscreenOverlay.style.zIndex = '2000';
    fullscreenOverlay.style.display = 'flex';
    fullscreenOverlay.style.flexDirection = 'column';
    fullscreenOverlay.style.alignItems = 'center';
    fullscreenOverlay.style.justifyContent = 'center';
    fullscreenOverlay.style.padding = '30px';
    
    // 创建关闭按钮
    const closeButton = document.createElement('button');
    closeButton.textContent = '关闭';
    // 使用标准按钮而不是内联HTML
    closeButton.innerHTML = ''; // 清除任何内容
    
    // 创建图标span
    const iconSpan = document.createElement('span');
    iconSpan.className = 'material-symbols-outlined';
    iconSpan.textContent = 'close';
    
    // 创建文本span
    const textSpan = document.createElement('span');
    textSpan.textContent = ' 关闭';
    
    // 添加图标和文本到按钮
    closeButton.appendChild(iconSpan);
    closeButton.appendChild(textSpan);
    
    closeButton.style.position = 'absolute';
    closeButton.style.top = '20px';
    closeButton.style.right = '20px';
    closeButton.style.backgroundColor = '#f44336';
    closeButton.style.color = 'white';
    closeButton.style.border = 'none';
    closeButton.style.borderRadius = '4px';
    closeButton.style.padding = '8px 15px';
    closeButton.style.cursor = 'pointer';
    closeButton.style.display = 'flex';
    closeButton.style.alignItems = 'center';
    closeButton.style.gap = '5px';
    closeButton.addEventListener('click', () => {
      document.body.removeChild(fullscreenOverlay);
    });
    
    // 创建标题
    const title = document.createElement('h2');
    title.style.marginBottom = '20px';
    
    // 创建图表容器
    const chartContainer = document.createElement('div');
    chartContainer.style.width = '80%';
    chartContainer.style.height = '70%';
    chartContainer.style.backgroundColor = 'white';
    chartContainer.style.boxShadow = '0 5px 15px rgba(0,0,0,0.1)';
    chartContainer.style.borderRadius = '8px';
    chartContainer.style.padding = '20px';
    
    // 根据图表类型设置内容
    switch(chartType) {
      case 'vulnerability-type':
        title.textContent = '漏洞类型分布';
        drawVulnerabilityChartInContainer(chartContainer);
        break;
      case 'severity':
        title.textContent = '漏洞严重程度分布';
        drawSeverityChartInContainer(chartContainer);
        break;
      case 'recent-activity':
        title.textContent = '最近检测活动';
        drawRecentActivityChartInContainer(chartContainer);
        break;
      case 'domain-distribution':
        title.textContent = '站点漏洞分布';
        drawDomainDistributionChartInContainer(chartContainer);
        break;
    }
    
    // 组装全屏视图
    fullscreenOverlay.appendChild(closeButton);
    fullscreenOverlay.appendChild(title);
    fullscreenOverlay.appendChild(chartContainer);
    document.body.appendChild(fullscreenOverlay);
  }
  
  // 在指定容器中绘制漏洞类型图表
  function drawVulnerabilityChartInContainer(container) {
    // 复用现有的绘制逻辑，但针对新容器
    // 获取漏洞类型分布的数据
    const vulnerabilityTypes = {};
    let totalVulnerabilities = 0;

    // 计算各类型漏洞数量
    allVulnerabilities.forEach(vulnerability => {
      const type = vulnerability.type || 'Other';
      vulnerabilityTypes[type] = (vulnerabilityTypes[type] || 0) + 1;
      totalVulnerabilities++;
    });
    
    // 清空容器
    while (container.firstChild) {
      container.removeChild(container.firstChild);
    }
    
    // 如果没有漏洞数据，显示提示信息
    if (totalVulnerabilities === 0) {
      const noDataDiv = document.createElement('div');
      noDataDiv.className = 'no-data';
      noDataDiv.textContent = '暂无漏洞数据';
      container.appendChild(noDataDiv);
      return;
    }
    
    // 创建Canvas元素
    const canvas = document.createElement('canvas');
    canvas.width = container.clientWidth - 40; // 考虑内边距
    canvas.height = container.clientHeight - 40;
    container.appendChild(canvas);
    
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
    const centerY = canvas.height / 2 - 30; // 向上偏移一点，为图例留出空间
    const radius = Math.min(centerX, centerY) * 0.7;
    
    let startAngle = 0;
    
    // 创建图例容器
    const legendDiv = document.createElement('div');
    legendDiv.style.display = 'flex';
    legendDiv.style.flexWrap = 'wrap';
    legendDiv.style.justifyContent = 'center';
    legendDiv.style.gap = '10px';
    legendDiv.style.marginTop = '20px';
    legendDiv.style.fontSize = '14px';
    
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
      legendItem.style.padding = '5px 10px';
      legendItem.style.backgroundColor = 'rgba(255, 255, 255, 0.7)';
      legendItem.style.borderRadius = '4px';
      legendItem.style.boxShadow = '0 1px 3px rgba(0,0,0,0.1)';
      
      // 创建颜色方块
      const colorBox = document.createElement('span');
      colorBox.style.display = 'inline-block';
      colorBox.style.width = '14px';
      colorBox.style.height = '14px';
      colorBox.style.backgroundColor = CHART_COLORS.vulnerabilityTypes[labels[index]] || CHART_COLORS.vulnerabilityTypes['default'];
      colorBox.style.marginRight = '8px';
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
    container.appendChild(legendDiv);
  }
  
  // 在指定容器中绘制严重程度图表
  function drawSeverityChartInContainer(container) {
    // 与drawVulnerabilityChartInContainer类似，但处理严重程度数据
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
      const severity = (vulnerability.details && vulnerability.details.severity) 
        ? vulnerability.details.severity.toLowerCase() 
        : 'info';
      
      // 确保使用有效的严重级别键
      const validSeverity = severityCounts.hasOwnProperty(severity) ? severity : 'info';
      severityCounts[validSeverity]++;
      totalVulnerabilities++;
    });
    
    // 清空容器
    while (container.firstChild) {
      container.removeChild(container.firstChild);
    }
    
    // 如果没有漏洞数据，显示提示信息
    if (totalVulnerabilities === 0) {
      const noDataDiv = document.createElement('div');
      noDataDiv.className = 'no-data';
      noDataDiv.textContent = '暂无漏洞数据';
      container.appendChild(noDataDiv);
      return;
    }
    
    // 创建Canvas元素
    const canvas = document.createElement('canvas');
    canvas.width = container.clientWidth - 40;
    canvas.height = container.clientHeight - 40;
    container.appendChild(canvas);
    
    // 获取绘图上下文
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    
    // 准备饼图数据
    const data = [];
    const labels = [];
    const percentages = [];
    
    for (const severity in severityCounts) {
      if (severityCounts[severity] > 0) {
        const count = severityCounts[severity];
        const percentage = (count / totalVulnerabilities) * 100;
        
        data.push(count);
        labels.push(severity);
        percentages.push(percentage.toFixed(1));
      }
    }
    
    // 绘制饼图
    const centerX = canvas.width / 2;
    const centerY = canvas.height / 2 - 30;
    const radius = Math.min(centerX, centerY) * 0.7;
    
    let startAngle = 0;
    
    // 创建图例容器
    const legendDiv = document.createElement('div');
    legendDiv.style.display = 'flex';
    legendDiv.style.flexWrap = 'wrap';
    legendDiv.style.justifyContent = 'center';
    legendDiv.style.gap = '10px';
    legendDiv.style.marginTop = '20px';
    legendDiv.style.fontSize = '14px';
    
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
      ctx.fillStyle = CHART_COLORS.severityLevels[labels[index]];
      ctx.strokeStyle = 'white';
      ctx.lineWidth = 2;
      ctx.fill();
      ctx.stroke();
      
      // 创建图例项
      const legendItem = document.createElement('div');
      legendItem.style.display = 'flex';
      legendItem.style.alignItems = 'center';
      legendItem.style.padding = '5px 10px';
      legendItem.style.backgroundColor = 'rgba(255, 255, 255, 0.7)';
      legendItem.style.borderRadius = '4px';
      legendItem.style.boxShadow = '0 1px 3px rgba(0,0,0,0.1)';
      
      // 创建颜色方块
      const colorBox = document.createElement('span');
      colorBox.style.display = 'inline-block';
      colorBox.style.width = '14px';
      colorBox.style.height = '14px';
      colorBox.style.backgroundColor = CHART_COLORS.severityLevels[labels[index]];
      colorBox.style.marginRight = '8px';
      colorBox.style.borderRadius = '2px';
      
      // 创建标签文本
      const labelText = document.createElement('span');
      // 将严重程度首字母大写
      const severityLabel = labels[index].charAt(0).toUpperCase() + labels[index].slice(1);
      labelText.textContent = `${severityLabel}: ${value} (${percentages[index]}%)`;
      
      // 组装图例项
      legendItem.appendChild(colorBox);
      legendItem.appendChild(labelText);
      legendDiv.appendChild(legendItem);
      
      // 更新起始角度
      startAngle = endAngle;
    });
    
    // 添加图例到容器
    container.appendChild(legendDiv);
  }
  
  // 在指定容器中绘制最近活动图表
  function drawRecentActivityChartInContainer(container) {
    // 实现此函数...
    // 类似于drawRecentActivityChart，但针对新容器
  }
  
  // 在指定容器中绘制域名分布图表
  function drawDomainDistributionChartInContainer(container) {
    // 实现此函数...
    // 类似于drawDomainDistributionChart，但针对新容器
  }
  
  // 注册所有事件监听器
  function initEventListeners() {
    try {
      // 导出按钮
      const exportMarkdown = safeGetElement('export-markdown');
      if (exportMarkdown) {
        exportMarkdown.addEventListener('click', exportReport);
      }
      
      const exportCsv = safeGetElement('export-csv');
      if (exportCsv) {
        exportCsv.addEventListener('click', exportAsCSV);
      }
      
      const exportPdf = safeGetElement('export-pdf');
      if (exportPdf) {
        exportPdf.addEventListener('click', exportAsPDF);
      }
      
      const exportJson = safeGetElement('export-json');
      if (exportJson) {
        exportJson.addEventListener('click', exportAsJSON);
      }
      
      // 返回设置按钮
      const backButton = safeGetElement('back-to-settings');
      if (backButton) {
        backButton.addEventListener('click', () => {
          window.location.href = 'popup.html';
        });
      }
      
      // 筛选器 - 仅用于数据导出
      const typeFilter = safeGetElement('type-filter');
      if (typeFilter) {
        typeFilter.addEventListener('change', () => {
          // 更新筛选条件，但不再显示漏洞列表
          updateFilters();
        });
      }
      
      const domainFilter = safeGetElement('domain-filter');
      if (domainFilter) {
        domainFilter.addEventListener('change', () => {
          // 更新筛选条件，但不再显示漏洞列表
          updateFilters();
        });
      }
      
      // 处理可能缺失的元素
      safelyAddEventListeners();
      
      // 处理图片加载错误
      const images = document.querySelectorAll('img');
      images.forEach(img => {
        img.addEventListener('error', function() {
          this.src = 'icon48.png'; // 使用默认图标作为后备
          console.warn(`无法加载图片: ${this.src}`);
        });
      });
      
    } catch (error) {
      console.error('初始化事件监听器时出错:', error);
      showErrorMessage('初始化界面时出错: ' + (error.message || '未知错误'));
    }
  }
  
  // 搜索漏洞
  function searchVulnerabilities(query) {
    filteredVulnerabilities = allVulnerabilities.filter(vuln => {
      // 搜索类型
      if (vuln.type && vuln.type.toLowerCase().includes(query)) {
        return true;
      }
      
      // 搜索URL
      if (vuln.details && vuln.details.location && 
          vuln.details.location.toLowerCase().includes(query)) {
        return true;
      }
      
      // 搜索证据
      if (vuln.details && vuln.details.evidence && 
          vuln.details.evidence.toLowerCase().includes(query)) {
        return true;
      }
      
      // 搜索严重程度
      if (vuln.details && vuln.details.severity && 
          vuln.details.severity.toLowerCase().includes(query)) {
        return true;
      }
      
      return false;
    });
    
    // 重置到第一页
    currentPage = 1;
    displayVulnerabilities();
    updatePagination();
  }
  
  // 显示消息
  function showErrorMessage(message, type = 'error', duration = 3000) {
    // 根据类型确定日志级别
    switch(type) {
      case 'error':
        console.error(message);
        break;
      case 'warning':
        console.warn(message);
        break;
      case 'info':
        console.info(message);
        break;
      default:
        console.log(message);
    }
    
    // 创建消息元素
    const messageDiv = document.createElement('div');
    messageDiv.className = `message-box ${type}-message`;
    messageDiv.textContent = message;
    
    // 确定样式
    let bgColor, textColor, borderColor;
    switch(type) {
      case 'error':
        bgColor = '#f8d7da';
        textColor = '#721c24';
        borderColor = '#f5c6cb';
        break;
      case 'warning':
        bgColor = '#fff3cd';
        textColor = '#856404';
        borderColor = '#ffeeba';
        break;
      case 'info':
        bgColor = '#d1ecf1';
        textColor = '#0c5460';
        borderColor = '#bee5eb';
        break;
      default:
        bgColor = '#d4edda';
        textColor = '#155724';
        borderColor = '#c3e6cb';
    }
    
    // 添加样式
    messageDiv.style.padding = '10px 15px';
    messageDiv.style.margin = '10px 0';
    messageDiv.style.backgroundColor = bgColor;
    messageDiv.style.color = textColor;
    messageDiv.style.border = `1px solid ${borderColor}`;
    messageDiv.style.borderRadius = '4px';
    messageDiv.style.boxShadow = '0 2px 4px rgba(0,0,0,0.1)';
    messageDiv.style.position = 'relative';
    messageDiv.style.animation = 'fadeIn 0.3s ease-in-out';
    
    // 添加关闭按钮
    const closeButton = document.createElement('span');
    // 使用文本内容而不是innerHTML
    closeButton.textContent = '×'; // 使用文本叉号而不是HTML实体
    closeButton.style.position = 'absolute';
    closeButton.style.top = '5px';
    closeButton.style.right = '10px';
    closeButton.style.fontSize = '16px';
    closeButton.style.cursor = 'pointer';
    closeButton.style.fontWeight = 'bold';
    closeButton.addEventListener('click', () => {
      if (messageDiv.parentNode) {
        messageDiv.parentNode.removeChild(messageDiv);
      }
    });
    messageDiv.appendChild(closeButton);
    
    // 查找消息容器
    const messageContainer = document.getElementById('error-container') || 
                           document.getElementById('messages') || 
                           document.body;
    
    if (messageContainer) {
      // 在容器的顶部插入消息
      messageContainer.insertBefore(messageDiv, messageContainer.firstChild);
      
      // 指定时间后自动移除消息
      if (duration > 0) {
        setTimeout(() => {
          if (messageDiv.parentNode) {
            // 添加淡出效果
            messageDiv.style.opacity = '0';
            messageDiv.style.transition = 'opacity 0.5s';
            
            // 完全移除元素
            setTimeout(() => {
              if (messageDiv.parentNode) {
                messageDiv.parentNode.removeChild(messageDiv);
              }
            }, 500);
          }
        }, duration);
      }
    } else {
      console.error('找不到消息容器元素');
    }
  }

  // 清除漏洞数据
  function clearData() {
    try {
      if (confirm('确定要清除所有漏洞数据吗？此操作不可撤销。')) {
        safeSendMessage({action: 'clearVulnerabilities'}, (response) => {
          try {
          if (response && response.success) {
              // 清除本地数据
            allVulnerabilities = [];
            filteredVulnerabilities = [];
            domains = new Set();
            
              // 更新UI
            showNoResults();
            updateStatistics();
              
              // 重置过滤器
              const typeFilterElem = document.getElementById('type-filter');
              if (typeFilterElem) typeFilterElem.value = 'all';
              
              const domainFilterElem = document.getElementById('domain-filter');
              if (domainFilterElem) {
                // 清空现有选项
                while (domainFilterElem.firstChild) {
                  domainFilterElem.removeChild(domainFilterElem.firstChild);
                }
                
                // 添加"所有站点"选项
                const allOption = document.createElement('option');
                allOption.value = 'all';
                allOption.textContent = '所有站点';
                domainFilterElem.appendChild(allOption);
              }
              
              // 通知用户
              showErrorMessage('所有漏洞数据已清除');
              
              // 重新绘制图表
              refreshAllCharts();
            } else {
              showErrorMessage('清除数据失败: ' + (response?.error || '未知错误'));
            }
          } catch (innerError) {
            console.error('处理清除数据响应时出错:', innerError);
            showErrorMessage('清除数据时出错: ' + (innerError.message || '未知错误'));
          }
        });
      }
    } catch (error) {
      console.error('调用清除数据功能时出错:', error);
      showErrorMessage('清除数据时出错: ' + (error.message || '未知错误'));
    }
  }
  
  // 刷新所有图表
  function refreshAllCharts() {
    try {
      // 使用函数存在性检查来避免错误
      if (typeof drawVulnerabilityChart === 'function') {
        drawVulnerabilityChart();
      }
      if (typeof drawSeverityChart === 'function') {
        drawSeverityChart();
      }
      if (typeof drawDomainDistributionChart === 'function') {
        drawDomainDistributionChart();
      }
      if (typeof drawRecentActivityChart === 'function') {
        drawRecentActivityChart();
      }
    } catch (error) {
      console.error('刷新图表时出错:', error);
    }
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
  
  // 导出CSV格式
  function exportAsCSV() {
    // 准备CSV头
    let csvContent = "类型,URL,严重程度,发现时间,证据\n";
    
    // 添加每个漏洞的数据
    allVulnerabilities.forEach(vuln => {
      const type = vuln.type || '';
      let url = '';
      try {
        url = new URL(vuln.details.location).toString();
      } catch (e) {
        url = vuln.details.location || '';
      }
      const severity = (vuln.details && vuln.details.severity) || '';
      const timestamp = vuln.timestamp ? new Date(vuln.timestamp).toLocaleString() : '';
      let evidence = '';
      if (vuln.details && vuln.details.evidence) {
        // 处理CSV中的特殊字符
        evidence = vuln.details.evidence.replace(/"/g, '""');
      }
      
      // 将字段用双引号包围，以处理包含逗号的内容
      csvContent += `"${type}","${url}","${severity}","${timestamp}","${evidence}"\n`;
    });
    
    // 创建下载
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `漏洞报告_${new Date().toISOString().split('T')[0]}.csv`;
    document.body.appendChild(a);
    a.click();
    
    // 清理
    setTimeout(() => {
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    }, 100);
  }
  
  // 导出JSON格式
  function exportAsJSON() {
    // 准备JSON数据
    const exportData = {
      summary: {
        totalVulnerabilities: allVulnerabilities.length,
        domains: Array.from(domains),
        generatedAt: new Date().toISOString(),
        version: '1.2.0'
      },
      vulnerabilities: allVulnerabilities
    };
    
    // 转换为JSON字符串
    const jsonContent = JSON.stringify(exportData, null, 2);
    
    // 创建下载
    const blob = new Blob([jsonContent], { type: 'application/json;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `漏洞报告_${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(a);
    a.click();
    
    // 清理
    setTimeout(() => {
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    }, 100);
  }
  
  // 导出PDF格式
  function exportAsPDF() {
    try {
      // 显示暂不支持的消息
      showErrorMessage('PDF导出功能暂未实现，请使用Markdown或CSV格式导出', 'info');
      
      // 未来的PDF导出逻辑将在这里实现
      console.log('PDF导出功能将在未来版本中实现');
    } catch (error) {
      console.error('PDF导出时出错:', error);
      showErrorMessage('PDF导出失败: ' + (error.message || '未知错误'));
    }
  }
  
  // 刷新特定图表
  function refreshChart(chartType) {
    switch(chartType) {
      case 'vulnerability-type':
        drawVulnerabilityChart();
        break;
      case 'severity':
        drawSeverityChart();
        break;
      case 'recent-activity':
        drawRecentActivityChart();
        break;
      case 'domain-distribution':
        drawDomainDistributionChart();
        break;
    }
  }
  
  // 初始化页面
  function initPage() {
    try {
      // 处理图片加载错误
      handleImagesErrorEvent();
      
      // 检查存储中的漏洞数据格式
      chrome.storage.local.get('vulnerabilities', (result) => {
        console.log('存储中的漏洞数据:', result && result.vulnerabilities ? '已找到' : '未找到');
        if (result && result.vulnerabilities) {
          // 检查数据结构
          console.log('数据结构:', 
                      '有byDomain:', !!result.vulnerabilities.byDomain,
                      '有statistics:', !!result.vulnerabilities.statistics,
                      '有items:', !!result.vulnerabilities.items);
          
          // 检查vulnerabilities中的条目数
          if (Array.isArray(result.vulnerabilities.items)) {
            console.log('漏洞items数组长度:', result.vulnerabilities.items.length);
          }
          
          // 检查byDomain结构
          if (result.vulnerabilities.byDomain) {
            const domainCount = Object.keys(result.vulnerabilities.byDomain).length;
            console.log('byDomain域名数量:', domainCount);
            console.log('域名列表:', Object.keys(result.vulnerabilities.byDomain));
          }
        }
      });
      
      // 初始化标签
      initTabs();
      
      // 初始化事件监听
      initEventListeners();
      
      // 初始化按钮点击事件
      initChartButtonEvents();
      
      // 加载漏洞数据
      loadVulnerabilities();
    } catch (error) {
      console.error('初始化页面时出错:', error);
      showErrorMessage('初始化页面时出错: ' + (error.message || '未知错误'));
    }
  }
  
  // 初始化标签页切换功能
  function initTabs() {
    const tabs = document.querySelectorAll('.tab');
    const tabContents = document.querySelectorAll('.tab-content');
    
    console.log('初始化标签页 - 找到标签数量:', tabs.length);
    console.log('初始化标签页 - 找到内容区域数量:', tabContents.length);
    
    tabs.forEach(tab => {
      tab.addEventListener('click', () => {
        const tabId = tab.getAttribute('data-tab');
        console.log('点击标签:', tabId);
        
        // 移除所有标签的活动状态
        tabs.forEach(t => t.classList.remove('active'));
        
        // 激活当前标签
        tab.classList.add('active');
        
        // 隐藏所有标签内容
        tabContents.forEach(content => {
          content.classList.remove('active');
          console.log('标签内容ID:', content.id);
        });
        
        // 显示当前标签内容
        const activeContent = document.getElementById(tabId);
        console.log('要激活的内容元素:', activeContent ? activeContent.id : '未找到');
        
        if (activeContent) {
          activeContent.classList.add('active');
          console.log(tabId + ' 标签页已激活');
          
          // 如果点击的是域名标签，确保更新域名分析
          if (tabId === 'domains') {
            console.log('触发域名分析更新');
            // 检查域名列表容器是否存在
            checkDomainContainers();
            updateDomainAnalysis();
          }
        } else {
          console.warn(`找不到ID为 ${tabId} 的标签内容`);
        }
      });
    });
  }

  // 初始化图表按钮事件
  function initChartButtonEvents() {
    // 刷新图表按钮
    const refreshButtons = document.querySelectorAll('.refresh-chart');
    refreshButtons.forEach(button => {
      button.addEventListener('click', (e) => {
        const chartType = button.getAttribute('data-chart');
        refreshChart(chartType);
        e.stopPropagation();
      });
    });
    
    // 全屏查看按钮
    const fullscreenButtons = document.querySelectorAll('.fullscreen-chart');
    fullscreenButtons.forEach(button => {
      button.addEventListener('click', (e) => {
        const chartType = button.getAttribute('data-chart');
        openChartFullscreen(chartType);
        e.stopPropagation();
      });
    });
  }

  // 处理可能不存在的元素
  function safelyAddEventListeners() {
    // 安全地绑定事件到可能不存在的元素
    const elementIds = [
      'detection-mode', 'detection-depth', 
      'detect-xss', 'detect-sqli', 'detect-csrf', 'detect-ssrf',
      'detect-info-leakage', 'detect-headers',
      'reset-vulnerability-settings', 'clear-data'
    ];
    
    // 记录缺失元素
    const missingElements = [];
    
    elementIds.forEach(id => {
      const element = document.getElementById(id);
      if (element) {
        if (id === 'clear-data') {
          element.addEventListener('click', clearData);
        } else if (id === 'reset-vulnerability-settings') {
          element.addEventListener('click', function() {
            if (confirm('确定要重置所有漏洞检测设置吗？')) {
              safeSendMessage({action: 'resetVulnerabilitySettings'}, function(response) {
                if (response && response.success) {
                  showErrorMessage('漏洞检测设置已重置为默认值');
                } else {
                  showErrorMessage('重置漏洞检测设置失败');
                }
              });
            }
          });
        }
      } else {
        // 收集缺失元素，而不是单独警告
        missingElements.push(id);
      }
    });
    
    // 只记录一次汇总的警告信息
    if (missingElements.length > 0) {
      // 记录单个警告信息而不是多个
      console.warn(`一些配置元素不存在 (${missingElements.length}个): ${missingElements.join(', ')}`);
      
      // 创建一个隐藏的状态元素，用于调试但不打扰用户
      const statusDiv = document.createElement('div');
      statusDiv.style.display = 'none';
      statusDiv.id = 'missing-elements-info';
      statusDiv.dataset.missingElements = missingElements.join(',');
      
      const container = document.querySelector('.container') || document.body;
      if (container) {
        container.appendChild(statusDiv);
      }
    }
  }

  // 初始化
  initPage();

  // 处理图片加载错误
  function handleImagesErrorEvent() {
    // 为所有图片添加错误处理
    const images = document.querySelectorAll('img');
    images.forEach(img => {
      // 添加onerror事件处理器
      img.onerror = function() {
        console.warn(`图片加载失败: ${this.src}`);
        // 保存原始src以便记录
        const originalSrc = this.src;
        // 替换为默认图标
        this.src = 'icon48.png';
        // 添加提示信息
        this.title = `原图片加载失败: ${originalSrc}`;
        // 添加视觉提示
        this.style.border = '1px dashed #ccc';
        this.style.padding = '2px';
        // 防止无限循环（如果默认图标也无法加载）
        this.onerror = null;
      };
    });
    
    // 设置页面级别的图片加载错误处理
    document.addEventListener('error', function(e) {
      const target = e.target;
      // 只处理图片元素
      if (target.tagName.toLowerCase() === 'img') {
        console.warn(`捕获到图片加载错误: ${target.src}`);
        // 如果还没有设置替代图标，则设置
        if (target.src !== 'icon48.png') {
          const originalSrc = target.src;
          target.src = 'icon48.png';
          target.title = `原图片加载失败: ${originalSrc}`;
          target.style.border = '1px dashed #ccc';
          target.style.padding = '2px';
        }
        // 防止事件冒泡
        e.stopPropagation();
      }
    }, true); // 使用捕获阶段
    
    // 修复Promise中可能出现的图片加载错误
    window.addEventListener('unhandledrejection', function(event) {
      // 检查是否是图片加载相关的错误
      if (event.reason && event.reason.message && 
          (event.reason.message.includes('Unable to download') || 
           event.reason.message.includes('Failed to fetch') ||
           event.reason.message.includes('Network error'))) {
        console.warn('捕获到未处理的Promise rejection:', event.reason.message);
        // 显示友好的用户提示（可选）
        // showErrorMessage('部分图像无法加载，已替换为默认图标');
        // 阻止错误显示在控制台
        event.preventDefault();
      }
    });
  }

  // 更新站点分析标签页内容
  function updateDomainAnalysis() {
    try {
      // 添加调试信息
      console.log('更新站点分析 - 漏洞数量:', allVulnerabilities.length);
      
      // 获取域名列表容器
      const domainListContainer = document.getElementById('domain-list');
      console.log('域名列表容器:', domainListContainer ? '找到' : '未找到');
      
      if (!domainListContainer) {
        console.warn('找不到域名列表容器');
        return;
      }
      
      // 清空现有内容
      while (domainListContainer.firstChild) {
        domainListContainer.removeChild(domainListContainer.firstChild);
      }
      
      // 按域名对漏洞进行分组
      const vulnerabilitiesByDomain = {};
      let validVulnerabilitiesCount = 0;
      
      allVulnerabilities.forEach(vuln => {
        try {
          if (!vuln || !vuln.details || !vuln.details.location) {
            console.warn('漏洞数据缺少location信息:', vuln);
            return;
          }
          
          const url = new URL(vuln.details.location);
          const hostname = url.hostname;
          validVulnerabilitiesCount++;
          
          if (!vulnerabilitiesByDomain[hostname]) {
            vulnerabilitiesByDomain[hostname] = [];
          }
          vulnerabilitiesByDomain[hostname].push(vuln);
        } catch (e) {
          // 忽略无效URL
          console.warn('处理漏洞URL时出错:', e.message, '数据:', vuln);
        }
      });
      
      console.log('有效漏洞数量:', validVulnerabilitiesCount);
      console.log('按域名分组:', Object.keys(vulnerabilitiesByDomain).length, '个域名');
      
      // 检查是否有域名数据
      if (Object.keys(vulnerabilitiesByDomain).length === 0) {
        console.log('没有发现域名数据，显示无数据提示');
        const noDataDiv = document.createElement('div');
        noDataDiv.className = 'no-data';
        noDataDiv.textContent = '暂无站点数据';
        domainListContainer.appendChild(noDataDiv);
        return;
      }
      
      // 为每个域名创建一个条目
      Object.entries(vulnerabilitiesByDomain).forEach(([domain, vulns]) => {
        console.log(`添加域名项: ${domain}, 漏洞数: ${vulns.length}`);
        
        // 创建域名容器
        const domainItem = document.createElement('div');
        domainItem.className = 'domain-item';
        domainItem.dataset.domain = domain;
        
        // 统计各严重程度漏洞数
        const severityCounts = {
          critical: 0,
          high: 0, 
          medium: 0,
          low: 0,
          info: 0
        };
        
        vulns.forEach(vuln => {
          const severity = (vuln.details && vuln.details.severity) 
            ? vuln.details.severity.toLowerCase() 
            : 'info';
          
          if (severityCounts.hasOwnProperty(severity)) {
            severityCounts[severity]++;
          } else {
            severityCounts.info++;
          }
        });
        
        // 创建域名标题
        const domainHeader = document.createElement('div');
        domainHeader.className = 'domain-header';
        
        // 域名图标
        const domainIcon = document.createElement('span');
        domainIcon.className = 'material-symbols-outlined';
        domainIcon.textContent = 'language';
        domainHeader.appendChild(domainIcon);
        
        // 域名文本
        const domainName = document.createElement('h3');
        domainName.textContent = domain;
        domainHeader.appendChild(domainName);
        
        // 漏洞计数
        const vulnCount = document.createElement('span');
        vulnCount.className = 'vuln-count';
        vulnCount.textContent = `${vulns.length} 个漏洞`;
        domainHeader.appendChild(vulnCount);
        
        domainItem.appendChild(domainHeader);
        
        // 创建漏洞概览
        const vulnSummary = document.createElement('div');
        vulnSummary.className = 'domain-summary';
        
        // 添加严重程度指示器
        if (severityCounts.critical > 0) {
          const criticalIndicator = document.createElement('span');
          criticalIndicator.className = 'severity-indicator critical';
          criticalIndicator.textContent = `严重: ${severityCounts.critical}`;
          vulnSummary.appendChild(criticalIndicator);
        }
        
        if (severityCounts.high > 0) {
          const highIndicator = document.createElement('span');
          highIndicator.className = 'severity-indicator high';
          highIndicator.textContent = `高危: ${severityCounts.high}`;
          vulnSummary.appendChild(highIndicator);
        }
        
        if (severityCounts.medium > 0) {
          const mediumIndicator = document.createElement('span');
          mediumIndicator.className = 'severity-indicator medium';
          mediumIndicator.textContent = `中危: ${severityCounts.medium}`;
          vulnSummary.appendChild(mediumIndicator);
        }
        
        if (severityCounts.low > 0) {
          const lowIndicator = document.createElement('span');
          lowIndicator.className = 'severity-indicator low';
          lowIndicator.textContent = `低危: ${severityCounts.low}`;
          vulnSummary.appendChild(lowIndicator);
        }
        
        domainItem.appendChild(vulnSummary);
        
        // 添加点击事件，显示详细漏洞信息
        domainItem.addEventListener('click', () => {
          showDomainVulnerabilities(domain, vulns);
          
          // 移除其他域名项的活动状态
          document.querySelectorAll('.domain-item').forEach(item => {
            item.classList.remove('active');
          });
          
          // 添加当前域名项的活动状态
          domainItem.classList.add('active');
        });
        
        domainListContainer.appendChild(domainItem);
      });
      
      console.log('所有域名项已添加');
      
      // 默认选中第一个域名
      const firstDomainItem = domainListContainer.querySelector('.domain-item');
      if (firstDomainItem) {
        console.log('自动选中第一个域名项');
        firstDomainItem.click();
      } else {
        console.warn('没有找到域名项可选中');
      }
      
    } catch (error) {
      console.error('更新站点分析时出错:', error);
      showErrorMessage('更新站点分析时出错: ' + (error.message || '未知错误'));
    }
  }
  
  // 显示特定域名的漏洞详情
  function showDomainVulnerabilities(domain, vulnerabilities) {
    const domainDetailsContainer = safeGetElement('domain-vulnerabilities');
    if (!domainDetailsContainer) {
      console.warn('找不到域名详情容器');
      return;
    }
    
    // 清空现有内容
    while (domainDetailsContainer.firstChild) {
      domainDetailsContainer.removeChild(domainDetailsContainer.firstChild);
    }
    
    // 添加标题
    const titleElement = document.createElement('h2');
    titleElement.textContent = `${domain} 的漏洞 (${vulnerabilities.length})`;
    domainDetailsContainer.appendChild(titleElement);
    
    // 按严重程度对漏洞进行排序
    const severityOrder = {
      'critical': 0,
      'high': 1,
      'medium': 2,
      'low': 3,
      'info': 4
    };
    
    const sortedVulnerabilities = [...vulnerabilities].sort((a, b) => {
      const severityA = (a.details && a.details.severity) ? a.details.severity.toLowerCase() : 'info';
      const severityB = (b.details && b.details.severity) ? b.details.severity.toLowerCase() : 'info';
      
      const orderA = severityOrder[severityA] || 4;
      const orderB = severityOrder[severityB] || 4;
      
      return orderA - orderB;
    });
    
    // 创建漏洞列表
    sortedVulnerabilities.forEach(vuln => {
      const severity = (vuln.details && vuln.details.severity) 
        ? vuln.details.severity.toLowerCase() 
        : 'info';
        
      const vulnerabilityElement = document.createElement('div');
      vulnerabilityElement.className = `vulnerability ${severity}`;
      
      // 漏洞标题
      const titleElement = document.createElement('h3');
      titleElement.textContent = vuln.type;
      vulnerabilityElement.appendChild(titleElement);
      
      // 漏洞详情
      const detailsDiv = document.createElement('div');
      detailsDiv.className = 'vulnerability-details';
      
      // URL信息
      const urlLabelDiv = document.createElement('div');
      urlLabelDiv.className = 'label';
      urlLabelDiv.textContent = 'URL:';
      detailsDiv.appendChild(urlLabelDiv);
      
      const urlValueDiv = document.createElement('div');
      const urlLink = document.createElement('a');
      urlLink.href = vuln.details.location;
      urlLink.textContent = vuln.details.location;
      urlLink.target = '_blank';
      urlValueDiv.appendChild(urlLink);
      detailsDiv.appendChild(urlValueDiv);
      
      // 严重程度信息
      const severityLabelDiv = document.createElement('div');
      severityLabelDiv.className = 'label';
      severityLabelDiv.textContent = '严重程度:';
      detailsDiv.appendChild(severityLabelDiv);
      
      const severityValueDiv = document.createElement('div');
      const severityBadge = document.createElement('span');
      severityBadge.className = `severity-badge ${severity}`;
      
      const severityNames = {
        'critical': '严重',
        'high': '高危',
        'medium': '中危',
        'low': '低危',
        'info': '信息'
      };
      
      severityBadge.textContent = severityNames[severity] || severity;
      severityValueDiv.appendChild(severityBadge);
      detailsDiv.appendChild(severityValueDiv);
      
      // 证据信息
      const evidenceLabelDiv = document.createElement('div');
      evidenceLabelDiv.className = 'label';
      evidenceLabelDiv.textContent = '证据:';
      detailsDiv.appendChild(evidenceLabelDiv);
      
      const evidenceValueDiv = document.createElement('div');
      evidenceValueDiv.textContent = vuln.details.evidence || '无详细信息';
      detailsDiv.appendChild(evidenceValueDiv);
      
      vulnerabilityElement.appendChild(detailsDiv);
      
      // 时间戳
      const timestampDiv = document.createElement('div');
      timestampDiv.className = 'timestamp';
      timestampDiv.textContent = '发现时间: ' + new Date(vuln.timestamp).toLocaleString();
      vulnerabilityElement.appendChild(timestampDiv);
      
      domainDetailsContainer.appendChild(vulnerabilityElement);
    });
  }

  // 检查域名相关的容器
  function checkDomainContainers() {
    const domainTab = document.querySelector('.tab[data-tab="domains"]');
    const domainsContainer = document.getElementById('domains');
    const domainList = document.getElementById('domain-list');
    const domainDetails = document.getElementById('domain-details');
    const domainVulnerabilities = document.getElementById('domain-vulnerabilities');
    
    console.log('域名标签:', domainTab ? '找到' : '未找到');
    console.log('域名容器:', domainsContainer ? '找到' : '未找到');
    console.log('域名列表:', domainList ? '找到' : '未找到');
    console.log('域名详情:', domainDetails ? '找到' : '未找到');
    console.log('域名漏洞列表:', domainVulnerabilities ? '找到' : '未找到');
    
    if (domainsContainer) {
      console.log('域名容器可见性:', domainsContainer.style.display, 
                  '类名:', domainsContainer.className, 
                  '是否有active类:', domainsContainer.classList.contains('active'));
    }
    
    // 检查所有标签页的容器
    document.querySelectorAll('.tab-content').forEach(content => {
      console.log(`标签内容 #${content.id}:`, 
                  '可见性:', content.style.display, 
                  '类名:', content.className, 
                  '是否有active类:', content.classList.contains('active'));
    });
  }
}); 