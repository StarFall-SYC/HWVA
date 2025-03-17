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
  }
  
  // 导出报告
  function exportReport() {
    chrome.runtime.sendMessage({
      action: 'generateReport'
    });
  }
  
  // 清空数据
  function clearData() {
    if (confirm('确定要清空所有漏洞数据吗？此操作不可撤销。')) {
      chrome.runtime.sendMessage(
        {
          action: 'clearVulnerabilities'
        },
        (response) => {
          if (response && response.success) {
            allVulnerabilities = [];
            filteredVulnerabilities = [];
            domains = new Set();
            
            showNoResults();
            updateStatistics();
            
            if (filterDomain) {
              filterDomain.innerHTML = '<option value="all">所有站点</option>';
            } else {
              console.warn('找不到域名过滤器元素');
            }
          }
        }
      );
    }
  }
}); 