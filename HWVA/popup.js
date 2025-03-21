// 等待DOM加载完成
document.addEventListener('DOMContentLoaded', () => {
  // 安全地获取元素，如果元素不存在则返回一个默认对象
  function safeGetElement(id) {
    const element = document.getElementById(id);
    if (!element) {
      console.warn(`元素 ${id} 不存在`);
      // 返回一个带有常用属性和方法的默认对象
      return {
        checked: false,
        value: '',
        classList: {
          add: () => {},
          remove: () => {},
          toggle: () => {}
        },
        addEventListener: () => {},
        nextElementSibling: {
          style: { display: 'none' }
        },
        style: {},
        // 添加空的setter，这样赋值时不会报错
        set checked(val) {},
        set value(val) {},
        set textContent(val) {}
      };
    }
    return element;
  }
  
  // 安全地获取元素集合，如果选择器没有匹配项则返回空数组
  function safeQuerySelectorAll(selector) {
    const elements = document.querySelectorAll(selector);
    return elements || [];
  }
  
  // 获取DOM元素
  const tabs = safeQuerySelectorAll('.tab');
  const tabContents = safeQuerySelectorAll('.tab-content');
  const startScanButton = safeGetElement('start-scan');
  const startMultiScanButton = safeGetElement('start-multi-scan');
  const statusPanel = safeGetElement('status-panel');
  const statusText = safeGetElement('status-text');
  const progressBar = safeGetElement('progress-bar');
  const currentTarget = safeGetElement('current-target');
  const saveSettingsButton = safeGetElement('save-settings');
  const resetSettingsButton = safeGetElement('reset-settings');
  const viewReportButton = safeGetElement('view-report');
  const exportCsvButton = safeGetElement('export-csv');
  const collapsibles = safeQuerySelectorAll('.collapsible');
  
  // 获取高级设置子标签
  const subTabs = safeQuerySelectorAll('.sub-tab');
  const subTabContents = safeQuerySelectorAll('.sub-tab-content');
  
  // 滑块元素
  const mouseSpeedSlider = safeGetElement('mouse-speed');
  const typingSpeedSlider = safeGetElement('typing-speed');
  const operationIntervalSlider = safeGetElement('operation-interval');
  const mouseSpeedValue = safeGetElement('mouse-speed-value');
  const typingSpeedValue = safeGetElement('typing-speed-value');
  const operationIntervalValue = safeGetElement('operation-interval-value');
  
  // 全局变量
  let currentScanIndex = 0;
  let totalSites = 0;
  let targetSites = [];
  let scanningInProgress = false;
  
  // 默认设置
  const defaultSettings = {
    fingerprint: {
      enabled: true,
      updateInterval: 30,
      userAgent: true,
      canvas: true,
      webrtc: true,
      fonts: true,
      hardware: true,
      screen: true
    },
    humanBehavior: {
      mouseSpeed: 3,
      typingSpeed: 3,
      operationInterval: 3,
      eyeTracking: true,
      typos: true
    },
    compliance: {
      respectRobots: true,
      checkLegal: true,
      limitRequests: true,
      requestInterval: 500
    },
    vulnerabilityTypes: {
      xss: true,
      sqli: true,
      csrf: true,
      ssrf: true,
      xxe: true,
      cors: true,
      jwt: true,
      redirect: true
    },
    batchProcessing: {
      maxParallel: 1,
      timeout: 30,
      autoCloseTabs: true
    },
    vulnerabilityDetection: {
      detectionMode: 'active',
      detectionDepth: 3,
      vulnerabilityTypes: {
        xss: true,
        sqli: true,
        csrf: true,
        ssrf: true,
        infoLeakage: true,
        headers: true
      }
    }
  };
  
  // 当前设置
  let currentSettings = JSON.parse(JSON.stringify(defaultSettings));
  
  // 初始化设置
  loadSettings();
  
  // 初始化子标签页
  initSubTabs();
  
  // 安全地添加事件监听器
  function safeAddEventListener(element, event, callback) {
    if (element) {
      element.addEventListener(event, callback);
    } else {
      console.warn(`无法为不存在的元素添加${event}事件监听器`);
    }
  }
  
  // 标签切换处理
  tabs.forEach(tab => {
    safeAddEventListener(tab, 'click', () => {
      // 更新标签激活状态
      tabs.forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      
      // 隐藏所有内容
      tabContents.forEach(content => {
        content.classList.remove('active');
      });
      
      // 显示对应面板
      const tabId = tab.dataset.tab;
      if (tabId === 'single') {
        document.getElementById('single-mode').classList.add('active');
      } else if (tabId === 'multi') {
        document.getElementById('multi-mode').classList.add('active');
      } else if (tabId === 'advanced') {
        document.getElementById('advanced-mode').classList.add('active');
      } else if (tabId === 'results') {
        document.getElementById('results-mode').classList.add('active');
        loadRecentResults();
      }
    });
  });
  
  // 高级设置子标签页切换功能
  subTabs.forEach(subTab => {
    safeAddEventListener(subTab, 'click', () => {
      // 更新子标签激活状态
      subTabs.forEach(t => t.classList.remove('active'));
      subTab.classList.add('active');
      
      // 隐藏所有子标签内容
      subTabContents.forEach(content => {
        content.style.display = 'none';
      });
      
      // 显示对应子标签内容
      const subTabId = subTab.dataset.subtab;
      if (subTabId) {
        const contentElement = document.getElementById(`${subTabId}-tab`);
        if (contentElement) {
          contentElement.style.display = 'block';
        }
      }
    });
  });
  
  // 人格类型选择
  const personalityTypes = safeQuerySelectorAll('.personality-type');
  
  // 移除可能的滑动指示器
  const existingSlider = document.querySelector('.personality-slider');
  if (existingSlider) {
    existingSlider.parentNode.removeChild(existingSlider);
  }
  
  personalityTypes.forEach(personality => {
    safeAddEventListener(personality, 'click', () => {
      // 移除其他人格类型的激活状态
      personalityTypes.forEach(p => p.classList.remove('active'));
      // 激活当前选择的人格类型
      personality.classList.add('active');
      
      // 保存选择的人格类型
      const personalityType = personality.dataset.personality;
      if (personalityType) {
        // 根据人格类型调整相关设置
        switch (personalityType) {
          case 'methodical':
            // 条理型：中等鼠标速度，中等打字速度，较长操作间隔
            mouseSpeedSlider.value = 3;
            typingSpeedSlider.value = 3;
            operationIntervalSlider.value = 4;
            break;
          case 'impulsive':
            // 冲动型：快速鼠标移动，快速打字，短操作间隔
            mouseSpeedSlider.value = 5;
            typingSpeedSlider.value = 5;
            operationIntervalSlider.value = 2;
            break;
          case 'thorough':
            // 细致型：慢速鼠标移动，中等打字速度，长操作间隔
            mouseSpeedSlider.value = 2;
            typingSpeedSlider.value = 3;
            operationIntervalSlider.value = 5;
            break;
          case 'casual':
            // 随意型：中等鼠标速度，不规则节奏，中等操作间隔
            mouseSpeedSlider.value = 3;
            typingSpeedSlider.value = 4;
            operationIntervalSlider.value = 3;
            break;
        }
        
        // 更新滑块显示值
        updateSliderValue(mouseSpeedSlider, mouseSpeedValue);
        updateSliderValue(typingSpeedSlider, typingSpeedValue);
        updateSliderValue(operationIntervalSlider, operationIntervalValue);
      }
    });
  });
  
  // 可折叠面板处理
  collapsibles.forEach(collapsible => {
    safeAddEventListener(collapsible, 'click', function() {
      this.classList.toggle('active');
      const content = this.nextElementSibling;
      if (content.style.display === 'block') {
        content.style.display = 'none';
      } else {
        content.style.display = 'block';
      }
    });
  });
  
  // 滑块值更新
  safeAddEventListener(mouseSpeedSlider, 'input', () => {
    updateSliderValue(mouseSpeedSlider, mouseSpeedValue);
  });
  
  safeAddEventListener(typingSpeedSlider, 'input', () => {
    updateSliderValue(typingSpeedSlider, typingSpeedValue);
  });
  
  safeAddEventListener(operationIntervalSlider, 'input', () => {
    updateSliderValue(operationIntervalSlider, operationIntervalValue);
  });
  
  // 保存设置
  safeAddEventListener(saveSettingsButton, 'click', () => {
    // 更新人类行为设置
    currentSettings.humanBehavior.mouseSpeed = parseInt(mouseSpeedSlider.value);
    currentSettings.humanBehavior.typingSpeed = parseInt(typingSpeedSlider.value);
    currentSettings.humanBehavior.operationInterval = parseInt(operationIntervalSlider.value);
    
    // 更新指纹伪装设置
    currentSettings.fingerprint.enabled = safeGetElement('enable-fingerprint').checked;
    currentSettings.fingerprint.updateInterval = parseInt(safeGetElement('fingerprint-interval').value) || 30;
    currentSettings.fingerprint.userAgent = safeGetElement('fp-useragent').checked;
    currentSettings.fingerprint.canvas = safeGetElement('fp-canvas').checked;
    currentSettings.fingerprint.webrtc = safeGetElement('fp-webrtc').checked;
    currentSettings.fingerprint.fonts = safeGetElement('fp-fonts').checked;
    currentSettings.fingerprint.hardware = safeGetElement('fp-hardware').checked;
    currentSettings.fingerprint.screen = safeGetElement('fp-screen').checked;
    
    // 更新漏洞检测设置
    updateVulnerabilitySettingsFromUI();
    
    // 保存所有设置
    saveSettings();
    
    // 显示保存成功提示
    alert('设置已保存');
  });
  
  // 重置设置
  safeAddEventListener(resetSettingsButton, 'click', () => {
    if (confirm('确定要恢复默认设置吗？')) {
      resetSettings();
      showNotification('已恢复默认设置');
    }
  });
  
  // 查看报告
  safeAddEventListener(viewReportButton, 'click', () => {
    chrome.tabs.create({ url: 'report.html' });
  });
  
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
  
  // 导出CSV
  safeAddEventListener(exportCsvButton, 'click', () => {
    safeSendMessage({ action: 'exportCSV' }, (response) => {
      if (response && response.csv) {
        downloadCSV(response.csv);
      } else if (response && response.error) {
        showNotification('导出失败: ' + response.error);
      } else {
        showNotification('导出失败，请稍后重试');
      }
    });
  });
  
  // 单站点扫描
  safeAddEventListener(startScanButton, 'click', () => {
    const targetUrl = safeGetElement('target-url').value.trim();
    const scanDepth = safeGetElement('scan-depth').value;
    
    if (!targetUrl) {
      alert('请输入目标网站URL');
      return;
    }
    
    if (!isValidUrl(targetUrl)) {
      alert('请输入有效的URL，包含http://或https://');
      return;
    }
    
    // 获取选中的漏洞类型
    const vulnerabilityTypes = getSelectedVulnerabilityTypes();
    
    // 显示状态面板
    statusPanel.style.display = 'block';
    statusText.textContent = '正在检测...';
    progressBar.style.width = '0%';
    currentTarget.textContent = `当前目标: ${targetUrl}`;
    
    // 准备漏洞检测设置
    prepareVulnerabilityDetection();
    
    // 使用chrome API打开新标签页
    chrome.tabs.create({ url: targetUrl }, (tab) => {
      // 发送消息到content script
      setTimeout(() => {
        chrome.tabs.sendMessage(tab.id, {
          action: 'startDetection',
          scanDepth: scanDepth,
          settings: currentSettings,
          vulnerabilityTypes: vulnerabilityTypes
        }, response => {
          // 处理可能的错误
          if (chrome.runtime.lastError) {
            console.error(`向标签页发送消息失败: ${chrome.runtime.lastError.message}`);
            showNotification('无法启动扫描，请刷新页面后重试');
          }
        });
        
        // 模拟进度更新
        simulateProgress(100);
      }, 2000); // 等待页面加载完成
    });
  });
  
  // 多站点批量扫描
  safeAddEventListener(startMultiScanButton, 'click', () => {
    const multiTargetsText = safeGetElement('multi-targets').value.trim();
    const scanInterval = parseInt(safeGetElement('interval').value, 10) * 60 * 1000; // 转换为毫秒
    const scanDepth = safeGetElement('multi-scan-depth').value;
    const maxParallel = parseInt(safeGetElement('max-parallel').value, 10) || 1;
    const timeout = parseInt(safeGetElement('timeout').value, 10) * 60 * 1000; // 转换为毫秒
    const autoCloseTabs = safeGetElement('auto-close-tabs').checked;
    
    if (!multiTargetsText) {
      alert('请输入至少一个目标网站URL');
      return;
    }
    
    // 分割和验证URL
    targetSites = multiTargetsText.split('\n')
      .map(url => url.trim())
      .filter(url => url && isValidUrl(url));
    
    if (targetSites.length === 0) {
      alert('请输入至少一个有效的URL，包含http://或https://');
      return;
    }
    
    // 获取选中的漏洞类型
    const vulnerabilityTypes = getSelectedVulnerabilityTypes();
    
    // 更新批处理设置
    currentSettings.batchProcessing.maxParallel = maxParallel;
    currentSettings.batchProcessing.timeout = timeout / 60000; // 转换回分钟
    currentSettings.batchProcessing.autoCloseTabs = autoCloseTabs;
    
    totalSites = targetSites.length;
    currentScanIndex = 0;
    scanningInProgress = true;
    
    // 显示状态面板
    statusPanel.style.display = 'block';
    statusText.textContent = `共${totalSites}个目标，正在扫描第1个`;
    progressBar.style.width = '0%';
    currentTarget.textContent = `当前目标: ${targetSites[0]}`;
    
    // 准备漏洞检测设置
    prepareVulnerabilityDetection();
    
    // 开始批量扫描
    scanNextSite(scanDepth, scanInterval, vulnerabilityTypes);
  });
  
  // 扫描下一个站点
  function scanNextSite(scanDepth, scanInterval, vulnerabilityTypes) {
    if (currentScanIndex >= totalSites || !scanningInProgress) {
      finishScanning();
      return;
    }
    
    const currentSite = targetSites[currentScanIndex];
    currentTarget.textContent = `当前目标: ${currentSite}`;
    statusText.textContent = `共${totalSites}个目标，正在扫描第${currentScanIndex + 1}个`;
    
    // 计算并更新进度条
    const progress = (currentScanIndex / totalSites) * 100;
    progressBar.style.width = `${progress}%`;
    
    // 打开新标签页并开始扫描
    chrome.tabs.create({ url: currentSite }, (tab) => {
      setTimeout(() => {
        chrome.tabs.sendMessage(tab.id, {
          action: 'startDetection',
          scanDepth: scanDepth,
          settings: currentSettings,
          vulnerabilityTypes: vulnerabilityTypes,
          batchMode: true,
          batchIndex: currentScanIndex,
          totalSites: totalSites
        }, response => {
          // 处理可能的错误
          if (chrome.runtime.lastError) {
            console.error(`向标签页发送消息失败: ${chrome.runtime.lastError.message}`);
            // 继续扫描下一个站点，即使当前站点失败
            setTimeout(() => {
              scanNextSite(scanDepth, scanInterval, vulnerabilityTypes);
            }, 1000);
          }
        });
        
        // 设置随机操作时长（根据深度不同）
        let operationTime = 30000; // 默认30秒
        if (scanDepth === 'medium') operationTime = 60000; // 中度1分钟
        if (scanDepth === 'deep') operationTime = 120000; // 深度2分钟
        
        // 添加随机性
        operationTime += Math.random() * 20000;
        
        // 操作完成后，关闭标签并继续下一个
        setTimeout(() => {
          if (currentSettings.batchProcessing.autoCloseTabs) {
          chrome.tabs.remove(tab.id);
          }
          currentScanIndex++;
          setTimeout(() => {
            scanNextSite(scanDepth, scanInterval, vulnerabilityTypes);
          }, scanInterval);
        }, operationTime);
      }, 3000); // 给页面加载的时间
    });
  }
  
  // 完成扫描
  function finishScanning() {
    scanningInProgress = false;
    statusText.textContent = '扫描完成!';
    progressBar.style.width = '100%';
    currentTarget.textContent = '';
    
    // 5秒后隐藏状态面板
    setTimeout(() => {
      statusPanel.style.display = 'none';
    }, 5000);
  }
  
  // 模拟进度条更新
  function simulateProgress(duration) {
    let progress = 0;
    const interval = setInterval(() => {
      progress += 1;
      progressBar.style.width = `${progress}%`;
      
      if (progress >= 100) {
        clearInterval(interval);
        statusText.textContent = '检测完成!';
        
        // 5秒后隐藏状态面板
        setTimeout(() => {
          statusPanel.style.display = 'none';
        }, 5000);
      }
    }, duration / 100);
  }
  
  // 验证URL
  function isValidUrl(url) {
    try {
      const parsedUrl = new URL(url);
      return parsedUrl.protocol === 'http:' || parsedUrl.protocol === 'https:';
    } catch (e) {
      return false;
    }
  }
  
  // 获取选中的漏洞类型
  function getSelectedVulnerabilityTypes() {
    const select = document.getElementById('vulnerability-types');
    if (!select) {
      console.error('找不到漏洞类型选择元素');
      return {
        xss: true,
        sqli: true,
        csrf: true,
        ssrf: true,
        xxe: true,
        cors: true,
        jwt: true,
        redirect: true
      };
    }
    
    const result = {
      xss: false,
      sqli: false,
      csrf: false,
      ssrf: false,
      xxe: false,
      cors: false,
      jwt: false,
      redirect: false
    };
    
    // 遍历所有选中的选项
    for (let i = 0; i < select.options.length; i++) {
      const option = select.options[i];
      if (option.selected) {
        if (option.value === 'xss') result.xss = true;
        else if (option.value === 'sqli') result.sqli = true;
        else if (option.value === 'csrf') result.csrf = true;
        else if (option.value === 'ssrf') result.ssrf = true;
        else if (option.value === 'xxe') result.xxe = true;
        else if (option.value === 'cors') result.cors = true;
        else if (option.value === 'jwt') result.jwt = true;
        else if (option.value === 'open-redirect') result.redirect = true;
      }
    }
    
    return result;
  }
  
  // 更新滑块值显示
  function updateSliderValue(slider, valueElement) {
    if (!slider || !valueElement) {
      console.warn('滑块或值元素不存在');
      return;
    }
    
    const value = slider.value;
    let textValue = '中等';
    
    switch (parseInt(value)) {
      case 1:
        textValue = '非常慢';
        break;
      case 2:
        textValue = '慢';
        break;
      case 3:
        textValue = '中等';
        break;
      case 4:
        textValue = '快';
        break;
      case 5:
        textValue = '非常快';
        break;
    }
    
    valueElement.textContent = textValue;
    
    // 更新设置
    if (slider.id === 'mouse-speed') {
      currentSettings.humanBehavior.mouseSpeed = parseInt(value);
    } else if (slider.id === 'typing-speed') {
      currentSettings.humanBehavior.typingSpeed = parseInt(value);
    } else if (slider.id === 'operation-interval') {
      currentSettings.humanBehavior.operationInterval = parseInt(value);
    }
  }
  
  // 加载设置
  function loadSettings() {
    chrome.storage.local.get('hwvaSettings', (result) => {
      if (result.hwvaSettings) {
        currentSettings = result.hwvaSettings;
        applySettingsToUI();
      } else {
        // 如果没有保存的设置，使用默认设置
        currentSettings = JSON.parse(JSON.stringify(defaultSettings));
        saveSettings();
      }
    });
  }
  
  // 保存设置
  function saveSettings() {
    // 从UI更新设置
    updateSettingsFromUI();
    
    // 保存到存储
    chrome.storage.local.set({ 'hwvaSettings': currentSettings });
  }
  
  // 重置设置
  function resetSettings() {
    currentSettings = JSON.parse(JSON.stringify(defaultSettings));
    applySettingsToUI();
    saveSettings();
  }
  
  // 从UI更新设置
  function updateSettingsFromUI() {
    // 指纹混淆设置
    currentSettings.fingerprint.enabled = safeGetElement('enable-fingerprint').checked;
    currentSettings.fingerprint.updateInterval = parseInt(safeGetElement('fingerprint-interval').value) || 30;
    currentSettings.fingerprint.userAgent = safeGetElement('fp-useragent').checked;
    currentSettings.fingerprint.canvas = safeGetElement('fp-canvas').checked;
    currentSettings.fingerprint.webrtc = safeGetElement('fp-webrtc').checked;
    currentSettings.fingerprint.fonts = safeGetElement('fp-fonts').checked;
    currentSettings.fingerprint.hardware = safeGetElement('fp-hardware').checked;
    currentSettings.fingerprint.screen = safeGetElement('fp-screen').checked;
    
    // 人类行为设置
    currentSettings.humanBehavior.mouseSpeed = parseInt(safeGetElement('mouse-speed').value) || 3;
    currentSettings.humanBehavior.typingSpeed = parseInt(safeGetElement('typing-speed').value) || 3;
    currentSettings.humanBehavior.operationInterval = parseInt(safeGetElement('operation-interval').value) || 3;
    currentSettings.humanBehavior.eyeTracking = safeGetElement('enable-eye-tracking').checked;
    currentSettings.humanBehavior.typos = safeGetElement('enable-typos').checked;
    
    // 合规性设置
    currentSettings.compliance.respectRobots = safeGetElement('respect-robots').checked;
    currentSettings.compliance.checkLegal = safeGetElement('check-legal').checked;
    currentSettings.compliance.limitRequests = safeGetElement('limit-requests').checked;
    currentSettings.compliance.requestInterval = parseInt(safeGetElement('request-interval').value) || 500;
    
    // 漏洞类型设置
    currentSettings.vulnerabilityTypes = getSelectedVulnerabilityTypes();
    
    // 批处理设置
    currentSettings.batchProcessing.maxParallel = parseInt(safeGetElement('max-parallel').value) || 1;
    currentSettings.batchProcessing.timeout = parseInt(safeGetElement('timeout').value) || 30;
    currentSettings.batchProcessing.autoCloseTabs = safeGetElement('auto-close-tabs').checked;
  }
  
  // 将设置应用到UI
  function applySettingsToUI() {
    // 指纹混淆设置
    safeGetElement('enable-fingerprint').checked = currentSettings.fingerprint.enabled;
    safeGetElement('fingerprint-interval').value = currentSettings.fingerprint.updateInterval;
    safeGetElement('fp-useragent').checked = currentSettings.fingerprint.userAgent;
    safeGetElement('fp-canvas').checked = currentSettings.fingerprint.canvas;
    safeGetElement('fp-webrtc').checked = currentSettings.fingerprint.webrtc;
    safeGetElement('fp-fonts').checked = currentSettings.fingerprint.fonts;
    safeGetElement('fp-hardware').checked = currentSettings.fingerprint.hardware;
    safeGetElement('fp-screen').checked = currentSettings.fingerprint.screen;
    
    // 人类行为设置
    safeGetElement('mouse-speed').value = currentSettings.humanBehavior.mouseSpeed;
    safeGetElement('typing-speed').value = currentSettings.humanBehavior.typingSpeed;
    safeGetElement('operation-interval').value = currentSettings.humanBehavior.operationInterval;
    safeGetElement('enable-eye-tracking').checked = currentSettings.humanBehavior.eyeTracking;
    safeGetElement('enable-typos').checked = currentSettings.humanBehavior.typos;
    
    // 更新滑块显示值
    updateSliderValue(mouseSpeedSlider, mouseSpeedValue);
    updateSliderValue(typingSpeedSlider, typingSpeedValue);
    updateSliderValue(operationIntervalSlider, operationIntervalValue);
    
    // 合规性设置
    safeGetElement('respect-robots').checked = currentSettings.compliance.respectRobots;
    safeGetElement('check-legal').checked = currentSettings.compliance.checkLegal;
    safeGetElement('limit-requests').checked = currentSettings.compliance.limitRequests;
    safeGetElement('request-interval').value = currentSettings.compliance.requestInterval;
    
    // 漏洞类型设置
    const vulnerabilityTypes = document.getElementById('vulnerability-types');
    if (vulnerabilityTypes) {
      for (let i = 0; i < vulnerabilityTypes.options.length; i++) {
        const option = vulnerabilityTypes.options[i];
        let selected = false;
        
        if (option.value === 'xss') selected = currentSettings.vulnerabilityTypes.xss;
        else if (option.value === 'sqli') selected = currentSettings.vulnerabilityTypes.sqli;
        else if (option.value === 'csrf') selected = currentSettings.vulnerabilityTypes.csrf;
        else if (option.value === 'ssrf') selected = currentSettings.vulnerabilityTypes.ssrf;
        else if (option.value === 'xxe') selected = currentSettings.vulnerabilityTypes.xxe;
        else if (option.value === 'cors') selected = currentSettings.vulnerabilityTypes.cors;
        else if (option.value === 'jwt') selected = currentSettings.vulnerabilityTypes.jwt;
        else if (option.value === 'open-redirect') selected = currentSettings.vulnerabilityTypes.redirect;
        
        option.selected = selected;
      }
    }
    
    // 批处理设置
    safeGetElement('max-parallel').value = currentSettings.batchProcessing.maxParallel;
    safeGetElement('timeout').value = currentSettings.batchProcessing.timeout;
    safeGetElement('auto-close-tabs').checked = currentSettings.batchProcessing.autoCloseTabs;
  }
  
  // 加载最近检测结果
  function loadRecentResults() {
    const recentResultsContainer = document.getElementById('recent-results');
    
    // 检查元素是否存在
    if (!recentResultsContainer) {
      console.warn('找不到recent-results元素，无法加载最近检测结果');
      return;
    }
    
    chrome.storage.local.get('vulnerabilities', (result) => {
      if (result.vulnerabilities && result.vulnerabilities.length > 0) {
        const vulnerabilities = result.vulnerabilities;
        recentResultsContainer.innerHTML = '';
        
        // 按类型统计漏洞
        const vulnByType = {};
        vulnerabilities.forEach(vuln => {
          if (!vulnByType[vuln.type]) {
            vulnByType[vuln.type] = 0;
          }
          vulnByType[vuln.type]++;
        });
        
        // 创建统计表格
        const table = document.createElement('table');
        table.style.width = '100%';
        table.style.borderCollapse = 'collapse';
        table.style.marginBottom = '15px';
        
        // 添加表头
        const thead = document.createElement('thead');
        const headerRow = document.createElement('tr');
        const typeHeader = document.createElement('th');
        typeHeader.textContent = '漏洞类型';
        typeHeader.style.textAlign = 'left';
        typeHeader.style.padding = '8px';
        typeHeader.style.borderBottom = '1px solid #ddd';
        
        const countHeader = document.createElement('th');
        countHeader.textContent = '数量';
        countHeader.style.textAlign = 'right';
        countHeader.style.padding = '8px';
        countHeader.style.borderBottom = '1px solid #ddd';
        
        headerRow.appendChild(typeHeader);
        headerRow.appendChild(countHeader);
        thead.appendChild(headerRow);
        table.appendChild(thead);
        
        // 添加表体
        const tbody = document.createElement('tbody');
        for (const [type, count] of Object.entries(vulnByType)) {
          const row = document.createElement('tr');
          
          const typeCell = document.createElement('td');
          typeCell.textContent = type;
          typeCell.style.padding = '8px';
          typeCell.style.borderBottom = '1px solid #eee';
          
          const countCell = document.createElement('td');
          countCell.textContent = count;
          countCell.style.textAlign = 'right';
          countCell.style.padding = '8px';
          countCell.style.borderBottom = '1px solid #eee';
          countCell.style.fontWeight = 'bold';
          
          row.appendChild(typeCell);
          row.appendChild(countCell);
          tbody.appendChild(row);
        }
        
        // 添加总计行
        const totalRow = document.createElement('tr');
        
        const totalLabelCell = document.createElement('td');
        totalLabelCell.textContent = '总计';
        totalLabelCell.style.padding = '8px';
        totalLabelCell.style.fontWeight = 'bold';
        
        const totalCountCell = document.createElement('td');
        totalCountCell.textContent = vulnerabilities.length;
        totalCountCell.style.textAlign = 'right';
        totalCountCell.style.padding = '8px';
        totalCountCell.style.fontWeight = 'bold';
        
        totalRow.appendChild(totalLabelCell);
        totalRow.appendChild(totalCountCell);
        tbody.appendChild(totalRow);
        
        table.appendChild(tbody);
        recentResultsContainer.appendChild(table);
        
        // 添加最近发现的漏洞
        const recentTitle = document.createElement('h3');
        recentTitle.textContent = '最近发现的漏洞';
        recentTitle.style.fontSize = '14px';
        recentTitle.style.marginBottom = '10px';
        recentResultsContainer.appendChild(recentTitle);
        
        // 显示最近5个漏洞
        const recentVulns = vulnerabilities.slice(-5).reverse();
        recentVulns.forEach(vuln => {
          const vulnDiv = document.createElement('div');
          vulnDiv.style.padding = '8px';
          vulnDiv.style.marginBottom = '8px';
          vulnDiv.style.backgroundColor = '#f5f5f5';
          vulnDiv.style.borderRadius = '4px';
          vulnDiv.style.fontSize = '12px';
          
          const vulnType = document.createElement('div');
          vulnType.textContent = vuln.type;
          vulnType.style.fontWeight = 'bold';
          vulnType.style.marginBottom = '5px';
          
          const vulnUrl = document.createElement('div');
          vulnUrl.textContent = vuln.details.location;
          vulnUrl.style.color = '#777';
          vulnUrl.style.whiteSpace = 'nowrap';
          vulnUrl.style.overflow = 'hidden';
          vulnUrl.style.textOverflow = 'ellipsis';
          
          vulnDiv.appendChild(vulnType);
          vulnDiv.appendChild(vulnUrl);
          recentResultsContainer.appendChild(vulnDiv);
        });
      } else {
        recentResultsContainer.innerHTML = '<div class="no-results">暂无检测结果</div>';
      }
    });
  }
  
  // 下载CSV文件
  function downloadCSV(csvContent) {
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.setAttribute('href', url);
    link.setAttribute('download', `漏洞报告_${new Date().toISOString().slice(0, 10)}.csv`);
    link.style.visibility = 'hidden';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  }
  
  // 显示通知
  function showNotification(message) {
    const notification = document.createElement('div');
    notification.textContent = message;
    notification.style.position = 'fixed';
    notification.style.bottom = '20px';
    notification.style.left = '50%';
    notification.style.transform = 'translateX(-50%)';
    notification.style.backgroundColor = '#4CAF50';
    notification.style.color = 'white';
    notification.style.padding = '10px 20px';
    notification.style.borderRadius = '4px';
    notification.style.zIndex = '1000';
    notification.style.boxShadow = '0 2px 10px rgba(0,0,0,0.2)';
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
      notification.style.opacity = '0';
      notification.style.transition = 'opacity 0.5s';
      setTimeout(() => {
        document.body.removeChild(notification);
      }, 500);
    }, 2000);
  }
  
  // 初始化子标签页
  function initSubTabs() {
    // 默认选中第一个子标签
    if (subTabs.length > 0) {
      subTabs[0].classList.add('active');
    }
    
    // 确保只有第一个子标签内容显示
    subTabContents.forEach((content, index) => {
      if (index === 0) {
        content.style.display = 'block';
      } else {
        content.style.display = 'none';
      }
    });
  }
  
  // 漏洞检测设置元素
  const detectionModeSelect = safeGetElement('detection-mode');
  const detectionDepthSlider = safeGetElement('detection-depth');
  const detectXssCheckbox = safeGetElement('detect-xss');
  const detectSqliCheckbox = safeGetElement('detect-sqli');
  const detectCsrfCheckbox = safeGetElement('detect-csrf');
  const detectSsrfCheckbox = safeGetElement('detect-ssrf');
  const detectInfoLeakageCheckbox = safeGetElement('detect-info-leakage');
  const detectHeadersCheckbox = safeGetElement('detect-headers');
  const resetVulnerabilitySettingsBtn = safeGetElement('reset-vulnerability-settings');
  
  // 默认漏洞检测设置
  const defaultVulnerabilitySettings = {
    detectionMode: 'active',
    detectionDepth: 3,
    vulnerabilityTypes: {
      xss: true,
      sqli: true,
      csrf: true,
      ssrf: true,
      infoLeakage: true,
      headers: true
    }
  };
  
  // 当前漏洞检测设置
  let currentVulnerabilitySettings = JSON.parse(JSON.stringify(defaultVulnerabilitySettings));
  
  // 更新默认设置以包含漏洞检测设置
  defaultSettings.vulnerabilityDetection = defaultVulnerabilitySettings;
  currentSettings.vulnerabilityDetection = currentVulnerabilitySettings;
  
  // 加载漏洞检测设置
  function loadVulnerabilitySettings() {
    try {
      // 从chrome.storage加载设置
      chrome.storage.local.get('vulnerabilitySettings', (result) => {
        if (result.vulnerabilitySettings) {
          currentVulnerabilitySettings = result.vulnerabilitySettings;
          
          // 更新UI
          updateVulnerabilitySettingsUI();
        } else {
          // 如果没有保存的设置，使用默认设置
          currentVulnerabilitySettings = JSON.parse(JSON.stringify(defaultVulnerabilitySettings));
          saveVulnerabilitySettings();
        }
      });
    } catch (error) {
      console.error('加载漏洞检测设置时出错:', error);
      
      // 出错时使用默认设置
      currentVulnerabilitySettings = JSON.parse(JSON.stringify(defaultVulnerabilitySettings));
      updateVulnerabilitySettingsUI();
    }
  }
  
  // 保存漏洞检测设置
  function saveVulnerabilitySettings() {
    try {
      chrome.storage.local.set({ 'vulnerabilitySettings': currentVulnerabilitySettings }, () => {
        if (chrome.runtime.lastError) {
          console.error('保存漏洞检测设置时出错:', chrome.runtime.lastError);
        } else {
          console.log('漏洞检测设置已保存');
          
          // 更新全局设置
          currentSettings.vulnerabilityDetection = currentVulnerabilitySettings;
          
          // 通知后台脚本设置已更新
          chrome.runtime.sendMessage({
            action: 'updateVulnerabilitySettings',
            settings: currentVulnerabilitySettings
          });
        }
      });
    } catch (error) {
      console.error('保存漏洞检测设置过程中出错:', error);
    }
  }
  
  // 更新漏洞检测设置UI
  function updateVulnerabilitySettingsUI() {
    // 更新检测模式
    detectionModeSelect.value = currentVulnerabilitySettings.detectionMode;
    
    // 更新检测深度
    detectionDepthSlider.value = currentVulnerabilitySettings.detectionDepth;
    
    // 更新漏洞类型复选框
    detectXssCheckbox.checked = currentVulnerabilitySettings.vulnerabilityTypes.xss;
    detectSqliCheckbox.checked = currentVulnerabilitySettings.vulnerabilityTypes.sqli;
    detectCsrfCheckbox.checked = currentVulnerabilitySettings.vulnerabilityTypes.csrf;
    detectSsrfCheckbox.checked = currentVulnerabilitySettings.vulnerabilityTypes.ssrf;
    detectInfoLeakageCheckbox.checked = currentVulnerabilitySettings.vulnerabilityTypes.infoLeakage;
    detectHeadersCheckbox.checked = currentVulnerabilitySettings.vulnerabilityTypes.headers;
  }
  
  // 重置漏洞检测设置为默认值
  function resetVulnerabilitySettings() {
    currentVulnerabilitySettings = JSON.parse(JSON.stringify(defaultVulnerabilitySettings));
    updateVulnerabilitySettingsUI();
    saveVulnerabilitySettings();
  }
  
  // 从UI更新漏洞检测设置
  function updateVulnerabilitySettingsFromUI() {
    currentVulnerabilitySettings.detectionMode = detectionModeSelect.value;
    currentVulnerabilitySettings.detectionDepth = parseInt(detectionDepthSlider.value);
    
    currentVulnerabilitySettings.vulnerabilityTypes = {
      xss: detectXssCheckbox.checked,
      sqli: detectSqliCheckbox.checked,
      csrf: detectCsrfCheckbox.checked,
      ssrf: detectSsrfCheckbox.checked,
      infoLeakage: detectInfoLeakageCheckbox.checked,
      headers: detectHeadersCheckbox.checked
    };
    
    saveVulnerabilitySettings();
  }
  
  // 初始化漏洞检测设置
  loadVulnerabilitySettings();
  
  // 添加事件监听器
  safeAddEventListener(detectionModeSelect, 'change', updateVulnerabilitySettingsFromUI);
  safeAddEventListener(detectionDepthSlider, 'change', updateVulnerabilitySettingsFromUI);
  safeAddEventListener(detectXssCheckbox, 'change', updateVulnerabilitySettingsFromUI);
  safeAddEventListener(detectSqliCheckbox, 'change', updateVulnerabilitySettingsFromUI);
  safeAddEventListener(detectCsrfCheckbox, 'change', updateVulnerabilitySettingsFromUI);
  safeAddEventListener(detectSsrfCheckbox, 'change', updateVulnerabilitySettingsFromUI);
  safeAddEventListener(detectInfoLeakageCheckbox, 'change', updateVulnerabilitySettingsFromUI);
  safeAddEventListener(detectHeadersCheckbox, 'change', updateVulnerabilitySettingsFromUI);
  safeAddEventListener(resetVulnerabilitySettingsBtn, 'click', resetVulnerabilitySettings);
  
  // 开始扫描前设置漏洞检测选项
  function prepareVulnerabilityDetection() {
    try {
      // 发送漏洞检测设置到后台脚本
      chrome.runtime.sendMessage({
        action: 'prepareVulnerabilityDetection',
        settings: currentVulnerabilitySettings
      }, (response) => {
        if (chrome.runtime.lastError) {
          console.error('发送漏洞检测设置时出错:', chrome.runtime.lastError);
        } else if (response && response.success) {
          console.log('漏洞检测设置已应用');
        }
      });
    } catch (error) {
      console.error('准备漏洞检测设置时出错:', error);
    }
  }
}); 