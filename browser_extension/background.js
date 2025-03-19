/**
 * 浏览器扩展后台脚本
 * 用于处理浏览器扩展的后台任务
 */

// 全局变量声明
let humanoidSimulator;

class HumanoidSimulator {
  constructor() {
    this.operationIntervals = [1200, 2500, 3000];
    this.mouseTrajectory = [];
    this.detectedVulnerabilities = [];
    this.currentTargets = {};
    this.scanningInProgress = false;
    
    // 新增TCP/IP指纹混淆配置
    this.tcpFingerprint = {
      enabled: true,
      rotationInterval: 20 * 60 * 1000, // 20分钟
      lastRotationTime: Date.now(),
      currentProfile: null
    };
    
    // 初始化TCP/IP指纹配置文件
    this.initTCPProfiles();

    // 漏洞信息存储
    this.vulnerabilities = {
      byDomain: {},
      byType: {
        'XSS': [],
        'SQL注入': [],
        'CSRF': [],
        'SSRF漏洞': [],
        '敏感信息泄露': [],
        '不安全的HTTP头部': [],
        '不安全的CORS配置': [],
        '开放重定向': [],
        '其他': []
      },
      timestamp: Date.now(),
      statistics: {
        totalCount: 0,
        domains: new Set(),
        typeCounts: {}
      }
    };

    // 漏洞检测设置
    this.vulnerabilityDetectionSettings = {
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
    
    // 加载之前保存的漏洞检测设置
    this.loadVulnerabilityDetectionSettings();
  }

  // 初始化TCP/IP指纹配置文件
  initTCPProfiles() {
    this.tcpProfiles = [
      {
        name: "Chrome Windows 10",
        windowSize: 64240,
        ttl: 128,
        mss: 1460,
        cipherSuites: [
          'TLS_AES_128_GCM_SHA256',
          'TLS_AES_256_GCM_SHA384',
          'TLS_CHACHA20_POLY1305_SHA256'
        ],
        supportedGroups: ['x25519', 'secp256r1', 'secp384r1'],
        signatureAlgorithms: ['ecdsa_secp256r1_sha256', 'rsa_pss_rsae_sha256']
      },
      {
        name: "Firefox Windows 10",
        windowSize: 65535,
        ttl: 128,
        mss: 1460,
        cipherSuites: [
          'TLS_AES_128_GCM_SHA256',
          'TLS_CHACHA20_POLY1305_SHA256',
          'TLS_AES_256_GCM_SHA384'
        ],
        supportedGroups: ['x25519', 'secp256r1'],
        signatureAlgorithms: ['ecdsa_secp256r1_sha256', 'rsa_pss_rsae_sha256']
      },
      {
        name: "Safari macOS",
        windowSize: 65535,
        ttl: 64,
        mss: 1460,
        cipherSuites: [
          'TLS_AES_128_GCM_SHA256',
          'TLS_AES_256_GCM_SHA384',
          'TLS_CHACHA20_POLY1305_SHA256'
        ],
        supportedGroups: ['x25519', 'secp256r1'],
        signatureAlgorithms: ['ecdsa_secp256r1_sha256', 'rsa_pss_rsae_sha256']
      },
      {
        name: "Edge Windows 10",
        windowSize: 64240,
        ttl: 128,
        mss: 1460,
        cipherSuites: [
          'TLS_AES_128_GCM_SHA256',
          'TLS_AES_256_GCM_SHA384',
          'TLS_CHACHA20_POLY1305_SHA256'
        ],
        supportedGroups: ['x25519', 'secp256r1', 'secp384r1'],
        signatureAlgorithms: ['ecdsa_secp256r1_sha256', 'rsa_pss_rsae_sha256']
      }
    ];
    
    // 随机选择一个配置文件
    this.rotateTCPProfile();
  }
  
  // 轮换TCP/IP指纹配置
  rotateTCPProfile() {
    const randomIndex = Math.floor(Math.random() * this.tcpProfiles.length);
    this.tcpFingerprint.currentProfile = this.tcpProfiles[randomIndex];
    this.tcpFingerprint.lastRotationTime = Date.now();
    
    console.log(`[TCP指纹] 已切换到配置: ${this.tcpFingerprint.currentProfile.name}`);
    
    // 更新规则
    this.updateTCPRules();
  }
  
  // 更新TCP规则
  updateTCPRules() {
    if (!this.tcpFingerprint.enabled || !this.tcpFingerprint.currentProfile) {
      return;
    }
    
    // 这里我们只能通过修改HTTP头部来模拟一些TCP/IP特征
    // 真正的TCP/IP栈修改需要更底层的访问权限
    
    // 更新规则集
    chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: [1001, 1002, 1003],
      addRules: [
        {
          id: 1001,
          priority: 100,
          action: {
            type: "modifyHeaders",
            requestHeaders: [
              {
                header: "Connection",
                operation: "set",
                value: "keep-alive"
              }
            ]
          },
          condition: {
            urlFilter: "*",
            resourceTypes: ["main_frame", "sub_frame", "xmlhttprequest"]
          }
        },
        {
          id: 1002,
          priority: 100,
          action: {
            type: "modifyHeaders",
            requestHeaders: [
              {
                header: "Accept-Encoding",
                operation: "set",
                value: "gzip, deflate, br"
              }
            ]
          },
          condition: {
            urlFilter: "*",
            resourceTypes: ["main_frame", "sub_frame", "xmlhttprequest"]
          }
        },
        {
          id: 1003,
          priority: 100,
          action: {
            type: "modifyHeaders",
            requestHeaders: [
              {
                header: "Sec-CH-UA-Platform",
                operation: "set",
                value: this.tcpFingerprint.currentProfile.name.includes("Windows") ? "\"Windows\"" : "\"macOS\""
              }
            ]
          },
          condition: {
            urlFilter: "*",
            resourceTypes: ["main_frame", "sub_frame"]
          }
        }
      ]
    });
  }
  
  // 检查是否需要轮换TCP/IP指纹
  checkTCPProfileRotation() {
    if (!this.tcpFingerprint.enabled) {
      return;
    }
    
    const elapsed = Date.now() - this.tcpFingerprint.lastRotationTime;
    if (elapsed >= this.tcpFingerprint.rotationInterval) {
      this.rotateTCPProfile();
    }
  }

  // 生成随机操作间隔
  getRandomInterval() {
    return this.operationIntervals[Math.floor(Math.random() * this.operationIntervals.length)];
  }

  // 模拟视觉轨迹
  generateEyeMovement(element) {
    const rect = element.getBoundingClientRect();
    const baseX = rect.left + rect.width/2;
    const baseY = rect.top + rect.height/2;
    
    // 生成带随机偏移的轨迹点
    for(let i=0; i<5; i++) {
      this.mouseTrajectory.push({
        x: baseX + Math.random()*10 -5,
        y: baseY + Math.random()*10 -5,
        t: Date.now() + i*100
      });
    }
  }
  
  // 添加漏洞记录 - 增强错误处理
  addVulnerability(data) {
    try {
      if (!data) {
        console.error('添加漏洞: 数据为空');
        return null;
      }

      const vulnerability = data.vulnerability;
      const tabId = data.tabId || this.currentTabId;
      
      if (!vulnerability) {
        console.error('添加漏洞: vulnerability对象为空');
        return null;
      }

      if (!vulnerability.type) {
        console.error('添加漏洞: 漏洞类型为空');
        return null;
      }
      
      // 确保vulnerabilities对象已初始化
      if (!this.vulnerabilities) {
        this.initEmptyVulnerabilityData();
      }

      // 确保统计信息已初始化
      if (!this.vulnerabilities.statistics) {
        this.vulnerabilities.statistics = {
          totalCount: 0,
          domains: new Set(),
          typeCounts: {}
        };
      }
      
      // 获取漏洞的域名
      let domain = '';
      if (vulnerability.details && vulnerability.details.location) {
        try {
          const url = new URL(vulnerability.details.location);
          domain = url.hostname;
        } catch (e) {
          console.error('解析漏洞URL时出错', e);
          domain = 'unknown-domain';
        }
      } else {
        domain = 'unknown-domain';
      }
      
      // 如果域名不存在，则初始化
      if (!this.vulnerabilities.byDomain) {
        this.vulnerabilities.byDomain = {};
      }
      
      if (!this.vulnerabilities.byDomain[domain]) {
        this.vulnerabilities.byDomain[domain] = [];
      }
      
      // 确保漏洞类型存在
      if (!this.vulnerabilities.byType) {
        this.vulnerabilities.byType = {
          'XSS': [],
          'SQL注入': [],
          'CSRF': [],
          'SSRF漏洞': [],
          '敏感信息泄露': [],
          '不安全的HTTP头部': [],
          '不安全的CORS配置': [],
          '开放重定向': [],
          '其他': []
        };
      }
      
      if (!this.vulnerabilities.byType[vulnerability.type]) {
        this.vulnerabilities.byType[vulnerability.type] = [];
      }
      
      // 为漏洞添加额外信息
      vulnerability.domain = domain;
      vulnerability.tabId = tabId;
      
      // 添加时间戳（如果没有）
      if (!vulnerability.timestamp) {
        vulnerability.timestamp = Date.now();
      }
      
      // 确保details对象存在
      if (!vulnerability.details) {
        vulnerability.details = {};
      }
      
      // 添加严重程度（如果没有）
      if (!vulnerability.details.severity) {
        vulnerability.details.severity = this.determineSeverity(vulnerability.type);
      }
      
      // 添加唯一ID（如果没有）
      if (!vulnerability.id) {
        vulnerability.id = `vuln_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
      }
      
      // 检查是否重复
      const isDuplicate = this.checkDuplicateVulnerability(vulnerability);
      if (isDuplicate) {
        console.log(`[漏洞检测] 忽略重复漏洞: ${vulnerability.type} at ${domain}`);
        return null;
      }
      
      // 添加到按域名索引的列表
      this.vulnerabilities.byDomain[domain].push(vulnerability);
      
      // 添加到按类型索引的列表
      this.vulnerabilities.byType[vulnerability.type].push(vulnerability);
      
      // 更新统计信息
      if (!this.vulnerabilities.statistics) {
        this.vulnerabilities.statistics = {
          totalCount: 0,
          domains: new Set(),
          typeCounts: {}
        };
      }
      
      this.vulnerabilities.statistics.totalCount++;
      
      // 确保domains是Set对象
      if (!this.vulnerabilities.statistics.domains) {
        this.vulnerabilities.statistics.domains = new Set();
      }
      
      // 确保是可用的Set对象
      if (typeof this.vulnerabilities.statistics.domains.add !== 'function') {
        this.vulnerabilities.statistics.domains = new Set();
      }
      
      this.vulnerabilities.statistics.domains.add(domain);
      
      // 确保typeCounts对象存在
      if (!this.vulnerabilities.statistics.typeCounts) {
        this.vulnerabilities.statistics.typeCounts = {};
      }
      
      if (!this.vulnerabilities.statistics.typeCounts[vulnerability.type]) {
        this.vulnerabilities.statistics.typeCounts[vulnerability.type] = 0;
      }
      this.vulnerabilities.statistics.typeCounts[vulnerability.type]++;
      
      // 更新时间戳
      this.vulnerabilities.timestamp = Date.now();
      
      // 存储漏洞数据
      this.saveVulnerabilities();
      
      // 发送通知
      try {
        this.notifyVulnerability(vulnerability);
      } catch (notifyError) {
        console.error('发送漏洞通知时出错:', notifyError);
      }
      
      console.log(`[漏洞检测] 添加新漏洞: ${vulnerability.type} at ${domain}`);
      
      // 将漏洞信息发送到报告页面
      if (this.reportTabId) {
        try {
          chrome.tabs.sendMessage(this.reportTabId, {
            action: 'updateVulnerabilities',
            vulnerabilities: this.vulnerabilities
          }).catch(err => {
            console.log(`向报告页面发送更新消息失败: ${err.message || '未知错误'}`);
          });
        } catch (e) {
          console.error('向报告页面发送漏洞信息时出错', e);
        }
      }
      
      return vulnerability;
    } catch (error) {
      console.error('添加漏洞过程中出错:', error ? (error.message || error.toString()) : '未知错误');
      return null;
    }
  }

  // 检查是否为重复漏洞
  checkDuplicateVulnerability(newVulnerability) {
    const domain = newVulnerability.domain;
    const existingVulns = this.vulnerabilities.byDomain[domain] || [];
    
    return existingVulns.some(existing => {
      // 检查类型是否相同
      if (existing.type !== newVulnerability.type) {
        return false;
      }
      
      // 检查位置是否相同
      if (existing.details.location !== newVulnerability.details.location) {
        return false;
      }
      
      // 检查证据是否类似
      if (existing.details.evidence && newVulnerability.details.evidence) {
        return this.similarityScore(existing.details.evidence, newVulnerability.details.evidence) > 0.8;
      }
      
      return false;
    });
  }
  
  // 计算两个字符串的相似度（简单实现）
  similarityScore(str1, str2) {
    // 如果字符串为空或null，返回0
    if (!str1 || !str2) return 0;
    
    // 将两个字符串转为小写，并截取前100个字符（避免过长）
    const s1 = str1.toLowerCase().substring(0, 100);
    const s2 = str2.toLowerCase().substring(0, 100);
    
    // 如果字符串完全相同，返回1
    if (s1 === s2) return 1;
    
    // 计算Levenshtein距离的简化版本
    let longer = s1;
    let shorter = s2;
    
    if (s1.length < s2.length) {
      longer = s2;
      shorter = s1;
    }
    
    // 共同字符数量
    let commonChars = 0;
    for (let i = 0; i < shorter.length; i++) {
      if (longer.includes(shorter[i])) {
        commonChars++;
      }
    }
    
    return commonChars / longer.length;
  }
  
  // 确定漏洞的严重程度
  determineSeverity(type) {
    const criticalVulnerabilities = ['SQL注入', 'SSRF漏洞', 'XXE漏洞', '远程代码执行'];
    const highVulnerabilities = ['XSS', '不安全的CORS配置', 'CSRF', '潜在的CSRF漏洞'];
    const mediumVulnerabilities = ['敏感信息泄露', '不安全的HTTP头部', '开放重定向'];
    
    if (criticalVulnerabilities.includes(type)) return 'Critical';
    if (highVulnerabilities.includes(type)) return 'High';
    if (mediumVulnerabilities.includes(type)) return 'Medium';
    
    return 'Low';
  }
  
  // 发送漏洞通知
  notifyVulnerability(vulnerability) {
    const type = vulnerability.type;
    const domain = vulnerability.domain;
    const severity = vulnerability.details.severity || 'Medium';
    
    // 根据严重程度选择图标
    let iconPath = "icons/icon48.png";
    if (severity === 'Critical') {
      iconPath = "icons/critical.png";
    } else if (severity === 'High') {
      iconPath = "icons/high.png";
    } else if (severity === 'Medium') {
      iconPath = "icons/medium.png";
    } else if (severity === 'Low') {
      iconPath = "icons/low.png";
    }
    
    // 通知标题
    const title = `检测到 ${severity} 级别漏洞`;
    
    // 通知内容
    let message = `域名 ${domain} 存在 ${type} 漏洞`;
    if (vulnerability.details.description) {
      message += `\n${vulnerability.details.description}`;
    }
    
    // 创建通知
    const notificationOptions = {
      type: 'basic',
      iconUrl: iconPath,
      title: title,
      message: message,
      priority: 2
    };
    
    // 显示通知
    const notificationId = `vuln_${Date.now()}`;
    chrome.notifications.create(notificationId, notificationOptions);
    
    // 添加通知点击事件处理
    chrome.notifications.onClicked.addListener((id) => {
      if (id === notificationId) {
        // 打开报告页面
        this.openReportPage();
      }
    });
  }
  
  // 存储漏洞数据
  saveVulnerabilities() {
    try {
      // 将Set转换为数组，以便正确存储
      const dataToSave = JSON.parse(JSON.stringify(this.vulnerabilities));
      dataToSave.statistics.domains = Array.from(this.vulnerabilities.statistics.domains);
      
      chrome.storage.local.set({ 'vulnerabilities': dataToSave }, () => {
        if (chrome.runtime.lastError) {
          console.error('存储漏洞数据时出错:', chrome.runtime.lastError);
        } else {
          console.log('漏洞数据已保存');
        }
      });
    } catch (error) {
      console.error('准备漏洞数据以进行存储时出错:', error);
    }
  }
  
  // 加载漏洞数据
  loadVulnerabilities() {
    return new Promise((resolve) => {
      try {
        chrome.storage.local.get('vulnerabilities', (result) => {
          try {
            if (chrome.runtime.lastError) {
              console.log('加载漏洞数据时出错:', chrome.runtime.lastError.message || '未知错误');
              this.initEmptyVulnerabilityData();
              resolve(false);
              return;
            }
            
            if (!result || !result.vulnerabilities) {
              console.log('未找到存储的漏洞数据');
              this.initEmptyVulnerabilityData();
              resolve(false);
              return;
            }
            
            // 安全地赋值
            this.initEmptyVulnerabilityData(); // 先初始化空数据结构
            
            // 然后尝试合并数据
            try {
              // 从存储的数据中复制简单属性
              if (result.vulnerabilities.timestamp) {
                this.vulnerabilities.timestamp = result.vulnerabilities.timestamp;
              }
              
              // 处理byDomain
              if (result.vulnerabilities.byDomain) {
                this.vulnerabilities.byDomain = result.vulnerabilities.byDomain;
              }
              
              // 处理byType
              if (result.vulnerabilities.byType) {
                this.vulnerabilities.byType = result.vulnerabilities.byType;
              }
              
              // 处理统计信息
              if (result.vulnerabilities.statistics) {
                // 复制计数
                if (result.vulnerabilities.statistics.totalCount !== undefined) {
                  this.vulnerabilities.statistics.totalCount = result.vulnerabilities.statistics.totalCount;
                }
                
                // 安全处理domains
                if (result.vulnerabilities.statistics.domains) {
                  if (Array.isArray(result.vulnerabilities.statistics.domains)) {
                    this.vulnerabilities.statistics.domains = new Set(result.vulnerabilities.statistics.domains);
                  } else if (result.vulnerabilities.statistics.domains instanceof Set) {
                    this.vulnerabilities.statistics.domains = new Set(
                      Array.from(result.vulnerabilities.statistics.domains)
                    );
                  }
                }
                
                // 复制类型计数
                if (result.vulnerabilities.statistics.typeCounts) {
                  this.vulnerabilities.statistics.typeCounts = { ...result.vulnerabilities.statistics.typeCounts };
                }
              }
              
              console.log('已加载漏洞数据');
              resolve(true);
            } catch (innerError) {
              console.log('处理漏洞数据时出错:', innerError ? (innerError.message || innerError.toString()) : '未知错误');
              this.initEmptyVulnerabilityData();
              resolve(false);
            }
          } catch (callbackError) {
            console.log('在callback中处理漏洞数据时出错:', 
              callbackError ? (callbackError.message || callbackError.toString()) : '未知错误');
            this.initEmptyVulnerabilityData();
            resolve(false);
          }
        });
      } catch (outerError) {
        console.log('调用chrome.storage.local.get时出错:', 
          outerError ? (outerError.message || outerError.toString()) : '未知错误');
        this.initEmptyVulnerabilityData();
        resolve(false);
      }
    });
  }
  
  // 初始化空的漏洞数据结构的辅助方法
  initEmptyVulnerabilityData() {
    this.vulnerabilities = {
      byDomain: {},
      byType: {
        'XSS': [],
        'SQL注入': [],
        'CSRF': [],
        'SSRF漏洞': [],
        '敏感信息泄露': [],
        '不安全的HTTP头部': [],
        '不安全的CORS配置': [],
        '开放重定向': [],
        '其他': []
      },
      timestamp: Date.now(),
      statistics: {
        totalCount: 0,
        domains: new Set(),
        typeCounts: {}
      }
    };
  }
  
  // 获取漏洞报告摘要
  getVulnerabilitySummary() {
    const summary = {
      totalVulnerabilities: this.vulnerabilities.statistics.totalCount,
      domains: Array.from(this.vulnerabilities.statistics.domains),
      typeCounts: this.vulnerabilities.statistics.typeCounts,
      severityCounts: {
        Critical: 0,
        High: 0,
        Medium: 0,
        Low: 0
      },
      mostVulnerableDomain: '',
      mostCommonVulnerability: '',
      timestamp: this.vulnerabilities.timestamp
    };
    
    // 计算每个严重程度的漏洞数量
    Object.values(this.vulnerabilities.byDomain).flat().forEach(vuln => {
      const severity = vuln.details.severity || 'Medium';
      summary.severityCounts[severity] = (summary.severityCounts[severity] || 0) + 1;
    });
    
    // 找出漏洞最多的域名
    let maxVulnCount = 0;
    Object.entries(this.vulnerabilities.byDomain).forEach(([domain, vulns]) => {
      if (vulns.length > maxVulnCount) {
        maxVulnCount = vulns.length;
        summary.mostVulnerableDomain = domain;
      }
    });
    
    // 找出最常见的漏洞类型
    let maxTypeCount = 0;
    Object.entries(this.vulnerabilities.statistics.typeCounts).forEach(([type, count]) => {
      if (count > maxTypeCount) {
        maxTypeCount = count;
        summary.mostCommonVulnerability = type;
      }
    });
    
    return summary;
  }
  
  // 打开报告页面
  openReportPage() {
    const reportUrl = chrome.runtime.getURL('report.html');
    
    // 检查是否已经有报告页面
    if (this.reportTabId) {
      // 尝试激活现有的报告标签页
      chrome.tabs.get(this.reportTabId, (tab) => {
        if (!chrome.runtime.lastError && tab) {
          chrome.tabs.update(this.reportTabId, { active: true });
        } else {
          // 如果标签页不存在，创建新的
          this.createReportTab(reportUrl);
        }
      });
    } else {
      // 创建新的报告标签页
      this.createReportTab(reportUrl);
    }
  }
  
  // 创建报告标签页
  createReportTab(reportUrl) {
    chrome.tabs.create({ url: reportUrl }, (tab) => {
      this.reportTabId = tab.id;
      
      // 监听标签页关闭
      chrome.tabs.onRemoved.addListener((tabId, removeInfo) => {
        if (tabId === this.reportTabId) {
          this.reportTabId = null;
        }
      });
    });
  }

  // 加载漏洞检测设置
  loadVulnerabilityDetectionSettings() {
    chrome.storage.local.get('vulnerabilitySettings', (result) => {
      if (chrome.runtime.lastError) {
        console.error('加载漏洞检测设置时出错:', chrome.runtime.lastError);
        return;
      }
      
      if (result.vulnerabilitySettings) {
        this.vulnerabilityDetectionSettings = result.vulnerabilitySettings;
        console.log('已加载漏洞检测设置:', this.vulnerabilityDetectionSettings);
      } else {
        console.log('使用默认漏洞检测设置');
      }
    });
  }
  
  // 向内容脚本发送漏洞检测设置
  sendVulnerabilityDetectionSettings(tabId) {
    try {
      chrome.tabs.sendMessage(tabId, {
        action: 'prepareVulnerabilityDetection',
        settings: this.vulnerabilityDetectionSettings
      }).catch(err => console.error(`向标签 ${tabId} 发送漏洞检测设置时出错:`, err));
    } catch (error) {
      console.error('发送漏洞检测设置时出错:', error);
    }
  }
  
  // 开始模拟（修改现有方法）
  startSimulation(tabId, options = {}) {
    // ... existing code ...
    
    // 向标签页发送开始模拟命令
    chrome.tabs.sendMessage(tabId, {
      action: 'startSimulation',
      options: options
    });
    
    // 发送当前的漏洞检测设置
    this.sendVulnerabilityDetectionSettings(tabId);
    
    // ... existing code ...
  }
}

// 加载指纹混淆脚本
function loadFingerprintObfuscatorScript(tabId) {
  return new Promise((resolve, reject) => {
    // 首先检查标签页是否仍然存在
    chrome.tabs.get(tabId, (tab) => {
      if (chrome.runtime.lastError) {
        console.error(`标签页 ${tabId} 不存在:`, chrome.runtime.lastError.message);
        reject(new Error(`标签页不存在: ${chrome.runtime.lastError.message}`));
        return;
      }
      
      // 确保URL是有效的HTTP/HTTPS URL
      if (!tab.url || (!tab.url.startsWith('http://') && !tab.url.startsWith('https://'))) {
        console.error(`标签页 ${tabId} URL不是http/https:`, tab.url);
        reject(new Error(`标签页URL不支持: ${tab.url}`));
        return;
      }
      
      // 如果标签页有效，执行脚本注入
      chrome.scripting.executeScript({
        target: { tabId: tabId },
        files: ['injected_scripts/fingerprint_obfuscator.js']
      })
      .then(() => {
        console.log(`成功在标签页 ${tabId} 上加载指纹混淆脚本`);
        resolve();
      })
      .catch(error => {
        console.error(`在标签页 ${tabId} 上执行脚本时出错:`, error);
        reject(error);
      });
    });
  });
}

// 初始化指纹混淆
function initFingerprintObfuscation() {
  // 监听标签页更新事件
  chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    // 只有当页面完全加载完成时才处理
    if (changeInfo.status === 'complete' && tab.url && (tab.url.startsWith('http://') || tab.url.startsWith('https://'))) {
      console.log(`标签页 ${tabId} 已加载完成: ${tab.url}`);
      
      try {
        // 添加一些延迟，确保DOM已经准备好
        setTimeout(() => {
          // 尝试加载指纹混淆脚本
          loadFingerprintObfuscatorScript(tabId)
            .then(() => {
              console.log(`已在标签页 ${tabId} 上加载指纹混淆脚本`);
            })
            .catch(error => {
              // 处理可能的错误，如标签页已关闭或导航到其他页面
              console.error(`无法在标签页 ${tabId} 上加载指纹混淆脚本:`, error);
              // 不要尝试重试，以避免无限循环
            });
        }, 500); // 延迟500毫秒加载脚本
      } catch (error) {
        console.error(`处理标签页 ${tabId} 更新时出错:`, error);
      }
    }
  });
  
  // 使用更高效的方式定期更新浏览器指纹
  let updateIntervalId;
  
  // 从存储中获取设置
  chrome.storage.local.get('hwvaSettings', (result) => {
    const settings = result.hwvaSettings || {};
    const fingerprintSettings = settings.fingerprint || {};
    
    // 检查是否启用指纹混淆
    if (fingerprintSettings.enabled !== false) {
      // 获取更新间隔（分钟）
      const updateInterval = (fingerprintSettings.updateInterval || 30) * 60 * 1000;
      
      // 清除之前的定时器（如果存在）
      if (updateIntervalId) {
        clearInterval(updateIntervalId);
      }
      
      // 设置新的定时器
      updateIntervalId = setInterval(() => {
        updateBrowserFingerprint(fingerprintSettings);
      }, updateInterval);
      
      // 立即执行一次
      updateBrowserFingerprint(fingerprintSettings);
      
      console.log(`指纹混淆已启用，更新间隔: ${updateInterval/60000} 分钟`);
    } else {
      console.log('指纹混淆已禁用');
      
      // 清除定时器
      if (updateIntervalId) {
        clearInterval(updateIntervalId);
        updateIntervalId = null;
      }
    }
  });
  
  // 使用更高效的事件监听方式
  try {
    // 在Manifest V3中，不能再使用blocking选项
    // 监听网络请求，但只用于观察
    chrome.webRequest.onBeforeSendHeaders.addListener(
      details => {
        // 只记录请求，不修改
        console.log('请求发送:', details.url);
        return { requestHeaders: details.requestHeaders };
      },
      { urls: ["<all_urls>"] },
      ["requestHeaders"]
    );
    
    // 监听网络响应，检测安全头部
    chrome.webRequest.onHeadersReceived.addListener(
      checkSecurityHeaders,
      { urls: ["<all_urls>"] },
      ["responseHeaders"]
    );
    
    // 使用declarativeNetRequest API来修改请求头
    // 这部分在updateTCPRules和initFingerprintObfuscation中已经实现
    
    console.log('网络请求监听器已设置');
  } catch (error) {
    console.error('设置网络请求监听器失败:', error);
    
    // 尝试使用备用方法
    try {
      // 使用declarativeNetRequest API作为备用
      console.log('尝试使用declarativeNetRequest API作为备用');
      
      // 这里不需要额外代码，因为我们已经在manifest.json中设置了rules.json
    } catch (backupError) {
      console.error('备用方法也失败:', backupError);
    }
  }
}

// 更新浏览器指纹
function updateBrowserFingerprint(settings = {}) {
  console.log("更新浏览器指纹...");
  
  // 创建一个任务队列，避免同时执行多个高CPU操作
  const tasks = [];
  
  // 根据设置决定要更新的指纹
  if (settings.userAgent !== false) {
    tasks.push(() => modifyUserAgent());
  }
  
  if (settings.screen !== false) {
    tasks.push(() => modifyScreenResolution());
  }
  
  if (settings.canvas !== false) {
    tasks.push(() => modifyCanvasFingerprint());
  }
  
  if (settings.webrtc !== false) {
    tasks.push(() => modifyWebRTCFingerprint());
  }
  
  if (settings.fonts !== false) {
    tasks.push(() => modifyFontFingerprint());
  }
  
  if (settings.hardware !== false) {
    tasks.push(() => modifyHardwareInfo());
  }
  
  // 使用Promise.all并发执行任务
  Promise.all(tasks.map(task => {
    // 添加随机延迟，避免同时执行
    return new Promise(resolve => {
      setTimeout(() => {
        try {
          resolve(task());
        } catch (error) {
          console.error('执行指纹更新任务失败:', error);
          resolve(null);
        }
      }, Math.random() * 1000);
    });
  }))
  .then(() => {
    console.log("浏览器指纹已更新完成");
    
    // 通知所有活动标签页指纹已更新
    chrome.tabs.query({}, tabs => {
      tabs.forEach(tab => {
        // 添加回调函数处理错误
        chrome.tabs.sendMessage(tab.id, { action: 'fingerprintUpdated' }, response => {
          // 忽略错误，chrome.runtime.lastError会自动清除
          if (chrome.runtime.lastError) {
            // 可以在这里记录错误，但不必抛出
            console.log(`向标签页 ${tab.id} 发送消息失败: ${chrome.runtime.lastError.message}`);
          }
        });
      });
    });
  })
  .catch(error => {
    console.error("更新浏览器指纹时出错:", error);
  });
}
  
  // 修改用户代理
function modifyUserAgent() {
    const userAgents = [
    // Windows + Chrome
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36",
    
    // Windows + Edge
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36 Edg/96.0.1054.62",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36 Edg/97.0.1072.62",
    
    // Windows + Firefox
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:95.0) Gecko/20100101 Firefox/95.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:96.0) Gecko/20100101 Firefox/96.0",
    
    // macOS + Chrome
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36",
    
    // macOS + Safari
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.2 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.3 Safari/605.1.15",
    
    // iOS + Safari
    "Mozilla/5.0 (iPhone; CPU iPhone OS 15_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 15_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.3 Mobile/15E148 Safari/604.1",
    
    // Android + Chrome
    "Mozilla/5.0 (Linux; Android 12; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.104 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 12; Pixel 6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.87 Mobile Safari/537.36"
  ];
  
  // 随机选择一个用户代理
  const randomUserAgent = userAgents[Math.floor(Math.random() * userAgents.length)];
  
  // 保存到存储中，供content script使用
  chrome.storage.local.set({ 'currentUserAgent': randomUserAgent });
  
  console.log("用户代理已更新为:", randomUserAgent);
}

// 修改屏幕分辨率
function modifyScreenResolution() {
  // 常见的屏幕分辨率
  const resolutions = [
    { width: 1366, height: 768 },
    { width: 1920, height: 1080 },
    { width: 1536, height: 864 },
    { width: 1440, height: 900 },
    { width: 1280, height: 720 },
    { width: 1600, height: 900 },
    { width: 2560, height: 1440 },
    { width: 3840, height: 2160 }
  ];
  
  // 随机选择一个分辨率
  const randomResolution = resolutions[Math.floor(Math.random() * resolutions.length)];
  
  // 添加微小的随机偏移 (±50像素)
  const modifiedResolution = {
    width: randomResolution.width + Math.floor(Math.random() * 100 - 50),
    height: randomResolution.height + Math.floor(Math.random() * 100 - 50)
  };
  
  // 保存到存储中，供content script使用
  chrome.storage.local.set({ 'screenResolution': modifiedResolution });
  
  console.log("屏幕分辨率已更新为:", modifiedResolution);
}

// 修改Canvas指纹
function modifyCanvasFingerprint() {
  // 生成随机的Canvas噪声参数
  const canvasNoise = {
    noiseLevel: 0.1 + Math.random() * 0.2,  // 噪声级别 (0.1-0.3)
    noiseColor: Math.floor(Math.random() * 255),  // 噪声颜色
    noiseType: Math.random() > 0.5 ? 'subtle' : 'visible'  // 噪声类型
  };
  
  // 保存到存储中，供content script使用
  chrome.storage.local.set({ 'canvasNoise': canvasNoise });
  
  console.log("Canvas指纹已更新");
}

// 修改WebRTC指纹
function modifyWebRTCFingerprint() {
  // WebRTC设置
  const webRTCSettings = {
    // 是否完全禁用WebRTC (true/false)
    disabled: Math.random() > 0.7,
    
    // 是否仅在使用VPN时禁用 (true/false)
    disableOnlyWithVPN: Math.random() > 0.5,
    
    // IP处理策略 ('default_public_and_private_interfaces', 'default_public_interface_only', 'disable_non_proxied_udp')
    ipHandlingPolicy: ['default_public_and_private_interfaces', 'default_public_interface_only', 'disable_non_proxied_udp'][Math.floor(Math.random() * 3)]
  };
  
  // 保存到存储中，供content script使用
  chrome.storage.local.set({ 'webRTCSettings': webRTCSettings });
  
  console.log("WebRTC指纹已更新");
}

// 修改字体指纹
function modifyFontFingerprint() {
  // 常见字体列表
  const commonFonts = [
    'Arial', 'Helvetica', 'Times New Roman', 'Times', 'Courier New', 'Courier', 'Verdana',
    'Georgia', 'Palatino', 'Garamond', 'Bookman', 'Tahoma', 'Trebuchet MS', 'Arial Black',
    'Impact', 'Comic Sans MS', 'Microsoft Sans Serif', 'Lucida Sans Unicode', 'Lucida Grande',
    'Lucida Sans', 'Lucida Console', 'Geneva', 'Calibri', 'Cambria', 'Candara', 'Consolas',
    'Corbel', 'Franklin Gothic Medium', 'Segoe UI', 'Symbol', 'Webdings', 'Wingdings'
  ];
  
  // 随机选择一部分字体作为"已安装"字体
  const numFonts = 10 + Math.floor(Math.random() * 10);  // 10-20个字体
  const installedFonts = [];
  
  for (let i = 0; i < numFonts; i++) {
    const randomIndex = Math.floor(Math.random() * commonFonts.length);
    installedFonts.push(commonFonts[randomIndex]);
    commonFonts.splice(randomIndex, 1);  // 避免重复
  }
  
  // 保存到存储中，供content script使用
  chrome.storage.local.set({ 'installedFonts': installedFonts });
  
  console.log("字体指纹已更新");
}

// 修改硬件信息
function modifyHardwareInfo() {
  // 硬件并发数
  const hardwareConcurrency = [2, 4, 6, 8, 12, 16][Math.floor(Math.random() * 6)];
  
  // 设备内存
  const deviceMemory = [2, 4, 8, 16, 32][Math.floor(Math.random() * 5)];
  
  // 保存到存储中，供content script使用
  chrome.storage.local.set({
    'hardwareConcurrency': hardwareConcurrency,
    'deviceMemory': deviceMemory
  });
  
  console.log("硬件信息已更新");
}

// 检查响应头中的安全头部
function checkSecurityHeaders(details) {
  // 安全头部检查
  const securityHeaders = {
    'strict-transport-security': false,
    'content-security-policy': false,
    'x-content-type-options': false,
    'x-frame-options': false,
    'x-xss-protection': false,
    'referrer-policy': false,
    'permissions-policy': false,
    'access-control-allow-origin': false
  };
  
  // 检查响应头
  for (let i = 0; i < details.responseHeaders.length; i++) {
    const headerName = details.responseHeaders[i].name.toLowerCase();
    if (securityHeaders.hasOwnProperty(headerName)) {
      securityHeaders[headerName] = true;
    }
  }
  
  // 检查是否缺少安全头部
  const missingHeaders = [];
  for (const header in securityHeaders) {
    if (!securityHeaders[header]) {
      missingHeaders.push(header);
    }
  }
  
  // 如果缺少安全头部，记录漏洞
  if (missingHeaders.length > 0) {
    const vulnerability = {
      type: '不安全的HTTP头部',
      details: {
        evidence: `缺少安全HTTP头部: ${missingHeaders.join(', ')}`,
        location: details.url,
        severity: 'Medium',
        description: '网站缺少重要的安全HTTP头部，可能导致安全风险。'
      },
      timestamp: new Date().toISOString()
    };
    
    // 添加到漏洞列表
    humanoidSimulator.addVulnerability({
      vulnerability: vulnerability,
      tabId: details.tabId
    });
  }
}

// 检查合规性
function checkCompliance(details) {
  // 检查robots.txt
  if (details.url.endsWith('/robots.txt')) {
    fetch(details.url)
      .then(response => {
        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
        }
        return response.text();
      })
      .then(text => {
        // 解析robots.txt
        const disallowedPaths = [];
        const lines = text.split('\n');
        
        for (const line of lines) {
          const trimmedLine = line.trim();
          if (trimmedLine.startsWith('Disallow:')) {
            const path = trimmedLine.substring('Disallow:'.length).trim();
            if (path) {
              disallowedPaths.push(path);
            }
          }
        }
        
        // 保存禁止访问的路径
        chrome.storage.local.set({
          'disallowedPaths': disallowedPaths,
          'robotsTxtChecked': true
        });
        
        console.log("已解析robots.txt，禁止访问的路径:", disallowedPaths);
      })
      .catch(error => {
        console.error('获取robots.txt时出错:', error);
      });
  }
  
  // 检查法律声明页面
  if (details.url.toLowerCase().includes('terms') || 
      details.url.toLowerCase().includes('legal') || 
      details.url.toLowerCase().includes('privacy')) {
    // 标记为已检查法律声明
    chrome.storage.local.set({ 'legalChecked': true });
  }
}

// 生成漏洞报告
async function generateReport() {
  // 获取所有漏洞
  const vulnerabilities = await new Promise(resolve => {
    chrome.storage.local.get('vulnerabilities', result => {
      resolve(result.vulnerabilities || []);
    });
  });
  
  if (vulnerabilities.length === 0) {
    return "未发现漏洞";
  }
  
  // 按网站分组漏洞
  const vulnerabilitiesByDomain = {};
  
  for (const vuln of vulnerabilities) {
    try {
      const url = new URL(vuln.details.location);
      const domain = url.hostname;
      
      if (!vulnerabilitiesByDomain[domain]) {
        vulnerabilitiesByDomain[domain] = [];
      }
      
      vulnerabilitiesByDomain[domain].push(vuln);
    } catch (e) {
      // 处理无效URL
      if (!vulnerabilitiesByDomain['unknown']) {
        vulnerabilitiesByDomain['unknown'] = [];
      }
      vulnerabilitiesByDomain['unknown'].push(vuln);
    }
  }
  
  // 生成报告
  let report = "# 漏洞扫描报告\n\n";
  report += `生成时间: ${new Date().toLocaleString()}\n\n`;
  report += `总计发现 ${vulnerabilities.length} 个潜在漏洞\n\n`;
  
  // 按域名添加漏洞详情
  for (const domain in vulnerabilitiesByDomain) {
    report += `## ${domain}\n\n`;
    
    for (const vuln of vulnerabilitiesByDomain[domain]) {
      report += `### ${vuln.type}\n\n`;
      report += `- **严重程度**: ${vuln.details.severity || '未知'}\n`;
      report += `- **URL**: ${vuln.details.location}\n`;
      report += `- **描述**: ${vuln.details.description || '无描述'}\n`;
      report += `- **证据**: ${vuln.details.evidence}\n`;
      report += `- **发现时间**: ${new Date(vuln.timestamp).toLocaleString()}\n\n`;
    }
  }
  
  return report;
}

// 导出漏洞报告为CSV
function exportReportAsCSV() {
  return new Promise(resolve => {
    chrome.storage.local.get('vulnerabilities', result => {
      const vulnerabilities = result.vulnerabilities || [];
      
      if (vulnerabilities.length === 0) {
        resolve("未发现漏洞");
        return;
      }
      
      // CSV头
      let csv = "类型,严重程度,URL,描述,证据,发现时间\n";
      
      // 添加每个漏洞
      for (const vuln of vulnerabilities) {
        const row = [
          `"${vuln.type}"`,
          `"${vuln.details.severity || '未知'}"`,
          `"${vuln.details.location}"`,
          `"${(vuln.details.description || '无描述').replace(/"/g, '""')}"`,
          `"${(vuln.details.evidence || '').replace(/"/g, '""')}"`,
          `"${new Date(vuln.timestamp).toLocaleString()}"`
        ];
        
        csv += row.join(',') + '\n';
      }
      
      resolve(csv);
    });
  });
}

// 初始化
function init() {
  // 创建HumanoidSimulator实例
  humanoidSimulator = new HumanoidSimulator();
  
  // 加载已保存的漏洞
  humanoidSimulator.loadVulnerabilities();

  // 初始化指纹混淆
  initFingerprintObfuscation();
  
  // 监听标签页更新
  chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab.url) {
      // 检查合规性
      checkCompliance({ url: tab.url, tabId });
    }
  });
  
  // 监听来自content script的消息
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === 'vulnerabilityDetected') {
      try {
        // 添加漏洞
        if (!message.vulnerability) {
          console.error('收到的漏洞消息缺少vulnerability字段:', message);
          sendResponse({ success: false, error: '缺少vulnerability字段' });
          return true;
        }
        
        humanoidSimulator.addVulnerability({
          vulnerability: message.vulnerability,
          tabId: sender.tab ? sender.tab.id : null
        });
        sendResponse({ success: true });
      } catch (error) {
        console.error('处理漏洞检测消息时出错:', error ? (error.message || error.toString()) : '未知错误');
        sendResponse({ success: false, error: error ? error.message : '未知错误' });
      }
      return true;
    } else if (message.action === 'executeScript') {
      // 处理脚本执行请求
      if (sender.tab && sender.tab.id) {
        try {
          // 首先验证标签页是否仍然存在
          chrome.tabs.get(sender.tab.id, (tab) => {
            if (chrome.runtime.lastError) {
              console.error(`标签页 ${sender.tab.id} 不存在:`, chrome.runtime.lastError.message);
              sendResponse({ success: false, error: `标签页不存在: ${chrome.runtime.lastError.message}` });
              return;
            }
            
            // 确保URL是有效的HTTP/HTTPS URL
            if (!tab.url || (!tab.url.startsWith('http://') && !tab.url.startsWith('https://'))) {
              console.error(`标签页 ${sender.tab.id} URL不是http/https:`, tab.url);
              sendResponse({ success: false, error: `标签页URL不支持: ${tab.url}` });
              return;
            }
            
            // 直接注入代码，使用更安全的方法
            chrome.scripting.executeScript({
              target: { tabId: sender.tab.id },
              func: (code) => {
                try {
                  // 创建并执行脚本元素的安全方法
                  const script = document.createElement('script');
                  script.textContent = code;
                  document.head.appendChild(script);
                  // 脚本执行后删除，避免污染页面
                  setTimeout(() => {
                    if (script.parentNode) {
                      script.parentNode.removeChild(script);
                    }
                  }, 100);
                  return { success: true };
                } catch (error) {
                  console.error('执行脚本失败:', error);
                  return { success: false, error: error.message };
                }
              },
              args: [message.scriptContent],
              world: "MAIN"
            }).then(results => {
              if (results && results[0] && results[0].result) {
                sendResponse(results[0].result);
              } else {
                sendResponse({ success: false, error: '执行结果未知' });
              }
            }).catch(error => {
              console.error(`chrome.scripting.executeScript 在标签页 ${sender.tab.id} 上失败:`, error);
              sendResponse({ success: false, error: error.message });
            });
          });
          return true; // 异步响应
        } catch (outerError) {
          console.error('尝试执行脚本时出错:', outerError);
          sendResponse({ success: false, error: outerError.message });
        }
      } else {
        console.error('无法确定标签页ID');
        sendResponse({ success: false, error: '无法确定标签页ID' });
      }
    } else if (message.action === 'getFingerprint') {
      // 获取当前指纹设置
      chrome.storage.local.get([
        'currentUserAgent',
        'screenResolution',
        'canvasNoise',
        'webRTCSettings',
        'installedFonts',
        'hardwareConcurrency',
        'deviceMemory'
      ], result => {
        sendResponse(result);
      });
      return true; // 异步响应
    } else if (message.action === 'exportReport') {
      // 导出报告
      generateReport().then(report => {
        sendResponse({ report });
      });
      return true; // 保持消息通道开放，以便异步响应
    } else if (message.action === 'exportCSV') {
      // 导出CSV
      exportReportAsCSV().then(csv => {
        sendResponse({ csv });
      });
      return true; // 保持消息通道开放，以便异步响应
    } else if (message.action === 'startScan') {
      // 处理开始扫描消息
      // ...
    } else if (message.action === 'getVulnerabilities') {
      // 返回已检测到的漏洞
      sendResponse(humanoidSimulator.detectedVulnerabilities);
    } else if (message.action === 'clearVulnerabilities') {
      // 清空漏洞数据
      humanoidSimulator.detectedVulnerabilities = [];
      humanoidSimulator.saveVulnerabilities();
      sendResponse({ success: true });
    } else if (message.action === 'updateFingerprint') {
      // 更新指纹设置
      updateBrowserFingerprint(message.settings);
      sendResponse({ success: true });
    } else if (message.action === 'enableTCPFingerprinting') {
      // 启用TCP/IP指纹混淆
      humanoidSimulator.tcpFingerprint.enabled = true;
      
      // 如果提供了设置，则更新
      if (message.settings) {
        // 更新密码套件等设置
        if (humanoidSimulator.tcpFingerprint.currentProfile) {
          if (message.settings.cipherSuites) {
            humanoidSimulator.tcpFingerprint.currentProfile.cipherSuites = message.settings.cipherSuites;
          }
          if (message.settings.supportedGroups) {
            humanoidSimulator.tcpFingerprint.currentProfile.supportedGroups = message.settings.supportedGroups;
          }
          if (message.settings.signatureAlgorithms) {
            humanoidSimulator.tcpFingerprint.currentProfile.signatureAlgorithms = message.settings.signatureAlgorithms;
          }
        }
      }
      
      // 立即轮换TCP配置
      humanoidSimulator.rotateTCPProfile();
      
      sendResponse({ success: true });
    } else if (message.action === 'updateVulnerabilitySettings') {
      // 处理漏洞检测设置更新
      try {
        console.log('[后台] 收到漏洞检测设置更新:', message.settings);
        
        // 保存设置
        chrome.storage.local.set({ 'vulnerabilitySettings': message.settings }, () => {
          if (chrome.runtime.lastError) {
            console.error('保存漏洞检测设置时出错:', chrome.runtime.lastError);
            sendResponse({ success: false, error: chrome.runtime.lastError.message });
          } else {
            console.log('漏洞检测设置已保存到后台');
            
            // 将设置传递给当前活动标签
            chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
              if (tabs && tabs.length > 0) {
                chrome.tabs.sendMessage(tabs[0].id, {
                  action: 'prepareVulnerabilityDetection',
                  settings: message.settings
                }).catch(err => console.error('向内容脚本发送设置时出错:', err));
              }
            });
            
            sendResponse({ success: true });
          }
        });
        
        return true; // 保持消息通道打开以进行异步响应
      } catch (error) {
        console.error('处理漏洞检测设置更新时出错:', error);
        sendResponse({ success: false, error: error.message });
      }
    } else if (message.action === 'prepareVulnerabilityDetection') {
      // 处理准备漏洞检测
      try {
        console.log('[后台] 准备漏洞检测:', message.settings);
        
        // 保存设置以便将来使用
        chrome.storage.local.set({ 'vulnerabilitySettings': message.settings }, () => {
          if (chrome.runtime.lastError) {
            console.error('保存漏洞检测设置时出错:', chrome.runtime.lastError);
          }
        });
        
        // 将设置传递给当前标签
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
          if (tabs && tabs.length > 0) {
            chrome.tabs.sendMessage(tabs[0].id, {
              action: 'prepareVulnerabilityDetection',
              settings: message.settings
            }).catch(err => console.error('向内容脚本发送设置时出错:', err));
          }
        });
        
        sendResponse({ success: true });
        return true; // 保持消息通道打开以进行异步响应
      } catch (error) {
        console.error('准备漏洞检测时出错:', error);
        sendResponse({ success: false, error: error.message });
      }
    }
    
    // 返回true表示异步响应
    return true;
  });
  
  // 设置定时器，定期轮换TCP/IP指纹
  setInterval(() => {
    humanoidSimulator.checkTCPProfileRotation();
  }, 60000); // 每分钟检查一次
  
  console.log("Humanoid Web Vulnerability Assistant 已初始化");
}

// 启动初始化
init();