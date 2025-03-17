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
  
  // 添加发现的漏洞
  addVulnerability(data) {
    // 添加timestamp和唯一ID
    const vulnerability = {
      ...data.vulnerability,
      id: Date.now() + '_' + Math.random().toString(36).substr(2, 9),
      tabId: data.tabId
    };
    
    // 避免重复漏洞（同一类型、同一URL）
    const isDuplicate = this.detectedVulnerabilities.some(v => 
      v.type === vulnerability.type && 
      v.details.location === vulnerability.details.location
    );
    
    if (!isDuplicate) {
      this.detectedVulnerabilities.push(vulnerability);
      this.saveVulnerabilities();
      
      // 发送桌面通知
      chrome.notifications.create({
        type: 'basic',
        iconUrl: 'icon128.png',
        title: '发现潜在漏洞 - ' + vulnerability.type,
        message: `URL: ${vulnerability.details.location.substring(0, 50)}...`,
        priority: 2
      });
    }
  }
  
  // 保存漏洞到本地存储
  saveVulnerabilities() {
    chrome.storage.local.set({
      'vulnerabilities': this.detectedVulnerabilities
    });
  }
  
  // 加载已保存的漏洞
  loadVulnerabilities() {
    chrome.storage.local.get('vulnerabilities', (result) => {
      if (result.vulnerabilities) {
        this.detectedVulnerabilities = result.vulnerabilities;
      }
    });
  }
  
  // 导出漏洞报告
  exportVulnerabilityReport() {
    if (this.detectedVulnerabilities.length === 0) {
      return null;
    }
    
    // 按照网站分组漏洞
    const vulnByDomain = {};
    this.detectedVulnerabilities.forEach(vuln => {
      try {
        const url = new URL(vuln.details.location);
        const domain = url.hostname;
        
        if (!vulnByDomain[domain]) {
          vulnByDomain[domain] = [];
        }
        
        vulnByDomain[domain].push(vuln);
      } catch (e) {
        // 处理无效URL
        if (!vulnByDomain['unknown']) {
          vulnByDomain['unknown'] = [];
        }
        vulnByDomain['unknown'].push(vuln);
      }
    });
    
    // 创建报告HTML
    let reportHtml = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>漏洞检测报告</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 0; padding: 20px; color: #333; }
    h1 { color: #2c3e50; border-bottom: 2px solid #eee; padding-bottom: 10px; }
    h2 { color: #2980b9; margin-top: 30px; }
    h3 { color: #c0392b; }
    .vulnerability { background: #f8f9fa; border-left: 4px solid #e74c3c; padding: 15px; margin: 15px 0; border-radius: 0 4px 4px 0; }
    .evidence { background: #ecf0f1; padding: 10px; border-radius: 4px; font-family: monospace; }
    .timestamp { color: #7f8c8d; font-size: 0.8em; }
    .summary { background: #e8f4f8; padding: 15px; border-radius: 4px; margin: 20px 0; }
  </style>
</head>
<body>
  <h1>漏洞检测报告</h1>
  <div class="summary">
    <p>生成时间: ${new Date().toLocaleString()}</p>
    <p>检测目标总数: ${Object.keys(vulnByDomain).length}</p>
    <p>发现漏洞总数: ${this.detectedVulnerabilities.length}</p>
  </div>
`;
    
    // 添加每个域的漏洞
    for (const [domain, vulns] of Object.entries(vulnByDomain)) {
      reportHtml += `<h2>目标: ${domain}</h2>`;
      reportHtml += `<p>发现漏洞数: ${vulns.length}</p>`;
      
      // 按照漏洞类型分组
      const vulnByType = {};
      vulns.forEach(vuln => {
        if (!vulnByType[vuln.type]) {
          vulnByType[vuln.type] = [];
        }
        vulnByType[vuln.type].push(vuln);
      });
      
      // 添加每种类型的漏洞
      for (const [type, typeVulns] of Object.entries(vulnByType)) {
        reportHtml += `<h3>${type} (${typeVulns.length})</h3>`;
        
        typeVulns.forEach(vuln => {
          reportHtml += `
<div class="vulnerability">
  <p><strong>URL:</strong> ${vuln.details.location}</p>
  <p><strong>证据:</strong></p>
  <div class="evidence">${vuln.details.evidence}</div>
  <p class="timestamp">发现时间: ${new Date(vuln.timestamp).toLocaleString()}</p>
</div>`;
        });
      }
    }
    
    reportHtml += `
</body>
</html>`;

    return reportHtml;
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
      // 添加漏洞
      humanoidSimulator.addVulnerability({
        vulnerability: message.vulnerability,
        tabId: sender.tab.id
      });
      sendResponse({ success: true });
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