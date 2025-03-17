/**
 * 浏览器指纹混淆模块
 * 用于在页面中注入脚本，混淆浏览器指纹
 */

class FingerprintObfuscator {
  constructor() {
    // 默认设置
    this.settings = {
      currentUserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36",
      screenResolution: { width: 1920, height: 1080 },
      canvasNoise: { noiseLevel: 0.1, noiseColor: 128, noiseType: 'subtle' },
      webRTCSettings: { disabled: true, disableOnlyWithVPN: false, ipHandlingPolicy: 'default_public_interface_only' },
      installedFonts: ['Arial', 'Times New Roman', 'Courier New', 'Verdana', 'Georgia'],
      hardwareConcurrency: 4,
      deviceMemory: 8,
      // 新增动态变化设置
      dynamicFingerprint: {
        enabled: true,
        changeInterval: 30, // 分钟
        lastChangeTime: Date.now(),
        variationRange: {
          screenResolution: { width: 50, height: 50 },
          canvasNoise: { noiseLevel: 0.05 },
          hardwareConcurrency: 2,
          deviceMemory: 2
        }
      },
      // 新增TLS指纹混淆
      tlsFingerprint: {
        enabled: true,
        cipherSuites: [
          'TLS_AES_128_GCM_SHA256',
          'TLS_AES_256_GCM_SHA384',
          'TLS_CHACHA20_POLY1305_SHA256'
        ],
        supportedGroups: [
          'x25519',
          'secp256r1',
          'secp384r1'
        ],
        signatureAlgorithms: [
          'rsa_pkcs1_sha256',
          'rsa_pss_rsae_sha256',
          'ecdsa_secp256r1_sha256'
        ]
      },
      // 新增电池状态混淆
      batteryStatus: {
        enabled: true,
        charging: Math.random() > 0.5,
        level: 0.1 + Math.random() * 0.9,
        chargingTime: Math.floor(1000 + Math.random() * 3000),
        dischargingTime: Math.floor(1000 + Math.random() * 5000)
      }
    };
    
    // 加载设置
    this.loadSettings();
    
    // 应用混淆
    this.applyObfuscation();
    
    // 设置定时器，定期更新指纹
    if (this.settings.dynamicFingerprint.enabled) {
      this.setupDynamicFingerprint();
    }
  }
  
  // 安全地发送消息
  safeSendMessage(message, callback) {
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
  
  // 从background script加载设置
  loadSettings() {
    // 从存储中加载设置
    this.safeSendMessage({ action: 'getFingerprint' }, (response) => {
      if (response && response.settings) {
        this.settings = response.settings;
        console.log('[指纹混淆] 已加载设置');
      } else {
        console.log('[指纹混淆] 使用默认设置');
      }
      
      // 设置动态指纹更新计时器
      if (this.settings.dynamicFingerprint.enabled) {
        this.setupDynamicFingerprint();
      }
    });
  }
  
  // 设置动态指纹变化
  setupDynamicFingerprint() {
    // 清除现有定时器
    if (this.fingerprintTimer) {
      clearInterval(this.fingerprintTimer);
    }
    
    // 设置新定时器
    const interval = this.settings.dynamicFingerprint.changeInterval * 60 * 1000; // 转换为毫秒
    this.fingerprintTimer = setInterval(() => {
      this.updateDynamicFingerprint();
    }, interval);
    
    // 检查是否需要立即更新
    const lastChange = this.settings.dynamicFingerprint.lastChangeTime;
    const elapsed = Date.now() - lastChange;
    if (elapsed >= interval) {
      this.updateDynamicFingerprint();
    }
  }
  
  // 更新动态指纹
  updateDynamicFingerprint() {
    console.log('[指纹混淆] 更新动态指纹');
    
    // 生成新的随机值
    this.settings.currentUserAgent = this.getRandomUserAgent();
    this.settings.screenResolution = this.getRandomScreenResolution();
    this.settings.hardwareConcurrency = this.getRandomHardwareConcurrency();
    this.settings.deviceMemory = this.getRandomDeviceMemory();
    
    // 更新上次变更时间
    this.settings.dynamicFingerprint.lastChangeTime = Date.now();
    
    // 发送更新到后台脚本
    this.safeSendMessage({
      action: 'updateFingerprint',
      settings: this.settings
    });
    
    // 重新应用混淆
    this.applyObfuscation();
  }
  
  // 应用所有混淆技术
  applyObfuscation() {
    this.obfuscateUserAgent();
    this.obfuscateScreenResolution();
    this.obfuscateCanvas();
    this.obfuscateWebRTC();
    this.obfuscateFonts();
    this.obfuscateHardwareInfo();
    this.obfuscateTimezone();
    this.obfuscateLanguages();
    this.obfuscatePlugins();
    this.obfuscateWebGL();
    this.obfuscateAudioContext();
    this.obfuscateBatteryAPI();
    this.obfuscateClientRects();
    this.obfuscatePerformanceAPI();
    this.obfuscateTCPFingerprint();
  }
  
  // 混淆用户代理
  obfuscateUserAgent() {
    const userAgent = this.settings.currentUserAgent;
    
    // 注入脚本覆盖navigator.userAgent
    this.injectScript(`
      Object.defineProperty(navigator, 'userAgent', {
        get: function() { return '${userAgent}'; }
      });
    `);
  }
  
  // 混淆屏幕分辨率
  obfuscateScreenResolution() {
    const { width, height } = this.settings.screenResolution;
    
    // 注入脚本覆盖screen属性
    this.injectScript(`
      Object.defineProperty(screen, 'width', {
        get: function() { return ${width}; }
      });
      Object.defineProperty(screen, 'height', {
        get: function() { return ${height}; }
      });
      Object.defineProperty(screen, 'availWidth', {
        get: function() { return ${width}; }
      });
      Object.defineProperty(screen, 'availHeight', {
        get: function() { return ${height}; }
      });
      Object.defineProperty(window, 'innerWidth', {
        get: function() { return ${width}; }
      });
      Object.defineProperty(window, 'innerHeight', {
        get: function() { return ${height}; }
      });
      Object.defineProperty(window, 'outerWidth', {
        get: function() { return ${width}; }
      });
      Object.defineProperty(window, 'outerHeight', {
        get: function() { return ${height}; }
      });
    `);
  }
  
  // 混淆Canvas指纹
  obfuscateCanvas() {
    const { noiseLevel, noiseColor, noiseType } = this.settings.canvasNoise;
    
    // 注入脚本覆盖Canvas方法
    this.injectScript(`
      // 保存原始方法
      const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
      const originalGetImageData = CanvasRenderingContext2D.prototype.getImageData;
      
      // 添加噪声函数
      function addNoise(imageData) {
        const pixels = imageData.data;
        const noiseLevel = ${noiseLevel};
        const noiseColor = ${noiseColor};
        const noiseType = '${noiseType}';
        
        for (let i = 0; i < pixels.length; i += 4) {
          // 根据噪声类型添加不同的噪声
          if (noiseType === 'subtle') {
            // 微妙的噪声 - 只在最低有效位上添加噪声
            pixels[i] = pixels[i] & 0xFC | (Math.random() * 4) & 0x03;     // R
            pixels[i+1] = pixels[i+1] & 0xFC | (Math.random() * 4) & 0x03; // G
            pixels[i+2] = pixels[i+2] & 0xFC | (Math.random() * 4) & 0x03; // B
          } else {
            // 可见噪声 - 添加更明显的噪声
            const noise = (Math.random() - 0.5) * noiseLevel * 255;
            pixels[i] = Math.min(255, Math.max(0, pixels[i] + noise));     // R
            pixels[i+1] = Math.min(255, Math.max(0, pixels[i+1] + noise)); // G
            pixels[i+2] = Math.min(255, Math.max(0, pixels[i+2] + noise)); // B
          }
        }
        
        return imageData;
      }
      
      // 覆盖toDataURL方法
      HTMLCanvasElement.prototype.toDataURL = function() {
        // 检查是否是指纹检测
        const isFingerprinting = new Error().stack.includes('CanvasFingerprint') ||
                                 document.documentElement.innerHTML.includes('Fingerprint') ||
                                 document.documentElement.innerHTML.includes('fingerprint');
        
        if (isFingerprinting || Math.random() < 0.5) {
          // 获取原始图像数据
          const context = this.getContext('2d');
          const imageData = context.getImageData(0, 0, this.width, this.height);
          
          // 添加噪声
          const noisyImageData = addNoise(imageData);
          
          // 将修改后的图像数据放回Canvas
          context.putImageData(noisyImageData, 0, 0);
        }
        
        // 调用原始方法
        return originalToDataURL.apply(this, arguments);
      };
      
      // 覆盖getImageData方法
      CanvasRenderingContext2D.prototype.getImageData = function() {
        // 获取原始图像数据
        const imageData = originalGetImageData.apply(this, arguments);
        
        // 检查是否是指纹检测
        const isFingerprinting = new Error().stack.includes('CanvasFingerprint') ||
                                 document.documentElement.innerHTML.includes('Fingerprint') ||
                                 document.documentElement.innerHTML.includes('fingerprint');
        
        if (isFingerprinting || Math.random() < 0.5) {
          // 添加噪声
          return addNoise(imageData);
        }
        
        return imageData;
      };
    `);
  }
  
  // 混淆WebRTC
  obfuscateWebRTC() {
    const { disabled, disableOnlyWithVPN, ipHandlingPolicy } = this.settings.webRTCSettings;
    
    // 注入脚本覆盖WebRTC方法
    this.injectScript(`
      // 检查是否应该禁用WebRTC
      const shouldDisableWebRTC = ${disabled} || (${disableOnlyWithVPN} && navigator.userAgent.includes('VPN'));
      
      if (shouldDisableWebRTC) {
        // 完全禁用WebRTC
        const originalRTCPeerConnection = window.RTCPeerConnection || window.webkitRTCPeerConnection || window.mozRTCPeerConnection;
        
        if (originalRTCPeerConnection) {
          window.RTCPeerConnection = function() {
            // 返回一个不会泄露IP的假RTCPeerConnection
            const pc = new originalRTCPeerConnection({
              iceServers: []
            });
            
            // 覆盖createOffer方法
            const originalCreateOffer = pc.createOffer.bind(pc);
            pc.createOffer = function(successCallback, failureCallback, options) {
              return originalCreateOffer(options)
                .then(offer => {
                  // 修改SDP以移除IP地址
                  offer.sdp = offer.sdp.replace(/IP4 \\d+\\.\\d+\\.\\d+\\.\\d+/g, 'IP4 0.0.0.0');
                  
                  if (successCallback) {
                    successCallback(offer);
                  }
                  
                  return offer;
                })
                .catch(error => {
                  if (failureCallback) {
                    failureCallback(error);
                  }
                  
                  throw error;
                });
            };
            
            return pc;
          };
          
          // 同样覆盖webkitRTCPeerConnection和mozRTCPeerConnection
          if (window.webkitRTCPeerConnection) {
            window.webkitRTCPeerConnection = window.RTCPeerConnection;
          }
          
          if (window.mozRTCPeerConnection) {
            window.mozRTCPeerConnection = window.RTCPeerConnection;
          }
        }
      } else {
        // 设置IP处理策略
        const ipHandlingPolicy = '${ipHandlingPolicy}';
        
        // 注入策略设置
        if (navigator.mediaDevices && navigator.mediaDevices.getUserMedia) {
          const originalGetUserMedia = navigator.mediaDevices.getUserMedia.bind(navigator.mediaDevices);
          
          navigator.mediaDevices.getUserMedia = function(constraints) {
            // 添加IP处理策略
            if (!constraints) constraints = {};
            if (!constraints.optional) constraints.optional = [];
            
            constraints.optional.push({ ipHandlingPolicy: ipHandlingPolicy });
            
            return originalGetUserMedia(constraints);
          };
        }
      }
    `);
  }
  
  // 混淆字体列表
  obfuscateFonts() {
    const installedFonts = JSON.stringify(this.settings.installedFonts);
    
    // 注入脚本覆盖字体检测方法
    this.injectScript(`
      // 模拟的已安装字体列表
      const installedFonts = ${installedFonts};
      
      // 覆盖document.fonts.check方法
      if (document.fonts && document.fonts.check) {
        const originalCheck = document.fonts.check.bind(document.fonts);
        
        document.fonts.check = function(font, text) {
          // 提取字体名称
          const fontName = font.split(' ').pop().replace(/['"]/g, '');
          
          // 检查是否在我们的已安装字体列表中
          if (installedFonts.includes(fontName)) {
            return true;
          } else {
            // 对于不在列表中的字体，有10%的概率返回true
            return Math.random() < 0.1;
          }
        };
      }
      
      // 覆盖FontFace.load方法
      if (window.FontFace) {
        const originalFontFace = window.FontFace;
        
        window.FontFace = function(family, source, descriptors) {
          const fontFace = new originalFontFace(family, source, descriptors);
          
          // 覆盖load方法
          const originalLoad = fontFace.load.bind(fontFace);
          
          fontFace.load = function() {
            // 提取字体名称
            const fontName = family.replace(/['"]/g, '');
            
            // 检查是否在我们的已安装字体列表中
            if (installedFonts.includes(fontName)) {
              return originalLoad();
            } else {
              // 对于不在列表中的字体，有10%的概率成功加载
              if (Math.random() < 0.1) {
                return originalLoad();
              } else {
                return Promise.reject(new Error('Font not found'));
              }
            }
          };
          
          return fontFace;
        };
      }
    `);
  }
  
  // 混淆硬件信息
  obfuscateHardwareInfo() {
    const hardwareConcurrency = this.settings.hardwareConcurrency;
    const deviceMemory = this.settings.deviceMemory;
    
    // 注入脚本覆盖硬件信息
    this.injectScript(`
      // 覆盖硬件并发数
      Object.defineProperty(navigator, 'hardwareConcurrency', {
        get: function() { return ${hardwareConcurrency}; }
      });
      
      // 覆盖设备内存
      Object.defineProperty(navigator, 'deviceMemory', {
        get: function() { return ${deviceMemory}; }
      });
    `);
  }
  
  // 混淆时区
  obfuscateTimezone() {
    // 随机选择一个时区偏移
    const timezoneOffsets = [-720, -660, -600, -570, -540, -480, -420, -360, -300, -240, -210, -180, -120, -60, 0, 60, 120, 180, 210, 240, 270, 300, 330, 345, 360, 390, 420, 480, 525, 540, 570, 600, 630, 660, 720];
    const randomOffset = timezoneOffsets[Math.floor(Math.random() * timezoneOffsets.length)];
    
    // 注入脚本覆盖时区方法
    this.injectScript(`
      // 保存原始方法
      const originalGetTimezoneOffset = Date.prototype.getTimezoneOffset;
      
      // 覆盖getTimezoneOffset方法
      Date.prototype.getTimezoneOffset = function() {
        // 检查是否是指纹检测
        const isFingerprinting = new Error().stack.includes('Fingerprint') ||
                                 document.documentElement.innerHTML.includes('Fingerprint') ||
                                 document.documentElement.innerHTML.includes('fingerprint');
        
        if (isFingerprinting || Math.random() < 0.5) {
          return ${randomOffset};
        }
        
        return originalGetTimezoneOffset.apply(this);
      };
    `);
  }
  
  // 混淆语言设置
  obfuscateLanguages() {
    // 常见语言组合
    const languageSets = [
      ['zh-CN', 'zh', 'en-US', 'en'],
      ['en-US', 'en', 'zh-CN', 'zh'],
      ['en-GB', 'en', 'fr', 'de'],
      ['fr-FR', 'fr', 'en', 'de'],
      ['de-DE', 'de', 'en', 'fr'],
      ['ja-JP', 'ja', 'en-US', 'en'],
      ['ru-RU', 'ru', 'en', 'uk']
    ];
    
    // 随机选择一组语言
    const randomLanguages = languageSets[Math.floor(Math.random() * languageSets.length)];
    
    // 注入脚本覆盖语言设置
    this.injectScript(`
      // 覆盖navigator.languages
      Object.defineProperty(navigator, 'languages', {
        get: function() { return ${JSON.stringify(randomLanguages)}; }
      });
      
      // 覆盖navigator.language
      Object.defineProperty(navigator, 'language', {
        get: function() { return '${randomLanguages[0]}'; }
      });
    `);
  }
  
  // 混淆插件信息
  obfuscatePlugins() {
    // 注入脚本覆盖插件信息
    this.injectScript(`
      // 覆盖navigator.plugins
      Object.defineProperty(navigator, 'plugins', {
        get: function() {
          // 创建一个空的PluginArray
          const plugins = Object.create(PluginArray.prototype);
          
          // 设置length属性
          Object.defineProperty(plugins, 'length', {
            get: function() { return 0; }
          });
          
          // 添加item和namedItem方法
          plugins.item = function() { return null; };
          plugins.namedItem = function() { return null; };
          
          // 使其不可枚举
          Object.defineProperty(plugins, 'item', { enumerable: false });
          Object.defineProperty(plugins, 'namedItem', { enumerable: false });
          
          return plugins;
        }
      });
      
      // 覆盖navigator.mimeTypes
      Object.defineProperty(navigator, 'mimeTypes', {
        get: function() {
          // 创建一个空的MimeTypeArray
          const mimeTypes = Object.create(MimeTypeArray.prototype);
          
          // 设置length属性
          Object.defineProperty(mimeTypes, 'length', {
            get: function() { return 0; }
          });
          
          // 添加item和namedItem方法
          mimeTypes.item = function() { return null; };
          mimeTypes.namedItem = function() { return null; };
          
          // 使其不可枚举
          Object.defineProperty(mimeTypes, 'item', { enumerable: false });
          Object.defineProperty(mimeTypes, 'namedItem', { enumerable: false });
          
          return mimeTypes;
        }
      });
    `);
  }
  
  // 混淆WebGL信息
  obfuscateWebGL() {
    // 注入脚本覆盖WebGL信息
    this.injectScript(`
      // 保存原始方法
      const originalGetParameter = WebGLRenderingContext.prototype.getParameter;
      
      // 覆盖getParameter方法
      WebGLRenderingContext.prototype.getParameter = function(parameter) {
        // 检查是否是指纹相关参数
        if (parameter === 37445) { // UNMASKED_VENDOR_WEBGL
          const vendors = ['Intel Inc.', 'NVIDIA Corporation', 'AMD', 'Google Inc.', 'Apple'];
          return vendors[Math.floor(Math.random() * vendors.length)];
        }
        
        if (parameter === 37446) { // UNMASKED_RENDERER_WEBGL
          const renderers = [
            'Intel HD Graphics 6000',
            'NVIDIA GeForce GTX 1060',
            'AMD Radeon RX 580',
            'Mesa DRI Intel(R) HD Graphics 620',
            'Apple GPU',
            'Google SwiftShader'
          ];
          return renderers[Math.floor(Math.random() * renderers.length)];
        }
        
        // 对于其他参数，使用原始方法
        return originalGetParameter.apply(this, arguments);
      };
      
      // 同样覆盖WebGL2RenderingContext
      if (window.WebGL2RenderingContext) {
        WebGL2RenderingContext.prototype.getParameter = WebGLRenderingContext.prototype.getParameter;
      }
    `);
  }
  
  // 混淆AudioContext指纹
  obfuscateAudioContext() {
    // 注入脚本覆盖AudioContext方法
    this.injectScript(`
      // 检查是否支持AudioContext
      if (window.AudioContext || window.webkitAudioContext) {
        // 保存原始构造函数
        const OriginalAudioContext = window.AudioContext || window.webkitAudioContext;
        
        // 创建一个新的构造函数
        const ModifiedAudioContext = function() {
          const audioContext = new OriginalAudioContext();
          
          // 覆盖createOscillator方法
          const originalCreateOscillator = audioContext.createOscillator.bind(audioContext);
          audioContext.createOscillator = function() {
            const oscillator = originalCreateOscillator();
            
            // 添加随机噪声
            const originalStart = oscillator.start.bind(oscillator);
            oscillator.start = function() {
              // 随机调整频率
              if (Math.random() < 0.5) {
                oscillator.frequency.value += (Math.random() - 0.5) * 0.01;
              }
              
              return originalStart.apply(this, arguments);
            };
            
            return oscillator;
          };
          
          // 覆盖createAnalyser方法
          const originalCreateAnalyser = audioContext.createAnalyser.bind(audioContext);
          audioContext.createAnalyser = function() {
            const analyser = originalCreateAnalyser();
            
            // 覆盖getFloatFrequencyData方法
            const originalGetFloatFrequencyData = analyser.getFloatFrequencyData.bind(analyser);
            analyser.getFloatFrequencyData = function(array) {
              originalGetFloatFrequencyData(array);
              
              // 添加随机噪声
              for (let i = 0; i < array.length; i++) {
                array[i] += (Math.random() - 0.5) * 0.1;
              }
            };
            
            // 覆盖getByteFrequencyData方法
            const originalGetByteFrequencyData = analyser.getByteFrequencyData.bind(analyser);
            analyser.getByteFrequencyData = function(array) {
              originalGetByteFrequencyData(array);
              
              // 添加随机噪声
              for (let i = 0; i < array.length; i++) {
                array[i] = Math.min(255, Math.max(0, array[i] + Math.floor((Math.random() - 0.5) * 3)));
              }
            };
            
            return analyser;
          };
          
          return audioContext;
        };
        
        // 替换原始构造函数
        window.AudioContext = ModifiedAudioContext;
        if (window.webkitAudioContext) {
          window.webkitAudioContext = ModifiedAudioContext;
        }
      }
    `);
  }
  
  // 混淆Battery API
  obfuscateBatteryAPI() {
    if (!this.settings.batteryStatus.enabled) return;
    
    const { charging, level, chargingTime, dischargingTime } = this.settings.batteryStatus;
    
    this.injectScript(`
      // 拦截Battery API
      if (navigator.getBattery) {
        const originalGetBattery = navigator.getBattery;
        navigator.getBattery = function() {
          return new Promise((resolve) => {
            const fakeBattery = {
              charging: ${charging},
              level: ${level},
              chargingTime: ${chargingTime},
              dischargingTime: ${dischargingTime},
              addEventListener: function() {},
              removeEventListener: function() {}
            };
            resolve(fakeBattery);
          });
        };
      }
    `);
  }
  
  // 混淆ClientRects和DOMRects
  obfuscateClientRects() {
    this.injectScript(`
      // 拦截Element.getBoundingClientRect
      const originalGetBoundingClientRect = Element.prototype.getBoundingClientRect;
      Element.prototype.getBoundingClientRect = function() {
        const rect = originalGetBoundingClientRect.apply(this);
        
        // 添加微小随机偏移
        const noise = 0.5;
        const result = {
          x: rect.x + (Math.random() * noise * 2 - noise),
          y: rect.y + (Math.random() * noise * 2 - noise),
          width: rect.width + (Math.random() * noise * 2 - noise),
          height: rect.height + (Math.random() * noise * 2 - noise),
          top: rect.top + (Math.random() * noise * 2 - noise),
          right: rect.right + (Math.random() * noise * 2 - noise),
          bottom: rect.bottom + (Math.random() * noise * 2 - noise),
          left: rect.left + (Math.random() * noise * 2 - noise),
          toJSON: rect.toJSON
        };
        
        return result;
      };
      
      // 拦截Element.getClientRects
      const originalGetClientRects = Element.prototype.getClientRects;
      Element.prototype.getClientRects = function() {
        const rects = originalGetClientRects.apply(this);
        
        // 创建一个新的DOMRectList
        const result = {
          length: rects.length,
          item: function(index) {
            return this[index];
          },
          [Symbol.iterator]: function* () {
            for (let i = 0; i < this.length; i++) {
              yield this[i];
            }
          }
        };
        
        // 添加微小随机偏移到每个DOMRect
        for (let i = 0; i < rects.length; i++) {
          const rect = rects[i];
          const noise = 0.5;
          
          result[i] = {
            x: rect.x + (Math.random() * noise * 2 - noise),
            y: rect.y + (Math.random() * noise * 2 - noise),
            width: rect.width + (Math.random() * noise * 2 - noise),
            height: rect.height + (Math.random() * noise * 2 - noise),
            top: rect.top + (Math.random() * noise * 2 - noise),
            right: rect.right + (Math.random() * noise * 2 - noise),
            bottom: rect.bottom + (Math.random() * noise * 2 - noise),
            left: rect.left + (Math.random() * noise * 2 - noise)
          };
        }
        
        return result;
      };
    `);
  }
  
  // 混淆Performance API
  obfuscatePerformanceAPI() {
    this.injectScript(`
      // 拦截performance.now()
      const originalNow = performance.now;
      performance.now = function() {
        const realTime = originalNow.call(performance);
        // 添加0-2ms的随机偏移
        return realTime + (Math.random() * 2);
      };
      
      // 拦截performance.timing
      if (performance.timing) {
        const originalTiming = performance.timing;
        Object.defineProperty(performance, 'timing', {
          get: function() {
            // 添加随机偏移到所有时间戳
            const noise = Math.floor(Math.random() * 10);
            const result = {};
            
            for (let key in originalTiming) {
              if (typeof originalTiming[key] === 'number') {
                result[key] = originalTiming[key] + noise;
              } else {
                result[key] = originalTiming[key];
              }
            }
            
            return result;
          }
        });
      }
    `);
  }
  
  // 混淆TCP/IP指纹
  obfuscateTCPFingerprint() {
    // 发送消息到后台脚本，请求更新TCP/IP指纹
    this.safeSendMessage({
      action: 'updateTCPFingerprint',
      profile: this.settings.tlsFingerprint.currentProfile
    });
    
    return true;
  }
  
  // 注入脚本到页面
  injectScript(scriptContent) {
    try {
      const script = document.createElement('script');
      script.textContent = scriptContent;
      document.documentElement.appendChild(script);
      script.remove();
    } catch (e) {
      console.error('指纹混淆脚本注入失败:', e);
    }
  }
}

// 创建并初始化指纹混淆器
const fingerprintObfuscator = new FingerprintObfuscator();

// 每30分钟更新一次设置
setInterval(() => {
  fingerprintObfuscator.loadSettings();
}, 30 * 60 * 1000); 