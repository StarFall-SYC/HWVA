/**
 * 浏览器指纹混淆注入脚本
 * 此文件包含用于混淆浏览器指纹的函数
 */

// 混淆用户代理
function obfuscateUserAgent(userAgent) {
  Object.defineProperty(navigator, 'userAgent', {
    get: function() { return userAgent; }
  });
}

// 混淆屏幕分辨率
function obfuscateScreenResolution(width, height) {
  Object.defineProperty(screen, 'width', {
    get: function() { return width; }
  });
  Object.defineProperty(screen, 'height', {
    get: function() { return height; }
  });
  Object.defineProperty(screen, 'availWidth', {
    get: function() { return width; }
  });
  Object.defineProperty(screen, 'availHeight', {
    get: function() { return height; }
  });
  Object.defineProperty(window, 'innerWidth', {
    get: function() { return width; }
  });
  Object.defineProperty(window, 'innerHeight', {
    get: function() { return height; }
  });
  Object.defineProperty(window, 'outerWidth', {
    get: function() { return width; }
  });
  Object.defineProperty(window, 'outerHeight', {
    get: function() { return height; }
  });
}

// 混淆硬件信息
function obfuscateHardwareInfo(hardwareConcurrency, deviceMemory) {
  Object.defineProperty(navigator, 'hardwareConcurrency', {
    get: function() { return hardwareConcurrency; }
  });
  
  Object.defineProperty(navigator, 'deviceMemory', {
    get: function() { return deviceMemory; }
  });
}

// 混淆语言设置
function obfuscateLanguages(languages, language) {
  Object.defineProperty(navigator, 'languages', {
    get: function() { return languages; }
  });
  
  Object.defineProperty(navigator, 'language', {
    get: function() { return language; }
  });
}

// 导出函数
window.fingerprintObfuscator = {
  obfuscateUserAgent,
  obfuscateScreenResolution,
  obfuscateHardwareInfo,
  obfuscateLanguages
}; 