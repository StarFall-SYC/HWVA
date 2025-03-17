/**
 * 高级人类行为模拟模块
 * 用于模拟真实人类的浏览行为、注意力模式和操作习惯
 */

class HumanBehaviorSimulator {
  constructor() {
    // 基本人类特征
    this.traits = {
      // 注意力特征
      attention: {
        span: 15000 + Math.floor(Math.random() * 10000), // 注意力持续时间 (毫秒)
        distractionProbability: 0.05 + Math.random() * 0.1, // 分心概率
        focusDecayRate: 0.01 + Math.random() * 0.02, // 专注度衰减率
        currentFocus: 1.0, // 当前专注度 (0-1)
        lastFocusTime: Date.now() // 上次专注时间
      },
      
      // 阅读特征
      reading: {
        speed: 200 + Math.floor(Math.random() * 100), // 阅读速度 (每分钟字数)
        comprehensionLevel: 0.7 + Math.random() * 0.3, // 理解水平 (0-1)
        scanningProbability: 0.3 + Math.random() * 0.2, // 扫描概率 (跳读)
        regressionRate: 0.1 + Math.random() * 0.1 // 回读率
      },
      
      // 鼠标操作特征
      mouse: {
        speed: 800 + Math.floor(Math.random() * 400), // 鼠标移动速度 (像素/秒)
        precision: 0.8 + Math.random() * 0.2, // 精确度 (0-1)
        doubleClickInterval: 300 + Math.floor(Math.random() * 200), // 双击间隔 (毫秒)
        clickDelay: 50 + Math.floor(Math.random() * 100), // 点击延迟 (毫秒)
        jitterAmount: 0.5 + Math.random() * 1.5, // 抖动量 (像素)
        currentPosition: { x: 0, y: 0 } // 当前鼠标位置
      },
      
      // 键盘输入特征
      keyboard: {
        typingSpeed: 200 + Math.floor(Math.random() * 100), // 打字速度 (每分钟字符数)
        errorRate: 0.05 + Math.random() * 0.05, // 错误率 (0-1)
        correctionProbability: 0.8 + Math.random() * 0.2, // 纠错概率
        burstPattern: [
          // 输入突发模式 (连续输入字符数及间隔)
          { chars: 3 + Math.floor(Math.random() * 3), interval: 100 + Math.floor(Math.random() * 100) },
          { chars: 5 + Math.floor(Math.random() * 5), interval: 200 + Math.floor(Math.random() * 150) },
          { chars: 8 + Math.floor(Math.random() * 4), interval: 300 + Math.floor(Math.random() * 200) }
        ],
        currentBurst: 0 // 当前突发模式索引
      },
      
      // 滚动特征
      scrolling: {
        pattern: 'natural', // 滚动模式: 'natural', 'chunked', 'smooth'
        speed: 300 + Math.floor(Math.random() * 200), // 滚动速度 (像素/秒)
        pauseFrequency: 0.2 + Math.random() * 0.3, // 暂停频率
        pauseDuration: 500 + Math.floor(Math.random() * 1000), // 暂停持续时间 (毫秒)
        direction: 'vertical', // 滚动方向: 'vertical', 'horizontal', 'both'
        acceleration: 1.2 + Math.random() * 0.5, // 加速度
        deceleration: 0.8 + Math.random() * 0.2 // 减速度
      },
      
      // 视觉注意力特征
      visualAttention: {
        foveaRadius: 100 + Math.floor(Math.random() * 50), // 中央凹半径 (像素)
        peripheralRadius: 300 + Math.floor(Math.random() * 100), // 周边视觉半径 (像素)
        saccadeSpeed: 400 + Math.floor(Math.random() * 200), // 眼跳速度 (像素/秒)
        fixationDuration: 200 + Math.floor(Math.random() * 100), // 注视持续时间 (毫秒)
        currentPosition: { x: 0, y: 0 } // 当前视觉焦点
      },
      
      // 决策特征
      decision: {
        impulsivity: 0.2 + Math.random() * 0.3, // 冲动性 (0-1)
        thoroughness: 0.6 + Math.random() * 0.4, // 彻底性 (0-1)
        explorationRate: 0.3 + Math.random() * 0.4, // 探索率
        riskAversion: 0.5 + Math.random() * 0.5 // 风险规避程度 (0-1)
      }
    };
    
    // 行为状态
    this.state = {
      currentActivity: 'idle', // 当前活动: 'idle', 'reading', 'searching', 'interacting'
      fatigue: 0, // 疲劳度 (0-1)
      lastBreakTime: Date.now(), // 上次休息时间
      breakInterval: 15 * 60 * 1000 + Math.floor(Math.random() * 10 * 60 * 1000), // 休息间隔 (毫秒)
      breakDuration: 30 * 1000 + Math.floor(Math.random() * 60 * 1000), // 休息持续时间 (毫秒)
      interactionHistory: [], // 交互历史
      lastInteractionTime: Date.now() // 上次交互时间
    };
    
    // 初始化
    this.initializeRandomPersonality();
  }
  
  // 初始化随机人格特征
  initializeRandomPersonality() {
    // 人格类型: 'methodical', 'impulsive', 'thorough', 'casual'
    const personalityTypes = ['methodical', 'impulsive', 'thorough', 'casual'];
    this.personality = personalityTypes[Math.floor(Math.random() * personalityTypes.length)];
    
    // 根据人格类型调整特征
    switch (this.personality) {
      case 'methodical':
        this.traits.decision.thoroughness += 0.2;
        this.traits.decision.impulsivity -= 0.1;
        this.traits.reading.comprehensionLevel += 0.1;
        this.traits.mouse.precision += 0.1;
        break;
      case 'impulsive':
        this.traits.decision.impulsivity += 0.2;
        this.traits.decision.thoroughness -= 0.1;
        this.traits.mouse.speed += 100;
        this.traits.scrolling.speed += 100;
        break;
      case 'thorough':
        this.traits.decision.thoroughness += 0.3;
        this.traits.reading.comprehensionLevel += 0.2;
        this.traits.reading.speed -= 50;
        this.traits.attention.span += 5000;
        break;
      case 'casual':
        this.traits.decision.explorationRate += 0.2;
        this.traits.scrolling.speed += 50;
        this.traits.reading.scanningProbability += 0.1;
        this.traits.attention.distractionProbability += 0.1;
        break;
    }
    
    console.log(`[人类行为] 已初始化人格类型: ${this.personality}`);
  }
  
  // 模拟人类鼠标移动
  async simulateHumanMouseMovement(startX, startY, endX, endY) {
    // 更新当前鼠标位置
    this.traits.mouse.currentPosition = { x: startX, y: startY };
    
    // 计算距离和所需时间
    const distance = Math.sqrt(Math.pow(endX - startX, 2) + Math.pow(endY - startY, 2));
    const baseTime = distance / this.traits.mouse.speed * 1000;
    
    // 应用Fitts定律: 移动时间与距离和目标大小有关
    // T = a + b * log2(2D/W)，其中a和b是经验常数，D是距离，W是目标宽度
    // 这里我们简化为目标宽度固定为30像素
    const targetWidth = 30;
    const fittsTime = 100 + 150 * Math.log2(2 * distance / targetWidth);
    
    // 最终移动时间 (基础时间和Fitts定律的加权平均)
    const movementTime = 0.3 * baseTime + 0.7 * fittsTime;
    
    // 生成贝塞尔曲线控制点 (模拟自然曲线)
    const controlPoint1 = {
      x: startX + (endX - startX) / 3 + (Math.random() * 100 - 50),
      y: startY + (endY - startY) / 3 + (Math.random() * 100 - 50)
    };
    
    const controlPoint2 = {
      x: startX + 2 * (endX - startX) / 3 + (Math.random() * 100 - 50),
      y: startY + 2 * (endY - startY) / 3 + (Math.random() * 100 - 50)
    };
    
    // 生成轨迹点
    const trajectory = [];
    const steps = Math.max(10, Math.ceil(movementTime / 16)); // 每16ms一个点 (约60fps)
    
    for (let i = 0; i <= steps; i++) {
      const t = i / steps;
      
      // 三次贝塞尔曲线公式
      const x = Math.pow(1 - t, 3) * startX + 
                3 * Math.pow(1 - t, 2) * t * controlPoint1.x + 
                3 * (1 - t) * Math.pow(t, 2) * controlPoint2.x + 
                Math.pow(t, 3) * endX;
                
      const y = Math.pow(1 - t, 3) * startY + 
                3 * Math.pow(1 - t, 2) * t * controlPoint1.y + 
                3 * (1 - t) * Math.pow(t, 2) * controlPoint2.y + 
                Math.pow(t, 3) * endY;
      
      // 添加微小抖动 (手部震颤)
      const jitter = this.traits.mouse.jitterAmount;
      const jitteredX = x + (Math.random() * jitter * 2 - jitter);
      const jitteredY = y + (Math.random() * jitter * 2 - jitter);
      
      trajectory.push({
        x: jitteredX,
        y: jitteredY,
        t: Date.now() + (i / steps) * movementTime
      });
    }
    
    // 返回轨迹和总时间
    return {
      trajectory,
      totalTime: movementTime
    };
  }
  
  // 模拟人类点击
  async simulateHumanClick(x, y) {
    // 先移动鼠标到目标位置
    const movement = await this.simulateHumanMouseMovement(
      this.traits.mouse.currentPosition.x,
      this.traits.mouse.currentPosition.y,
      x, y
    );
    
    // 等待鼠标移动完成
    await new Promise(resolve => setTimeout(resolve, movement.totalTime));
    
    // 更新鼠标位置
    this.traits.mouse.currentPosition = { x, y };
    
    // 点击前的微小延迟 (决策时间)
    const clickDelay = this.traits.mouse.clickDelay * (0.8 + Math.random() * 0.4);
    await new Promise(resolve => setTimeout(resolve, clickDelay));
    
    // 记录交互
    this.recordInteraction('click', { x, y });
    
    // 返回总操作时间
    return movement.totalTime + clickDelay;
  }
  
  // 模拟人类键盘输入
  async simulateHumanTyping(text) {
    if (!text) return 0;
    
    let totalTime = 0;
    let typedText = '';
    let i = 0;
    
    while (i < text.length) {
      // 计算当前突发模式
      const burstIndex = this.traits.keyboard.currentBurst;
      const burst = this.traits.keyboard.burstPattern[burstIndex];
      
      // 计算本次突发要输入的字符数
      const charsToType = Math.min(burst.chars, text.length - i);
      
      // 对每个字符进行处理
      for (let j = 0; j < charsToType; j++) {
        // 检查是否出错
        const makeError = Math.random() < this.traits.keyboard.errorRate;
        
        if (makeError) {
          // 输入错误字符
          const errorChar = this.getRandomChar();
          typedText += errorChar;
          
          // 等待一小段时间
          const charTime = 60000 / this.traits.keyboard.typingSpeed;
          await new Promise(resolve => setTimeout(resolve, charTime));
          totalTime += charTime;
          
          // 检查是否会纠正错误
          const willCorrect = Math.random() < this.traits.keyboard.correctionProbability;
          
          if (willCorrect) {
            // 删除错误字符
            typedText = typedText.slice(0, -1);
            
            // 等待一小段时间 (发现并纠正错误)
            const correctionTime = 300 + Math.random() * 200;
            await new Promise(resolve => setTimeout(resolve, correctionTime));
            totalTime += correctionTime;
            
            // 输入正确字符
            typedText += text[i + j];
          }
        } else {
          // 输入正确字符
          typedText += text[i + j];
        }
        
        // 字符间的微小延迟
        const charTime = 60000 / this.traits.keyboard.typingSpeed * (0.8 + Math.random() * 0.4);
        await new Promise(resolve => setTimeout(resolve, charTime));
        totalTime += charTime;
      }
      
      // 突发输入后的暂停
      await new Promise(resolve => setTimeout(resolve, burst.interval));
      totalTime += burst.interval;
      
      // 更新索引
      i += charsToType;
      
      // 切换到下一个突发模式
      this.traits.keyboard.currentBurst = (burstIndex + 1) % this.traits.keyboard.burstPattern.length;
    }
    
    // 记录交互
    this.recordInteraction('typing', { text: typedText });
    
    return totalTime;
  }
  
  // 模拟人类滚动
  async simulateHumanScrolling(distance, direction = 'vertical') {
    // 根据滚动模式确定滚动行为
    let scrollTime = 0;
    let scrollSteps = [];
    
    // 计算基础滚动时间
    const baseTime = Math.abs(distance) / this.traits.scrolling.speed * 1000;
    
    switch (this.traits.scrolling.pattern) {
      case 'natural':
        // 自然滚动: 先加速，后减速
        scrollTime = baseTime;
        
        // 生成滚动步骤
        const steps = Math.max(5, Math.ceil(scrollTime / 50)); // 每50ms一步
        
        for (let i = 0; i <= steps; i++) {
          const t = i / steps;
          
          // 使用缓动函数模拟自然滚动
          // 先加速后减速的三次方缓动
          const progress = t < 0.5 
            ? 4 * t * t * t 
            : 1 - Math.pow(-2 * t + 2, 3) / 2;
          
          // 计算当前步骤的滚动距离
          const currentDistance = distance * progress;
          
          // 添加微小随机偏移 (模拟不精确滚动)
          const jitter = Math.random() * 2 - 1;
          
          scrollSteps.push({
            distance: currentDistance + jitter,
            time: Date.now() + t * scrollTime
          });
        }
        break;
        
      case 'chunked':
        // 分块滚动: 多次小滚动
        const chunkSize = 120 + Math.floor(Math.random() * 80); // 每块滚动距离
        const chunks = Math.ceil(Math.abs(distance) / chunkSize);
        
        let accumulatedDistance = 0;
        let accumulatedTime = 0;
        
        for (let i = 0; i < chunks; i++) {
          // 计算当前块的滚动距离
          const remainingDistance = distance - accumulatedDistance;
          const currentChunkSize = Math.min(chunkSize, Math.abs(remainingDistance));
          const currentChunkDistance = remainingDistance > 0 ? currentChunkSize : -currentChunkSize;
          
          // 计算当前块的滚动时间
          const chunkTime = currentChunkSize / this.traits.scrolling.speed * 1000;
          
          // 添加到滚动步骤
          scrollSteps.push({
            distance: accumulatedDistance + currentChunkDistance,
            time: Date.now() + accumulatedTime + chunkTime
          });
          
          accumulatedDistance += currentChunkDistance;
          accumulatedTime += chunkTime;
          
          // 块间暂停
          if (i < chunks - 1 && Math.random() < this.traits.scrolling.pauseFrequency) {
            const pauseTime = this.traits.scrolling.pauseDuration * (0.8 + Math.random() * 0.4);
            accumulatedTime += pauseTime;
          }
        }
        
        scrollTime = accumulatedTime;
        break;
        
      case 'smooth':
        // 平滑滚动: 恒定速度
        scrollTime = baseTime;
        
        // 生成滚动步骤
        const smoothSteps = Math.max(5, Math.ceil(scrollTime / 50));
        
        for (let i = 0; i <= smoothSteps; i++) {
          const t = i / smoothSteps;
          scrollSteps.push({
            distance: distance * t,
            time: Date.now() + t * scrollTime
          });
        }
        break;
    }
    
    // 记录交互
    this.recordInteraction('scroll', { 
      distance, 
      direction, 
      pattern: this.traits.scrolling.pattern 
    });
    
    return {
      scrollSteps,
      totalTime: scrollTime
    };
  }
  
  // 模拟视觉注意力移动
  async simulateVisualAttention(targetX, targetY) {
    // 当前视觉焦点位置
    const { x: currentX, y: currentY } = this.traits.visualAttention.currentPosition;
    
    // 计算距离
    const distance = Math.sqrt(Math.pow(targetX - currentX, 2) + Math.pow(targetY - currentY, 2));
    
    // 如果目标在当前视觉范围内，直接关注
    if (distance <= this.traits.visualAttention.foveaRadius) {
      this.traits.visualAttention.currentPosition = { x: targetX, y: targetY };
      return 0;
    }
    
    // 计算眼跳时间
    const saccadeTime = distance / this.traits.visualAttention.saccadeSpeed * 1000;
    
    // 生成视觉轨迹
    const visualTrajectory = [];
    const steps = Math.max(3, Math.ceil(saccadeTime / 16));
    
    for (let i = 0; i <= steps; i++) {
      const t = i / steps;
      
      // 使用缓动函数模拟眼跳
      // 眼跳通常是快速加速然后迅速减速
      const progress = this.easeOutQuint(t);
      
      const x = currentX + (targetX - currentX) * progress;
      const y = currentY + (targetY - currentY) * progress;
      
      visualTrajectory.push({
        x, y,
        t: Date.now() + t * saccadeTime
      });
    }
    
    // 更新当前视觉焦点
    this.traits.visualAttention.currentPosition = { x: targetX, y: targetY };
    
    // 注视时间
    const fixationTime = this.traits.visualAttention.fixationDuration * (0.8 + Math.random() * 0.4);
    
    // 记录交互
    this.recordInteraction('visualAttention', { 
      from: { x: currentX, y: currentY },
      to: { x: targetX, y: targetY },
      saccadeTime,
      fixationTime
    });
    
    return {
      visualTrajectory,
      totalTime: saccadeTime + fixationTime
    };
  }
  
  // 模拟注意力分散
  simulateDistraction() {
    // 检查是否会分心
    const willDistract = Math.random() < this.traits.attention.distractionProbability;
    
    if (willDistract) {
      // 计算分心持续时间
      const distractionTime = 1000 + Math.random() * 3000;
      
      // 降低当前专注度
      this.traits.attention.currentFocus *= 0.7;
      
      // 记录交互
      this.recordInteraction('distraction', { 
        duration: distractionTime,
        newFocusLevel: this.traits.attention.currentFocus
      });
      
      return distractionTime;
    }
    
    return 0;
  }
  
  // 模拟疲劳积累
  updateFatigue() {
    // 计算距离上次休息的时间
    const timeSinceLastBreak = Date.now() - this.state.lastBreakTime;
    
    // 增加疲劳度 (随时间线性增加)
    this.state.fatigue += timeSinceLastBreak / (8 * 60 * 60 * 1000); // 8小时达到最大疲劳
    
    // 限制疲劳度在0-1范围内
    this.state.fatigue = Math.min(1, Math.max(0, this.state.fatigue));
    
    // 检查是否需要休息
    if (timeSinceLastBreak > this.state.breakInterval) {
      return this.takeBreak();
    }
    
    return 0;
  }
  
  // 模拟休息
  takeBreak() {
    // 计算休息时间
    const breakTime = this.state.breakDuration * (0.8 + Math.random() * 0.4);
    
    // 更新状态
    this.state.lastBreakTime = Date.now();
    this.state.fatigue *= 0.5; // 休息后疲劳减半
    
    // 重置专注度
    this.traits.attention.currentFocus = 0.9 + Math.random() * 0.1;
    
    // 记录交互
    this.recordInteraction('break', { 
      duration: breakTime,
      newFatigueLevel: this.state.fatigue
    });
    
    return breakTime;
  }
  
  // 记录交互历史
  recordInteraction(type, details) {
    this.state.interactionHistory.push({
      type,
      details,
      timestamp: Date.now()
    });
    
    // 限制历史记录长度
    if (this.state.interactionHistory.length > 100) {
      this.state.interactionHistory.shift();
    }
    
    // 更新最后交互时间
    this.state.lastInteractionTime = Date.now();
  }
  
  // 获取随机字符 (用于模拟打字错误)
  getRandomChar() {
    const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    return chars.charAt(Math.floor(Math.random() * chars.length));
  }
  
  // 缓动函数: easeOutQuint
  easeOutQuint(t) {
    return 1 - Math.pow(1 - t, 5);
  }
}

// 导出模块
window.HumanBehaviorSimulator = HumanBehaviorSimulator; 