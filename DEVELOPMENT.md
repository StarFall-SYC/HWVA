# 开发文档

本文档主要面向开发者，提供Humanoid Web Vulnerability Assistant (HWVA)的技术实现细节、架构说明和贡献指南。

## 项目架构

HWVA采用标准的Chrome扩展架构，主要包含以下几个部分：

### 1. 核心组件

- **后台脚本** (`background.js`): 
  - 扩展的中央控制器
  - 处理消息通信
  - 管理浏览器指纹混淆
  - TCP/IP指纹管理
  - 漏洞数据存储与管理

- **内容脚本** (`content.js`):
  - DOM分析和操作
  - 漏洞测试实现
  - 漏洞检测逻辑
  - 页面交互模拟

- **指纹混淆模块** (`fingerprint.js`):
  - 浏览器指纹保护实现
  - 各种API的混淆方法
  - 动态指纹生成

- **人类行为模拟模块** (`human_behavior.js`):
  - 人格特征系统
  - 鼠标行为模拟
  - 键盘输入模拟
  - 滚动行为模拟
  - 视觉注意力模拟

### 2. 用户界面

- **弹出窗口** (`popup.html`, `popup.js`):
  - 主要设置界面
  - 扫描控制面板
  - 行为模拟配置
  - 指纹保护配置

- **报告页面** (`report.html`, `report.js`):
  - 漏洞报告展示
  - 数据可视化图表
  - 数据筛选与导出功能

### 3. 注入脚本

- **指纹混淆注入脚本** (`injected_scripts/fingerprint_obfuscator.js`):
  - 在页面上下文中运行的指纹混淆代码
  - 修改浏览器对象属性
  - 拦截和修改API调用

## 数据流

1. 用户在弹出窗口配置设置并启动扫描
2. 后台脚本接收命令，初始化指纹保护和行为模拟配置
3. 后台脚本通过 `chrome.tabs` API打开目标网站
4. 内容脚本在页面加载后被激活，进行DOM分析和漏洞测试
5. 人类行为模拟模块控制页面交互的方式和节奏
6. 检测到漏洞时，内容脚本发送消息给后台脚本
7. 后台脚本存储漏洞数据到 `chrome.storage`
8. 用户访问报告页面查看结果，报告页面从 `chrome.storage` 加载数据并展示

## 数据可视化实现详解

### 图表系统架构

报告系统使用原生Canvas API而非第三方库实现图表，主要原因是：
- 减少依赖，降低扩展体积
- 提高加载速度和性能
- 自定义功能的灵活性
- 避免潜在的安全问题

### 主要图表类型与实现

1. **漏洞类型分布图**
   - 实现：饼图，使用弧形路径绘制
   - 数据源：按漏洞类型(XSS, SQL注入等)分组统计
   - 文件位置：`report.js` 中的 `drawVulnerabilityChart` 函数
   - 关键技术：Canvas arc() 方法绘制扇形，动态计算扇区角度

2. **漏洞严重程度分布图**
   - 实现：饼图，使用弧形路径绘制
   - 数据源：按严重程度(严重, 高危, 中危, 低危)分组统计
   - 文件位置：`report.js` 中的 `drawSeverityChart` 函数
   - 特色：使用预定义颜色映射不同严重程度

3. **最近检测活动图**
   - 实现：折线图，使用线段和点连接
   - 数据源：最近7天按日期分组的漏洞检测数据
   - 文件位置：`report.js` 中的 `drawRecentActivityChart` 函数
   - 特色：绘制坐标轴和网格线，显示数据点标签

4. **站点漏洞分布图**
   - 实现：水平柱状图
   - 数据源：按域名分组的漏洞数量统计
   - 文件位置：`report.js` 中的 `drawDomainDistributionChart` 函数
   - 特色：限制显示前8个站点，溢出提示，文本截断处理

### 图表绘制流程

1. **数据准备阶段**
   - 从 `allVulnerabilities` 数组中提取分类数据
   - 计算总计和百分比
   - 准备颜色映射

2. **元素创建阶段**
   - 获取图表容器元素
   - 创建 Canvas 元素并调整尺寸
   - 获取绘图上下文 (ctx)

3. **绘制阶段**
   - 清空容器
   - 绘制图表背景与边框
   - 根据数据绘制图表元素(扇形、条形、线段等)
   - 添加标签和图例

4. **响应式处理**
   - 根据容器尺寸调整图表大小
   - 处理不同数据量的显示策略

5. **交互处理**
   - 图例项与图表的连接
   - 数据标签的格式化和定位

## 新功能开发指南

### 添加新的图表类型

1. 在 `report.js` 中创建新的绘图函数，如 `drawNewChartType()`
2. 在 `report.html` 中添加图表容器
3. 在 `updateStatistics()` 函数中调用新的绘图函数
4. 注意处理以下情况:
   - 无数据时的提示
   - 容器尺寸自适应
   - 颜色一致性
   - 图例格式

示例代码:
```javascript
function drawNewChartType() {
  // 获取图表容器
  const chartContainer = safeGetElement('new-chart-container');
  if (!chartContainer) return;
  
  // 清空容器
  chartContainer.innerHTML = '';
  
  // 检查数据是否为空
  if (noDataAvailable) {
    chartContainer.innerHTML = '<div class="no-data">暂无数据</div>';
    return;
  }
  
  // 创建Canvas元素
  const canvas = document.createElement('canvas');
  canvas.width = chartContainer.clientWidth;
  canvas.height = chartContainer.clientHeight;
  chartContainer.appendChild(canvas);
  
  // 获取绘图上下文
  const ctx = canvas.getContext('2d');
  if (!ctx) return;
  
  // 绘制图表...
}
```

### 增强漏洞检测

1. 在 `content.js` 的 `VulnerabilityDetector` 类中添加新的检测方法
2. 更新 `PayloadGenerator` 类以生成适合新漏洞类型的测试数据
3. 在 `background.js` 中添加相关处理逻辑
4. 更新报告系统以显示新类型的漏洞

### 改进人类行为模拟

1. 在 `human_behavior.js` 中添加新的行为模拟方法
2. 更新 `content.js` 中的调用逻辑
3. 如需用户配置，在 `popup.html` 和 `popup.js` 中添加对应设置项

## 代码风格指南

为保持代码一致性和可维护性，请遵循以下规范：

1. **JavaScript风格**
   - 使用ES6+语法，但注意浏览器兼容性
   - 使用2空格缩进
   - 使用分号结束语句
   - 使用camelCase命名变量和函数
   - 使用PascalCase命名类
   - 使用单引号字符串，模板字符串使用反引号

2. **注释规范**
   - 为所有函数添加描述注释，说明功能、参数和返回值
   - 为复杂逻辑添加详细的行内注释
   - 中文注释使用`UTF-8`编码

3. **安全编码原则**
   - 避免使用`eval`和`Function`构造函数
   - 避免使用`innerHTML`，优先使用`textContent`
   - 使用参数化方法处理用户输入
   - 安全地处理异常

## 测试指南

### 单元测试

目前项目未包含自动化测试，未来计划添加基于Jest的单元测试。

### 手动测试

开发新功能或修复bug后，请至少完成以下手动测试：

1. **基本功能测试**
   - 扩展能否正常加载和配置
   - 目标网站能否正常扫描
   - 报告能否正确显示

2. **人类行为模拟测试**
   - 鼠标移动是否自然
   - 键盘输入是否符合真实习惯
   - 滚动行为是否自然

3. **指纹保护测试**
   - 使用网站如https://amiunique.org/检查指纹是否被有效混淆
   - 验证各种API保护是否有效

4. **兼容性测试**
   - 在Chrome和Edge最新版本上测试
   - 不同操作系统(Windows, macOS, Linux)上测试

## 发布流程

1. 更新 `manifest.json` 中的版本号
2. 更新 `CHANGELOG.md` 添加新版本的变更记录
3. 创建发布分支，命名为 `release-vX.Y.Z`
4. 构建扩展包(ZIP文件)
5. 提交至Chrome网上应用店(如适用)

## 故障排除

### 常见问题及解决方案

1. **扩展无法加载**
   - 检查 `manifest.json` 格式是否正确
   - 检查权限设置是否合理
   - 检查控制台错误信息

2. **人类行为模拟不正常**
   - 检查 `human_behavior.js` 参数配置
   - 检查浏览器版本兼容性
   - 尝试调整模拟参数

3. **图表不显示或显示错误**
   - 检查 `report.js` 中的数据处理逻辑
   - 验证数据格式是否正确
   - 检查Canvas支持和兼容性

4. **消息通信问题**
   - 检查 `chrome.runtime.sendMessage` 调用
   - 确认接收方正确处理消息
   - 检查扩展权限是否足够

## 联系与支持

如有开发相关问题，请通过以下方式联系:

- 提交Issue到项目仓库
- 发送邮件至[开发团队邮箱]
- 加入开发者社区讨论组

## 贡献指南

欢迎贡献代码、提交bug报告或功能请求。贡献步骤:

1. Fork项目仓库
2. 创建功能分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m 'Add some amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 创建Pull Request

感谢您对Humanoid Web Vulnerability Assistant的贡献! 