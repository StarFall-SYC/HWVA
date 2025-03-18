# Humanoid Web Vulnerability Assistant (HWVA)

模拟人类操作行为的网站漏洞检测助手，合规实现多目标网站漏洞检测。

## 项目概述

Humanoid Web Vulnerability Assistant是一个浏览器扩展，专为网络安全工程师和白帽子设计，用于模拟人类行为检测网站漏洞。该工具严格遵循"人工测试"原则，不使用自动化扫描工具，符合漏洞赏金平台（如补天）的规定。

## 核心功能

- **人类行为模拟**：模拟真实人类操作习惯，包括鼠标轨迹、点击、滚动和输入行为
- **多站点批处理**：支持同时检查多个目标网站的漏洞
- **自动漏洞检测**：检测XSS、SQL注入、CSRF等常见漏洞
- **指纹混淆**：动态修改浏览器指纹，避免被目标网站识别为自动化工具
- **合规性保障**：自动解析robots.txt，尊重网站访问规则
- **结果报告**：生成详细的漏洞报告和数据可视化图表，方便分析和提交给漏洞赏金平台

## 技术特点

### 人类行为模拟系统
- **智能操作决策引擎**：基于视觉重要性识别可交互元素
- **自然鼠标轨迹**：使用贝塞尔曲线生成自然的鼠标移动轨迹
- **眼球移动模拟**：模拟人类视觉注意力模式
- **真实打字模式**：变速输入、随机错误和修正
- **自然滚动行为**：非线性页面滚动，模拟阅读节奏
- **人格类型系统**：支持条理型、冲动型、细致型和随意型四种人格，影响操作行为
- **疲劳与休息模拟**：模拟人类疲劳积累和定期休息行为
- **注意力分散模拟**：随机模拟注意力分散，增加行为真实性

### 指纹混淆系统
- **动态浏览器特征**：定期更改浏览器指纹
- **Canvas指纹混淆**：添加微小噪声，避免被识别
- **WebRTC保护**：防止IP地址泄露
- **硬件信息伪装**：修改CPU核心数、内存等硬件特征
- **字体和语言混淆**：随机化已安装字体和语言偏好
- **TCP/IP指纹混淆**：模拟不同浏览器的TCP/IP栈特征
- **电池状态API混淆**：随机化电池状态信息
- **ClientRects混淆**：为元素位置信息添加微小随机偏移
- **Performance API混淆**：修改时间测量API，防止基于时间的指纹识别

### 漏洞检测引擎
- **上下文感知测试**：根据页面内容动态选择测试策略
- **多种漏洞类型**：支持XSS、SQL注入、CSRF、敏感信息泄露等
- **智能Payload生成**：根据输入字段类型生成合适的测试数据
- **三重验证机制**：通过DOM分析、响应分析和状态比较确认漏洞

### 数据可视化与报告系统
- **漏洞类型分布图表**：直观展示不同类型漏洞的占比
- **严重程度分布图表**：分析漏洞严重程度的比例分布
- **最近检测活动图表**：跟踪7天内的漏洞发现趋势
- **站点漏洞分布图表**：分析各目标站点的漏洞分布情况
- **详细漏洞列表**：提供每个漏洞的详细信息和证据
- **多格式导出**：支持Markdown和CSV格式导出报告

## 最新优化内容

### 1. 增强的人类行为模拟
- **人格类型系统**：新增四种人格类型（条理型、冲动型、细致型、随意型），每种类型有不同的行为特征
- **高级鼠标轨迹**：使用Fitts定律和三次贝塞尔曲线生成更自然的鼠标移动轨迹
- **真实键盘输入**：模拟突发式输入模式、错误率和纠错行为
- **视觉注意力模拟**：模拟人类眼球运动和注视行为
- **阅读行为模拟**：基于文本长度和阅读速度计算阅读时间，支持扫描和深度阅读模式
- **疲劳与休息周期**：模拟人类疲劳积累和定期休息行为

### 2. 增强的指纹保护
- **动态指纹变化**：定期自动更新浏览器指纹，避免长时间使用同一指纹
- **TCP/IP指纹混淆**：模拟不同浏览器的TCP/IP栈特征，包括窗口大小、TTL值等
- **电池状态API混淆**：随机化电池状态信息，防止通过Battery API进行指纹识别
- **ClientRects混淆**：为元素位置信息添加微小随机偏移，防止基于布局的指纹识别
- **Performance API混淆**：修改时间测量API，防止基于时间的指纹识别

### 3. 改进的用户界面和数据可视化
- **行为模拟设置面板**：可视化配置人类行为模拟参数
- **指纹保护设置面板**：详细控制各种指纹保护机制
- **人格类型选择**：直观选择不同的人格类型，影响整体行为模式
- **实时反馈**：扫描过程中提供更详细的状态反馈
- **高级数据图表**：添加四种数据可视化图表，提升报告分析能力
- **交互式报告界面**：支持按类型、域名筛选漏洞数据

## 安装步骤

1. 克隆本仓库到本地
   ```
   git clone <repository-url>
   ```

2. 在Chrome/Edge浏览器中加载扩展：
   - 打开 `chrome://extensions` 或 `edge://extensions`
   - 开启"开发者模式"
   - 点击"加载已解压的扩展程序"
   - 选择本项目的 `browser_extension` 文件夹

## 使用方法

### 单站点检测
1. 点击浏览器工具栏中的扩展图标
2. 输入目标网站URL
3. 选择检测深度
4. 点击"开始检测"按钮

### 多站点批处理
1. 点击浏览器工具栏中的扩展图标
2. 切换到"批量扫描"标签
3. 在文本框中输入多个URL（每行一个）
4. 设置站点间检测间隔
5. 点击"开始批量检测"按钮

### 配置人类行为模拟
1. 点击浏览器工具栏中的扩展图标
2. 切换到"行为模拟"标签
3. 选择人格类型或自定义行为参数
4. 点击"保存行为设置"按钮

### 配置指纹保护
1. 点击浏览器工具栏中的扩展图标
2. 切换到"指纹保护"标签
3. 配置浏览器指纹、动态指纹和TCP/IP指纹设置
4. 点击"保存指纹设置"按钮

### 查看结果报告
1. 点击"查看检测报告"按钮
2. 在报告页面可以：
   - 查看漏洞类型和严重程度的分布图表
   - 查看最近7天的漏洞检测趋势
   - 分析不同站点的漏洞分布情况
   - 按类型或域名筛选漏洞列表
   - 导出报告为Markdown或CSV格式

## 漏洞检测原理

### XSS检测
- 注入特制的JavaScript代码，检测其执行情况
- 监控DOM变化，识别成功的XSS攻击
- 分析页面响应，查找XSS特征

### SQL注入检测
- 使用常见的SQL注入payload，监测数据库错误消息
- 分析页面内容变化，识别SQL注入漏洞
- 使用时间延迟技术检测盲注漏洞

### CSRF检测
- 分析表单是否含有CSRF保护机制
- 检查请求头中是否包含CSRF令牌
- 测试跨域请求是否成功

### 敏感信息泄露检测
- 扫描页面内容，查找可能的敏感信息（如身份证号、信用卡号）
- 分析HTML注释，查找开发者遗留的敏感信息
- 检查HTTP响应头，识别信息泄露

## 注意事项

- 本工具仅供安全专业人员在授权的情况下使用
- 使用前请确保已获得目标网站的明确授权
- 不要对关键业务系统或生产环境使用
- 遵守相关法律法规和道德准则

## 技术架构

- **前端**：JavaScript, HTML, CSS
- **浏览器API**：Chrome Extension API
- **行为模拟**：自定义的人类行为模拟算法
- **漏洞检测**：特征匹配和上下文分析
- **数据可视化**：Canvas绘图API

## 许可证

MIT

## 免责声明

本工具仅用于授权的安全测试，使用者应自行承担使用不当造成的一切后果。 