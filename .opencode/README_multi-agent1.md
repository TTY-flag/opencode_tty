# Multi-Agent C/C++ Vulnerability Scanner

基于 [OpenCode](https://github.com/anomalyco/opencode) 的通用多 Agent C/C++ 源码漏洞扫描系统。

**通用性设计**: 本系统适用于任何 C/C++ 项目，不限于特定项目。

## 架构概览

```
┌─────────────────────────────────────────────────────────────┐
│                    Orchestrator (协调者)                      │
│                    mode: primary                             │
│              输出: scan_log.json (扫描日志)                   │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │  ArchitectureAnalysis │  ← 阶段1: 架构侦察
              │  • 项目架构分析        │
              │  • 攻击面识别          │
              │  • 威胁建模 (STRIDE)   │
              │  • 跨文件调用分析      │
              │                       │
              │  输出:                 │
              │  • project_model.json │
              │  • call_graph.json    │
              │  • threat_analysis_   │
              │    report.md          │
              └───────────┬───────────┘
                          │
        ┌─────────────────┴─────────────────┐
        ▼                                   ▼
┌───────────────────┐               ┌───────────────┐
│ DataFlowScanner   │  ← 阶段2:     │SecurityAuditor│
│   (协调者)        │    并行扫描   │ • 认证授权     │
│                   │               │ • 密码学       │
│ 输入:             │               │ • 跨文件追踪   │
│ • project_model   │               │               │
│ • call_graph      │               │ 输入:         │
│                   │               │ • project_model│
│ ┌───────────────┐ │               │ • call_graph  │
│ │ Module Scanner│ │               │               │
│ │  (模块1)      │ │               │ 输出:         │
│ ├───────────────┤ │               │ • candidates  │
│ │ Module Scanner│ │               │   .json       │
│ │  (模块2)      │ │               └───────┬───────┘
│ ├───────────────┤ │                       │
│ │ Module Scanner│ │                       │
│ │  (模块N)      │ │                       │
│ └───────────────┘ │                       │
│                   │                       │
│ 输出: candidates  │                       │
│       .json       │                       │
└─────────┬─────────┘                       │
          │                                 │
          └─────────────────┬───────────────┘
                            ▼
              ┌───────────────────────┐
              │     Verification      │  ← 阶段3: 漏洞验证
              │   • 降低误报率         │
              │   • 置信度评分         │
              │   • 跨文件路径验证     │
              │                       │
              │   输入: candidates.json│
              │   输出: verified.json │
              └───────────┬───────────┘
                          ▼
              ┌───────────────────────┐
              │       Reporter        │  ← 阶段4: 报告生成
              │   • Markdown 报告     │
              │                       │
              │   输入:               │
              │   • verified.json    │
              │   • project_model    │
              │                       │
              │   输出: report.md     │
              └───────────────────────┘
```

## Agent 输入输出详解

```
┌──────────────────────────────────────────────────────────────────────────┐
│                           数据流向图                                      │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  源代码 ──────────────────────────────────────────────────────────────┐  │
│     │                                                                 │  │
│     ▼                                                                 │  │
│  ┌─────────────┐    project_model.json    ┌─────────────────────┐    │  │
│  │ architecture│ ──────────────────────▶ │ dataflow-scanner    │    │  │
│  │             │    call_graph.json       │     (协调者)         │    │  │
│  │             │ ──────────────────────▶ │          │          │    │  │
│  │             │                          │          ▼          │    │  │
│  │             │                          │ ┌─────────────────┐ │    │  │
│  │             │                          │ │ module-scanner  │ │    │  │
│  │             │    project_model.json    │ │ (IPC模块)       │ │    │  │
│  │             │ ──────────────────────▶ │ ├─────────────────┤ │    │  │
│  │             │    call_graph.json       │ │ module-scanner  │ │    │  │
│  │             │ ──────────────────────▶ │ │ (插件模块)      │ │    │  │
│  └─────────────┘                          │ ├─────────────────┤ │    │  │
│         │                                 │ │ module-scanner  │ │    │  │
│         │    threat_analysis_report.md    │ │ (其他模块...)   │ │    │  │
│         └──────────────────────────────▶ │ └─────────────────┘ │    │  │
│                                           └──────────┬──────────┘    │  │
│                                                      │               │  │
│  ┌─────────────┐    project_model.json               │               │  │
│  │ security-   │ ◀──────────────────────             │               │  │
│  │ auditor     │    call_graph.json                  │               │  │
│  │             │ ◀──────────────────────             │               │  │
│  └──────┬──────┘                                     │               │  │
│         │                                            │               │  │
│         │    candidates.json                         │               │  │
│         └────────────────────┬───────────────────────┘               │  │
│                              ▼                                       │  │
│                    ┌─────────────────┐                               │  │
│                    │  verification   │                               │  │
│                    │                 │                               │  │
│                    │ candidates.json │                               │  │
│                    │       ▼         │                               │  │
│                    │ verified.json   │                               │  │
│                    └────────┬────────┘                               │  │
│                             │                                        │  │
│                             ▼                                        │  │
│                    ┌─────────────────┐                               │  │
│                    │    reporter     │                               │  │
│                    │                 │                               │  │
│                    │ verified.json   │                               │  │
│                    │ project_model   │                               │  │
│                    │       ▼         │                               │  │
│                    │   report.md     │ ─────────────────────────────▶│  │
│                    └─────────────────┘                      最终报告  │  │
│                                                                      │  │
└──────────────────────────────────────────────────────────────────────────┘
```

### 各 Agent 输入输出一览

| Agent | 输入 | 输出 | 说明 |
|-------|------|------|------|
| **orchestrator** | 用户指令 | `scan_log.json` | 协调全流程，记录扫描日志 |
| **architecture** | 源代码 | `project_model.json`<br>`call_graph.json`<br>`threat_analysis_report.md` | 架构分析、威胁建模 |
| **dataflow-scanner** | `project_model.json`<br>`call_graph.json` | `candidates.json` | 协调模块扫描 + 跨模块分析 |
| **dataflow-module-scanner** | 模块文件列表<br>调用图子集 | 模块内漏洞<br>跨模块数据流提示 | 单模块污点分析（子Agent） |
| **security-auditor** | `project_model.json`<br>`call_graph.json` | `candidates.json` | 安全逻辑审计 |
| **verification** | `candidates.json` | `verified.json` | 漏洞验证、置信度评分 |
| **reporter** | `verified.json`<br>`project_model.json` | `report.md` | 生成最终报告 |

## 核心特性

- **跨文件分析**: 追踪跨越多个文件的数据流和调用链（至少 3 层深度）
- **误报过滤**: 通过置信度评分系统有效降低误报率
- **文档优先**: 架构分析优先读取项目文档，提高分析准确性
- **代码可追溯**: 报告中所有漏洞都包含精确的文件路径和行号

## 快速开始

### 1. 安装 OpenCode

```bash
# NPM
npm i -g opencode-ai@latest

# Homebrew (macOS/Linux)
brew install anomalyco/tap/opencode

# Windows (Scoop)
scoop bucket add extras; scoop install extras/opencode
```

### 2. 克隆本项目到你的 C/C++ 项目

将 `.opencode/` 目录和 `opencode.json` 复制到你要扫描的 C/C++ 项目根目录。

### 3. 启动扫描

```bash
cd your-c-project
opencode
```

### 4. 调用扫描

在 OpenCode 中输入：

```
@orchestrator 请扫描这个项目的安全漏洞
```

或单独调用某个 Agent：

```
@architecture 分析项目架构
@dataflow-scanner 扫描内存安全问题
@security-auditor 审计认证相关代码
```

## Agent 说明

| Agent            | Mode     | 职责                               | 调用方式                 |
| ---------------- | -------- | ---------------------------------- | ------------------------ |
| orchestrator     | primary  | 协调整个扫描流程                   | Tab 切换或 @orchestrator |
| architecture     | subagent | 架构分析、威胁建模、跨文件调用图   | @architecture            |
| dataflow-scanner | subagent | **协调者**：按模块调度子Agent扫描  | @dataflow-scanner        |
| dataflow-module-scanner | subagent | 单模块污点分析（由协调者调度） | 由 dataflow-scanner 调用 |
| security-auditor | subagent | 认证/密码学审计、跨文件安全逻辑    | @security-auditor        |
| verification     | subagent | 漏洞验证、跨文件路径验证、降低误报 | @verification            |
| reporter         | subagent | 生成 Markdown 扫描报告             | @reporter                |

### DataFlow Scanner 层级架构

为解决大项目上下文爆炸问题，`dataflow-scanner` 采用层级架构：

```
@dataflow-scanner (协调者)
    │
    ├── 读取 project_model.json 获取模块列表
    │
    ├── @dataflow-module-scanner (IPC通信模块)
    │       └── 模块内污点分析 + 标记跨模块数据流
    │
    ├── @dataflow-module-scanner (插件系统模块)
    │       └── 模块内污点分析 + 标记跨模块数据流
    │
    ├── @dataflow-module-scanner (其他模块...)
    │       └── ...
    │
    ├── 收集所有模块的候选漏洞
    │
    └── 执行跨模块数据流分析
            └── 匹配模块间的数据流出/流入点
```

**优势**：
- 每个子 Agent 只处理一个模块，避免上下文爆炸
- 模块内聚性好，分析更完整
- 协调者负责跨模块分析，捕获模块边界漏洞

## 检测能力

### 数据流漏洞 (DataFlowScanner)

- 缓冲区溢出 (CWE-120, CWE-121, CWE-122)
- Use-After-Free (CWE-416)
- 双重释放 (CWE-415)
- 整数溢出 (CWE-190)
- 路径遍历 (CWE-22)
- 命令注入 (CWE-78)
- 格式化字符串 (CWE-134)

### 安全审计 (SecurityAuditor)

- 硬编码凭证 (CWE-798)
- 弱密码学 (CWE-327, CWE-328)
- 不安全随机数 (CWE-338)
- 时序攻击 (CWE-208)
- TLS 配置问题
- 权限提升风险
- 认证绕过

## 跨文件分析

系统支持跨文件数据流追踪，能够发现跨越多个源文件的漏洞：

```
recv() [network.c]           ← 外部输入
  → handle_request() [server.c]
    → parse_header() [request.c]
      → strcpy() [request.c]  ← 漏洞点
```

每个 Agent 都具备：

- LSP 优先的符号解析（Go to Definition / Find References）
- grep 作为 LSP 不可用时的回退
- 至少 3 层调用链深度
- 参数传递追踪
- 全局变量跨文件使用检测

## 置信度评分

系统使用 0-100 的置信度评分来减少误报：

| 分数   | 等级           | 处理方式        |
| ------ | -------------- | --------------- |
| 80-100 | CONFIRMED      | ✅ 报告         |
| 60-79  | LIKELY         | ✅ 报告         |
| 40-59  | POSSIBLE       | ⚠️ 低优先级报告 |
| 0-39   | FALSE_POSITIVE | ❌ 不报告       |

评分因素：

- 可达性（外部输入 +30 / 仅内部调用 +5）
- 数据可控性（完全可控 +25 / 部分可控 +15）
- 缓解措施（边界检查 -15 / 输入验证 -20）
- 上下文（测试代码 -50 / static 函数 -15）

## 报告结构

生成的 `scan-results/report.md` 包含：

1. **扫描摘要**: 漏洞统计表格 + Top 5 关键漏洞
2. **攻击面分析**: 入口点和外部接口列表
3. **漏洞详情**: 按严重性分组，每个漏洞包含代码片段和达成路径

## 项目结构

```
your-project/
├── .opencode/
│   └── agent/                      # Agent 定义
│       ├── orchestrator.md         # 扫描协调者
│       ├── architecture.md         # 架构分析
│       ├── dataflow-scanner.md     # 数据流扫描协调者
│       ├── dataflow-module-scanner.md  # 模块级扫描子Agent
│       ├── security-auditor.md     # 安全审计
│       ├── verification.md         # 漏洞验证
│       └── reporter.md             # 报告生成
└── scan-results/                   # 扫描输出（自动创建）
    ├── .context/                   # 结构化上下文（Agent 间通信）
    │   ├── project_model.json      # 项目模型（architecture 输出）
    │   ├── call_graph.json         # 调用图（architecture 输出）
    │   ├── candidates.json         # 候选漏洞（scanner 输出）
    │   ├── verified.json           # 验证后漏洞（verification 输出）
    │   └── scan_log.json           # 扫描日志（orchestrator 输出）
    ├── threat_analysis_report.md   # 威胁分析报告（architecture 输出）
    └── report.md                   # 最终漏洞报告（reporter 输出）
```

## 适用场景

本扫描系统适用于任何 C/C++ 项目，包括但不限于：

- Web 服务器
- 数据库系统
- 网络库
- 操作系统组件
- 嵌入式系统固件
- 命令行工具
- 库和框架

## 参考资料

- [OpenCode 文档](https://opencode.ai/docs/)
- [OpenCode Agent 配置](https://opencode.ai/docs/agents/)
- [CWE 漏洞分类](https://cwe.mitre.org/)
- [STRIDE 威胁模型](https://docs.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats)

## 许可证

MIT License
