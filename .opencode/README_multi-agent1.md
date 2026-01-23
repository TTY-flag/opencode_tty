# Multi-Agent C/C++ Vulnerability Scanner

基于 [OpenCode](https://github.com/anomalyco/opencode) 的通用多 Agent C/C++ 源码漏洞扫描系统。

**通用性设计**: 本系统适用于任何 C/C++ 项目，不限于特定项目。

## 架构概览

```
┌─────────────────────────────────────────────────────────────┐
│                    Orchestrator (协调者)                      │
│                    mode: primary                             │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │  ArchitectureAnalysis │  ← 阶段1: 架构侦察
              │  • 项目架构分析        │
              │  • 攻击面识别          │
              │  • 威胁建模 (STRIDE)   │
              │  • 跨文件调用分析      │
              └───────────┬───────────┘
                          │
        ┌─────────────────┴─────────────────┐
        ▼                                   ▼
┌───────────────┐                   ┌───────────────┐
│DataFlowScanner│  ← 阶段2:         │SecurityAuditor│
│ • 内存安全     │    并行扫描       │ • 认证授权     │
│ • 输入验证     │                   │ • 密码学       │
│ • 注入检测     │                   │ • 跨文件追踪   │
│ • 跨文件追踪   │                   │               │
└───────┬───────┘                   └───────┬───────┘
        │                                   │
        └─────────────────┬─────────────────┘
                          ▼
              ┌───────────────────────┐
              │     Verification      │  ← 阶段3: 漏洞验证
              │   • 降低误报率         │
              │   • 置信度评分         │
              │   • 跨文件路径验证     │
              └───────────┬───────────┘
                          ▼
              ┌───────────────────────┐
              │       Reporter        │  ← 阶段4: 报告生成
              │   • Markdown 报告     │
              └───────────────────────┘
```

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
| dataflow-scanner | subagent | 内存/输入/注入漏洞、跨文件追踪     | @dataflow-scanner        |
| security-auditor | subagent | 认证/密码学审计、跨文件安全逻辑    | @security-auditor        |
| verification     | subagent | 漏洞验证、跨文件路径验证、降低误报 | @verification            |
| reporter         | subagent | 生成 Markdown 扫描报告             | @reporter                |

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
│   └── agent/              # Agent 定义
│       ├── orchestrator.md
│       ├── architecture.md
│       ├── dataflow-scanner.md
│       ├── security-auditor.md
│       ├── verification.md
│       └── reporter.md
└── scan-results/           # 扫描输出（自动创建）
    ├── .context/           # 结构化上下文（Agent 间通信）
    │   ├── project_model.json
    │   ├── call_graph.json
    │   ├── candidates.json
    │   └── verified.json
    └── report.md
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
