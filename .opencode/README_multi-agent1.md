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
              │  • LSP 可用性检测      │
              │                       │
              │  输出:                 │
              │  • project_model.json │
              │  • call_graph.json    │
              │  • threat_analysis_   │
              │    report.md          │
              └───────────┬───────────┘
                          │
          ✅ 必须等待 ArchitectureAnalysis 完成
          （project_model.json + call_graph.json 写入成功）
                          │
        ┌─────────────────┴─────────────────┐
        ▼                                   ▼
┌───────────────────┐               ┌───────────────────┐
│ DataFlowScanner   │  ← 阶段2:     │ SecurityAuditor   │
│   (协调者)        │    并行扫描   │   (协调者)         │
│                   │               │                   │
│ ┌───────────────┐ │               │ ┌───────────────┐ │
│ │ Module Scanner│ │               │ │ Module Scanner│ │
│ │  (模块1)      │ │               │ │  (模块1)      │ │
│ ├───────────────┤ │               │ ├───────────────┤ │
│ │ Module Scanner│ │               │ │ Module Scanner│ │
│ │  (模块2)      │ │               │ │  (模块2)      │ │
│ ├───────────────┤ │               │ ├───────────────┤ │
│ │ Module Scanner│ │               │ │ Module Scanner│ │
│ │  (模块N)      │ │               │ │  (模块N)      │ │
│ └───────────────┘ │               │ └───────────────┘ │
│ + 跨模块数据流分析│               │ + 跨模块安全分析  │
│ + merge-json 合并 │               │ + merge-json 合并 │
│                   │               │                   │
│ 输出: candidates  │               │ 输出: candidates  │
│       _df.json    │               │       _sec.json   │
└─────────┬─────────┘               └─────────┬─────────┘
          │                                   │
          └─────────────────┬─────────────────┘
                            ▼
              ┌───────────────────────┐
              │  Verification (协调者) │  ← 阶段3: 漏洞验证
              │   • 合并 + 去重        │
              │   • 一票否决过滤       │
              │   • 置信度评分         │
              │   • 严重性重评估       │
              │                       │
              │ ┌───────────────┐     │
              │ │ Verif Worker  │     │
              │ │  (模块1)      │     │
              │ ├───────────────┤     │
              │ │ Verif Worker  │     │
              │ │  (模块N)      │     │
              │ └───────────────┘     │
              │ + 跨模块路径验证      │
              │ + merge-json 合并     │
              │                       │
              │   输入: candidates_df  │
              │        +candidates_sec │
              │   输出: verified.json  │
              └───────────┬───────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │       Reporter        │  ← 阶段4: 报告生成
              │   • Markdown 报告     │
              │   • 漏洞详情聚焦      │
              │                       │
              │   输入:               │
              │   • verified.json    │
              │   • project_model    │
              │                       │
              │   输出: report.md     │
              │   (threat_analysis   │
              │    _report.md 由     │
              │    architecture 生成)│
              └───────────────────────┘
```

## Agent 输入输出详解

### 各 Agent 输入输出一览

| Agent | 输入 | 输出 | 说明 |
|-------|------|------|------|
| **orchestrator** | 用户指令 | `scan_log.json` | 协调全流程，记录扫描日志 |
| **architecture** | 源代码 | `project_model.json`<br>`call_graph.json`<br>`threat_analysis_report.md` | 架构分析、威胁建模 |
| **dataflow-scanner** | `project_model.json`<br>`call_graph.json` | `candidates_df.json` | 协调模块扫描 + 跨模块分析 + merge-json 合并 |
| **dataflow-module-scanner** | 模块文件列表<br>调用图子集 | `candidates_df_{module}.json` | 单模块污点分析（子Agent） |
| **security-auditor** | `project_model.json`<br>`call_graph.json` | `candidates_sec.json` | 协调模块审计 + 跨模块安全分析 + merge-json 合并 |
| **security-module-scanner** | 模块文件列表<br>调用图子集 | `candidates_sec_{module}.json` | 单模块安全审计（子Agent） |
| **verification** | `candidates_df.json`<br>`candidates_sec.json` | `verified.json` | 协调漏洞验证：合并去重 + 分批调度 + 跨模块验证 + merge-json 合并 |
| **verification-worker** | 批次漏洞列表<br>调用图子集 | `verified_{module}.json` | 单批次深度验证 + 置信度评分 + 严重性重评估（子Agent） |
| **reporter** | `verified.json`<br>`project_model.json` | `report.md` | 生成最终报告 |

## 核心特性

- **跨文件分析**: 追踪跨越多个文件的数据流和调用链（至少 3 层深度）
- **三层误报过滤**: Scanner 预验证 → Verification 深度验证（含一票否决 + 去重） → Reporter 按 verified_severity 分组
- **一票否决机制**: 调用链断裂、不可达、测试代码直接判定为 FALSE_POSITIVE
- **严重性重评估**: Verification 根据置信度调整 Scanner 原始 severity
- **文档优先**: 架构分析优先读取项目文档，提高分析准确性
- **代码可追溯**: 报告中所有漏洞都包含精确的文件路径和行号
- **LSP 优先**: 优先使用 LSP 进行代码分析，grep 作为回退方案
- **自主补充验证**: Verification Worker 直接读取源码补充验证，无需外部反馈循环
- **评分规则可配置**: 置信度评分规则可通过 `scoring_rules.json` 自定义
- **merge-json 工具合并**: 使用自定义 Tool 程序化合并 JSON，避免 LLM 输出限制
- **模块化 Skill**: 知识型能力（污点规则、评分方法等）提取为独立 Skill，便于维护和扩展

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
| orchestrator     | primary  | 协调整个扫描流程，记录扫描日志     | Tab 切换或 @orchestrator |
| architecture     | subagent | 架构分析、威胁建模、LSP检测、调用图 | @architecture            |
| dataflow-scanner | subagent | **协调者**：按模块调度子Agent + 跨模块分析 + merge-json 合并 | @dataflow-scanner        |
| dataflow-module-scanner | subagent | 单模块污点分析 + 标记跨模块数据流 | 由 dataflow-scanner 调用 |
| security-auditor | subagent | **协调者**：按模块调度子Agent + 跨模块安全分析 + merge-json 合并 | @security-auditor        |
| security-module-scanner | subagent | 单模块安全审计 + 标记跨模块安全提示 | 由 security-auditor 调用 |
| verification     | subagent | **协调者**：合并去重 + 分批调度验证 + 跨模块验证 + merge-json 合并 | @verification            |
| verification-worker | subagent | 单批次深度验证 + 置信度评分 + 严重性重评估 | 由 verification 调用 |
| reporter         | subagent | 生成漏洞报告（与威胁报告分工）     | @reporter                |

### 层级架构

DataFlow Scanner、Security Auditor 和 Verification 都采用协调者-工作者层级架构解决大项目上下文爆炸问题：

```
@dataflow-scanner (协调者)                @security-auditor (协调者)
    │                                         │
    ├── 读取 project_model.json               ├── 读取 project_model.json
    │                                         │
    ├── @dataflow-module-scanner (模块1)      ├── @security-module-scanner (模块1)
    │       └── 模块内污点分析                │       └── 模块内安全审计
    │                                         │
    ├── @dataflow-module-scanner (模块2)      ├── @security-module-scanner (模块2)
    │       └── ...                           │       └── ...
    │                                         │
    ├── 收集所有模块的候选漏洞                ├── 收集所有模块的候选漏洞
    │                                         │
    ├── 执行跨模块数据流分析                  ├── 执行跨模块安全分析
    │                                         │
    └── merge-json 工具合并                   └── merge-json 工具合并
        → candidates_df.json                      → candidates_sec.json
```

```
@verification (协调者)
    │
    ├── 合并 candidates_df.json + candidates_sec.json
    ├── 按 (file, line_start, function) 去重
    ├── 按 source_module 分组
    │
    ├── @verification-worker (模块1批次)
    │       └── 深度验证 + 置信度评分 + 严重性重评估
    │
    ├── @verification-worker (模块2批次)
    │       └── ...
    │
    ├── 跨模块漏洞路径验证
    │
    └── merge-json 工具合并
        → verified.json
```

**优势**：
- 每个子 Agent 只处理一个模块/批次，避免上下文爆炸
- 模块内聚性好，分析更完整
- 协调者负责跨模块分析，捕获模块边界漏洞
- Verification 协调者负责去重，避免同一漏洞被重复验证
- 使用 merge-json 工具程序化合并，避免 LLM 输出限制

## Skill 说明

知识型能力提取为独立 Skill，便于单模块优化和多语言扩展：

| Skill | 路径 | 用途 | 引用者 |
|-------|------|------|--------|
| c-cpp-taint-tracking | `.opencode/skill/c-cpp-taint-tracking/` | 污点源/汇定义 | dataflow-module-scanner |
| pre-validation-rules | `.opencode/skill/pre-validation-rules/` | 误报过滤规则 | 所有 Scanner |
| confidence-scoring | `.opencode/skill/confidence-scoring/` | 置信度评分方法（含一票否决） | verification-worker |
| cross-file-analysis | `.opencode/skill/cross-file-analysis/` | 跨文件追踪方法 | architecture, 所有 Scanner, verification, verification-worker |
| agent-communication | `.opencode/skill/agent-communication/` | 路径约定、JSON Schema | 所有 Agent |

### 扩展新语言

要支持新语言（如 Java），只需：
1. 创建 `.opencode/skill/java-taint-tracking/SKILL.md`（定义 Java 的 Source/Sink）
2. 在 `pre-validation-rules` 中添加语言特有过滤条件
3. 修改 Scanner Agent 引用新的 Skill

## 自定义 Tool 说明

| Tool | 路径 | 用途 |
|------|------|------|
| merge-json | `.opencode/tool/merge-json.ts` | 合并多个 JSON 文件的数组字段 |

### merge-json

程序化合并多个 JSON 文件，避免 LLM 输出 token 限制。

参数：
- `directory`: 包含 JSON 文件的目录
- `pattern`: 文件名匹配模式（如 `candidates_df_*.json`）
- `output`: 合并后的输出文件路径
- `key`: 要合并的数组字段名（默认 `vulnerabilities`）

返回合并统计摘要，不返回完整内容。

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

### 追踪能力

每个 Agent 都具备（详见 `@skill:cross-file-analysis`）：

- LSP 优先的符号解析（Go to Definition / Find References）
- grep 作为 LSP 不可用时的回退
- 至少 3 层调用链深度
- 参数传递追踪
- 全局变量跨文件使用检测

## 三层误报过滤机制

### 第一层：Scanner 预验证

详见 `@skill:pre-validation-rules`。

### 第二层：Verification 深度验证

包含三个子机制：

1. **去重**: Verification 协调者在合并候选漏洞后，按 `(file, line_start, function)` 三元组去重，避免同一漏洞被重复验证
2. **一票否决**: 调用链断裂、不可达、测试代码直接判定为 FALSE_POSITIVE（confidence = 0），无需完整评分
3. **多维度评分**: 通过可达性、可控性、缓解措施、上下文、跨文件五个维度量化评分（详见 `@skill:confidence-scoring`）

### 第三层：严重性重评估

Verification Worker 根据置信度评分调整 Scanner 原始 severity（如 Critical 但 confidence < 60 降级为 High），Reporter 使用验证后的 `verified_severity` 分组排序。

## 自主补充验证

Verification Worker 拥有 `read`、`lsp`、`grep` 权限，信息不足时直接读取源码补充验证，无需外部反馈循环：

```
Verification Worker → 发现调用链不完整
    → LSP Go to Definition 确认函数定义
    → 读取源码验证参数传递
    → 完成评分
```

相比旧方案（通过 Orchestrator 绕回 Scanner），这种方式更高效、链路更短。

## 报告结构

系统生成两份独立报告，避免内容重复：

### 威胁分析报告 (`threat_analysis_report.md`)

由 Architecture Agent 生成，包含：

- 项目架构概览
- 模块风险评估
- 攻击面分析
- STRIDE 威胁建模
- 安全加固建议（架构层面）

### 漏洞扫描报告 (`report.md`)

由 Reporter Agent 生成，**聚焦于漏洞本身**：

1. **扫描摘要**: 漏洞统计表格 + Top 5 关键漏洞
2. **攻击面分析**: 入口点和外部接口列表
3. **漏洞详情**: 按验证后严重性（`verified_severity`）分组，每个漏洞包含：
   - 精确的文件路径和行号
   - 从实际代码读取的代码片段
   - 完整的数据流达成路径
   - 置信度评分和严重性重评估标注

## 项目结构

```
your-project/
├── .opencode/
│   ├── agent/                      # Agent 定义（10 个）
│   │   ├── orchestrator.md         # 扫描协调者
│   │   ├── architecture.md         # 架构分析
│   │   ├── dataflow-scanner.md     # 数据流扫描协调者
│   │   ├── dataflow-module-scanner.md  # 模块级扫描子Agent
│   │   ├── security-auditor.md     # 安全审计协调者
│   │   ├── security-module-scanner.md  # 模块级审计子Agent
│   │   ├── verification.md         # 漏洞验证协调者
│   │   ├── verification-worker.md  # 模块级验证子Agent
│   │   └── reporter.md             # 报告生成
│   ├── skill/                      # Skill 定义（6 个）
│   │   ├── agent-communication/    # Agent 间通信规范
│   │   ├── c-cpp-taint-tracking/   # C/C++ 污点追踪规则
│   │   ├── confidence-scoring/     # 置信度评分方法
│   │   ├── cross-file-analysis/    # 跨文件分析方法
│   │   ├── pre-validation-rules/   # 预验证/误报过滤
│   │   └── bun-file-io/            # Bun 文件 I/O（内置）
│   └── tool/                       # 自定义工具
│       ├── merge-json.ts           # JSON 文件合并工具
│       └── merge-json.txt          # 工具描述
└── scan-results/                   # 扫描输出（自动创建）
    ├── .context/                   # 结构化上下文（Agent 间通信）
    │   ├── project_model.json      # 项目模型（architecture 输出）
    │   ├── call_graph.json         # 调用图（architecture 输出）
    │   ├── candidates_df.json      # 数据流候选漏洞（merge-json 合并）
    │   ├── candidates_df_*.json    # 模块级数据流中间结果
    │   ├── candidates_sec.json     # 安全审计候选漏洞（merge-json 合并）
    │   ├── candidates_sec_*.json   # 模块级安全审计中间结果
    │   ├── verified.json           # 验证后漏洞（merge-json 合并）
    │   ├── verified_*.json         # 模块级验证中间结果
    │   ├── scan_log.json           # 扫描日志（orchestrator 输出）
    │   └── scoring_rules.json      # 评分规则（可选，自定义置信度评分）
    ├── threat_analysis_report.md   # 威胁分析报告（architecture 输出）
    └── report.md                   # 最终漏洞报告（reporter 输出）
```

### 路径约定

扫描过程中使用以下路径变量（详见 `@skill:agent-communication`）：

| 变量 | 说明 | 确定方式 |
|------|------|--------|
| `PROJECT_ROOT` | 被扫描项目的根目录 | **必须由用户在提示词中明确指定** |
| `SCAN_OUTPUT` | 扫描输出目录 | `{PROJECT_ROOT}/scan-results` |
| `CONTEXT_DIR` | 上下文存储目录 | `{SCAN_OUTPUT}/.context` |

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
