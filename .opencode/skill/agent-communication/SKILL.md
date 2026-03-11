---
name: agent-communication
description: 多 Agent 间的通信规范，包括路径约定、JSON Schema 定义、数据交换协议。所有参与漏洞扫描的 Agent 都应参考此 Skill。
---

## Use this when

- 需要确定文件读写路径
- 需要了解 JSON 数据格式
- 调用子 Agent 时需要传递路径上下文
- 读取或写入 Agent 间共享的数据文件

## 路径约定

扫描过程中使用以下三个路径变量：

| 变量 | 说明 | 确定方式 |
|------|------|----------|
| `PROJECT_ROOT` | 被扫描项目的根目录 | 由用户在提示词中明确指定，不得假设为当前工作目录 |
| `SCAN_OUTPUT` | 扫描输出目录 | `{PROJECT_ROOT}/scan-results` |
| `CONTEXT_DIR` | 上下文存储目录 | `{SCAN_OUTPUT}/.context` |

### 路径确定流程

```
1. 从用户提示词中提取目标项目路径，作为 PROJECT_ROOT
2. 验证 PROJECT_ROOT 存在且为目录，否则报错并停止
3. 拼接 SCAN_OUTPUT = {PROJECT_ROOT}/scan-results
4. 拼接 CONTEXT_DIR = {SCAN_OUTPUT}/.context
5. 创建目录: mkdir -p {CONTEXT_DIR}
6. 后续所有子 Agent 调用时传递这三个路径
```

### 调用子 Agent 时传递路径

每次调用子 Agent 时，**必须在开头传递路径上下文**：

```
@agent-name

## 路径上下文
- 项目根目录: {PROJECT_ROOT}
- 扫描输出目录: {SCAN_OUTPUT}
- 上下文目录: {CONTEXT_DIR}

## 任务
[具体任务内容...]
```

## 上下文文件一览

| 文件 | 写入者 | 读取者 | 用途 |
|------|--------|--------|------|
| `project_model.json` | @architecture | 所有 Scanner、@verification、@reporter | 项目结构和高风险文件 |
| `call_graph.json` | @architecture | 所有 Scanner、@verification | 函数调用关系图 |
| `candidates_df.json` | @dataflow-scanner（通过 merge-json tool） | @verification | 数据流候选漏洞列表 |
| `candidates_df_*.json` | @dataflow-module-scanner | @dataflow-scanner | 模块级数据流扫描中间结果 |
| `candidates_sec.json` | @security-auditor（通过 merge-json tool） | @verification | 安全审计候选漏洞列表 |
| `candidates_sec_*.json` | @security-module-scanner | @security-auditor | 模块级安全审计中间结果 |
| `verified.json` | @verification（通过 merge-json tool） | @reporter | 验证后的漏洞 |
| `verified_*.json` | @verification-worker | @verification | 模块级验证中间结果 |
| `scan_log.json` | @orchestrator | 用户/调试 | Agent 调用日志和扫描统计 |
| `scoring_rules.json` | 用户（可选） | @verification、@verification-worker | 自定义置信度评分规则 |

## JSON 格式规范（必须遵守）

### 写入规则

写入 JSON 文件时，**必须**遵守以下格式要求：

1. **纯 JSON 内容** — 直接写入 JSON 文本，不得包裹 markdown 代码围栏（` ```json ` / ` ``` `）
2. **禁止注释** — JSON 标准不支持注释，不得包含 `//` 或 `/* */`
3. **禁止尾随逗号** — 数组最后一个元素和对象最后一个属性后**不得**有逗号
4. **正确转义** — 字符串中的双引号用 `\"`、反斜杠用 `\\`、换行用 `\n`、制表符用 `\t`
5. **完整闭合** — 确保所有 `{` `}` `[` `]` 正确配对闭合
6. **使用缩进** — 写入时使用 2 空格缩进（`JSON.stringify(data, null, 2)` 格式）

### 写入后校验（必须执行）

每次写入 JSON 文件后，**必须调用 `validate-json` 工具进行校验**：

```
写入 JSON 文件 → 调用 validate-json 工具 → 检查返回结果
  ├── PASS → 校验通过，继续后续步骤
  └── FAIL → 根据错误信息修复文件内容，重新写入，再次校验
              └── 最多重试 2 次，仍失败则报错停止
```

**校验失败时的修复流程**：

1. 阅读 `validate-json` 返回的错误信息（包含出错行号和上下文片段）
2. 定位错误原因（尾随逗号、未转义字符、缺少闭合括号等）
3. 修复 JSON 内容，重新写入文件
4. 再次调用 `validate-json` 校验
5. 如果 2 次重试后仍失败，向协调者报告错误并停止

## JSON Schema 定义

### project_model.json

```json
{
  "project_name": "string",
  "scan_time": "ISO8601",
  "lsp_available": true,
  "total_files": 50,
  "total_lines": 25000,
  "project_profile": {
    "project_type": "network_service|cli_tool|library|kernel_module|embedded|gui_application",
    "deployment_model": "描述项目的典型部署方式（如：Linux 服务器上的守护进程、用户本地执行的命令行工具等）",
    "trust_boundaries": [
      {
        "boundary": "信任边界名称（如 Network Interface）",
        "trusted_side": "可信一侧（如 Application logic）",
        "untrusted_side": "不可信一侧（如 Remote clients）",
        "risk": "Critical|High|Medium|Low"
      }
    ]
  },
  "modules": [
    {
      "name": "模块名称",
      "path": "src/module",
      "components": ["file1.cpp", "file2.cpp"]
    }
  ],
  "files": [
    {
      "path": "src/network.c",
      "risk": "Critical|High|Medium|Low",
      "module": "network",
      "lines": 450,
      "priority": 1
    }
  ],
  "entry_points": [
    {
      "file": "src/server.c",
      "line": 89,
      "function": "handle_request",
      "type": "network|file|env|cmdline|stdin",
      "trust_level": "untrusted_network|untrusted_local|semi_trusted|trusted_admin|internal",
      "justification": "TCP 0.0.0.0:8080 上的公网接口，远程客户端可直接连接",
      "description": "接收HTTP请求"
    }
  ],
  "attack_surfaces": [
    "Unix Domain Socket: /opt/app/app.sock",
    "动态库加载: dlopen()"
  ]
}
```

**新增字段说明**：

| 字段 | 所属 | 说明 |
|------|------|------|
| `project_profile` | 顶层 | 项目定位信息，由 Architecture Agent 在攻击面识别前填写 |
| `project_profile.project_type` | project_profile | 项目类型枚举：`network_service`（网络服务）、`cli_tool`（CLI 工具）、`library`（库）、`kernel_module`（内核模块）、`embedded`（嵌入式）、`gui_application`（GUI 应用） |
| `project_profile.deployment_model` | project_profile | 项目的典型部署方式描述 |
| `project_profile.trust_boundaries` | project_profile | 系统信任边界列表，标注每条边界两侧的信任差异 |
| `trust_level` | entry_points[] | 入口点信任等级，决定该入口是否值得重点扫描 |
| `justification` | entry_points[] | 入口点可达性理由，要求 AI 解释为什么此入口是真实攻击面 |

### call_graph.json

```json
{
  "functions": {
    "function_name@file.c": {
      "defined_at": 45,
      "calls": ["callee@other.c"],
      "called_by": ["caller@main.c"],
      "receives_external_input": true,
      "risk": "Critical|High|Medium|Low"
    }
  },
  "data_flows": [
    {
      "source": "recv@src/network.c:50",
      "path": ["handle_request@src/server.c:60", "parse_header@src/request.c:85"],
      "sink": "strcpy@src/request.c:120",
      "sink_type": "memory_operation"
    }
  ]
}
```

### candidates_df.json / candidates_sec.json

```json
{
  "vulnerabilities": [
    {
      "id": "VULN-DF-001",
      "type": "buffer_overflow|use_after_free|command_injection|...",
      "severity": "Critical|High|Medium|Low",
      "cwe": "CWE-XXX",
      "file": "src/path/file.c",
      "line_start": 250,
      "line_end": 255,
      "function": "function_name",
      "code_snippet": "actual code from file",
      "data_flow": [
        {"file": "src/a.c", "line": 50, "description": "[SOURCE] 说明"},
        {"file": "src/b.c", "line": 80, "description": "[SINK] 说明"}
      ],
      "source_agent": "dataflow-scanner|security-auditor",
      "source_module": "模块名称",
      "pre_validated": true,
      "cross_module": false,
      "modules_involved": ["模块A", "模块B"]
    }
  ]
}
```

**字段说明**：

| 字段 | 必填 | 说明 |
|------|------|------|
| `source_agent` | 是 | Scanner 输出时为字符串（`"dataflow-scanner"` 或 `"security-auditor"`）。Verification 去重合并后转为数组 `source_agents`（如 `["dataflow-scanner", "security-auditor"]`） |
| `cross_module` | 是 | 是否为跨模块漏洞（默认 `false`） |
| `modules_involved` | 否 | 仅 `cross_module: true` 时填写，列出涉及的所有模块名称 |

### 模块中间文件（candidates_df_{模块简称}.json / candidates_sec_{模块简称}.json）

```json
{
  "module": "模块名称",
  "vulnerabilities": [
    {
      "id": "VULN-DF-IPC-001",
      "type": "buffer_overflow",
      "severity": "High",
      "cwe": "CWE-120",
      "file": "src/ipc/handler.cpp",
      "line_start": 250,
      "line_end": 255,
      "function": "RecvMessage",
      "code_snippet": "...",
      "data_flow": [...],
      "source_agent": "dataflow-scanner",
      "source_module": "IPC通信模块",
      "pre_validated": true
    }
  ]
}
```

**模块简称规则**：取模块名的英文部分，全部小写，空格替换为 `_`。若多个模块简称相同，追加数字后缀（如 `network`、`network_2`）。

### verified.json

**统一使用 `vulnerabilities` 单数组结构**，每个条目通过 `status` 字段标识分类，便于 `merge-json` 工具一次合并。

```json
{
  "scan_summary": {
    "total_candidates": 25,
    "deduplicated_candidates": 22,
    "confirmed": 5,
    "likely": 8,
    "possible": 4,
    "false_positives": 5,
    "veto_count": 3
  },
  "vulnerabilities": [
    {
      "id": "VULN-DF-001",
      "confidence": 85,
      "status": "CONFIRMED",
      "original_severity": "Critical",
      "verified_severity": "Critical",
      "source_agents": ["dataflow-scanner", "security-auditor"],
      "scoring_details": {
        "base": 30,
        "reachability": 30,
        "controllability": 15,
        "mitigations": -10,
        "context": 0,
        "cross_file": 0
      },
      "veto_applied": false,
      "veto_reason": null,
      "original": {}
    },
    {
      "id": "VULN-SEC-003",
      "confidence": 0,
      "status": "FALSE_POSITIVE",
      "original_severity": "Medium",
      "verified_severity": "Medium",
      "source_agents": ["security-auditor"],
      "scoring_details": null,
      "veto_applied": true,
      "veto_reason": "test_code",
      "reason": "测试代码中的硬编码凭证",
      "original": {}
    }
  ]
}
```

**字段说明**：

| 字段 | 说明 |
|------|------|
| `status` | 验证状态：`CONFIRMED`/`LIKELY`/`POSSIBLE`/`FALSE_POSITIVE` |
| `original_severity` | Scanner 原始评估的严重性 |
| `verified_severity` | 验证后根据置信度重评估的严重性 |
| `source_agents` | 数组，记录发现该漏洞的 Scanner（去重合并后可能有多个来源） |
| `veto_applied` | 布尔值，是否被一票否决（详见 `@skill:confidence-scoring`） |
| `veto_reason` | 一票否决原因（仅 `veto_applied: true` 时存在）：`chain_broken`/`unreachable`/`test_code` |
| `deduplicated_candidates` | 去重后的候选漏洞数（`scan_summary` 中） |
| `veto_count` | 被一票否决的漏洞数（`scan_summary` 中） |

**设计说明**：使用统一的 `vulnerabilities` 数组（而非 `confirmed`/`likely`/`possible`/`false_positives` 四个独立数组），使得 `merge-json` 工具可以一次合并（key=`vulnerabilities`），合并后协调者只需遍历数组按 `status` 统计 `scan_summary`。

### 验证中间文件（verified_{模块简称}.json）

结构与 `verified.json` 一致，`scan_summary` 仅统计该批次的漏洞。

```json
{
  "scan_summary": {
    "total_candidates": 5,
    "confirmed": 2,
    "likely": 1,
    "possible": 1,
    "false_positives": 1,
    "veto_count": 1
  },
  "vulnerabilities": [
    {
      "id": "VULN-DF-001",
      "status": "CONFIRMED",
      "confidence": 85,
      "...": "..."
    }
  ]
}
```

**模块简称规则**：取模块名的英文部分，全部小写，空格替换为 `_`。若多个模块简称相同，追加数字后缀（如 `network`、`network_2`）。

### scan_log.json

```json
{
  "scan_id": "UUID",
  "start_time": "ISO8601",
  "end_time": "ISO8601",
  "duration_seconds": 1800,
  "project_name": "项目名称",
  "status": "completed|failed|partial",
  "agents": [
    {
      "name": "agent-name",
      "start_time": "ISO8601",
      "end_time": "ISO8601",
      "duration_seconds": 325,
      "status": "success|failed|skipped",
      "outputs": ["file1.json", "file2.md"],
      "error": null
    }
  ],
  "summary": {
    "project_type": "network_service|cli_tool|library|kernel_module|embedded|gui_application",
    "total_files_scanned": 50,
    "total_lines": 25000,
    "candidates_found": 13,
    "confirmed_vulnerabilities": 5,
    "false_positives": 3,
    "lsp_available": true
  }
}
```

## 文件路径格式

- 所有输出中的文件路径使用**相对于 PROJECT_ROOT** 的格式
- 例如: `src/ipc/handler.cpp` 而不是绝对路径
- 使用正斜杠 `/` 作为路径分隔符
