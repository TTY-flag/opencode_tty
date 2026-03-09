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
| `verified.json` | @verification | @reporter | 验证后的漏洞 |
| `scan_log.json` | @orchestrator | 用户/调试 | Agent 调用日志和扫描统计 |
| `scoring_rules.json` | 用户（可选） | @verification | 自定义置信度评分规则 |

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
      "description": "接收HTTP请求"
    }
  ],
  "attack_surfaces": [
    "Unix Domain Socket: /opt/app/app.sock",
    "动态库加载: dlopen()"
  ]
}
```

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
      "cross_module": false
    }
  ]
}
```

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

**模块简称规则**：取模块名的英文部分，全部小写，空格替换为 `_`。

### verified.json

```json
{
  "scan_summary": {
    "total_candidates": 25,
    "confirmed": 5,
    "likely": 8,
    "possible": 4,
    "false_positives": 8
  },
  "confirmed": [
    {
      "id": "VULN-DF-001",
      "confidence": 85,
      "status": "CONFIRMED",
      "scoring_details": {
        "base": 50,
        "reachability": 30,
        "controllability": 15,
        "mitigations": -10,
        "context": 0,
        "cross_file": 0
      },
      "original": {}
    }
  ],
  "likely": [],
  "possible": [],
  "false_positives": [
    {
      "id": "VULN-SEC-003",
      "confidence": 25,
      "status": "FALSE_POSITIVE",
      "reason": "测试代码中的硬编码凭证"
    }
  ]
}
```

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
      "feedback_loops": 0,
      "error": null
    }
  ],
  "summary": {
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
