---
name: confidence-scoring
description: 漏洞置信度评分方法论。在验证候选漏洞时使用此 Skill 计算置信度分数并确定处理方式。
---

## Use this when

- 验证候选漏洞的真实性
- 需要为漏洞计算置信度评分
- 决定漏洞的报告级别（CONFIRMED / LIKELY / POSSIBLE / FALSE_POSITIVE）

## 评分公式

```
最终分 = base_score + reachability + controllability + mitigations + context + cross_file
最终分 = max(0, min(100, 最终分))
```

## 默认评分规则

如果存在 `{CONTEXT_DIR}/scoring_rules.json`，从文件读取覆盖以下默认值：

```json
{
  "base_score": 50,
  "reachability": {
    "direct_external": 30,
    "indirect_external": 20,
    "internal_only": 5,
    "unreachable": -30
  },
  "controllability": {
    "full": 25,
    "partial": 15,
    "length_only": 10,
    "none": 0
  },
  "mitigations": {
    "bounds_check": -15,
    "null_check": -10,
    "input_validation": -20,
    "sanitization": -25
  },
  "context": {
    "test_code": -50,
    "static_function": -15,
    "const_param": -20,
    "external_api": 0
  },
  "cross_file": {
    "chain_complete": 0,
    "has_safety_check": -15,
    "has_sanitization": -20,
    "chain_broken": -50
  }
}
```

## 各评分维度详解

### 1. 可达性（Reachability）

检查从外部输入到漏洞点是否存在可执行路径。

| 情况 | 评分 | 检查方法 |
|------|------|----------|
| 直接外部输入 | +30 | 输入源为 `recv`/`fread`/`getenv`/`argv` 等，直接到达漏洞点 |
| 间接外部输入 | +20 | 外部输入经过中间函数转发到达 |
| 仅内部调用 | +5 | 函数仅被内部代码调用，无外部输入路径 |
| 不可达 | -30 | 存在条件跳转阻断、`return`/`exit`/`abort` 提前终止、死代码 |

### 2. 数据可控性（Controllability）

| 情况 | 评分 | 说明 |
|------|------|------|
| 完全可控 | +25 | 数据内容和长度都由攻击者控制 |
| 部分可控 | +15 | 内容可控但格式受限，或长度有限制 |
| 仅长度可控 | +10 | 仅能控制数据长度，内容不可控 |
| 不可控 | 0 | 数据内容和长度都由程序控制 |

### 3. 缓解措施（Mitigations）

| 缓解类型 | 评分 | 检测模式 |
|----------|------|----------|
| 边界检查 | -15 | `if (len < sizeof)`, `if (size > MAX)` |
| 空指针检查 | -10 | `if (ptr == NULL)`, `if (!ptr)` |
| 输入验证 | -20 | `validate_*()`, `check_*()`, `verify_*()` |
| 数据清洗 | -25 | `escape_*()`, `encode_*()`, `sanitize_*()` |

多个缓解措施可叠加。

### 4. 上下文（Context）

| 情况 | 评分 | 说明 |
|------|------|------|
| 测试代码 | -50 | 路径含 `test/`、`mock/`、`example/` |
| static 函数 | -15 | 文件内部函数，攻击面小 |
| 常量参数 | -20 | 参数来自常量或配置 |
| 外部 API | 0 | 对外暴露的接口 |

### 5. 跨文件（Cross-file）

| 情况 | 评分 | 说明 |
|------|------|------|
| 调用链完整可达 | 0 | 每一步都验证了函数调用存在 |
| 中间有安全检查 | -15 | 调用链中某个中间函数有安全检查 |
| 中间有数据清洗 | -20 | 数据在传递过程中被清洗 |
| 调用链断裂 | -50 | 某一步的函数调用不存在或签名不匹配 |

## 置信度等级与处理方式

| 分数范围 | 等级 | 处理方式 |
|----------|------|----------|
| 80-100 | CONFIRMED | 报告（高优先级） |
| 60-79 | LIKELY | 报告 |
| 40-59 | POSSIBLE | 报告（低优先级，标记为待确认） |
| 0-39 | FALSE_POSITIVE | 不报告，记录到 `false_positives` 用于调优 |

## 快速判定规则

以下情况可直接判定为 FALSE_POSITIVE，无需完整评分：

- 使用编译时常量作为参数
- 有明确且正确的边界检查保护
- 测试文件中的代码（路径含 `test/`）
- 死代码块（`#if 0`、`if(false)`）
- 调用链中函数签名不匹配

## 评分输出格式

每个漏洞的评分结果应包含明细：

```json
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
  }
}
```
