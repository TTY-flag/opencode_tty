---
name: c-cpp-taint-tracking
description: C/C++ 污点追踪规则，定义污点源(Taint Sources)和污点汇(Taint Sinks)。进行数据流漏洞分析时使用此 Skill。未来可扩展为其他语言的变体（如 java-taint-tracking、python-taint-tracking）。
---

## Use this when

- 对 C/C++ 代码进行污点分析（数据流漏洞扫描）
- 需要确定哪些函数是外部输入源（Source）
- 需要确定哪些函数是危险操作汇（Sink）

## 污点源 (Taint Sources)

外部不可信数据进入程序的位置。追踪从这些位置流出的数据。

| 类别 | 函数 | 风险说明 |
|------|------|----------|
| 网络输入 | `recv`, `recvfrom`, `recvmsg`, `read`(socket), `SSL_read` | 完全可控的远程数据 |
| 文件输入 | `fread`, `fgets`, `getline`, `read`(file), `mmap` | 文件内容可被篡改 |
| 环境输入 | `getenv`, `secure_getenv` | 环境变量可被外部设置 |
| 用户输入 | `scanf`, `fscanf`, `gets`, `fgets`(stdin), `getchar` | 直接用户输入 |
| 命令行 | `argv`, `argc`, `getopt`, `getopt_long` | 命令行参数可控 |
| 模块入口 | 协调者传递的 `entry_points` 中标记的函数参数 | 来自其他模块的数据 |

### 隐式污点源

以下场景也应视为污点源：

- **回调函数参数**：注册到网络/事件框架的回调函数，其参数来自外部
- **共享内存/管道**：通过 `shmget`/`shmat`、`pipe`/`mkfifo` 接收的数据
- **数据库查询结果**：来自数据库的数据可能被其他方篡改
- **配置文件内容**：通过 INI/JSON/YAML 解析器读取的配置值

## 污点汇 (Taint Sinks)

污点数据到达以下函数时可能触发漏洞。

| 类别 | 函数 | 风险类型 | CWE |
|------|------|----------|-----|
| 内存操作 | `strcpy`, `strcat`, `sprintf`, `vsprintf`, `memcpy`, `memmove`, `gets` | 缓冲区溢出 | CWE-120/121/122 |
| 命令执行 | `system`, `popen`, `execl`, `execle`, `execlp`, `execv`, `execvp`, `execve` | 命令注入 | CWE-78 |
| 格式化 | `printf`, `fprintf`, `sprintf`, `snprintf`, `syslog`, `vsprintf` | 格式化字符串 | CWE-134 |
| 文件操作 | `open`, `fopen`, `access`, `unlink`, `rename`, `chmod`, `chown` | 路径遍历 | CWE-22 |
| 内存分配 | `malloc`, `calloc`, `realloc`, `alloca` | 整数溢出导致堆溢出 | CWE-190 |
| 动态加载 | `dlopen`, `dlsym`, `LoadLibrary` | 库注入 | CWE-426 |
| SQL | `sqlite3_exec`, `mysql_query`, `PQexec` | SQL 注入 | CWE-89 |

### 安全替代函数

以下函数是对应危险函数的安全替代，不应视为 Sink（但仍需检查参数是否正确）：

| 危险函数 | 安全替代 | 注意事项 |
|----------|----------|----------|
| `strcpy` | `strncpy`, `strlcpy` | 检查 n 参数是否正确 |
| `strcat` | `strncat`, `strlcat` | 检查 n 参数是否正确 |
| `sprintf` | `snprintf` | 检查缓冲区大小参数 |
| `gets` | `fgets` | 需指定最大长度 |
| `scanf` | 带宽度限制的 `scanf`（如 `%255s`） | 宽度是否匹配缓冲区 |

## 污点传播规则

### 传播（Propagation）

污点数据经过以下操作后仍保持污点状态：

- **赋值**：`char *p = tainted_data`
- **算术运算**：`int len = tainted_len + 1`
- **字符串操作**：`strdup(tainted)`, `strtok(tainted, ",")`
- **类型转换**：`(int)tainted_value`
- **结构体字段赋值**：`obj->field = tainted`
- **数组索引赋值**：`arr[i] = tainted`
- **函数返回值**：函数接收污点参数并返回衍生数据

### 清洗（Sanitization）

以下操作可移除或降低污点状态：

| 清洗类型 | 示例模式 | 效果 |
|----------|----------|------|
| 边界检查 | `if (len < sizeof(buf))` | 降低溢出风险 |
| 输入验证 | `validate_input()`, `check_range()` | 取决于验证逻辑 |
| 编码/转义 | `escape_string()`, `urlencode()` | 降低注入风险 |
| 白名单 | `if (is_allowed(input))` | 有效清洗 |
| 截断 | `input[MAX_LEN] = '\0'` | 限制长度 |

## 扩展指南

为新语言添加污点追踪规则时，创建对应的 Skill 文件（如 `.opencode/skill/java-taint-tracking/SKILL.md`），保持相同的表格结构，替换语言特有的函数和 API。
