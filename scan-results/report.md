# UBTurbo 项目漏洞扫描报告

**项目**: UBTurbo - 节点内资源管理框架
**扫描时间**: 2026-01-22 12:00:00 UTC
**扫描版本**: OpenCode Vulnerability Scanner v1.0
**报告生成时间**: 2026-01-22

---

## 执行摘要

### 项目概览

UBTurbo 是一个节点内资源管理框架，提供配置读取、插件加载、日志打印和 IPC 通信能力。项目包含 23 个文件，约 8500 行代码，主要模块包括：

- IPC 通信模块（Unix Domain Socket）
- 插件系统（动态加载）
- SMAP 内存管理（分级内存调度）
- 日志系统（异步环形缓冲区）
- 配置解析模块

### 总体风险评估

**风险等级**: 🔴 **CRITICAL**

UBTurbo 项目存在**严重的安全漏洞**，主要问题集中在：

1. **IPC 通信缺少认证和授权机制** - 任何客户端都可以连接并执行任意注册函数
2. **命令注入漏洞** - 日志压缩功能使用 `system()` 执行外部命令，无输入过滤
3. **多个缓冲区溢出漏洞** - 使用 VLA（变长数组）和未验证的用户输入导致栈/堆溢出
4. **插件加载缺少验证** - 动态库加载路径来自配置文件，无签名验证
5. **路径遍历漏洞** - 多处文件操作未验证输入路径

这些漏洞可能导致：
- 远程代码执行（RCE）
- 权限提升
- 敏感信息泄露
- 服务拒绝（DoS）

### 漏洞统计

| 指标 | 数量 |
|------|------|
| 确认漏洞 (CONFIRMED) | 6 |
| 候选漏洞 (CANDIDATE) | 10 |
| **需处理总数** | 16 |

| 严重性 | 数量 | 占比 |
|--------|------|------|
| 🔴 Critical | 6 | 37.5% |
| 🟠 High | 7 | 43.8% |
| 🟡 Medium | 3 | 18.7% |
| **总计** | 16 | 100% |

### 最关键的漏洞（Top 5）

1. **[VULN-DF-001]** 命令注入 - 日志压缩功能
   - **严重性**: Critical | **CWE**: CWE-78
   - **位置**: `src/log/rack_logger_filesink.cpp:164-181`
   - **影响**: 攻击者可通过 IPC 消息注入任意命令，获取 root 权限

2. **[VULN-SEC-001]** 缺少认证机制
   - **严重性**: Critical | **CWE**: CWE-306
   - **位置**: `src/ipc/server/turbo_ipc_handler.cpp:173-177`
   - **影响**: 任何客户端可连接 UDS socket，无需身份验证

3. **[VULN-SEC-002]** 缺少授权机制
   - **严重性**: Critical | **CWE**: CWE-862
   - **位置**: `src/ipc/server/turbo_ipc_handler.cpp:284-301`
   - **影响**: 认证后的客户端可执行任何已注册函数，无权限检查

4. **[VULN-DF-007]** 栈溢出（VLA）
   - **严重性**: Critical | **CWE**: CWE-121
   - **位置**: `src/smap/server/turbo_module_smap.cpp:427-453`
   - **影响**: 用户可控的数组大小导致栈溢出，可导致代码执行

5. **[VULN-DF-008]** 栈溢出（VLA）
   - **严重性**: Critical | **CWE**: CWE-121
   - **位置**: `src/smap/server/turbo_module_smap.cpp:455-477`
   - **影响**: 同上，NUMA 频率查询功能存在栈溢出

---

## 漏洞详情

## 🔴 Critical 漏洞（6个）

### [VULN-DF-001] 命令注入 - 日志压缩功能

**严重性**: Critical | **CWE**: CWE-78 | **置信度**: 85/100

**位置**
- 文件: `src/log/rack_logger_filesink.cpp`
- 行号: 164-181
- 函数: `RackLoggerFilesink::CompressFile()`

**描述**
日志压缩功能使用 `system()` 执行 `tar` 命令，文件名直接拼接进命令字符串，未做任何过滤或转义。攻击者可通过控制 `moduleName` 或文件路径注入恶意命令。

**漏洞代码** (`src/log/rack_logger_filesink.cpp:164-181`)

```cpp
std::string command = "tar -czf " + destFilename + " -C " + basePath + " " + fileName + ".log";
int result = system(command.c_str());
```

**达成路径**

1. `src/ipc/server/turbo_ipc_handler.cpp:250` - [SOURCE] recv() 接收网络数据
2. `src/ipc/server/turbo_ipc_handler.cpp:344` - 解析函数名和参数
3. `src/log/rack_logger_filesink.cpp:58` - 使用 moduleName 构造文件名
4. `src/log/rack_logger_filesink.cpp:167` - 拼接 tar 命令字符串
5. `src/log/rack_logger_filesink.cpp:168` - [SINK] system() 无过滤执行命令

**影响**
- 远程命令执行（RCE）
- 以 UBTurbo 进程权限（通常是 root）执行任意命令
- 完全控制宿主机

**修复建议**
```cpp
// 1. 使用 fork + exec 替代 system()
// 2. 验证文件名格式（仅允许字母数字、下划线、横杠）
// 3. 使用白名单机制
std::string ValidateFileName(const std::string& fileName) {
    std::regex validPattern("^[a-zA-Z0-9_-]+$");
    if (!std::regex_match(fileName, validPattern)) {
        throw std::runtime_error("Invalid file name");
    }
    return fileName;
}

// 4. 使用 posix_spawnp 替代 system()
pid_t pid;
char *argv[] = {"tar", "-czf", destFilename.c_str(),
                 "-C", basePath.c_str(),
                 (fileName + ".log").c_str(), nullptr};
posix_spawnp(&pid, "tar", nullptr, nullptr, argv, environ);
```

---

### [VULN-SEC-001] 缺少认证机制

**严重性**: Critical | **CWE**: CWE-306 | **置信度**: 95/100

**位置**
- 文件: `src/ipc/server/turbo_ipc_handler.cpp`
- 行号: 173-177
- 函数: `IpcHandler::PThreadListen()`

**描述**
IPC 服务器接受任何客户端的连接请求，无需身份验证。Unix Domain Socket 文件权限为 0640，只限制了文件访问，但同一用户组的任何进程都可以连接并执行 IPC 函数。

**漏洞代码** (`src/ipc/server/turbo_ipc_handler.cpp:173-177`)

```cpp
int fd = accept(listenFd, nullptr, nullptr);
if (fd < 0) {
    UBTURBO_LOG_ERROR(MODULE_NAME, MODULE_CODE) << "[Ipc][Server] Accept error.";
    continue;
}
```

**达成路径**

1. `src/ipc/server/turbo_ipc_handler.cpp:173` - [SOURCE] accept() 接受任何客户端连接
2. `src/ipc/server/turbo_ipc_handler.cpp:334` - PThreadHandle() 处理客户端请求
3. `src/ipc/server/turbo_ipc_handler.cpp:284` - HandleFunction() 执行注册的函数
4. `src/ipc/server/turbo_ipc_handler.cpp:294` - [SINK] 无认证直接执行敏感操作

**影响**
- 未授权访问所有 IPC 功能
- 访问敏感的 SMAP 内存管理接口
- 加载任意插件（需要配合其他漏洞）

**修复建议**
```cpp
// 1. 实现 Unix credential 验证
int fd = accept(listenFd, nullptr, nullptr);

struct ucred cred;
socklen_t len = sizeof(cred);
if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, < 0) {
    close(fd);
    continue;
}

// 2. 验证客户端 PID/UID/GID
if (cred.uid != 0 && !IsAuthorizedProcess(cred.pid)) {
    UBTURBO_LOG_WARN(...) << "[Ipc][Server] Unauthorized connection from PID " << cred.pid;
    close(fd);
    continue;
}

// 3. 或使用 SCRAM/Token 认证机制
```

---

### [VULN-SEC-002] 缺少授权机制

**严重性**: Critical | **CWE**: CWE-862 | **置信度**: 95/100

**位置**
- 文件: `src/ipc/server/turbo_ipc_handler.cpp`
- 行号: 284-301
- 函数: `IpcHandler::HandleFunction()`

**描述**
IPC 服务器执行任何已注册的函数，不检查客户端是否有权限调用该函数。一旦连接成功，客户端可以调用 `funcTable` 中注册的所有函数。

**漏洞代码** (`src/ipc/server/turbo_ipc_handler.cpp:284-301`)

```cpp
gLock.lock_shared();
auto it = funcTable.find(functionName);
if (it != funcTable.end()) {
    if (it->second(inputBuffer, outputBuffer) != 0) {
        retCode = IPC_FUNC_ERROR;
    }
}
```

**达成路径**

1. `src/ipc/server/turbo_ipc_handler.cpp:344` - [SOURCE] 从消息中解析函数名
2. `src/ipc/server/turbo_ipc_handler.cpp:287` - funcTable.find() 查找函数
3. `src/ipc/server/turbo_ipc_handler.cpp:295` - 调用回调函数（无权限检查）
4. `src/ipc/server/turbo_ipc_handler.cpp:295` - [SINK] 未授权执行任意注册函数

**影响**
- 访问受限的管理功能
- 操作其他进程的内存（SMAP 接口）
- 加载/卸载插件

**修复建议**
```cpp
// 1. 实现基于角色的权限控制（RBAC）
enum class IpcPermission {
    LOG_READ,
    LOG_WRITE,
    SMAP_QUERY,
    SMAP_MODIFY,
    PLUGIN_LOAD,
    PLUGIN_UNLOAD
};

struct ClientContext {
    pid_t pid;
    uid_t uid;
    std::set<IpcPermission> permissions;
};

// 2. 在调用前检查权限
auto it = funcTable.find(functionName);
if (it != funcTable.end()) {
    if (!client->HasPermission(it->second.requiredPermission)) {
        retCode = IPC_PERMISSION_DENIED;
    } else if (it->second(inputBuffer, outputBuffer) != 0) {
        retCode = IPC_FUNC_ERROR;
    }
}
```

---

### [VULN-SEC-008] 未授权库加载

**严重性**: Critical | **CWE**: CWE-427 | **置信度**: 90/100

**位置**
- 文件: `src/smap/server/turbo_module_smap.cpp`
- 行号: 35-603
- 函数: `OpenSmapHandler()`

**描述**
SMAP 模块直接从硬编码路径 `/usr/lib64/libsmap.so` 加载动态库，不验证库的完整性或签名。攻击者如果可以替换该文件，可以执行任意代码。

**漏洞代码** (`src/smap/server/turbo_module_smap.cpp:35-603`)

```cpp
constexpr const char *LIB_SMAP_PATH = "/usr/lib64/libsmap.so";
g_smapHandler = dlopen(LIB_SMAP_PATH, RTLD_LAZY);
```

**达成路径**

1. `src/smap/server/turbo_module_smap.cpp:602` - dlopen() 加载系统库
2. `src/smap/server/turbo_module_smap.cpp:608` - dlsym() 解析函数符号
3. `src/smap/server/turbo_module_smap.cpp:629` - [SINK] 未验证的库代码执行

**影响**
- 库劫持攻击
- 持久化后门
- 绕过系统安全机制

**修复建议**
```cpp
// 1. 验证库文件签名
bool VerifyLibrarySignature(const std::string& path) {
    // 使用 GPG 或其他签名验证机制
    // 检查库文件是否被篡改
}

// 2. 使用哈希验证
const std::string EXPECTED_HASH = "sha256:abc123...";
if (!VerifyFileHash(LIB_SMAP_PATH, EXPECTED_HASH)) {
    throw std::runtime_error("Library integrity check failed");
}

// 3. 设置安全的文件权限
// 确保 /usr/lib64/libsmap.so 权限为 0555（只读）
```

---

### [VULN-DF-007] 栈溢出 - 变长数组（VLA）

**严重性**: Critical | **CWE**: CWE-121 | **置信度**: 80/100

**位置**
- 文件: `src/smap/server/turbo_module_smap.cpp`
- 行号: 427-453
- 函数: `SmapQueryProcessConfigHandler()`

**描述**
使用用户控制的 `inLen` 作为变长数组（VLA）的大小，未做边界检查。攻击者可发送大的 `inLen` 值导致栈溢出。

**漏洞代码** (`src/smap/server/turbo_module_smap.cpp:427-453`)

```cpp
int outLen = 0;
struct ProcessPayload payload[inLen];  // VLA - 栈溢出风险
int result = g_smapQueryProcessConfig(nid, payload, inLen, &outLen);
```

**达成路径**

1. `src/ipc/server/turbo_ipc_handler.cpp:250` - [SOURCE] recv() 接收网络消息
2. `src/ipc/server/turbo_ipc_handler.cpp:284` - HandleFunction() 调用回调
3. `src/smap/smap_handler_msg.cpp:1079` - DecodeRequest() 解析 inLen
4. `src/smap/server/turbo_module_smap.cpp:432` - 获取 inLen
5. `src/smap/server/turbo_module_smap.cpp:444` - [SINK] struct ProcessPayload payload[inLen] 栈上 VLA

**影响**
- 栈溢出导致程序崩溃（DoS）
- 可能的代码执行（覆盖返回地址）

**修复建议**
```cpp
// 1. 禁用 VLA，使用固定大小数组或堆分配
#define MAX_PROCESS_PAYLOAD 1024

if (inLen > MAX_PROCESS_PAYLOAD) {
    return ERROR_INVALID_PARAMETER;
}

// 方案A: 使用固定大小数组
struct ProcessPayload payload[MAX_PROCESS_PAYLOAD];

// 方案B: 使用 std::vector（堆分配）
std::vector<ProcessPayload> payload(inLen);

// 方案C: 使用 alloca 但限制大小（仍不推荐）
if (inLen <= 1024) {
    struct ProcessPayload *payload = (ProcessPayload*)alloca(sizeof(ProcessPayload) * inLen);
} else {
    return ERROR_TOO_LARGE;
}
```

---

### [VULN-DF-008] 栈溢出 - 变长数组（VLA）

**严重性**: Critical | **CWE**: CWE-121 | **置信度**: 80/100

**位置**
- 文件: `src/smap/server/turbo_module_smap.cpp`
- 行号: 455-477
- 函数: `SmapQueryRemoteNumaFreqHandler()`

**描述**
与 VULN-DF-007 类似，使用用户控制的 `len` 作为变长数组大小，未做边界检查。

**漏洞代码** (`src/smap/server/turbo_module_smap.cpp:455-477`)

```cpp
int ret = codec.DecodeRequest(inputBuffer, numa, len);
uint64_t freq[len];  // VLA - 栈溢出风险
int result = g_smapQueryRemoteNumaFreq(numa, freq, len);
```

**达成路径**

1. `src/ipc/server/turbo_ipc_handler.cpp:250` - [SOURCE] recv() 接收网络消息
2. `src/ipc/server/turbo_ipc_handler.cpp:284` - HandleFunction() 调用回调
3. `src/smap/smap_handler_msg.cpp:1175` - DecodeRequest() 解析 len
4. `src/smap/server/turbo_module_smap.cpp:460` - 获取 len
5. `src/smap/server/turbo_module_smap.cpp:466` - [SINK] uint64_t freq[len] 栈上 VLA

**影响**
- 栈溢出导致程序崩溃（DoS）
- 可能的代码执行

**修复建议**
同 VULN-DF-007

---

## 🟠 High 漏洞（7个）

### [VULN-SEC-003] SMAP 接口缺少授权检查

**严重性**: High | **CWE**: CWE-862 | **置信度**: 90/100

**位置**
- 文件: `src/smap/smap_handler_msg.cpp`
- 行号: 41-69
- 函数: `SmapMigrateOutCodec::DecodeRequest()`

**描述**
SMAP 内存迁移接口接受任意进程 ID（PID），不验证调用者是否有权限操作该进程的内存。

**漏洞代码** (`src/smap/smap_handler_msg.cpp:41-69`)

```cpp
pidType = *static_cast<int *>(static_cast<void *>(buffer.data));
msg = *static_cast<MigrateOutMsg *>(static_cast<void *>(buffer.data + sizeof(int)));
```

**达成路径**

1. `src/ipc/server/turbo_ipc_handler.cpp:250` - [SOURCE] recv() 接收网络消息
2. `src/ipc/server/turbo_ipc_handler.cpp:284` - HandleFunction() 调用SMAP handler
3. `src/smap/smap_handler_msg.cpp:67` - 解析 pidType 和 msg
4. `src/smap/server/turbo_module_smap.cpp:68` - 调用 g_smapMigrateOut()
5. `src/smap/server/turbo_module_smap.cpp:68` - [SINK] 未授权迁移任意进程内存

**影响**
- 操作其他进程的内存
- 可能的权限提升
- 数据泄露

**修复建议**
```cpp
// 1. 验证客户端是否有权限操作目标 PID
if (cred.uid != 0 && cred.uid != GetProcessUid(pid)) {
    return ERROR_PERMISSION_DENIED;
}

// 2. 限制可操作的 PID 范围
// 只允许操作同一 UID 的进程，或管理员指定的进程列表
```

---

### [VULN-SEC-004] 插件加载缺少代码验证

**严重性**: High | **CWE**: CWE-494 | **置信度**: 85/100

**位置**
- 文件: `src/plugin/turbo_plugin_manager.cpp`
- 行号: 74-98
- 函数: `TurboPluginManager::LoadPlugin()`

**描述**
插件路径来自配置文件，虽然使用 `realpath()` 解析路径，但不验证插件的签名或哈希值。

**漏洞代码** (`src/plugin/turbo_plugin_manager.cpp:74-98`)

```cpp
void *handle = dlopen(canonicalPath, RTLD_NOW | RTLD_GLOBAL);
if (handle == nullptr) {
    UBTURBO_LOG_ERROR(MODULE_NAME, MODULE_CODE)
        << "[Plugin] Failed to load plugin " << pluginName << " so, error: " << dlerror();
    return TURBO_ERROR;
}
```

**达成路径**

1. `src/config/turbo_conf_manager.cpp:118` - [SOURCE] 配置文件读取 so 路径
2. `src/plugin/turbo_plugin_manager.cpp:81` - realpath() 解析路径
3. `src/plugin/turbo_plugin_manager.cpp:88` - dlopen() 加载动态库
4. `src/plugin/turbo_plugin_manager.cpp:102` - [SINK] 调用未验证的插件代码

**影响**
- 加载恶意插件
- 执行任意代码
- 持久化后门

**修复建议**
```cpp
// 1. 实现插件签名验证
bool VerifyPluginSignature(const std::string& path) {
    // 使用公钥验证插件签名
}

// 2. 限制插件目录白名单
const std::set<std::string> ALLOWED_DIRS = {
    "/opt/ubturbo/plugins/official/",
    "/usr/lib64/ubturbo/"
};

if (!IsPathInAllowedDirs(canonicalPath, ALLOWED_DIRS)) {
    throw std::runtime_error("Plugin path not in allowed directories");
}

// 3. 设置严格的文件权限检查
// 插件目录权限应为 0755，插件文件权限应为 0555
```

---

### [VULN-SEC-006] 日志文件路径遍历

**严重性**: High | **CWE**: CWE-22 | **置信度**: 80/100

**位置**
- 文件: `src/log/rack_logger_filesink.cpp`
- 行号: 52-88
- 函数: `RackLoggerFilesink::Write()`

**描述**
日志文件名直接来自模块名，不验证路径中的 `../` 序列，可能导致写入任意文件。

**漏洞代码** (`src/log/rack_logger_filesink.cpp:52-88`)

```cpp
std::string fileName = moduleName;
fileMap[fileName].filePath = basePath + "/" + fileName + ".log";
```

**达成路径**

1. `src/log/rack_logger_filesink.cpp:52` - [SOURCE] moduleName 来自日志模块名
2. `src/log/rack_logger_filesink.cpp:60` - 构造文件路径
3. `src/log/rack_logger_filesink.cpp:141` - 打开文件进行写入
4. `src/log/rack_logger_filesink.cpp:141` - [SINK] 可能的路径遍历攻击

**影响**
- 写入任意系统文件
- 覆盖关键配置文件
- 持久化后门

**修复建议**
```cpp
// 1. 验证文件名，拒绝路径遍历字符
std::string SanitizeFileName(const std::string& fileName) {
    std::string result;
    for (char c : fileName) {
        if (isalnum(c) || c == '_' || c == '-') {
            result += c;
        }
    }
    return result;
}

// 2. 使用绝对路径并验证前缀
std::string fullPath = basePath + "/" + fileName + ".log";
std::string canonicalPath = std::filesystem::canonical(fullPath);
if (!canonicalPath.starts_with(basePath)) {
    throw std::runtime_error("Path traversal detected");
}
```

---

### [VULN-DF-002] 整数溢出导致堆溢出

**严重性**: High | **CWE**: CWE-680 | **置信度**: 75/100

**位置**
- 文件: `src/ipc/server/turbo_ipc_handler.cpp`
- 行号: 259-275
- 函数: `RecvMessage()`

**描述**
消息长度从网络数据解析后直接用于 `new` 分配内存，虽然有最大长度检查，但可能存在整数溢出或类型转换问题。

**漏洞代码** (`src/ipc/server/turbo_ipc_handler.cpp:259-275`)

```cpp
int messageLength = static_cast<int>(GetHeader(receivedBuffer.get() + HEADER_OFFSET_LENGTH));
params.data = new (std::nothrow) uint8_t[messageLength];
```

**达成路径**

1. `src/ipc/server/turbo_ipc_handler.cpp:250` - [SOURCE] recv() 接收网络数据
2. `src/ipc/server/turbo_ipc_handler.cpp:259` - 解析消息长度（ntohl转换）
3. `src/ipc/server/turbo_ipc_handler.cpp:270` - 长度验证（存在绕过）
4. `src/ipc/server/turbo_ipc_handler.cpp:270` - new[] 分配内存（整数截断风险）
5. `src/ipc/server/turbo_ipc_handler.cpp:225` - [SINK] 缓冲区溢出风险

**影响**
- 堆溢出
- 程序崩溃
- 可能的代码执行

**修复建议**
```cpp
// 1. 使用无符号类型避免负值
uint32_t messageLength = ntohl(*(uint32_t*)(receivedBuffer.get() + HEADER_OFFSET_LENGTH));

// 2. 严格验证消息长度
const uint32_t MAX_MESSAGE_LENGTH = 1024 * 1024; // 1MB
if (messageLength > MAX_MESSAGE_LENGTH) {
    return ERROR_MESSAGE_TOO_LARGE;
}

// 3. 检查分配是否成功
uint8_t *data = new (std::nothrow) uint8_t[messageLength];
if (!data) {
    return ERROR_OUT_OF_MEMORY;
}
```

---

### [VULN-DF-003] 堆缓冲区溢出

**严重性**: High | **CWE**: CWE-122 | **置信度**: 75/100

**位置**
- 文件: `src/smap/smap_handler_msg.cpp`
- 行号: 424-452
- 函数: `SmapAddProcessTrackingCodec::DecodeRequest()`

**描述**
使用 `memcpy_s()` 复制 PID 数组，但长度来自网络数据，可能超过目标缓冲区大小。

**漏洞代码** (`src/smap/smap_handler_msg.cpp:424-452`)

```cpp
len = *static_cast<int *>(static_cast<void *>(buffer.data));
int ret = memcpy_s(pidArr, sizeof(pid_t) * MAX_NR_TRACKING, buffer.data + copied, sizeof(pid_t) * len);
```

**达成路径**

1. `src/ipc/server/turbo_ipc_handler.cpp:250` - [SOURCE] recv() 接收网络消息
2. `src/ipc/server/turbo_ipc_handler.cpp:284` - HandleFunction() 调用回调
3. `src/smap/smap_handler_msg.cpp:430` - 解析 len 字段
4. `src/smap/smap_handler_msg.cpp:438` - memcpy_s() 复制数据
5. `src/smap/smap_handler_msg.cpp:438` - [SINK] 堆缓冲区溢出风险

**影响**
- 堆溢出
- 程序崩溃
- 可能的代码执行

**修复建议**
```cpp
// 1. 验证长度不超过最大值
const int MAX_NR_TRACKING = 1024;
if (len > MAX_NR_TRACKING) {
    return ERROR_INVALID_PARAMETER;
}

// 2. 使用更安全的 API
size_t copySize = sizeof(pid_t) * len;
if (copySize > buffer.size - copied) {
    return ERROR_BUFFER_OVERFLOW;
}

memcpy_s(pidArr, sizeof(pid_t) * MAX_NR_TRACKING,
         buffer.data + copied, copySize);
```

---

### [VULN-DF-004] 插件路径遍历

**严重性**: High | **CWE**: CWE-22 | **置信度**: 80/100

**位置**
- 文件: `src/plugin/turbo_plugin_manager.cpp`
- 行号: 74-98
- 函数: `TurboPluginManager::LoadPlugin()`

**描述**
插件路径来自配置文件，虽然使用 `realpath()` 和 `fs::canonical()` 解析，但如果配置文件包含路径遍历序列，可能加载恶意库。

**漏洞代码** (`src/plugin/turbo_plugin_manager.cpp:74-98`)

```cpp
char *canonicalPath = realpath(fileName.c_str(), nullptr);
void *handle = dlopen(canonicalPath, RTLD_NOW | RTLD_GLOBAL);
```

**达成路径**

1. `src/config/turbo_conf_manager.cpp:118` - [SOURCE] ParseFile() 读取配置文件
2. `src/config/turbo_conf_manager.cpp:91` - 解析插件 so 路径
3. `src/config/turbo_conf_manager.cpp:96` - fs::canonical() 解析路径
4. `src/plugin/turbo_plugin_manager.cpp:81` - realpath() 规范化路径
5. `src/plugin/turbo_plugin_manager.cpp:88` - [SINK] dlopen() 加载动态库

**影响**
- 加载任意位置的动态库
- 执行恶意代码
- 绕过沙箱限制

**修复建议**
```cpp
// 1. 配置文件路径白名单
const std::vector<std::string> ALLOWED_PLUGIN_DIRS = {
    "/opt/ubturbo/plugins/",
    "/usr/lib64/ubturbo/"
};

// 2. 验证路径是否在允许的目录中
std::string canonicalPath = std::filesystem::canonical(fileName);
bool isAllowed = false;
for (const auto& allowedDir : ALLOWED_PLUGIN_DIRS) {
    if (canonicalPath.starts_with(allowedDir)) {
        isAllowed = true;
        break;
    }
}

if (!isAllowed) {
    throw std::runtime_error("Plugin path not in allowed directories");
}
```

---

### [VULN-DF-009] 栈溢出 - 变长数组（VLA）

**严重性**: High | **CWE**: CWE-121 | **置信度**: 75/100

**位置**
- 文件: `src/smap/server/turbo_module_smap.cpp`
- 行号: 309-330
- 函数: `SmapQueryFreqHandler()`

**描述**
与 VULN-DF-007 和 VULN-DF-008 类似，使用用户控制的 `lengthIn` 作为变长数组大小。

**漏洞代码** (`src/smap/server/turbo_module_smap.cpp:309-330`)

```cpp
int ret = codec.DecodeRequest(inputBuffer, pid, lengthIn, dataSource);
uint16_t data[lengthIn];  // VLA - 栈溢出风险
uint32_t lengthOut = lengthIn;
```

**达成路径**

1. `src/ipc/server/turbo_ipc_handler.cpp:250` - [SOURCE] recv() 接收网络消息
2. `src/ipc/server/turbo_ipc_handler.cpp:284` - HandleFunction() 调用回调
3. `src/smap/smap_handler_msg.cpp:702` - DecodeRequest() 解析 lengthIn
4. `src/smap/server/turbo_module_smap.cpp:312` - 获取 lengthIn
5. `src/smap/server/turbo_module_smap.cpp:321` - [SINK] uint16_t data[lengthIn] 栈上 VLA

**影响**
- 栈溢出导致程序崩溃
- 可能的代码执行

**修复建议**
同 VULN-DF-007

---

## 🟡 Medium 漏洞（3个）

### [VULN-SEC-005] Socket 文件权限过宽

**严重性**: Medium | **CWE**: CWE-732 | **置信度**: 85/100

**位置**
- 文件: `src/ipc/server/turbo_ipc_handler.cpp`
- 行号: 80-115
- 函数: `IpcHandler::StartListen()`

**描述**
Unix Domain Socket 文件权限设置为 0640，允许同一用户组的所有进程读写。如果用户组包含非特权进程，可能导致安全风险。

**漏洞代码** (`src/ipc/server/turbo_ipc_handler.cpp:80-115`)

```cpp
static const uint32_t SOCKET_MODE = 0640;
if (chmod(addr.sun_path, SOCKET_MODE) != 0) {
    UBTURBO_LOG_ERROR(MODULE_NAME, MODULE_CODE) << "[Ipc][Server] Chmod failed.";
    close(listenFd);
    return TURBO_ERROR;
}
```

**达成路径**

1. `src/ipc/server/turbo_ipc_handler.cpp:80` - SOCKET_MODE 定义为 0640
2. `src/ipc/server/turbo_ipc_handler.cpp:114` - chmod() 设置 socket 文件权限
3. `src/ipc/server/turbo_ipc_handler.cpp:114` - [SINK] 允许组读写，可能被非授权用户访问

**影响**
- 同组进程可连接 IPC
- 扩大攻击面

**修复建议**
```cpp
// 1. 使用更严格的权限（仅 owner）
static const uint32_t SOCKET_MODE = 0600;

// 2. 或使用专门的 IPC 用户组，严格控制成员
static const uint32_t SOCKET_MODE = 0660;
// 并确保 ubturbo 组只包含授权的进程
```

---

### [VULN-SEC-007] 敏感数据暴露 - 共享内存路径

**严重性**: Medium | **CWE**: CWE-200 | **置信度**: 70/100

**位置**
- 文件: `src/smap/server/turbo_module_smap.cpp`
- 行号: 33
- 函数: `const std::string FILE_NAME`

**描述**
共享内存文件路径硬编码为 `/dev/shm/ubturbo_page_type.dat`，路径可预测且可被其他进程访问。

**漏洞代码** (`src/smap/server/turbo_module_smap.cpp:33`)

```cpp
const std::string FILE_NAME = "/dev/shm/ubturbo_page_type.dat";
```

**达成路径**

1. `src/smap/server/turbo_module_smap.cpp:33` - 共享内存文件路径暴露
2. `src/smap/server/turbo_module_smap.cpp:757` - 写入 pageType 到共享文件
3. `src/smap/server/turbo_module_smap.cpp:789` - 从共享文件读取 pageType
4. `src/smap/server/turbo_module_smap.cpp:33` - [SINK] 硬编码的共享内存路径

**影响**
- 其他进程可读取共享内存
- 信息泄露

**修复建议**
```cpp
// 1. 使用随机文件名
#include <random>
std::string GenerateRandomShmName() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 0xFFFF);
    return "/dev/shm/ubturbo_" + std::to_string(dis(gen)) + ".dat";
}

// 2. 设置严格的文件权限
// 创建共享内存后立即设置为 0600
```

---

### [VULN-DF-005] 日志文件路径遍历

**严重性**: Medium | **CWE**: CWE-22 | **置信度**: 70/100

**位置**
- 文件: `src/log/rack_logger_filesink.cpp`
- 行号: 50-89
- 函数: `RackLoggerFilesink::Write()`

**描述**
与 VULN-SEC-006 相同的问题，但标记为 Medium 因为影响范围可能受限。

**漏洞代码** (`src/log/rack_logger_filesink.cpp:50-89`)

```cpp
std::string fileName = moduleName;
fileMap[fileName].filePath = basePath + "/" + fileName + ".log";
```

**达成路径**

1. `src/log/rack_logger_filesink.cpp:52` - 获取 moduleName
2. `src/log/rack_logger_filesink.cpp:58` - 构造文件路径
3. `src/log/rack_logger_filesink.cpp:141` - 文件打开操作
4. `src/log/rack_logger_filesink.cpp:141` - [SINK] 路径遍历风险

**影响**
- 写入任意文件（可能受限于日志目录权限）

**修复建议**
同 VULN-SEC-006

---

### [VULN-DF-006] 配置解析整数溢出

**严重性**: Medium | **CWE**: CWE-190 | **置信度**: 65/100

**位置**
- 文件: `src/config/turbo_conf_manager.cpp`
- 行号: 69-84
- 函数: `TurboPluginManager::InitPluginConf()`

**描述**
配置文件中的 `pluginCode` 字符串转换为 `uint16_t` 时可能溢出。

**漏洞代码** (`src/config/turbo_conf_manager.cpp:69-84`)

```cpp
uint16_t pluginCode = 0;
pluginCode = turbo::utils::Convert<uint16_t>(pluginCodeStr);
```

**达成路径**

1. `src/config/turbo_conf_manager.cpp:118` - [SOURCE] ParseFile() 读取配置
2. `src/config/turbo_conf_manager.cpp:139` - 解析 key-value 对
3. `src/config/turbo_conf_manager.cpp:79` - 转换 pluginCode 为 uint16_t
4. `src/config/turbo_conf_manager.cpp:85` - [SINK] 插件代码用于后续逻辑

**影响**
- 插件代码溢出
- 可能的逻辑错误

**修复建议**
```cpp
// 1. 使用 std::stoul 并检查范围
unsigned long code = std::stoul(pluginCodeStr);
if (code > UINT16_MAX) {
    throw std::runtime_error("pluginCode out of range");
}
uint16_t pluginCode = static_cast<uint16_t>(code);

// 2. 验证插件代码范围
if (pluginCode < 1000 || pluginCode > 9999) {
    throw std::runtime_error("Invalid pluginCode format");
}
```

---

## 模块风险评估

### IPC 通信模块 (`src/ipc`)

| 指标 | 数值 |
|------|------|
| 漏洞数量 | 3 |
| Critical | 2 |
| High | 0 |
| Medium | 1 |
| **风险等级** | 🔴 **CRITICAL** |

**关键问题**:
- 完全缺少认证机制（VULN-SEC-001）
- 完全缺少授权机制（VULN-SEC-002）
- Socket 权限过宽（VULN-SEC-005）

**建议**: 立即实施认证和授权机制，限制 IPC 访问。

---

### SMAP 内存管理模块 (`src/smap`)

| 指标 | 数值 |
|------|------|
| 漏洞数量 | 6 |
| Critical | 3 |
| High | 1 |
| Medium | 1 |
| **风险等级** | 🔴 **CRITICAL** |

**关键问题**:
- 3 个栈溢出漏洞（VLA 使用）
- 未授权访问进程内存（VULN-SEC-003）
- 库加载缺少验证（VULN-SEC-008）
- 共享内存路径可预测（VULN-SEC-007）

**建议**: 立即修复所有 VLA 栈溢出，实施进程权限验证。

---

### 日志系统模块 (`src/log`)

| 指标 | 数值 |
|------|------|
| 漏洞数量 | 3 |
| Critical | 1 |
| High | 1 |
| Medium | 1 |
| **风险等级** | 🟠 **HIGH** |

**关键问题**:
- 命令注入漏洞（VULN-DF-001）
- 路径遍历漏洞（VULN-SEC-006, VULN-DF-005）

**建议**: 立即禁用 `system()`，使用 fork+exec 或库函数。

---

### 插件系统模块 (`src/plugin`)

| 指标 | 数值 |
|------|------|
| 漏洞数量 | 2 |
| Critical | 0 |
| High | 2 |
| Medium | 0 |
| **风险等级** | 🟠 **HIGH** |

**关键问题**:
- 插件加载缺少签名验证（VULN-SEC-004）
- 路径遍历风险（VULN-DF-004）

**建议**: 实施插件签名验证，限制插件目录白名单。

---

### 配置解析模块 (`src/config`)

| 指标 | 数值 |
|------|------|
| 漏洞数量 | 1 |
| Critical | 0 |
| High | 0 |
| Medium | 1 |
| **风险等级** | 🟡 **MEDIUM** |

**关键问题**:
- 整数溢出风险（VULN-DF-006）

**建议**: 加强配置值验证，使用安全的转换函数。

---

## 修复路线图

### 第一阶段：紧急修复（1-2 周）

**优先级 P0 - 立即修复**

| ID | 漏洞 | 修复内容 | 预计时间 |
|----|------|----------|----------|
| VULN-DF-001 | 命令注入 | 使用 fork+exec 替代 system() | 2-3 天 |
| VULN-DF-007 | 栈溢出 VLA | 替换 VLA 为固定数组或 std::vector | 1 天 |
| VULN-DF-008 | 栈溢出 VLA | 替换 VLA 为固定数组或 std::vector | 1 天 |
| VULN-DF-009 | 栈溢出 VLA | 替换 VLA 为固定数组或 std::vector | 1 天 |

**验收标准**:
- 所有 VLA 替换为安全的内存分配方式
- 不再使用 system() 执行外部命令
- 所有用户输入经过严格验证

---

### 第二阶段：关键修复（2-4 周）

**优先级 P1 - 高优先级**

| ID | 漏洞 | 修复内容 | 预计时间 |
|----|------|----------|----------|
| VULN-SEC-001 | 缺少认证 | 实现 Unix credential 验证 | 3-5 天 |
| VULN-SEC-002 | 缺少授权 | 实现基于角色的权限控制（RBAC） | 5-7 天 |
| VULN-DF-002 | 整数溢出/堆溢出 | 严格验证消息长度 | 1-2 天 |
| VULN-DF-003 | 堆溢出 | 验证数组长度边界 | 1-2 天 |

**验收标准**:
- 所有 IPC 连接经过认证
- 所有 IPC 函数调用经过授权
- 网络数据严格验证

---

### 第三阶段：重要修复（1-2 个月）

**优先级 P2 - 中优先级**

| ID | 漏洞 | 修复内容 | 预计时间 |
|----|------|----------|----------|
| VULN-SEC-003 | SMAP 未授权访问 | 实现进程权限验证 | 3-5 天 |
| VULN-SEC-004 | 插件缺少验证 | 实施插件签名验证 | 1-2 周 |
| VULN-SEC-006 | 日志路径遍历 | 实现文件名白名单验证 | 2-3 天 |
| VULN-DF-004 | 插件路径遍历 | 限制插件目录白名单 | 2-3 天 |

**验收标准**:
- 所有文件操作经过路径验证
- 插件加载需要签名验证
- SMAP 接口需要进程权限检查

---

### 第四阶段：安全加固（持续）

**优先级 P3 - 低优先级**

| ID | 漏洞 | 修复内容 | 预计时间 |
|----|------|----------|----------|
| VULN-SEC-005 | Socket 权限过宽 | 调整为 0600 | 1 天 |
| VULN-SEC-007 | 共享内存路径暴露 | 使用随机文件名 | 2-3 天 |
| VULN-SEC-008 | 库加载缺少验证 | 实施库签名验证 | 1-2 周 |
| VULN-DF-005 | 日志路径遍历 | 实现文件名白名单验证 | 1-2 天 |
| VULN-DF-006 | 配置整数溢出 | 使用安全的转换函数 | 1-2 天 |

---

## 最佳实践建议

### 安全开发规范

#### 1. 输入验证原则

**所有外部输入必须验证**:
- 网络数据（IPC、Socket）
- 配置文件
- 环境变量
- 文件名、路径
- 命令行参数

**验证清单**:
```cpp
// 1. 长度检查
if (input.length() > MAX_LENGTH) return ERROR;

// 2. 格式检查（正则表达式）
if (!std::regex_match(input, validPattern)) return ERROR;

// 3. 范围检查
if (value < MIN_VALUE || value > MAX_VALUE) return ERROR;

// 4. 字符集检查
for (char c : input) {
    if (!isAllowed(c)) return ERROR;
}

// 5. 路径遍历检查
if (input.find("..") != std::string::npos) return ERROR;
```

---

#### 2. 禁止危险的 API

**永远不要使用**:
- `system()` - 使用 `fork() + exec()` 或 `posix_spawnp()`
- `strcpy()`, `strcat()` - 使用 `strncpy()`, `strncat()` 或 C++ string
- `sprintf()`, `vsprintf()` - 使用 `snprintf()`, `vsnprintf()`
- `gets()` - 使用 `fgets()`
- `scanf()` - 使用 `fscanf()` 或自定义解析
- 变长数组（VLA） - 使用 `std::vector` 或固定大小数组

**替代方案**:
```cpp
// ❌ 危险
system("tar -czf output.tar.gz input.txt");

// ✅ 安全
pid_t pid;
char *argv[] = {"tar", "-czf", "output.tar.gz", "input.txt", nullptr};
posix_spawnp(&pid, "tar", nullptr, nullptr, argv, environ);

// ❌ 危险
char buf[100];
strcpy(buf, user_input);

// ✅ 安全
std::string buf = user_input;
if (buf.length() >= 100) throw std::runtime_error("Too long");
```

---

#### 3. 认证和授权

**认证**:
```cpp
// Unix credential 验证
struct ucred cred;
socklen_t len = sizeof(cred);
getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len);

// 验证 UID/GID
if (cred.uid != 0 && !IsAuthorizedUser(cred.uid)) {
    close(fd);
    continue;
}
```

**授权**:
```cpp
// 基于角色的权限控制
enum class Permission {
    READ,
    WRITE,
    ADMIN
};

struct Client {
    std::set<Permission> permissions;
};

bool CheckPermission(Client* client, Permission required) {
    return client->permissions.count(required) > 0;
}
```

---

#### 4. 内存安全

**禁止使用**:
- 变长数组（VLA）
- `malloc()`/`free()` - 使用 `new`/`delete` 或智能指针
- `alloca()` - 不安全的栈分配
- 未检查的指针运算

**推荐使用**:
```cpp
// ✅ 使用 std::vector（堆分配，自动管理）
std::vector<uint8_t> data(size);
std::fill(data.begin(), data.end(), 0);

// ✅ 使用智能指针
std::unique_ptr<uint8_t[]> data(new uint8_t[size]);

// ✅ 使用固定大小数组（编译时常量）
constexpr size_t MAX_SIZE = 1024;
uint8_t data[MAX_SIZE];
```

---

#### 5. 文件操作安全

**路径验证**:
```cpp
// 1. 使用绝对路径
std::string fullPath = basePath + "/" + fileName;

// 2. 规范化路径
std::filesystem::path canonicalPath = std::filesystem::canonical(fullPath);

// 3. 验证前缀
if (!canonicalPath.string().starts_with(basePath)) {
    throw std::runtime_error("Path traversal detected");
}

// 4. 文件名白名单
std::regex validFileName("^[a-zA-Z0-9_-]+$");
if (!std::regex_match(fileName, validFileName)) {
    throw std::runtime_error("Invalid file name");
}
```

---

### 代码审查检查清单

#### 🔴 Critical Issues（必须修复）

- [ ] 是否使用 `system()` 或 `popen()`？
- [ ] 是否使用 `strcpy()`, `sprintf()`, `gets()`？
- [ ] 是否使用变长数组（VLA）？
- [ ] 是否接受未验证的网络输入？
- [ ] 是否缺少认证机制？
- [ ] 是否缺少授权机制？

#### 🟠 High Issues（应修复）

- [ ] 整数转换是否检查溢出？
- [ ] 数组访问是否检查边界？
- [ ] 动态内存分配是否检查失败？
- [ ] 文件路径是否验证？
- [ ] 插件/库加载是否验证？

#### 🟡 Medium Issues（建议修复）

- [ ] 硬编码的敏感路径？
- [ ] 日志是否包含敏感信息？
- [ ] 错误消息是否泄露信息？
- [ ] 文件权限是否正确？

---

### 安全测试建议

#### 1. 模糊测试（Fuzzing）

**工具**:
- AFL++ (American Fuzzy Lop)
- libFuzzer (LLVM)
- honggfuzz

**目标**:
- IPC 消息解析函数
- 配置文件解析
- SMAP 接口
- 插件加载器

**示例**:
```bash
# 对 IPC handler 进行模糊测试
afl-fuzz -i input_dir -o output_dir -- ./ubturbo_ipc_test @@

# 使用 libFuzzer
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    ProcessIpcMessage(data, size);
    return 0;
}
```

---

#### 2. 静态分析

**工具**:
- Clang Static Analyzer
- cppcheck
- SonarQube C/C++
- CodeQL

**检查项**:
- 缓冲区溢出
- 内存泄漏
- 空指针解引用
- 未初始化变量
- 危险 API 使用

---

#### 3. 动态分析

**工具**:
- Valgrind（内存错误检测）
- AddressSanitizer (ASan)
- UndefinedBehaviorSanitizer (UBSan)
- ThreadSanitizer (TSan)

**编译选项**:
```bash
# 启用 AddressSanitizer
export CFLAGS="-fsanitize=address -fno-omit-frame-pointer"
export LDFLAGS="-fsanitize=address"

# 启用 UndefinedBehaviorSanitizer
export CFLAGS="-fsanitize=undefined"
```

---

#### 4. 渗透测试

**测试场景**:
- 尝试连接 IPC socket，发送恶意消息
- 尝试注入命令到日志压缩功能
- 尝试触发栈溢出（发送大数组长度）
- 尝试路径遍历（使用 `../` 序列）
- 尝试加载恶意插件

**Payload 示例**:
```bash
# 1. 命令注入
echo -e 'module_name; rm -rf /' | nc -U /opt/ubturbo/ubturbo_ipc

# 2. 栈溢出
echo -e '{"length": 999999, "data": "..."}' | nc -U /opt/ubturbo/ubturbo_ipc

# 3. 路径遍历
echo -e 'module_name: ../../../../etc/passwd' | nc -U /opt/ubturbo/ubturbo_ipc
```

---

#### 5. 安全审计

**审计内容**:
- 代码架构审查
- 设计文档审查
- 威胁建模
- 安全需求符合性检查

**审计频率**:
- 重大更新后
- 每季度
- 发布新版本前

---

## 附录

### A. 漏洞分类统计

| CWE 分类 | 数量 | 占比 |
|----------|------|------|
| CWE-121: 栈溢出 | 3 | 18.8% |
| CWE-862: 缺少授权 | 2 | 12.5% |
| CWE-22: 路径遍历 | 4 | 25.0% |
| CWE-78: 命令注入 | 1 | 6.3% |
| CWE-306: 缺少认证 | 1 | 6.3% |
| CWE-494: 缺少代码验证 | 1 | 6.3% |
| CWE-427: 未授权库加载 | 1 | 6.3% |
| CWE-680: 整数溢出 | 1 | 6.3% |
| CWE-122: 堆溢出 | 1 | 6.3% |
| CWE-190: 整数溢出 | 1 | 6.3% |
| CWE-732: 文件权限问题 | 1 | 6.3% |
| CWE-200: 信息泄露 | 1 | 6.3% |

---

### B. 攻击面分析

| 攻击面 | 风险等级 | 相关漏洞 |
|--------|----------|----------|
| Unix Domain Socket (/opt/ubturbo/ubturbo_ipc) | 🔴 Critical | SEC-001, SEC-002, DF-002, DF-003, DF-007, DF-008, DF-009 |
| 日志文件操作 (/var/log/ubturbo/) | 🟠 High | DF-001, SEC-006, DF-005 |
| 插件加载 (/opt/ubturbo/plugins/) | 🟠 High | SEC-004, DF-004 |
| 共享内存 (/dev/shm/) | 🟡 Medium | SEC-007, SEC-008 |
| 配置文件 (/opt/ubturbo/conf/) | 🟡 Medium | DF-006 |

---

### C. 参考资料

**安全标准**:
- ISO/IEC 27001 - 信息安全管理体系
- OWASP Top 10 - Web 应用安全风险
- CWE Top 25 - 最常见软件缺陷
- CERT C Coding Standard - 安全编码标准

**工具文档**:
- [AddressSanitizer](https://github.com/google/sanitizers/wiki/AddressSanitizer)
- [AFL++](https://github.com/AFLplusplus/AFLplusplus)
- [cppcheck](https://cppcheck.sourceforge.io/)

**漏洞数据库**:
- [CVE - Common Vulnerabilities and Exposures](https://cve.mitre.org/)
- [NVD - National Vulnerability Database](https://nvd.nist.gov/)
- [CWE - Common Weakness Enumeration](https://cwe.mitre.org/)

---

## 总结

UBTurbo 项目存在**严重的安全问题**，共计发现 16 个漏洞，其中 6 个为 Critical 级别。最关键的问题包括：

1. **完全缺少认证和授权机制**（VULN-SEC-001, VULN-SEC-002）
2. **命令注入漏洞**（VULN-DF-001）
3. **多个栈溢出漏洞**（VULN-DF-007, VULN-DF-008, VULN-DF-009）

这些问题可能导致：
- 远程代码执行（RCE）
- 权限提升
- 数据泄露
- 服务拒绝（DoS）

**建议立即启动紧急修复计划**，按照修复路线图的第一阶段（1-2 周）优先修复所有 Critical 级别的缓冲区溢出和命令注入漏洞。

同时，建议：
1. 建立安全开发生命周期（SDL）
2. 实施持续的代码审计和安全测试
3. 引入静态分析工具到 CI/CD 流程
4. 定期进行渗透测试
5. 加强开发团队的安全意识培训

---

**报告生成**: OpenCode Vulnerability Scanner
**报告版本**: 1.0
**联系方式**: security@opencode.ai
