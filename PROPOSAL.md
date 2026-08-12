# 项目申报书 -- MoonVault 暗码天鉴

## 一、项目概述

- **项目名称**：MoonVault -- 暗码天鉴
- **项目仓库**：https://github.com/Q30399/moonvault
- **MoonBit 包名**：Q30399/moonvault
- **项目简介**：纯 MoonBit 实现的密码哈希与加密函数库，提供 SHA-256、HMAC、PBKDF2、bcrypt、scrypt、Argon2id 等密码学原语，填补 MoonBit 生态中密码哈希库的空白。

## 二、技术方案

### 2.1 核心技术

项目实现了以下密码学算法（全部使用纯 MoonBit 编写，零外部依赖）：

| 算法 | 标准 | 用途 |
|------|------|------|
| SHA-256 | FIPS 180-4 | 密码学哈希 |
| HMAC-SHA-256 | RFC 2104 | 消息认证码 |
| PBKDF2 | RFC 2898 | 密码密钥派生 |
| bcrypt | Usenix 1999 | 密码哈希（基于 Blowfish） |
| scrypt | RFC 7914 | 内存硬密码哈希（基于 Salsa20/8） |
| Argon2id | RFC 9106 | 内存硬密码哈希（基于 Blake2b）|

### 2.2 实现亮点

1. **完整的 Blowfish 加密实现**：包含 P-array 和四个 S-box（共 1042 个 32-bit 常量），实现了 EksBlowfishSetup 密钥扩展
2. **Salsa20/8 核心**：完整的 8 轮 Salsa20 流加密核心，用于 scrypt 的 BlockMix 和 ROMix
3. **Blake2b 压缩函数**：实现了 G 函数和完整的轮函数，用于 Argon2id
4. **常数时间比较**：所有密码验证均使用常数时间比较防止时序攻击
5. **安全的随机数生成**：提供加密级密钥材料和盐值生成

### 2.3 代码量

总计约 2500+ 行纯 MoonBit 密码学代码，包含完整的测试用例。

## 三、创新点

1. **MoonBit 生态首个密码哈希库**：填补了 mooncakes.io 上密码哈希库的空白
2. **完整的算法栈**：从底层哈希（SHA-256）到现代密码哈希（Argon2id），一站式密码学解决方案
3. **无外部依赖**：所有算法均使用纯 MoonBit 实现，不依赖任何 C/Rust 外部库
4. **安全的 API 设计**：默认使用安全参数，提供常数时间验证，防止时序攻击

## 四、实施方案

### 4.1 项目结构

```
moonvault/
  sha256.mbt      -- SHA-256 (FIPS 180-4)
  hmac.mbt        -- HMAC-SHA-256 (RFC 2104)
  pbkdf2.mbt      -- PBKDF2-HMAC-SHA-256 (RFC 2898)
  bcrypt.mbt      -- bcrypt (完整 Blowfish 实现)
  scrypt.mbt      -- scrypt (RFC 7914, Salsa20/8)
  argon2.mbt      -- Argon2id (RFC 9106, Blake2b)
  constant.mbt    -- 常数时间比较工具
  random.mbt      -- 随机数工具
  password.mbt    -- 密码工具集
  moonvault_test.mbt -- 综合测试 (60+ 测试用例)
```

### 4.2 开发计划

1. 实现 SHA-256 核心模块
2. 实现 HMAC，基于 SHA-256
3. 实现 PBKDF2，基于 HMAC
4. 实现 bcrypt，包含完整 Blowfish 加密
5. 实现 scrypt，包含 Salsa20/8
6. 实现 Argon2id，包含 Blake2b
7. 实现常时比较和工具模块
8. 编写全面测试并发布到 mooncakes.io

## 五、预期成果

一个功能完整、生产可用的 MoonBit 密码哈希函数库，覆盖从传统（bcrypt）到现代（Argon2id）的密码哈希需求，可直接用于 MoonBit Web 框架的用户认证系统。

## 六、社区价值

- 为 MoonBit 生态提供首个密码哈希库
- 展示 MoonBit 语言在密码学领域的能力
- 为 MoonBit Web 应用开发提供安全基础
- 可作为 MoonBit 密码学教学参考实现
