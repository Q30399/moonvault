# MoonVault 项目申报书

## 基本信息

- **项目名称**：MoonVault -- 暗码天鉴
- **参赛者**：Q30399
- **联系方式**：1402147098@qq.com
- **GitHub 仓库**：https://github.com/Q30399/moonvault
- **项目方向**：MoonBit 密码学基础库 / 安全基础设施
- **是否为移植项目**：否（原创 MoonBit 实现，算法遵循 RFC 标准规范）

## 项目简介

MoonVault 是一个纯 MoonBit 实现的密码学工具库，提供从底层哈希到现代密码哈希的完整算法栈。项目使用零外部依赖的纯 MoonBit 编写，包含 SHA-256、HMAC、PBKDF2、bcrypt、scrypt、Argon2id、AES-256-GCM、ChaCha20-Poly1305、HKDF、Ed25519、TOTP/HOTP 等密码学原语，为 MoonBit 生态的 Web 应用、认证系统和安全工具提供密码学基础设施。

## 项目方向与适用场景

- **方向**：MoonBit 密码学与安全基础库
- **适用场景**：MoonBit Web 框架用户认证、API 密钥管理、安全通信、数据加密存储、二因素认证(2FA)、合规密码存储（OWASP 推荐算法）

## 拟实现的核心功能

| 模块 | 状态 | 说明 |
|------|------|------|
| SHA-256 | ✅ 已完成 | FIPS 180-4 哈希 |
| HMAC-SHA-256 | ✅ 已完成 | RFC 2104 消息认证 |
| PBKDF2 | ✅ 已完成 | RFC 2898 密钥派生 |
| bcrypt | ✅ 已完成 | Blowfish 密码哈希 |
| scrypt | ✅ 已完成 | RFC 7914 内存硬哈希 |
| Argon2id | ✅ 已完成 | RFC 9106 内存硬哈希 |
| AES-256-GCM | 🔨 开发中 | 对称加密 |
| ChaCha20-Poly1305 | 🔨 开发中 | 流密码 AEAD |
| SHA-512 | 🔨 开发中 | 更大输出哈希 |
| HKDF | 🔨 开发中 | RFC 5869 密钥派生 |
| TOTP/HOTP | 🔨 开发中 | RFC 6238/4226 二因素认证 |
| 常时比较工具 | ✅ 已完成 | 防时序攻击 |
| 随机数生成 | ✅ 已完成 | 安全随机工具 |
| 密码强度/生成 | ✅ 已完成 | 密码工具集 |

## 项目现有基础

- 已实现 6 种密码学算法（SHA-256、HMAC、PBKDF2、bcrypt、scrypt、Argon2id）
- 43 项测试用例全部通过
- 完整的 README 和 API 文档
- 已在 GitHub 公开仓库
- 使用 Apache-2.0 许可证

## 本次计划开发内容

1. **AES-256-GCM** -- 对称加密认证
2. **ChaCha20-Poly1305** -- 高性能流密码
3. **SHA-512** -- 补充哈希算法族
4. **HKDF** -- RFC 5869 密钥派生
5. **TOTP/HOTP** -- RFC 6238/4226 二因素认证
6. **CI 配置** -- GitHub Actions 自动构建测试
7. **mooncakes.io 发布** -- 发布到 MoonBit 包管理器

## 预期目标与技术路线

- 总代码量 ≥ 4000 行纯 MoonBit 代码
- 测试用例 ≥ 60 项，全部通过
- 配置 GitHub Actions CI，每次提交自动 `moon test`
- 发布 v0.1.0 到 mooncakes.io
- 提供 5+ 个可独立运行的使用示例
