# MoonVault -- 暗码天鉴

Pure MoonBit password hashing and cryptographic library.

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![MoonBit](https://img.shields.io/badge/MoonBit-0.1.0-purple.svg)](https://www.moonbitlang.com/)

## 功能特性

| 模块 | 标准 | 说明 |
|------|------|------|
| **SHA-256** | FIPS 180-4 | 安全哈希算法 |
| **HMAC-SHA-256** | RFC 2104 | 密钥哈希消息认证码 |
| **PBKDF2** | RFC 2898 | 基于密码的密钥派生（HMAC-SHA-256） |
| **bcrypt** | — | 基于 Blowfish 的密码哈希 |
| **scrypt** | RFC 7914 | 内存硬密码哈希（Salsa20/8） |
| **Argon2id** | RFC 9106 | 内存硬密码哈希（Blake2b） |
| **Constant-time** | — | 常量时间比较，防御时序侧信道攻击 |
| **Random** | — | 密码学安全随机数生成 |
| **Password** | — | 密码强度检测、自动生成、升级检测 |

## 快速开始

```moonbit
// bcrypt 哈希与验证
let hash = hash_password("my_secure_password")
let ok = verify_password("my_secure_password", hash)

// SHA-256
let digest = sha256_hex("hello world")
// => "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"

// HMAC
let mac = hmac_sha256_hex("my_key", "my_message")

// PBKDF2
let dk = pbkdf2_hex("password", "salt", 100000, 32)

// 生成随机密码
let pwd = generate_password(16)

// 密码强度检测
let score = password_strength("Str0ng!Passw0rd")   // => 80+
let level = password_strength_level("Str0ng!Passw0rd") // => "strong"
```

## API 参考

### SHA-256

```moonbit
pub fn sha256(data : Bytes) -> Bytes
pub fn sha256_hex(s : String) -> String
pub fn str_to_utf8(s : String) -> Bytes
pub fn bytes_to_hex(bytes : Bytes) -> String
```

### HMAC-SHA-256

```moonbit
pub fn HmacSha256::new(key : Bytes) -> HmacSha256
pub fn HmacSha256::sign(self : HmacSha256, message : Bytes) -> Bytes
pub fn HmacSha256::sign_string(self : HmacSha256, s : String) -> Bytes
pub fn HmacSha256::verify(self : HmacSha256, message : Bytes, mac : Bytes) -> Bool
pub fn hmac_sha256(key : Bytes, message : Bytes) -> Bytes
pub fn hmac_sha256_hex(key : String, message : String) -> String
pub fn hmac_verify(key : Bytes, message : Bytes, mac : Bytes) -> Bool
```

### PBKDF2 (HMAC-SHA-256)

```moonbit
pub fn pbkdf2(password : String, salt : String, iterations : Int, key_len : Int) -> Bytes
pub fn pbkdf2_raw(password : Bytes, salt : Bytes, iterations : Int, key_len : Int) -> Bytes
pub fn pbkdf2_hex(password : String, salt : String, iterations : Int, key_len : Int) -> String
pub fn pbkdf2_verify(password : String, salt : String, iterations : Int, key_len : Int, expected : Bytes) -> Bool
```

### bcrypt

```moonbit
pub fn bcrypt_hash(password : String, cost : Int, salt : String) -> String
pub fn bcrypt_verify(password : String, hash : String) -> Bool
pub fn generate_salt() -> String
```

cost 范围：4–31，推荐 ≥ 10。

### scrypt

```moonbit
pub fn scrypt(password : String, salt : String, n : Int, r : Int, p : Int, dk_len : Int) -> Bytes
pub fn scrypt_hex(password : String, salt : String, n : Int, r : Int, p : Int, dk_len : Int) -> String
pub fn scrypt_verify(password : String, salt : String, n : Int, r : Int, p : Int, dk_len : Int, expected : Bytes) -> Bool

// 推荐参数
pub fn scrypt_params_interactive() -> (Int, Int, Int)  // (16384, 8, 1)
pub fn scrypt_params_sensitive() -> (Int, Int, Int)     // (1048576, 8, 1)
pub fn scrypt_params_paranoid() -> (Int, Int, Int)      // (4194304, 8, 1)
```

### Argon2id

```moonbit
pub fn argon2id(password : String, salt : String, t_cost : Int, m_cost : Int, parallelism : Int, hash_len : Int) -> Bytes
pub fn argon2id_hash(password : String, salt : String, t_cost : Int, m_cost : Int, parallelism : Int) -> String
pub fn argon2id_verify(password : String, salt : String, t_cost : Int, m_cost : Int, parallelism : Int, hash_len : Int, expected : Bytes) -> Bool

// 推荐参数
pub fn argon2id_params_interactive() -> (Int, Int, Int)  // (2, 65536, 1)
pub fn argon2id_params_moderate() -> (Int, Int, Int)      // (3, 262144, 1)
pub fn argon2id_params_sensitive() -> (Int, Int, Int)     // (4, 1048576, 1)
```

### Password 工具

```moonbit
// bcrypt 一键哈希/验证
pub fn hash_password(password : String) -> String
pub fn verify_password(password : String, hash : String) -> Bool

// scrypt 一键哈希/验证
pub fn hash_password_scrypt(password : String) -> String
pub fn verify_password_scrypt(password : String, hash : String) -> Bool

// Argon2id 一键哈希/验证
pub fn hash_password_argon2id(password : String) -> String
pub fn verify_password_argon2id(password : String, hash : String) -> Bool

// 工具函数
pub fn password_needs_rehash(hash : String) -> Bool           // 检测 $2a$ 需升级到 $2b$
pub fn generate_password(length : Int) -> String              // 生成随机密码
pub fn password_strength(password : String) -> Int            // 密码强度评分 (0–100)
pub fn password_strength_level(password : String) -> String   // "weak" | "fair" | "strong" | "very_strong"
```

### Random

```moonbit
pub fn random_bytes(len : Int) -> Bytes
pub fn random_u32() -> UInt
pub fn random_u64() -> UInt64
pub fn random_int() -> Int
pub fn random_uint_range(min : UInt, max : UInt) -> UInt
pub fn random_int_range(min : Int, max : Int) -> Int
pub fn[T] random_choice(items : Array[T]) -> T
pub fn[T] shuffle(arr : Array[T]) -> Array[T]
pub fn random_hex(len : Int) -> String
pub fn random_base64(len : Int) -> String
```

### Constant-time

```moonbit
pub fn constant_eq(a : Bytes, b : Bytes) -> Bool
pub fn constant_eq_string(a : String, b : String) -> Bool
pub fn constant_ne(a : Bytes, b : Bytes) -> Bool
pub fn constant_lt(a : Int, b : Int) -> Bool
pub fn constant_ge(a : Int, b : Int) -> Bool
pub fn constant_select(a : Int, b : Int, cond : Bool) -> Int
pub fn constant_is_zero(x : UInt) -> Bool
```

所有比较函数均为常量时间，防止时序侧信道攻击。

## 测试

```bash
moon test
```

43 项测试全部通过。

## 许可证

Apache-2.0
