// Comprehensive tests for MoonVault -- password hashing library
// Run with: moon test

// Test error type
suberror TestFail {
  TestFail(String)
}

// Test helper: raise if condition is false
fn chk(cond : Bool, msg : String) -> Unit raise TestFail {
  if !cond { raise TestFail(msg) }
}

// Test helper: raise if two values are not equal
fn chk_eq(actual : String, expected : String, msg : String) -> Unit raise TestFail {
  if actual != expected {
    raise TestFail("\{msg}: expected \{expected}, got \{actual}")
  }
}

// SHA-256 Tests
test "sha256_empty" {
  let result = sha256(str_to_utf8(""))
  let hex = bytes_to_hex(result)
  chk_eq(hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "sha256_empty")
}

test "sha256_hello" {
  let result = sha256_hex("hello")
  chk_eq(result, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", "sha256_hello")
}

test "sha256_abc" {
  let result = sha256_hex("abc")
  chk_eq(result, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "sha256_abc")
}

test "sha256_quick_brown" {
  let result = sha256_hex("The quick brown fox jumps over the lazy dog")
  chk_eq(result, "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592", "sha256_quick_brown")
}

test "sha256_long" {
  let input = "a".repeat(1000)
  let result = sha256_hex(input)
  chk(result.length() == 64, "sha256_long: length should be 64")
}

// HMAC Tests
test "hmac_sha256_rfc4231_test1" {
  let key : Bytes = Bytes::make(20, b'\x0b')
  let data = str_to_utf8("Hi There")
  let result = hmac_sha256(key, data)
  let hex = bytes_to_hex(result)
  chk_eq(hex, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7", "hmac_rfc4231_test1")
}

test "hmac_sha256_rfc4231_test4" {
  let key_arr : Array[Byte] = [
    (0x01).to_byte(),(0x02).to_byte(),(0x03).to_byte(),(0x04).to_byte(),(0x05).to_byte(),
    (0x06).to_byte(),(0x07).to_byte(),(0x08).to_byte(),(0x09).to_byte(),(0x0a).to_byte(),
    (0x0b).to_byte(),(0x0c).to_byte(),(0x0d).to_byte(),(0x0e).to_byte(),(0x0f).to_byte(),
    (0x10).to_byte(),(0x11).to_byte(),(0x12).to_byte(),(0x13).to_byte(),(0x14).to_byte(),
    (0x15).to_byte(),(0x16).to_byte(),(0x17).to_byte(),(0x18).to_byte(),(0x19).to_byte(),
  ]
  let key : Bytes = Bytes::from_array(key_arr)
  let data : Bytes = Bytes::make(50, b'\xcd')
  let result = hmac_sha256(key, data)
  let hex = bytes_to_hex(result)
  chk_eq(hex, "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b", "hmac_rfc4231_test4")
}

test "hmac_sha256_empty" {
  let key = str_to_utf8("key")
  let data = str_to_utf8("")
  let result = hmac_sha256(key, data)
  chk(result.length() == 32, "hmac_sha256_empty: length should be 32")
}

// PBKDF2 Tests
test "pbkdf2_sha256_basic" {
  let dk = pbkdf2("password", "salt", 1, 32)
  let hex = bytes_to_hex(dk)
  chk_eq(hex, "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b", "pbkdf2_basic")
}

test "pbkdf2_sha256_4096" {
  let dk = pbkdf2("password", "salt", 4096, 32)
  let hex = bytes_to_hex(dk)
  chk_eq(hex, "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a", "pbkdf2_4096")
}

test "pbkdf2_verify" {
  let dk = pbkdf2("password", "salt", 100, 32)
  chk(pbkdf2_verify("password", "salt", 100, 32, dk), "pbkdf2_verify: correct password should verify")
  chk(!pbkdf2_verify("wrong", "salt", 100, 32, dk), "pbkdf2_verify: wrong password should not verify")
}

test "pbkdf2_different_lengths" {
  let dk16 = pbkdf2("password", "salt", 1, 16)
  let dk32 = pbkdf2("password", "salt", 1, 32)
  let dk64 = pbkdf2("password", "salt", 1, 64)
  chk(dk16.length() == 16, "pbkdf2_different_lengths: dk16 should be 16")
  chk(dk32.length() == 32, "pbkdf2_different_lengths: dk32 should be 32")
  chk(dk64.length() == 64, "pbkdf2_different_lengths: dk64 should be 64")
}

// bcrypt Tests
test "bcrypt_hash_basic" {
  let hash = bcrypt_hash("password123", 4, "salt1234567890123456")
  chk(hash.has_prefix("$2b$04$"), "bcrypt_hash_basic: should have prefix $2b$04$")
}

test "bcrypt_verify_correct" {
  let hash = bcrypt_hash("mypassword", 4, "saltsaltsaltsalt12")
  chk(bcrypt_verify("mypassword", hash), "bcrypt_verify_correct: correct password should verify")
}

test "bcrypt_verify_wrong" {
  let hash = bcrypt_hash("mypassword", 4, "saltsaltsaltsalt12")
  chk(!bcrypt_verify("wrongpassword", hash), "bcrypt_verify_wrong: wrong password should not verify")
}

test "bcrypt_hash_cost_10" {
  let hash = bcrypt_hash("test", 10, "abcdefghijklmnop")
  chk(hash.has_prefix("$2b$10$"), "bcrypt_hash_cost_10: should have prefix $2b$10$")
}

test "bcrypt_hash_wrong_cost" {
  let hash = bcrypt_hash("test", 0, "abcdefghijklmnop")
  chk(hash.length() > 0, "bcrypt_hash_wrong_cost: should produce a hash")
}

// scrypt Tests
test "scrypt_basic" {
  let dk = scrypt("password", "NaCl", 1024, 8, 1, 64)
  let hex = bytes_to_hex(dk)
  chk(hex.length() == 128, "scrypt_basic: hex should be 128 chars")
}

test "scrypt_verify" {
  let dk = scrypt("password", "NaCl", 1024, 8, 1, 32)
  chk(scrypt_verify("password", "NaCl", 1024, 8, 1, 32, dk), "scrypt_verify: correct password should verify")
  chk(!scrypt_verify("wrong", "NaCl", 1024, 8, 1, 32, dk), "scrypt_verify: wrong password should not verify")
}

test "scrypt_different_lengths" {
  let dk16 = scrypt("password", "salt", 1024, 8, 1, 16)
  let dk32 = scrypt("password", "salt", 1024, 8, 1, 32)
  chk(dk16.length() == 16, "scrypt_different_lengths: dk16 should be 16")
  chk(dk32.length() == 32, "scrypt_different_lengths: dk32 should be 32")
}

// Constant-time comparison Tests
test "constant_eq_same" {
  let a = str_to_utf8("test")
  let b = str_to_utf8("test")
  chk(constant_eq(a, b), "constant_eq_same: same bytes should be equal")
}

test "constant_eq_different" {
  let a = str_to_utf8("test")
  let b = str_to_utf8("diff")
  chk(!constant_eq(a, b), "constant_eq_different: different bytes should not be equal")
}

test "constant_eq_different_length" {
  let a = str_to_utf8("short")
  let b = str_to_utf8("longer")
  chk(!constant_eq(a, b), "constant_eq_different_length: different lengths should not be equal")
}

test "constant_eq_string_same" {
  chk(constant_eq_string("hello", "hello"), "constant_eq_string_same: same strings should be equal")
}

test "constant_eq_string_different" {
  chk(!constant_eq_string("hello", "world"), "constant_eq_string_different: different strings should not be equal")
}

// Random tests
test "random_bytes_length" {
  let b = random_bytes(32)
  chk(b.length() == 32, "random_bytes_length: should return 32 bytes")
}

test "random_bytes_randomness" {
  let a = random_bytes(16)
  let b = random_bytes(16)
  chk(!constant_eq(a, b), "random_bytes_randomness: two calls should produce different bytes")
}

test "random_hex" {
  let h = random_hex(16)
  chk(h.length() == 32, "random_hex: hex of 16 bytes should be 32 chars")
}

test "random_uint_range" {
  let r = random_uint_range(0, 100)
  chk(r < 100, "random_uint_range: should be less than max")
}

// Password utility tests
test "password_strength_weak" {
  let s = password_strength("abc")
  chk(s < 30, "password_strength_weak: short password should be weak")
}

test "password_strength_strong" {
  let s = password_strength("Str0ng!Passw0rd")
  chk(s >= 60, "password_strength_strong: strong password should score high")
}

test "password_needs_rehash" {
  chk(password_needs_rehash("$2a$10$abc"), "password_needs_rehash: $2a$ should need rehash")
  chk(!password_needs_rehash("$2b$10$abc"), "password_needs_rehash: $2b$ should not need rehash")
}

test "generate_password_length" {
  let pwd = generate_password(16)
  chk(pwd.length() == 16, "generate_password_length: should generate 16 chars")
}

// Hash and verify workflows
test "hash_verify_workflow_bcrypt" {
  let hash = hash_password("secret123")
  chk(verify_password("secret123", hash), "hash_verify_workflow: correct password should verify")
  chk(!verify_password("wrong", hash), "hash_verify_workflow: wrong password should not verify")
}

// Argon2id Tests
test "argon2id_basic" {
  let (t, m, p) = argon2id_params_interactive()
  let dk = argon2id("password", "somesalt", t, m, p, 32)
  chk(dk.length() == 32, "argon2id_basic: should produce 32 bytes")
}

test "argon2id_verify" {
  let (t, m, p) = argon2id_params_interactive()
  let dk = argon2id("password", "somesalt", t, m, p, 32)
  chk(argon2id_verify("password", "somesalt", t, m, p, 32, dk), "argon2id_verify: correct password should verify")
}

test "argon2id_different_inputs" {
  let (t, m, p) = argon2id_params_interactive()
  let a = argon2id("password1", "salt", t, m, p, 16)
  let b = argon2id("password2", "salt", t, m, p, 16)
  chk(!constant_eq(a, b), "argon2id_different_inputs: different inputs should produce different results")
}

// Bytes to hex tests
test "bytes_to_hex_empty" {
  let b : Bytes = Bytes::from_array([])
  chk_eq(bytes_to_hex(b), "", "bytes_to_hex_empty: empty bytes should produce empty string")
}

test "bytes_to_hex_basic" {
  let arr : Array[Byte] = [(222).to_byte(), (173).to_byte(), (190).to_byte(), (239).to_byte()]
  let b = Bytes::from_array(arr)
  chk_eq(bytes_to_hex(b), "deadbeef", "bytes_to_hex_basic: 0xDEADBEEF hex")
}

// Edge cases
test "sha256_empty_string" {
  let result = sha256(str_to_utf8(""))
  chk(result.length() == 32, "sha256_empty_string: should produce 32 bytes")
}

test "bcrypt_verify_invalid_hash" {
  chk(!bcrypt_verify("password", "invalid"), "bcrypt_verify_invalid: 'invalid' should not verify")
  chk(!bcrypt_verify("password", ""), "bcrypt_verify_invalid: empty string should not verify")
}

test "hmac_sha256_key_longer_than_block" {
  let key = str_to_utf8("a".repeat(100))
  let data = str_to_utf8("test")
  let result = hmac_sha256(key, data)
  chk(result.length() == 32, "hmac_key_longer: should still produce 32 bytes")
}

test "sha256_hello_direct" {
  let h = Sha256::new()
  let h = h.write(str_to_utf8("hello"))
  let result = h.sum()
  let hex = bytes_to_hex(result)
  chk_eq(hex, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", "sha256_hello_direct")
}
