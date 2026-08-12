// Password utilities for MoonVault

pub fn hash_password(password : String) -> String {
  let salt = generate_salt()
  bcrypt_hash(password, 10, salt)
}

pub fn verify_password(password : String, hash : String) -> Bool {
  if hash.has_prefix("$2b$") || hash.has_prefix("$2a$") {
    return bcrypt_verify(password, hash)
  }
  false
}

pub fn hash_password_scrypt(password : String) -> String {
  let salt = random_hex(16)
  let (n, r, p) = scrypt_params_interactive()
  let hash = scrypt(password, salt, n, r, p, 32)
  "$s0$" + salt + "$" + bytes_to_hex(hash)
}

pub fn verify_password_scrypt(password : String, hash : String) -> Bool {
  if !hash.has_prefix("$s0$") { return false }
  let rest = hash[4:]
  let sep = rest.find("$")
  match sep {
    None => false
    Some(idx) => {
      let salt = rest[0:idx].to_owned()
      let hash_hex = rest[idx + 1:].to_owned()
      let (n, r, p) = scrypt_params_interactive()
      let computed = scrypt(password, salt, n, r, p, 32)
      let computed_hex = bytes_to_hex(computed)
      constant_eq_string(computed_hex, hash_hex)
    }
  }
}

pub fn hash_password_argon2id(password : String) -> String {
  let salt = random_hex(16)
  let (t, m, p) = argon2id_params_moderate()
  let hash = argon2id(password, salt, t, m, p, 32)
  "$argon2id$" + salt + "$" + bytes_to_hex(hash)
}

pub fn verify_password_argon2id(password : String, hash : String) -> Bool {
  if !hash.has_prefix("$argon2id$") { return false }
  let rest = hash[10:]
  let sep = rest.find("$")
  match sep {
    None => false
    Some(idx) => {
      let salt = rest[0:idx].to_owned()
      let hash_hex = rest[idx + 1:].to_owned()
      let (t, m, p) = argon2id_params_moderate()
      let computed = argon2id(password, salt, t, m, p, 32)
      let computed_hex = bytes_to_hex(computed)
      constant_eq_string(computed_hex, hash_hex)
    }
  }
}

pub fn password_needs_rehash(hash : String) -> Bool {
  hash.has_prefix("$2a$")
}

pub fn generate_password(length : Int) -> String {
  if length < 8 { return generate_password(8) }
  let upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
  let lower = "abcdefghijklmnopqrstuvwxyz"
  let digits = "0123456789"
  let special = "!@#$%^&*()-_=+[]{}|;:,.<>?"

  let all_chars = upper + lower + digits + special
  let mut result = ""
  let mut i = 0
  while i < length {
    let idx = random_int_range(0, all_chars.length())
    result = result + all_chars[idx:idx + 1].to_owned()
    i = i + 1
  }
  result
}

pub fn password_strength(password : String) -> Int {
  let mut score = 0
  let len = password.length()
  if len < 8 { return 0 }
  if len >= 8 { score = score + 10 }
  if len >= 12 { score = score + 10 }
  if len >= 16 { score = score + 10 }
  if len >= 20 { score = score + 10 }

  let mut has_upper = false
  let mut has_lower = false
  let mut has_digit = false
  let mut has_special = false

  let mut i = 0
  while i < len {
    let ch = password[i]
    if ch >= 'A' && ch <= 'Z' { has_upper = true }
    else if ch >= 'a' && ch <= 'z' { has_lower = true }
    else if ch >= '0' && ch <= '9' { has_digit = true }
    else { has_special = true }
    i = i + 1
  }

  if has_upper { score = score + 15 }
  if has_lower { score = score + 5 }
  if has_digit { score = score + 15 }
  if has_special { score = score + 20 }

  let total = (if has_upper { 1 } else { 0 }) + (if has_lower { 1 } else { 0 }) +
              (if has_digit { 1 } else { 0 }) + (if has_special { 1 } else { 0 })
  if total >= 4 { score = score + 15 }
  else if total >= 3 { score = score + 10 }

  let mut repeats = 0
  i = 1
  while i < len {
    if password[i] == password[i - 1] { repeats = repeats + 1 }
    i = i + 1
  }
  if repeats > 0 { score = score - (repeats * 5) }
  if score < 0 { score = 0 }
  if score > 100 { score = 100 }

  score
}

pub fn password_strength_level(password : String) -> String {
  let s = password_strength(password)
  if s < 30 { "weak" }
  else if s < 60 { "fair" }
  else if s < 80 { "strong" }
  else { "very_strong" }
}
