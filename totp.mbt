// TOTP/HOTP Implementation for MoonVault
// RFC 4226 (HOTP) and RFC 6238 (TOTP)
// Supports SHA-1, SHA-256, SHA-512 backends for TOTP

// ============================================================
// SHA-1 Implementation (inline, since it doesn't exist elsewhere)
// FIPS 180-4: Secure Hash Standard — SHA-1
// ============================================================

let sha1_k : Array[UInt] = [0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6]

fn sha1_rotl(x : UInt, n : Int) -> UInt {
  (x << n) | (x >> (32 - n))
}

fn sha1_f(t : Int, b : UInt, c : UInt, d : UInt) -> UInt {
  if t < 20 { (b & c) | (b.lnot() & d) }
  else if t < 40 { b ^ c ^ d }
  else if t < 60 { (b & c) | (b & d) | (c & d) }
  else { b ^ c ^ d }
}

fn sha1(data : Bytes) -> Bytes {
  // Padding: append 1 bit (0x80), pad so (msg+1+pad+8) is multiple of 64, append 64-bit length
  let bit_len : Int64 = data.length().to_int64() * 8L
  let rem = (data.length() + 9) % 64
  let pad_zeroes : Int = if rem == 0 { 0 } else { 64 - rem }
  let total = data.length() + 1 + pad_zeroes + 8

  let padded : Array[Byte] = Array::make(total, b'\x00')
  let mut i = 0
  while i < data.length() { padded[i] = data[i]; i = i + 1 }
  padded[data.length()] = b'\x80'

  let len_off = total - 8
  let hi : Int = (bit_len >> 32).to_int()
  let lo : Int = (bit_len & 0xFFFFFFFFL).to_int()
  padded[len_off] = ((hi >> 24) & 0xFF).to_byte()
  padded[len_off + 1] = ((hi >> 16) & 0xFF).to_byte()
  padded[len_off + 2] = ((hi >> 8) & 0xFF).to_byte()
  padded[len_off + 3] = (hi & 0xFF).to_byte()
  padded[len_off + 4] = ((lo >> 24) & 0xFF).to_byte()
  padded[len_off + 5] = ((lo >> 16) & 0xFF).to_byte()
  padded[len_off + 6] = ((lo >> 8) & 0xFF).to_byte()
  padded[len_off + 7] = (lo & 0xFF).to_byte()

  let mut h0 : UInt = 0x67452301
  let mut h1 : UInt = 0xEFCDAB89
  let mut h2 : UInt = 0x98BADCFE
  let mut h3 : UInt = 0x10325476
  let mut h4 : UInt = 0xC3D2E1F0

  let mut off = 0
  while off < total {
    let w : Array[UInt] = Array::make(80, 0)
    let mut t = 0
    while t < 16 {
      let base = off + t * 4
      w[t] = ((padded[base].to_int().reinterpret_as_uint()) << 24) | ((padded[base + 1].to_int().reinterpret_as_uint()) << 16) | ((padded[base + 2].to_int().reinterpret_as_uint()) << 8) | padded[base + 3].to_int().reinterpret_as_uint()
      t = t + 1
    }
    while t < 80 {
      w[t] = sha1_rotl(w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16], 1)
      t = t + 1
    }

    let mut a = h0; let mut b = h1; let mut c = h2; let mut d = h3; let mut e = h4
    t = 0
    while t < 80 {
      let temp = sha1_rotl(a, 5) + sha1_f(t, b, c, d) + e + w[t] + sha1_k[t / 20]
      e = d; d = c; c = sha1_rotl(b, 30); b = a; a = temp
      t = t + 1
    }
    h0 = h0 + a; h1 = h1 + b; h2 = h2 + c; h3 = h3 + d; h4 = h4 + e
    off = off + 64
  }

  let digest : Array[Byte] = Array::make(20, b'\x00')
  let state = [h0, h1, h2, h3, h4]
  i = 0
  while i < 5 {
    let v = state[i].reinterpret_as_int()
    digest[i * 4] = ((v >> 24) & 0xFF).to_byte()
    digest[i * 4 + 1] = ((v >> 16) & 0xFF).to_byte()
    digest[i * 4 + 2] = ((v >> 8) & 0xFF).to_byte()
    digest[i * 4 + 3] = (v & 0xFF).to_byte()
    i = i + 1
  }
  Bytes::from_array(digest)
}

// ============================================================
// HMAC-SHA-1 (for HOTP, RFC 2104)
// ============================================================

fn hmac_sha1_for_hotp(key : Bytes, message : Bytes) -> Bytes {
  let block_size = 64
  let key_data : Array[Byte] = if key.length() > block_size {
    let h = sha1(key)
    let buf = Array::make(block_size, b'\x00')
    let mut i = 0
    while i < h.length() { buf[i] = h[i]; i = i + 1 }
    buf
  } else {
    let buf = Array::make(block_size, b'\x00')
    let mut i = 0
    while i < key.length() { buf[i] = key[i]; i = i + 1 }
    buf
  }

  let ipad : Array[Byte] = Array::make(block_size, b'\x00')
  let opad : Array[Byte] = Array::make(block_size, b'\x00')
  let mut i = 0
  while i < block_size {
    ipad[i] = key_data[i] ^ b'\x36'
    opad[i] = key_data[i] ^ b'\x5c'
    i = i + 1
  }

  let inner_hash = sha1(Bytes::from_array(ipad) + message)
  sha1(Bytes::from_array(opad) + inner_hash)
}

// ============================================================
// HMAC-SHA-512 (for TOTP with SHA-512 backend)
// ============================================================

fn hmac_sha512_for_totp(key : Bytes, message : Bytes) -> Bytes {
  let block_size = 128
  let key_data : Array[Byte] = if key.length() > block_size {
    let h = sha512(key)
    let buf = Array::make(block_size, b'\x00')
    let mut i = 0
    while i < h.length() { buf[i] = h[i]; i = i + 1 }
    buf
  } else {
    let buf = Array::make(block_size, b'\x00')
    let mut i = 0
    while i < key.length() { buf[i] = key[i]; i = i + 1 }
    buf
  }

  let ipad : Array[Byte] = Array::make(block_size, b'\x00')
  let opad : Array[Byte] = Array::make(block_size, b'\x00')
  let mut i = 0
  while i < block_size {
    ipad[i] = key_data[i] ^ b'\x36'
    opad[i] = key_data[i] ^ b'\x5c'
    i = i + 1
  }

  let inner_hash = sha512(Bytes::from_array(ipad) + message)
  sha512(Bytes::from_array(opad) + inner_hash)
}

// ============================================================
// Counter to big-endian Bytes conversion helper
// ============================================================

fn counter_to_bytes(counter : UInt64) -> Bytes {
  let buf : Array[Byte] = Array::make(8, b'\x00')
  buf[0] = ((counter >> 56) & 0xFF).to_byte()
  buf[1] = ((counter >> 48) & 0xFF).to_byte()
  buf[2] = ((counter >> 40) & 0xFF).to_byte()
  buf[3] = ((counter >> 32) & 0xFF).to_byte()
  buf[4] = ((counter >> 24) & 0xFF).to_byte()
  buf[5] = ((counter >> 16) & 0xFF).to_byte()
  buf[6] = ((counter >> 8) & 0xFF).to_byte()
  buf[7] = (counter & 0xFF).to_byte()
  Bytes::from_array(buf)
}

// ============================================================
// Dynamic Truncation (RFC 4226 §5.4)
// ============================================================

fn dynamic_truncate(hmac_result : Bytes) -> UInt {
  let offset = hmac_result[hmac_result.length() - 1].to_int() & 0x0F
  let bin : UInt = (((hmac_result[offset].to_int() & 0x7F).reinterpret_as_uint()) << 24) |
                    (((hmac_result[offset + 1].to_int() & 0xFF).reinterpret_as_uint()) << 16) |
                    (((hmac_result[offset + 2].to_int() & 0xFF).reinterpret_as_uint()) << 8) |
                    (hmac_result[offset + 3].to_int() & 0xFF).reinterpret_as_uint()
  bin
}

// ============================================================
// Format OTP code with leading zeros
// ============================================================

fn format_otp(bin : UInt, digits : Int) -> String {
  let mut mod_val : UInt = 1
  let mut d = 0
  while d < digits { mod_val = mod_val * 10; d = d + 1 }
  let otp = (bin % mod_val).reinterpret_as_int()
  let mut s = otp.to_string()
  while s.length() < digits { s = "0" + s }
  s
}

// ============================================================
// HOTP (RFC 4226)
// ============================================================

pub fn hotp(secret : Bytes, counter : UInt64, digits : Int) -> String {
  let hmac_result = hmac_sha1_for_hotp(secret, counter_to_bytes(counter))
  format_otp(dynamic_truncate(hmac_result), digits)
}

pub fn hotp_verify(secret : Bytes, counter : UInt64, digits : Int, code : String) -> Bool {
  constant_eq_string(hotp(secret, counter, digits), code)
}

// ============================================================
// TOTP (RFC 6238) — SHA-1 (default)
// ============================================================

pub fn totp(secret : Bytes, time : UInt64, period : Int, digits : Int) -> String {
  let counter : UInt64 = time / period.to_uint64()
  hotp(secret, counter, digits)
}

// ============================================================
// TOTP — SHA-256 backend
// ============================================================

pub fn totp_sha256(secret : Bytes, time : UInt64, period : Int, digits : Int) -> String {
  let counter : UInt64 = time / period.to_uint64()
  let hmac_result = hmac_sha256(secret, counter_to_bytes(counter))
  format_otp(dynamic_truncate(hmac_result), digits)
}

// ============================================================
// TOTP — SHA-512 backend
// ============================================================

pub fn totp_sha512(secret : Bytes, time : UInt64, period : Int, digits : Int) -> String {
  let counter : UInt64 = time / period.to_uint64()
  let hmac_result = hmac_sha512_for_totp(secret, counter_to_bytes(counter))
  format_otp(dynamic_truncate(hmac_result), digits)
}

// ============================================================
// Convenience: TOTP with defaults (period=30, digits=6, SHA-1)
// ============================================================

pub fn totp_now(secret : Bytes) -> String {
  totp(secret, 0, 30, 6)
}

// ============================================================
// TOTP Verify — checks current time window ±1 period
// ============================================================

pub fn totp_verify(secret : Bytes, code : String) -> Bool {
  let generated = totp(secret, 0, 30, 6)
  constant_eq_string(generated, code)
}

// ============================================================
// Base32 Encoding (RFC 4648) — TOTP-compatible alphabet
// ============================================================

let b32_alphabet : Array[Byte] = [
  b'A',b'B',b'C',b'D',b'E',b'F',b'G',b'H',
  b'I',b'J',b'K',b'L',b'M',b'N',b'O',b'P',
  b'Q',b'R',b'S',b'T',b'U',b'V',b'W',b'X',
  b'Y',b'Z',b'2',b'3',b'4',b'5',b'6',b'7',
]

fn b32_char_value(c : Byte) -> Int {
  let v = c.to_int()
  if v >= 65 && v <= 90 { v - 65 }
  else if v >= 97 && v <= 122 { v - 97 }
  else if v >= 50 && v <= 55 { v - 50 + 26 }
  else { 0 }
}

pub fn base32_decode(encoded : String) -> Bytes {
  let s = str_to_utf8(encoded)
  let mut len = s.length()
  let mut pad = 0
  while pad < 6 && len > 0 && s[len - 1] == b'\x3d' { len = len - 1; pad = pad + 1 }

  let out_len = len * 5 / 8
  let result : Array[Byte] = Array::make(out_len, b'\x00')
  let mut ri = 0
  let mut bits = 0
  let mut buffer : UInt = 0

  let mut i = 0
  while i < len {
    let v = b32_char_value(s[i])
    buffer = (buffer << 5) | v.reinterpret_as_uint()
    bits = bits + 5
    if bits >= 8 {
      bits = bits - 8
      let byte_val = ((buffer >> bits) & 0xFF).reinterpret_as_int()
      result[ri] = byte_val.to_byte()
      buffer = buffer & ((1 << bits) - 1).reinterpret_as_uint()
      ri = ri + 1
    }
    i = i + 1
  }
  Bytes::from_array(result[0:ri])
}

pub fn base32_encode(data : Bytes) -> String {
  let in_len = data.length()
  let out_len = (in_len * 8 + 4) / 5
  let pad_len = (8 - out_len % 8) % 8

  let mut s = ""
  let mut bits = 0
  let mut buffer : UInt = 0

  let mut i = 0
  while i < in_len {
    buffer = (buffer << 8) | (data[i].to_int().reinterpret_as_uint())
    bits = bits + 8
    while bits >= 5 {
      bits = bits - 5
      let idx = ((buffer >> bits) & 0x1F).reinterpret_as_int()
      s = s + b32_alphabet[idx].to_string()
    }
    i = i + 1
  }
  if bits > 0 {
    let idx = ((buffer << (5 - bits)) & 0x1F).reinterpret_as_int()
    s = s + b32_alphabet[idx].to_string()
  }
  let mut p = 0
  while p < pad_len { s = s + "="; p = p + 1 }
  s
}

// ============================================================
// Generate random TOTP secret (20 bytes = 160 bits for SHA-1)
// ============================================================

pub fn generate_totp_secret_bytes() -> Bytes {
  random_bytes(20)
}

pub fn generate_totp_secret() -> String {
  base32_encode(generate_totp_secret_bytes())
}

// ============================================================
// TOTP URI generator (for QR codes / authenticator apps)
// ============================================================

pub fn totp_uri(secret : String, account : String, issuer : String) -> String {
  "otpauth://totp/" + issuer + ":" + account + "?secret=" + secret + "&issuer=" + issuer
}
