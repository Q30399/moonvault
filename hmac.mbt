// HMAC-SHA-256 for MoonVault
// RFC 2104: HMAC: Keyed-Hashing for Message Authentication

fn xor_bytes(a : Array[Byte], b : Byte, len : Int) -> Array[Byte] {
  let result : Array[Byte] = Array::make(len, b'\x00')
  let mut i = 0
  while i < len { result[i] = a[i] ^ b; i = i + 1 }
  result
}

struct HmacSha256 {
  ipad : Array[Byte]
  opad : Array[Byte]
}

fn normalize_key(key : Bytes) -> Array[Byte] {
  let block_size = 64
  if key.length() > block_size {
    let h = Sha256::new()
    let h = h.write(key)
    let hashed = h.sum()
    let buf = Array::make(block_size, b'\x00')
    let mut i = 0
    while i < hashed.length() { buf[i] = hashed[i]; i = i + 1 }
    buf
  } else {
    let buf = Array::make(block_size, b'\x00')
    let mut i = 0
    while i < key.length() { buf[i] = key[i]; i = i + 1 }
    buf
  }
}

pub fn HmacSha256::new(key : Bytes) -> HmacSha256 {
  let block_size = 64
  let key_data = normalize_key(key)
  {
    ipad: xor_bytes(key_data, b'\x36', block_size),
    opad: xor_bytes(key_data, b'\x5c', block_size),
  }
}

pub fn HmacSha256::sign(self : HmacSha256, message : Bytes) -> Bytes {
  let inner = Sha256::new()
  let inner = inner.write(Bytes::from_array(self.ipad))
  let inner = inner.write(message)
  let inner_hash = inner.sum()

  let outer = Sha256::new()
  let outer = outer.write(Bytes::from_array(self.opad))
  let outer = outer.write(inner_hash)
  outer.sum()
}

pub fn HmacSha256::sign_string(self : HmacSha256, s : String) -> Bytes {
  self.sign(str_to_utf8(s))
}

pub fn hmac_sha256(key : Bytes, message : Bytes) -> Bytes {
  let h = HmacSha256::new(key)
  h.sign(message)
}

pub fn hmac_sha256_hex(key : String, message : String) -> String {
  let h = HmacSha256::new(str_to_utf8(key))
  bytes_to_hex(h.sign_string(message))
}

pub fn HmacSha256::verify(self : HmacSha256, message : Bytes, mac : Bytes) -> Bool {
  let expected = self.sign(message)
  constant_eq(expected, mac)
}

pub fn hmac_verify(key : Bytes, message : Bytes, mac : Bytes) -> Bool {
  let h = HmacSha256::new(key)
  h.verify(message, mac)
}
