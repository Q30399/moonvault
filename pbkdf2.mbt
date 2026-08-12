// PBKDF2-HMAC-SHA-256 for MoonVault
// RFC 2898 / PKCS #5 v2.0: Password-Based Key Derivation Function 2

fn pbkdf2_hmac_sha256(password : Bytes, salt : Bytes, iterations : Int, key_len : Int) -> Bytes {
  let hmac_key = HmacSha256::new(password)
  let h_len = 32
  let blocks = (key_len + h_len - 1) / h_len

  let result : Array[Byte] = Array::make(blocks * h_len, b'\x00')

  let mut block = 1
  while block <= blocks {
    let u = hmac_key.sign(salt + int_to_be_bytes(block, 4))

    let accum = u.to_fixedarray()
    let mut prev = u  // U_1 for next round

    let mut i = 1
    while i < iterations {
      let u_next = hmac_key.sign(prev)  // U_i = PRF(P, U_{i-1})
      prev = u_next
      let u_arr = u_next.to_fixedarray()
      let mut j = 0
      while j < h_len {
        accum[j] = accum[j] ^ u_arr[j]
        j = j + 1
      }
      i = i + 1
    }

    let mut j = 0
    let offset = (block - 1) * h_len
    while j < h_len && offset + j < key_len {
      result[offset + j] = accum[j]
      j = j + 1
    }

    block = block + 1
  }
  Bytes::from_array(result[0:key_len])
}

fn int_to_be_bytes(n : Int, len : Int) -> Bytes {
  let buf : Array[Byte] = Array::make(len, b'\x00')
  let mut i = len - 1
  let mut v = n
  while i >= 0 {
    buf[i] = (v & 0xFF).to_byte()
    v = v >> 8
    i = i - 1
  }
  Bytes::from_array(buf)
}

pub fn pbkdf2(password : String, salt : String, iterations : Int, key_len : Int) -> Bytes {
  pbkdf2_hmac_sha256(str_to_utf8(password), str_to_utf8(salt), iterations, key_len)
}

pub fn pbkdf2_sha256(password : String, salt : String, iterations : Int, key_len : Int) -> Bytes {
  pbkdf2(password, salt, iterations, key_len)
}

pub fn pbkdf2_raw(password : Bytes, salt : Bytes, iterations : Int, key_len : Int) -> Bytes {
  pbkdf2_hmac_sha256(password, salt, iterations, key_len)
}

pub fn pbkdf2_hex(password : String, salt : String, iterations : Int, key_len : Int) -> String {
  bytes_to_hex(pbkdf2(password, salt, iterations, key_len))
}

pub fn pbkdf2_verify(password : String, salt : String, iterations : Int, key_len : Int, expected : Bytes) -> Bool {
  let dk = pbkdf2(password, salt, iterations, key_len)
  constant_eq(dk, expected)
}
