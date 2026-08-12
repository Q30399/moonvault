// HKDF for MoonVault
// RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function

fn hkdf_extract(salt : Bytes, ikm : Bytes) -> Bytes {
  let hmac_key = HmacSha256::new(if salt.length() == 0 { Bytes::make(32, b'\x00') } else { salt })
  hmac_key.sign(ikm)
}

fn hkdf_expand(prk : Bytes, info : Bytes, length : Int) -> Bytes {
  let hash_len = 32
  let n = (length + hash_len - 1) / hash_len
  let hmac_key = HmacSha256::new(prk)

  let result : Array[Byte] = Array::make(length, b'\x00')
  let mut prev : Bytes = Bytes::from_array([])

  let mut i = 1
  let mut written = 0
  while i <= n {
    let input_data = if i == 1 { info } else { prev + info + Bytes::from_array([(i).to_byte()]) }
    prev = hmac_key.sign(input_data)
    let chunk = prev.to_fixedarray()
    let mut j = 0
    while j < hash_len && written < length {
      result[written] = chunk[j]
      written = written + 1
      j = j + 1
    }
    i = i + 1
  }

  Bytes::from_array(result[0:length])
}

pub fn hkdf_sha256(ikm : Bytes, salt : Bytes, info : Bytes, length : Int) -> Bytes {
  let prk = hkdf_extract(salt, ikm)
  hkdf_expand(prk, info, length)
}

pub fn hkdf_sha256_hex(ikm : String, salt : String, info : String, length : Int) -> String {
  let ikm_bytes = str_to_utf8(ikm)
  let salt_bytes = str_to_utf8(salt)
  let info_bytes = str_to_utf8(info)
  let result = hkdf_sha256(ikm_bytes, salt_bytes, info_bytes, length)
  bytes_to_hex(result)
}

pub fn hkdf_extract_hex(key_material : String, salt : String) -> String {
  let km = str_to_utf8(key_material)
  let s = str_to_utf8(salt)
  let prk = hkdf_extract(s, km)
  bytes_to_hex(prk)
}

pub fn hkdf_expand_hex(prk_hex : String, info : String, length : Int) -> String {
  let prk = hex_to_bytes(prk_hex)
  let info_bytes = str_to_utf8(info)
  let result = hkdf_expand(prk, info_bytes, length)
  bytes_to_hex(result)
}
