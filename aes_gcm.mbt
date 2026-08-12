// AES-256-GCM for MoonVault
// FIPS 197: Advanced Encryption Standard (AES)
// NIST SP 800-38D: Galois/Counter Mode (GCM)

// AES S-box
let aes_sbox : Array[Byte] = [
  (0x63).to_byte(),(0x7c).to_byte(),(0x77).to_byte(),(0x7b).to_byte(),(0xf2).to_byte(),(0x6b).to_byte(),(0x6f).to_byte(),(0xc5).to_byte(),
  (0x30).to_byte(),(0x01).to_byte(),(0x67).to_byte(),(0x2b).to_byte(),(0xfe).to_byte(),(0xd7).to_byte(),(0xab).to_byte(),(0x76).to_byte(),
  (0xca).to_byte(),(0x82).to_byte(),(0xc9).to_byte(),(0x7d).to_byte(),(0xfa).to_byte(),(0x59).to_byte(),(0x47).to_byte(),(0xf0).to_byte(),
  (0xad).to_byte(),(0xd4).to_byte(),(0xa2).to_byte(),(0xaf).to_byte(),(0x9c).to_byte(),(0xa4).to_byte(),(0x72).to_byte(),(0xc0).to_byte(),
  (0xb7).to_byte(),(0xfd).to_byte(),(0x93).to_byte(),(0x26).to_byte(),(0x36).to_byte(),(0x3f).to_byte(),(0xf7).to_byte(),(0xcc).to_byte(),
  (0x34).to_byte(),(0xa5).to_byte(),(0xe5).to_byte(),(0xf1).to_byte(),(0x71).to_byte(),(0xd8).to_byte(),(0x31).to_byte(),(0x15).to_byte(),
  (0x04).to_byte(),(0xc7).to_byte(),(0x23).to_byte(),(0xc3).to_byte(),(0x18).to_byte(),(0x96).to_byte(),(0x05).to_byte(),(0x9a).to_byte(),
  (0x07).to_byte(),(0x12).to_byte(),(0x80).to_byte(),(0xe2).to_byte(),(0xeb).to_byte(),(0x27).to_byte(),(0xb2).to_byte(),(0x75).to_byte(),
  (0x09).to_byte(),(0x83).to_byte(),(0x2c).to_byte(),(0x1a).to_byte(),(0x1b).to_byte(),(0x6e).to_byte(),(0x5a).to_byte(),(0xa0).to_byte(),
  (0x52).to_byte(),(0x3b).to_byte(),(0xd6).to_byte(),(0xb3).to_byte(),(0x29).to_byte(),(0xe3).to_byte(),(0x2f).to_byte(),(0x84).to_byte(),
  (0x53).to_byte(),(0xd1).to_byte(),(0x00).to_byte(),(0xed).to_byte(),(0x20).to_byte(),(0xfc).to_byte(),(0xb1).to_byte(),(0x5b).to_byte(),
  (0x6a).to_byte(),(0xcb).to_byte(),(0xbe).to_byte(),(0x39).to_byte(),(0x4a).to_byte(),(0x4c).to_byte(),(0x58).to_byte(),(0xcf).to_byte(),
  (0xd0).to_byte(),(0xef).to_byte(),(0xaa).to_byte(),(0xfb).to_byte(),(0x43).to_byte(),(0x4d).to_byte(),(0x33).to_byte(),(0x85).to_byte(),
  (0x45).to_byte(),(0xf9).to_byte(),(0x02).to_byte(),(0x7f).to_byte(),(0x50).to_byte(),(0x3c).to_byte(),(0x9f).to_byte(),(0xa8).to_byte(),
  (0x51).to_byte(),(0xa3).to_byte(),(0x40).to_byte(),(0x8f).to_byte(),(0x92).to_byte(),(0x9d).to_byte(),(0x38).to_byte(),(0xf5).to_byte(),
  (0xbc).to_byte(),(0xb6).to_byte(),(0xda).to_byte(),(0x21).to_byte(),(0x10).to_byte(),(0xff).to_byte(),(0xf3).to_byte(),(0xd2).to_byte(),
  (0xcd).to_byte(),(0x0c).to_byte(),(0x13).to_byte(),(0xec).to_byte(),(0x5f).to_byte(),(0x97).to_byte(),(0x44).to_byte(),(0x17).to_byte(),
  (0xc4).to_byte(),(0xa7).to_byte(),(0x7e).to_byte(),(0x3d).to_byte(),(0x64).to_byte(),(0x5d).to_byte(),(0x19).to_byte(),(0x73).to_byte(),
  (0x60).to_byte(),(0x81).to_byte(),(0x4f).to_byte(),(0xdc).to_byte(),(0x22).to_byte(),(0x2a).to_byte(),(0x90).to_byte(),(0x88).to_byte(),
  (0x46).to_byte(),(0xee).to_byte(),(0xb8).to_byte(),(0x14).to_byte(),(0xde).to_byte(),(0x5e).to_byte(),(0x0b).to_byte(),(0xdb).to_byte(),
  (0xe0).to_byte(),(0x32).to_byte(),(0x3a).to_byte(),(0x0a).to_byte(),(0x49).to_byte(),(0x06).to_byte(),(0x24).to_byte(),(0x5c).to_byte(),
  (0xc2).to_byte(),(0xd3).to_byte(),(0xac).to_byte(),(0x62).to_byte(),(0x91).to_byte(),(0x95).to_byte(),(0xe4).to_byte(),(0x79).to_byte(),
  (0xe7).to_byte(),(0xc8).to_byte(),(0x37).to_byte(),(0x6d).to_byte(),(0x8d).to_byte(),(0xd5).to_byte(),(0x4e).to_byte(),(0xa9).to_byte(),
  (0x6c).to_byte(),(0x56).to_byte(),(0xf4).to_byte(),(0xea).to_byte(),(0x65).to_byte(),(0x7a).to_byte(),(0xae).to_byte(),(0x08).to_byte(),
  (0xba).to_byte(),(0x78).to_byte(),(0x25).to_byte(),(0x2e).to_byte(),(0x1c).to_byte(),(0xa6).to_byte(),(0xb4).to_byte(),(0xc6).to_byte(),
  (0xe8).to_byte(),(0xdd).to_byte(),(0x74).to_byte(),(0x1f).to_byte(),(0x4b).to_byte(),(0xbd).to_byte(),(0x8b).to_byte(),(0x8a).to_byte(),
  (0x70).to_byte(),(0x3e).to_byte(),(0xb5).to_byte(),(0x66).to_byte(),(0x48).to_byte(),(0x03).to_byte(),(0xf6).to_byte(),(0x0e).to_byte(),
  (0x61).to_byte(),(0x35).to_byte(),(0x57).to_byte(),(0xb9).to_byte(),(0x86).to_byte(),(0xc1).to_byte(),(0x1d).to_byte(),(0x9e).to_byte(),
  (0xe1).to_byte(),(0xf8).to_byte(),(0x98).to_byte(),(0x11).to_byte(),(0x69).to_byte(),(0xd9).to_byte(),(0x8e).to_byte(),(0x94).to_byte(),
  (0x9b).to_byte(),(0x1e).to_byte(),(0x87).to_byte(),(0xe9).to_byte(),(0xce).to_byte(),(0x55).to_byte(),(0x28).to_byte(),(0xdf).to_byte(),
  (0x8c).to_byte(),(0xa1).to_byte(),(0x89).to_byte(),(0x0d).to_byte(),(0xbf).to_byte(),(0xe6).to_byte(),(0x42).to_byte(),(0x68).to_byte(),
  (0x41).to_byte(),(0x99).to_byte(),(0x2d).to_byte(),(0x0f).to_byte(),(0xb0).to_byte(),(0x54).to_byte(),(0xbb).to_byte(),(0x16).to_byte(),
]

let rcon : Array[Byte] = [
  (0x00).to_byte(),(0x01).to_byte(),(0x02).to_byte(),(0x04).to_byte(),(0x08).to_byte(),
  (0x10).to_byte(),(0x20).to_byte(),(0x40).to_byte(),(0x80).to_byte(),(0x1b).to_byte(),
  (0x36).to_byte(),
]

fn sub_byte(b : Byte) -> Byte {
  aes_sbox[b.to_int() & 0xFF]
}

fn sub_word(w : Array[Byte]) -> Array[Byte] {
  [sub_byte(w[0]), sub_byte(w[1]), sub_byte(w[2]), sub_byte(w[3])]
}

fn rot_word(w : Array[Byte]) -> Array[Byte] {
  [w[1], w[2], w[3], w[0]]
}

fn xor_word(a : Array[Byte], b : Array[Byte]) -> Array[Byte] {
  [a[0] ^ b[0], a[1] ^ b[1], a[2] ^ b[2], a[3] ^ b[3]]
}

fn gf_mul2(b : Byte) -> Byte {
  let v = b.to_int()
  if (v & 0x80) != 0 { ((v << 1) ^ 0x1B).to_byte() } else { (v << 1).to_byte() }
}

fn gf_mul3(b : Byte) -> Byte {
  gf_mul2(b) ^ b
}

fn sub_bytes(state : Array[Byte]) -> Array[Byte] {
  let r : Array[Byte] = Array::make(16, b'\x00')
  let mut i = 0
  while i < 16 { r[i] = sub_byte(state[i]); i = i + 1 }
  r
}

fn shift_rows(state : Array[Byte]) -> Array[Byte] {
  [
    state[0], state[5], state[10], state[15],
    state[4], state[9], state[14], state[3],
    state[8], state[13], state[2], state[7],
    state[12], state[1], state[6], state[11],
  ]
}

fn mix_columns(state : Array[Byte]) -> Array[Byte] {
  let r : Array[Byte] = Array::make(16, b'\x00')
  let mut col = 0
  while col < 4 {
    let i = col * 4
    let s0 = state[i]; let s1 = state[i+1]; let s2 = state[i+2]; let s3 = state[i+3]
    r[i] = gf_mul2(s0) ^ gf_mul3(s1) ^ s2 ^ s3
    r[i+1] = s0 ^ gf_mul2(s1) ^ gf_mul3(s2) ^ s3
    r[i+2] = s0 ^ s1 ^ gf_mul2(s2) ^ gf_mul3(s3)
    r[i+3] = gf_mul3(s0) ^ s1 ^ s2 ^ gf_mul2(s3)
    col = col + 1
  }
  r
}

fn add_round_key(state : Array[Byte], key : Array[Byte]) -> Array[Byte] {
  let r : Array[Byte] = Array::make(16, b'\x00')
  let mut i = 0
  while i < 16 { r[i] = state[i] ^ key[i]; i = i + 1 }
  r
}

fn aes256_key_expansion(key : Bytes) -> Array[Array[Byte]] {
  let w_count = 60
  let w : Array[Array[Byte]] = Array::make(w_count, [b'\x00',b'\x00',b'\x00',b'\x00'])
  let mut i = 0
  while i < 8 {
    w[i] = [key[i*4], key[i*4+1], key[i*4+2], key[i*4+3]]
    i = i + 1
  }
  i = 8
  while i < 60 {
    let mut temp = w[i - 1]
    if i % 8 == 0 {
      temp = xor_word(sub_word(rot_word(temp)), [rcon[i/8], b'\x00', b'\x00', b'\x00'])
    } else if i % 8 == 4 {
      temp = sub_word(temp)
    }
    w[i] = xor_word(w[i - 8], temp)
    i = i + 1
  }
  w
}

fn words_to_round_key(w : Array[Array[Byte]], start : Int) -> Array[Byte] {
  let rk : Array[Byte] = Array::make(16, b'\x00')
  let mut j = 0
  while j < 16 { rk[j] = w[start + j/4][j%4]; j = j + 1 }
  rk
}

fn aes256_encrypt_block(block : Array[Byte], w : Array[Array[Byte]]) -> Array[Byte] {
  let mut state = block

  // Initial round
  state = add_round_key(state, words_to_round_key(w, 0))

  // 13 rounds with MixColumns
  let mut round = 1
  while round < 14 {
    state = sub_bytes(state)
    state = shift_rows(state)
    state = mix_columns(state)
    state = add_round_key(state, words_to_round_key(w, round * 4))
    round = round + 1
  }

  // Final round (no MixColumns)
  state = sub_bytes(state)
  state = shift_rows(state)
  state = add_round_key(state, words_to_round_key(w, 56))

  state
}

// GCM: Galois/Counter Mode

fn inc_counter(counter : Array[Byte]) -> Array[Byte] {
  let r : Array[Byte] = Array::make(16, b'\x00')
  let mut i = 0
  while i < 16 { r[i] = counter[i]; i = i + 1 }
  let mut j = 15
  while j >= 0 {
    let v = r[j].to_int() + 1
    r[j] = (v & 0xFF).to_byte()
    if v <= 0xFF { break }
    j = j - 1
  }
  r
}

fn gcm_mul(x : Array[Byte], y : Array[Byte]) -> Array[Byte] {
  let z : Array[Byte] = Array::make(16, b'\x00')
  let v : Array[Byte] = Array::make(16, b'\x00')
  let mut i = 0
  while i < 16 { v[i] = x[i]; i = i + 1 }

  let r_byte : Byte = (0xe1).to_byte()

  let mut bit_pos = 0
  while bit_pos < 128 {
    let byte_idx = 15 - (bit_pos / 8)
    let bit_idx = bit_pos % 8
    let y_bit = (y[byte_idx].to_int() >> bit_idx) & 1
    if y_bit != 0 {
      let mut k = 0
      while k < 16 { z[k] = z[k] ^ v[k]; k = k + 1 }
    }
    let lsb = v[15].to_int() & 1
    let mut j = 15
    while j > 0 {
      let cur = v[j].to_int() >> 1
      let prev = (v[j-1].to_int() & 1) << 7
      v[j] = (cur | prev).to_byte()
      j = j - 1
    }
    v[0] = (v[0].to_int() >> 1).to_byte()
    if lsb != 0 {
      v[0] = v[0] ^ r_byte
    }
    bit_pos = bit_pos + 1
  }
  z
}

fn xor_blocks_16(a : Array[Byte], b : Array[Byte]) -> Array[Byte] {
  let r : Array[Byte] = Array::make(16, b'\x00')
  let mut i = 0
  while i < 16 { r[i] = a[i] ^ b[i]; i = i + 1 }
  r
}

fn bytes_to_block(b : Bytes, off : Int) -> Array[Byte] {
  let block : Array[Byte] = Array::make(16, b'\x00')
  let end = if off + 16 < b.length() { off + 16 } else { b.length() }
  let mut i = off
  while i < end { block[i - off] = b[i]; i = i + 1 }
  block
}

pub fn aes256_gcm_encrypt(key : Bytes, nonce : Bytes, plaintext : Bytes, aad : Bytes) -> (Bytes, Bytes) {
  let w = aes256_key_expansion(key)

  // Generate H = AES(K, 0^128)
  let zero_block : Array[Byte] = Array::make(16, b'\x00')
  let hkey_arr = aes256_encrypt_block(zero_block, w)

  // Initialize counter: nonce padded to 96 bits (12 bytes) + 4 bytes counter
  let nlen = nonce.length()
  let counter : Array[Byte] = Array::make(16, b'\x00')
  let mut i = 0
  while i < nlen { counter[i] = nonce[i]; i = i + 1 }
  counter[15] = b'\x02'

  // Encrypt plaintext with CTR mode
  let ct_len = plaintext.length()
  let ciphertext : Array[Byte] = Array::make(ct_len, b'\x00')
  let mut off = 0
  let mut current_counter = counter
  while off < ct_len {
    let keystream = aes256_encrypt_block(current_counter, w)
    let chunk_end = if off + 16 < ct_len { off + 16 } else { ct_len }
    let mut j = off
    while j < chunk_end {
      ciphertext[j] = keystream[j - off] ^ plaintext[j]
      j = j + 1
    }
    current_counter = inc_counter(current_counter)
    off = off + 16
  }

  // Compute authentication tag using GHASH
  let ct_bytes = Bytes::from_array(ciphertext[0:ct_len])
  let tag = ghash_result(hkey_arr, aad, ct_bytes)

  // Encrypt tag: AES(K, Y0) where Y0 = initial counter (=1)
  let y0 : Array[Byte] = Array::make(16, b'\x00')
  i = 0
  while i < nlen { y0[i] = nonce[i]; i = i + 1 }
  y0[15] = b'\x01'
  let ek_y0 = aes256_encrypt_block(y0, w)
  let auth_tag : Array[Byte] = Array::make(16, b'\x00')
  i = 0
  while i < 16 { auth_tag[i] = tag[i] ^ ek_y0[i]; i = i + 1 }

  (Bytes::from_array(ciphertext[0:ct_len]), Bytes::from_array(auth_tag))
}

pub fn aes256_gcm_decrypt(key : Bytes, nonce : Bytes, ciphertext : Bytes, aad : Bytes, tag : Bytes) -> Bytes? {
  let w = aes256_key_expansion(key)

  let zero_block : Array[Byte] = Array::make(16, b'\x00')
  let hkey_arr = aes256_encrypt_block(zero_block, w)

  // Verify tag first
  let computed_tag = ghash_result(hkey_arr, aad, ciphertext)

  let nlen = nonce.length()
  let y0 : Array[Byte] = Array::make(16, b'\x00')
  let mut i = 0
  while i < nlen { y0[i] = nonce[i]; i = i + 1 }
  y0[15] = b'\x01'
  let ek_y0 = aes256_encrypt_block(y0, w)

  let expected_tag : Array[Byte] = Array::make(16, b'\x00')
  i = 0
  while i < 16 { expected_tag[i] = computed_tag[i] ^ ek_y0[i]; i = i + 1 }

  let expected = Bytes::from_array(expected_tag)
  if !constant_eq(tag, expected) { return None }

  // Decrypt ciphertext with CTR mode
  let counter : Array[Byte] = Array::make(16, b'\x00')
  i = 0
  while i < nlen { counter[i] = nonce[i]; i = i + 1 }
  counter[15] = b'\x02'

  let pt_len = ciphertext.length()
  let plaintext : Array[Byte] = Array::make(pt_len, b'\x00')
  let mut off = 0
  let mut current_counter = counter
  while off < pt_len {
    let keystream = aes256_encrypt_block(current_counter, w)
    let chunk_end = if off + 16 < pt_len { off + 16 } else { pt_len }
    let mut j = off
    while j < chunk_end {
      plaintext[j] = keystream[j - off] ^ ciphertext[j]
      j = j + 1
    }
    current_counter = inc_counter(current_counter)
    off = off + 16
  }

  Some(Bytes::from_array(plaintext[0:pt_len]))
}

fn ghash_result(h : Array[Byte], aad : Bytes, ct : Bytes) -> Array[Byte] {
  let mut state : Array[Byte] = Array::make(16, b'\x00')

  // Hash AAD: state = (state ^ block) * H
  let aad_len = aad.length()
  let mut off = 0
  while off < aad_len {
    let block = bytes_to_block(aad, off)
    state = gcm_mul(h, xor_blocks_16(state, block))
    off = off + 16
  }

  // Hash ciphertext
  let ct_len = ct.length()
  off = 0
  while off < ct_len {
    let block = bytes_to_block(ct, off)
    state = gcm_mul(h, xor_blocks_16(state, block))
    off = off + 16
  }

  // Final block: lengths
  let len_block : Array[Byte] = Array::make(16, b'\x00')
  let aad_bits : UInt64 = aad_len.to_uint64() * 8
  let ct_bits : UInt64 = ct_len.to_uint64() * 8
  let mut j = 0
  while j < 8 {
    len_block[j] = ((aad_bits >> (56 - j * 8)) & 0xFF).to_byte()
    len_block[8 + j] = ((ct_bits >> (56 - j * 8)) & 0xFF).to_byte()
    j = j + 1
  }
  gcm_mul(h, xor_blocks_16(state, len_block))
}

pub fn aes256_gcm_encrypt_hex(key : String, nonce : String, plaintext : String, aad : String) -> (String, String) {
  let k = hex_to_bytes(key)
  let n = hex_to_bytes(nonce)
  let p = str_to_utf8(plaintext)
  let a = str_to_utf8(aad)
  let (ct, tag) = aes256_gcm_encrypt(k, n, p, a)
  (bytes_to_hex(ct), bytes_to_hex(tag))
}

fn hex_char(c : Int) -> Int? {
  if c >= '0'.to_int() && c <= '9'.to_int() { Some(c - '0'.to_int()) }
  else if c >= 'a'.to_int() && c <= 'f'.to_int() { Some(c - 'a'.to_int() + 10) }
  else if c >= 'A'.to_int() && c <= 'F'.to_int() { Some(c - 'A'.to_int() + 10) }
  else { None }
}

fn hex_to_bytes(hex : String) -> Bytes {
  let s = str_to_utf8(hex)
  let n = s.length() / 2
  let buf : Array[Byte] = Array::make(n, b'\x00')
  let mut i = 0
  while i < n {
    let hi = hex_char(s[i * 2].to_int()).unwrap()
    let lo = hex_char(s[i * 2 + 1].to_int()).unwrap()
    buf[i] = ((hi * 16 + lo) & 0xFF).to_byte()
    i = i + 1
  }
  Bytes::from_array(buf)
}

pub fn generate_aes_key_256() -> Bytes {
  random_bytes(32)
}

pub fn generate_nonce_96() -> Bytes {
  random_bytes(12)
}
