// ChaCha20-Poly1305 AEAD for MoonVault
// RFC 8439: ChaCha20 and Poly1305 for IETF Protocols
//
// ChaCha20: 256-bit key, 96-bit nonce, 32-bit counter
// Poly1305: one-time authenticator in GF(2^130 - 5)

// ─── ChaCha20 Constants ─────────────────────────────────────────────────

let c0 : UInt = (0x61707865).reinterpret_as_uint()
let c1 : UInt = (0x3320646e).reinterpret_as_uint()
let c2 : UInt = (0x79622d32).reinterpret_as_uint()
let c3 : UInt = (0x6b206574).reinterpret_as_uint()

// ─── ChaCha20 Quarter Round ─────────────────────────────────────────────

fn quarter_round(state : Array[UInt], a : Int, b : Int, c : Int, d : Int) -> Unit {
  let mut sa = state[a]
  let mut sb = state[b]
  let mut sc = state[c]
  let mut sd = state[d]

  sa = sa + sb
  sd = sd ^ sa
  sd = (sd << 16) | (sd >> 16)

  sc = sc + sd
  sb = sb ^ sc
  sb = (sb << 12) | (sb >> 20)

  sa = sa + sb
  sd = sd ^ sa
  sd = (sd << 8) | (sd >> 24)

  sc = sc + sd
  sb = sb ^ sc
  sb = (sb << 7) | (sb >> 25)

  state[a] = sa
  state[b] = sb
  state[c] = sc
  state[d] = sd
}

// ─── Read/write little-endian 32-bit words ──────────────────────────────

fn read_le_u32(b : Bytes, off : Int) -> UInt {
  (b[off].to_uint()) |
  (b[off + 1].to_uint() << 8) |
  (b[off + 2].to_uint() << 16) |
  (b[off + 3].to_uint() << 24)
}

fn write_le_u32(buf : Array[Byte], off : Int, v : UInt) -> Unit {
  let vi = v.reinterpret_as_int()
  buf[off]     = (vi & 0xFF).to_byte()
  buf[off + 1] = ((vi >> 8) & 0xFF).to_byte()
  buf[off + 2] = ((vi >> 16) & 0xFF).to_byte()
  buf[off + 3] = ((vi >> 24) & 0xFF).to_byte()
}

// ─── ChaCha20 Block Function (generates 64 bytes of keystream) ──────────

fn chacha20_block(key : Bytes, nonce : Bytes, counter : UInt) -> Array[Byte] {
  // Initialize 16-word state: constants (4) + key (8) + counter (1) + nonce (3)
  let state : Array[UInt] = Array::make(16, (0).reinterpret_as_uint())

  state[0]  = c0
  state[1]  = c1
  state[2]  = c2
  state[3]  = c3

  state[4]  = read_le_u32(key, 0)
  state[5]  = read_le_u32(key, 4)
  state[6]  = read_le_u32(key, 8)
  state[7]  = read_le_u32(key, 12)
  state[8]  = read_le_u32(key, 16)
  state[9]  = read_le_u32(key, 20)
  state[10] = read_le_u32(key, 24)
  state[11] = read_le_u32(key, 28)

  state[12] = counter

  state[13] = read_le_u32(nonce, 0)
  state[14] = read_le_u32(nonce, 4)
  state[15] = read_le_u32(nonce, 8)

  // Copy to working state
  let work : Array[UInt] = Array::make(16, (0).reinterpret_as_uint())
  let mut i = 0
  while i < 16 {
    work[i] = state[i]
    i = i + 1
  }

  // 20 rounds = 10 double rounds
  let mut round = 0
  while round < 10 {
    // Column round
    quarter_round(work, 0, 4, 8, 12)
    quarter_round(work, 1, 5, 9, 13)
    quarter_round(work, 2, 6, 10, 14)
    quarter_round(work, 3, 7, 11, 15)
    // Diagonal round
    quarter_round(work, 0, 5, 10, 15)
    quarter_round(work, 1, 6, 11, 12)
    quarter_round(work, 2, 7, 8, 13)
    quarter_round(work, 3, 4, 9, 14)
    round = round + 1
  }

  // Add original state to working state
  i = 0
  while i < 16 {
    work[i] = work[i] + state[i]
    i = i + 1
  }

  // Serialize to 64 bytes
  let out : Array[Byte] = Array::make(64, b'\x00')
  i = 0
  while i < 16 {
    write_le_u32(out, i * 4, work[i])
    i = i + 1
  }
  out
}

// ─── ChaCha20 Encrypt / Decrypt ─────────────────────────────────────────

pub fn chacha20_encrypt(key : Bytes, nonce : Bytes, plaintext : Bytes) -> Bytes {
  chacha20_xor(key, nonce, plaintext, (0).reinterpret_as_uint())
}

pub fn chacha20_decrypt(key : Bytes, nonce : Bytes, ciphertext : Bytes) -> Bytes {
  chacha20_xor(key, nonce, ciphertext, (0).reinterpret_as_uint())
}

fn chacha20_xor(key : Bytes, nonce : Bytes, input : Bytes, start_counter : UInt) -> Bytes {
  let len = input.length()
  let out : Array[Byte] = Array::make(len, b'\x00')
  let mut counter = start_counter
  let mut off = 0
  while off < len {
    let keystream = chacha20_block(key, nonce, counter)
    let chunk = if off + 64 < len { 64 } else { len - off }
    let mut j = 0
    while j < chunk {
      out[off + j] = keystream[j] ^ input[off + j]
      j = j + 1
    }
    counter = counter + (1).reinterpret_as_uint()
    off = off + 64
  }
  Bytes::from_array(out)
}

// ─── Poly1305 ───────────────────────────────────────────────────────────
// One-time authenticator over GF(2^130 - 5)

/// Clamp r: r[i] &= 0x0F for i in {3,7,11,15}; r[i] &= 0xFC for i in {4,8,12}
fn poly1305_clamp_r(r_bytes : Bytes) -> (UInt64, UInt64) {
  let r0_low : UInt64 = r_bytes[0].to_uint64() |
    (r_bytes[1].to_uint64() << 8) |
    (r_bytes[2].to_uint64() << 16) |
    ((r_bytes[3].to_uint64() & 0x0FUL) << 24) |
    (r_bytes[4].to_uint64() << 32) |
    ((r_bytes[5].to_uint64() & 0xFCUL) << 40) |
    (r_bytes[6].to_uint64() << 48) |
    (r_bytes[7].to_uint64() << 56)
  let r1_low : UInt64 = ((r_bytes[5].to_uint64() & 0x0FUL) >> 4) |
    (r_bytes[8].to_uint64() << 4) |
    ((r_bytes[9].to_uint64() & 0xFCUL) << 12) |
    (r_bytes[10].to_uint64() << 20) |
    ((r_bytes[11].to_uint64() & 0x0FUL) << 28) |
    (r_bytes[12].to_uint64() << 36) |
    ((r_bytes[13].to_uint64() & 0xFCUL) << 44) |
    (r_bytes[14].to_uint64() << 52)
  (r0_low, r1_low)
}

/// Read second 16 bytes of key as s
fn poly1305_read_s(key : Bytes) -> (UInt64, UInt64) {
  let s0 : UInt64 = key[16].to_uint64() |
    (key[17].to_uint64() << 8) |
    (key[18].to_uint64() << 16) |
    (key[19].to_uint64() << 24) |
    (key[20].to_uint64() << 32) |
    (key[21].to_uint64() << 40) |
    (key[22].to_uint64() << 48) |
    (key[23].to_uint64() << 56)
  let s1 : UInt64 = key[24].to_uint64() |
    (key[25].to_uint64() << 8) |
    (key[26].to_uint64() << 16) |
    (key[27].to_uint64() << 24) |
    (key[28].to_uint64() << 32) |
    (key[29].to_uint64() << 40) |
    (key[30].to_uint64() << 48) |
    (key[31].to_uint64() << 56)
  (s0, s1)
}

/// Read 16-byte block (or fewer) as LE number, append 0x01 byte.
/// Returns (block_lo, block_hi) as two UInt64.
fn poly1305_read_block(msg : Bytes, start : Int, block_len : Int) -> (UInt64, UInt64, UInt64) {
  let mut lo : UInt64 = 0UL
  let mut hi : UInt64 = 0UL
  let mut top : UInt64 = 0UL
  let mut i = 0
  while i < block_len {
    let byte_val : UInt64 = msg[start + i].to_uint64()
    if i < 8 {
      lo = lo | (byte_val << (i * 8))
    } else if i < 16 {
      hi = hi | (byte_val << ((i - 8) * 8))
    } else {
      // Won't happen for <= 16
    }
    i = i + 1
  }
  // Append 0x01 byte
  if block_len < 16 {
    if block_len <= 8 {
      let shift = block_len * 8
      lo = lo | (1UL << shift)
    } else {
      let shift = (block_len - 8) * 8
      hi = hi | (1UL << shift)
    }
  } else {
    // block_len == 16, 0x01 goes after 16 bytes => in the "top" limb
    top = 1UL
  }
  (lo, hi, top)
}

/// Add two 3-limb big numbers: acc += val
fn poly1305_add3(
  a0 : UInt64, a1 : UInt64, a2 : UInt64,
  b0 : UInt64, b1 : UInt64, b2 : UInt64
) -> (UInt64, UInt64, UInt64) {
  let r0 = a0 + b0
  let mut carry : UInt64 = if r0 < a0 { 1UL } else { 0UL }
  let r1 = a1 + b1 + carry
  carry = if r1 < a1 || (carry == 1UL && r1 == a1) { 1UL } else { 0UL }
  let r2 = a2 + b2 + carry
  (r0, r1, r2)
}

/// Multiply 3-limb a by 2-limb b, producing 5-limb result
fn poly1305_mul32(
  a0 : UInt64, a1 : UInt64, a2 : UInt64,
  b0 : UInt64, b1 : UInt64
) -> Array[UInt64] {
  let p : Array[UInt64] = Array::make(5, 0UL)

  // a0 * b0
  let p00_lo = a0 * b0
  let p00_hi = overflow_mul_hi(a0, b0)
  p[0] = p00_lo
  p[1] = p00_hi

  // a1 * b0
  let p10_lo = a1 * b0
  let p10_hi = overflow_mul_hi(a1, b0)
  let mut tmp = p[1] + p10_lo
  let mut carry : UInt64 = if tmp < p[1] { 1UL } else { 0UL }
  p[1] = tmp
  p[2] = p10_hi + carry

  // a2 * b0
  let p20_lo = a2 * b0
  let p20_hi = overflow_mul_hi(a2, b0)
  tmp = p[2] + p20_lo
  carry = if tmp < p[2] { 1UL } else { 0UL }
  p[2] = tmp
  p[3] = p20_hi + carry

  // a0 * b1
  let p01_lo = a0 * b1
  let p01_hi = overflow_mul_hi(a0, b1)
  tmp = p[1] + p01_lo
  carry = if tmp < p[1] { 1UL } else { 0UL }
  p[1] = tmp
  let mut tmp2 = p[2] + p01_hi + carry
  carry = if tmp2 < p[2] { 1UL } else { 0UL }
  p[2] = tmp2
  p[3] = p[3] + carry
  if p[3] < carry { p[4] = p[4] + 1UL }

  // a1 * b1
  let p11_lo = a1 * b1
  let p11_hi = overflow_mul_hi(a1, b1)
  tmp = p[2] + p11_lo
  carry = if tmp < p[2] { 1UL } else { 0UL }
  p[2] = tmp
  tmp2 = p[3] + p11_hi + carry
  carry = if tmp2 < p[3] { 1UL } else { 0UL }
  p[3] = tmp2
  p[4] = p[4] + carry

  // a2 * b1
  let p21_lo = a2 * b1
  let p21_hi = overflow_mul_hi(a2, b1)
  tmp = p[3] + p21_lo
  carry = if tmp < p[3] { 1UL } else { 0UL }
  p[3] = tmp
  tmp2 = p[4] + p21_hi + carry
  p[4] = tmp2

  p
}

/// Get high 64 bits of 64x64 multiply
fn overflow_mul_hi(a : UInt64, b : UInt64) -> UInt64 {
  let mask32 : UInt64 = 0xFFFFFFFFUL
  let a_lo = a & mask32
  let a_hi = a >> 32
  let b_lo = b & mask32
  let b_hi = b >> 32

  let cross = a_lo * b_hi + a_hi * b_lo
  let cross_hi = cross >> 32
  let cross_lo = cross & mask32

  let lo = a_lo * b_lo
  let hi = a_hi * b_hi

  let mid = (lo >> 32) + cross_lo
  let mid_carry = mid >> 32
  hi + cross_hi + mid_carry
}

/// Reduce 5-limb value modulo 2^130 - 5 → 3 limbs
fn poly1305_reduce(p : Array[UInt64]) -> (UInt64, UInt64, UInt64) {
  // Extract low 130 bits
  let lo0 = p[0]
  let lo1 = p[1]
  let lo2 = p[2] & 0x3UL

  // Extract high bits (above bit 130)
  let hi0 = (p[2] >> 2) | (p[3] << 62)
  let hi1 = (p[3] >> 2) | (p[4] << 62)

  // Multiply high bits by 5 = (hi << 2) + hi
  let five_hi0 = hi0 * 5UL
  let five_hi1 = hi1 * 5UL

  // Add high*5 to low
  let mut r0 = lo0 + five_hi0
  let mut carry : UInt64 = if r0 < lo0 { 1UL } else { 0UL }
  let mut r1 = lo1 + five_hi1 + carry
  carry = if r1 < lo1 || (carry == 1UL && r1 == lo1) { 1UL } else { 0UL }
  let mut r2 = lo2 + carry

  // If result >= 2^130 - 5, subtract 2^130 - 5
  // 2^130 - 5 in little-endian limbs: 0xFFFFFFFFFFFFFFFB, 0xFFFFFFFFFFFFFFFF, 0x3
  let p130_5_0 : UInt64 = 0xFFFFFFFFFFFFFFFBUL
  let p130_5_1 : UInt64 = 0xFFFFFFFFFFFFFFFFUL
  let p130_5_2 : UInt64 = 0x0000000000000003UL

  let mut need_sub = false
  if r2 > p130_5_2 {
    need_sub = true
  } else if r2 == p130_5_2 {
    if r1 > p130_5_1 {
      need_sub = true
    } else if r1 == p130_5_1 {
      if r0 >= p130_5_0 {
        need_sub = true
      }
    }
  }

  if need_sub {
    let b0 = r0
    let borrow0 = if b0 < p130_5_0 { 1UL } else { 0UL }
    r0 = b0 - p130_5_0
    let b1 = r1
    let borrow1 = if b1 < p130_5_1 + borrow0 { 1UL } else { 0UL }
    r1 = b1 - p130_5_1 - borrow0
    r2 = r2 - p130_5_2 - borrow1
  }

  (r0, r1, r2)
}

/// Write 16-byte tag from accumulator + s
fn poly1305_finalize(h0 : UInt64, h1 : UInt64, h2 : UInt64, s0 : UInt64, s1 : UInt64) -> Bytes {
  // h = h + s (discard overflow beyond 128 bits for the tag)
  let t0 = h0 + s0
  let carr : UInt64 = if t0 < h0 { 1UL } else { 0UL }
  let t1 = h1 + s1 + carr
  let carr2 : UInt64 = if t1 < h1 || (carr == 1UL && t1 == h1) { 1UL } else { 0UL }
  let _ = h2 + carr2  // overflow beyond 128-bit tag, not needed

  // Serialize low 128 bits as 16-byte LE tag
  let tag : Array[Byte] = Array::make(16, b'\x00')
  let mut i = 0
  while i < 8 {
    tag[i] = ((t0 >> (i * 8)) & 0xFF).to_byte()
    tag[i + 8] = ((t1 >> (i * 8)) & 0xFF).to_byte()
    i = i + 1
  }
  Bytes::from_array(tag)
}

pub fn poly1305_mac(key : Bytes, message : Bytes) -> Bytes {
  let (r0, r1) = poly1305_clamp_r(key)
  let (s0, s1) = poly1305_read_s(key)

  let mut h0 : UInt64 = 0UL
  let mut h1 : UInt64 = 0UL
  let mut h2 : UInt64 = 0UL

  let msg_len = message.length()
  let mut off = 0
  while off < msg_len {
    let block_len = if off + 16 <= msg_len { 16 } else { msg_len - off }
    let (c0, c1, c2) = poly1305_read_block(message, off, block_len)
    let (a0, a1, a2) = poly1305_add3(h0, h1, h2, c0, c1, c2)
    let p = poly1305_mul32(a0, a1, a2, r0, r1)
    let (red0, red1, red2) = poly1305_reduce(p)
    h0 = red0
    h1 = red1
    h2 = red2
    off = off + 16
  }

  poly1305_finalize(h0, h1, h2, s0, s1)
}

// ─── AEAD: ChaCha20-Poly1305 Encrypt ────────────────────────────────────

fn pad16_to_array(len : Int) -> Array[Byte] {
  let pad_len = if len % 16 == 0 { 0 } else { 16 - (len % 16) }
  if pad_len == 0 { return [] }
  Array::make(pad_len, b'\x00')
}

fn write_le_u64(buf : Array[Byte], off : Int, v : UInt64) -> Unit {
  let mut i = 0
  while i < 8 {
    buf[off + i] = ((v >> (i * 8)) & 0xFF).to_byte()
    i = i + 1
  }
}

pub fn chacha20_poly1305_encrypt(key : Bytes, nonce : Bytes, plaintext : Bytes, aad : Bytes) -> (Bytes, Bytes) {
  // Step 1: Generate Poly1305 one-time key using ChaCha20 block with counter=0
  let poly_key_block = chacha20_block(key, nonce, (0).reinterpret_as_uint())
  let poly_key = Bytes::from_array(poly_key_block[0:32])

  // Step 2: Encrypt plaintext with ChaCha20 starting from counter=1
  let ciphertext = chacha20_xor(key, nonce, plaintext, (1).reinterpret_as_uint())

  // Step 3: Build authenticated data for Poly1305
  // aad || pad16(aad) || ciphertext || pad16(ct) || le64(aad_len) || le64(ct_len)
  let aad_len = aad.length()
  let ct_len = ciphertext.length()

  let aad_pad = pad16_to_array(aad_len)
  let ct_pad = pad16_to_array(ct_len)

  let total = aad_len + aad_pad.length() + ct_len + ct_pad.length() + 16
  let mac_data : Array[Byte] = Array::make(total, b'\x00')

  // Copy AAD
  let mut pos = 0
  let mut i = 0
  while i < aad_len { mac_data[pos] = aad[i]; i = i + 1; pos = pos + 1 }
  // Copy AAD padding
  i = 0
  while i < aad_pad.length() { mac_data[pos] = aad_pad[i]; i = i + 1; pos = pos + 1 }
  // Copy ciphertext
  i = 0
  while i < ct_len { mac_data[pos] = ciphertext[i]; i = i + 1; pos = pos + 1 }
  // Copy ciphertext padding
  i = 0
  while i < ct_pad.length() { mac_data[pos] = ct_pad[i]; i = i + 1; pos = pos + 1 }
  // Copy lengths (8 bytes each, little-endian)
  write_le_u64(mac_data, pos, aad_len.to_uint64())
  write_le_u64(mac_data, pos + 8, ct_len.to_uint64())

  // Step 4: Compute Poly1305 MAC
  let mac_input = Bytes::from_array(mac_data)
  let tag = poly1305_mac(poly_key, mac_input)

  (ciphertext, tag)
}

// ─── AEAD: ChaCha20-Poly1305 Decrypt ────────────────────────────────────

pub fn chacha20_poly1305_decrypt(key : Bytes, nonce : Bytes, ciphertext : Bytes, aad : Bytes, tag : Bytes) -> Bytes? {
  // Step 1: Generate Poly1305 one-time key (same as encrypt)
  let poly_key_block = chacha20_block(key, nonce, (0).reinterpret_as_uint())
  let poly_key = Bytes::from_array(poly_key_block[0:32])

  // Step 2: Reconstruct authenticated data
  let aad_len = aad.length()
  let ct_len = ciphertext.length()

  let aad_pad = pad16_to_array(aad_len)
  let ct_pad = pad16_to_array(ct_len)

  let total = aad_len + aad_pad.length() + ct_len + ct_pad.length() + 16
  let mac_data : Array[Byte] = Array::make(total, b'\x00')

  let mut pos = 0
  let mut i = 0
  while i < aad_len { mac_data[pos] = aad[i]; i = i + 1; pos = pos + 1 }
  i = 0
  while i < aad_pad.length() { mac_data[pos] = aad_pad[i]; i = i + 1; pos = pos + 1 }
  i = 0
  while i < ct_len { mac_data[pos] = ciphertext[i]; i = i + 1; pos = pos + 1 }
  i = 0
  while i < ct_pad.length() { mac_data[pos] = ct_pad[i]; i = i + 1; pos = pos + 1 }
  write_le_u64(mac_data, pos, aad_len.to_uint64())
  write_le_u64(mac_data, pos + 8, ct_len.to_uint64())

  // Step 3: Compute expected tag and verify (constant-time)
  let mac_input = Bytes::from_array(mac_data)
  let expected_tag = poly1305_mac(poly_key, mac_input)

  if !constant_eq(tag, expected_tag) { return None }

  // Step 4: Decrypt ciphertext
  let plaintext = chacha20_xor(key, nonce, ciphertext, (1).reinterpret_as_uint())

  Some(plaintext)
}

// ─── Key Generation Utilities ───────────────────────────────────────────

pub fn generate_chacha20_key() -> Bytes {
  random_bytes(32)
}

// generate_nonce_96 is provided by aes_gcm.mbt (shared utility)
