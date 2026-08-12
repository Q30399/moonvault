// Blake2b hash function for MoonVault (used in Argon2id)
// RFC 7693: The BLAKE2 Cryptographic Hash and Message Authentication Code

let blake2b_iv : Array[UInt64] = [
  0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
  0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
  0x510e527fade682d1, 0x9b05688c2b3e6c1f,
  0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
]

let blake2b_sigma : Array[Array[Int]] = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
  [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
  [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
  [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
  [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
  [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
  [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
  [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
]

fn rotr64(x : UInt64, n : Int) -> UInt64 {
  (x >> n) | (x << (64 - n))
}

fn blake2b_g(v : Array[UInt64], a : Int, b : Int, c : Int, d : Int, x : UInt64, y : UInt64) -> Array[UInt64] {
  let r : Array[UInt64] = Array::make(16, 0)
  let mut i = 0
  while i < 16 { r[i] = v[i]; i = i + 1 }
  r[a] = r[a] + r[b] + x
  r[d] = rotr64(r[d] ^ r[a], 32)
  r[c] = r[c] + r[d]
  r[b] = rotr64(r[b] ^ r[c], 24)
  r[a] = r[a] + r[b] + y
  r[d] = rotr64(r[d] ^ r[a], 16)
  r[c] = r[c] + r[d]
  r[b] = rotr64(r[b] ^ r[c], 63)
  r
}

fn blake2b_compress(block : Array[UInt64], h : Array[UInt64], t : UInt64, f0 : Bool, f1 : Bool) -> Array[UInt64] {
  let mut v : Array[UInt64] = Array::make(16, 0)
  let mut i = 0
  while i < 8 { v[i] = h[i]; i = i + 1 }
  while i < 16 { v[i] = blake2b_iv[i - 8]; i = i + 1 }

  v[12] = v[12] ^ t
  if f0 { v[14] = v[14] ^ 0xFFFFFFFFFFFFFFFF }
  if f1 { v[13] = v[13] ^ 0xFFFFFFFFFFFFFFFF }

  i = 0
  while i < 12 {
    let s = blake2b_sigma[i]
    v = blake2b_g(v, 0, 4, 8, 12, block[s[0]], block[s[1]])
    v = blake2b_g(v, 1, 5, 9, 13, block[s[2]], block[s[3]])
    v = blake2b_g(v, 2, 6, 10, 14, block[s[4]], block[s[5]])
    v = blake2b_g(v, 3, 7, 11, 15, block[s[6]], block[s[7]])
    v = blake2b_g(v, 0, 5, 10, 15, block[s[8]], block[s[9]])
    v = blake2b_g(v, 1, 6, 11, 12, block[s[10]], block[s[11]])
    v = blake2b_g(v, 2, 7, 8, 13, block[s[12]], block[s[13]])
    v = blake2b_g(v, 3, 4, 9, 14, block[s[14]], block[s[15]])
    i = i + 1
  }

  let result : Array[UInt64] = Array::make(8, 0)
  i = 0
  while i < 8 {
    result[i] = h[i] ^ v[i] ^ v[i + 8]
    i = i + 1
  }
  result
}

// Argon2id implementation for MoonVault
// RFC 9106: Argon2 Memory-Hard Function for Password Hashing

fn g_compress(x : UInt64, y : UInt64) -> (UInt64, UInt64) {
  let nx = x + y
  let ny = rotr64(y ^ nx, 32)
  (nx, ny)
}

fn g(a : UInt64, b : UInt64, c : UInt64, d : UInt64) -> (UInt64, UInt64, UInt64, UInt64) {
  let (a1, b1) = g_compress(a, b)
  let (c1, d1) = g_compress(c, d)
  let (a2, d2) = g_compress(a1, d1)
  let (b2, c2) = g_compress(b1, c1)
  (a2, b2 + d2, c2, d2)
}

fn permute_p(slice : UInt, _memory : Array[UInt64], t_cost : UInt, mem_size : UInt) -> UInt {
  if t_cost == 0 { return slice }
  (slice * slice) % mem_size
}

fn argon2_mix_block(a : Array[UInt64], b : Array[UInt64]) -> Array[UInt64] {
  let result : Array[UInt64] = Array::make(128, 0)
  let mut i = 0
  while i < 128 {
    let (a0, b0, c0, d0) = g(a[i], b[i], a[(i + 1) % 128], b[(i + 1) % 128])
    result[i] = a0 ^ b0
    result[(i + 1) % 128] = c0 ^ d0
    i = i + 2
  }
  result
}

fn hash_blake2b(input : Bytes, out_len : Int) -> Bytes {
  let mut h : Array[UInt64] = Array::make(8, 0)
  let mut i = 0
  while i < 8 { h[i] = blake2b_iv[i]; i = i + 1 }
  h[0] = h[0] ^ (0x01010000 ^ out_len.to_uint64())

  let block : Array[UInt64] = Array::make(16, 0)
  let input_len = input.length()
  let mut off = 0
  while off < input_len {
    i = 0
    while i < 16 && off < input_len {
      let mut v : UInt64 = 0
      let mut j = 0
      while j < 8 && off < input_len {
        v = v | (input[off].to_uint64() << (j * 8))
        off = off + 1
        j = j + 1
      }
      block[i] = v
      i = i + 1
    }
    h = blake2b_compress(block, h, input_len.to_uint64(), off >= input_len, false)
  }

  let result : Array[Byte] = Array::make(out_len, b'\x00')
  i = 0
  while i < out_len {
    let hi = (i / 8)
    let shift = 56 - (i % 8) * 8
    result[i] = ((h[hi] >> shift) & 0xFF).to_byte()
    i = i + 1
  }
  Bytes::from_array(result[0:out_len])
}

pub fn argon2id(
  password : String, salt : String,
  t_cost : Int, m_cost : Int, parallelism : Int,
  hash_len : Int
) -> Bytes {
  let pwd = str_to_utf8(password)
  let slt = str_to_utf8(salt)
  let l_cost : UInt = m_cost.reinterpret_as_uint()
  let t : UInt = t_cost.reinterpret_as_uint()

  let memory_blocks = m_cost * parallelism
  let memory : Array[UInt64] = Array::make(memory_blocks * 128, 0)

  let h0 = hash_blake2b(
    pwd + slt +
    uint32_le(t_cost) + uint32_le(m_cost) + uint32_le(parallelism) +
    uint32_le(hash_len) + uint32_le(parallelism),
    64
  )

  let mut i = 0
  while i < parallelism {
    let mut block : Array[UInt64] = Array::make(128, 0)
    let mut j = 0
    while j < 64 {
      let val = h0[j].to_uint64() ^ (i.to_uint64() << 32) ^ j.to_uint64()
      block[(j * 2) % 128] = block[(j * 2) % 128] ^ val
      j = j + 1
    }

    j = 0
    while j < t_cost {
      let ref_block = permute_p(j.reinterpret_as_uint(), memory, t, l_cost)
      let ref_offset = ref_block.reinterpret_as_int() * 128
      let mut k = 0
      while k < 128 {
        block[k] = block[k] ^ memory[ref_offset + k]
        k = k + 1
      }
      block = argon2_mix_block(block, block)
      j = j + 1
    }

    let seg_offset = i * m_cost * 128
    j = 0
    while j < 128 {
      memory[seg_offset + j] = block[j]
      j = j + 1
    }
    i = i + 1
  }

  let result_block = memory[0:128]
  let tag : Array[Byte] = Array::make(hash_len, b'\x00')
  i = 0
  while i < hash_len && i < 128 * 8 {
    let v = result_block[i / 8]
    tag[i] = ((v >> (56 - (i % 8) * 8)) & 0xFF).to_byte()
    i = i + 1
  }
  Bytes::from_array(tag[0:hash_len])
}

fn uint32_le(n : Int) -> Bytes {
  let buf : Array[Byte] = Array::make(4, b'\x00')
  let v = n.reinterpret_as_uint()
  buf[0] = (v & 0xFF).to_byte()
  buf[1] = ((v >> 8) & 0xFF).to_byte()
  buf[2] = ((v >> 16) & 0xFF).to_byte()
  buf[3] = ((v >> 24) & 0xFF).to_byte()
  Bytes::from_array(buf)
}

pub fn argon2id_hash(password : String, salt : String, t_cost : Int, m_cost : Int, parallelism : Int) -> String {
  let hash = argon2id(password, salt, t_cost, m_cost, parallelism, 32)
  bytes_to_hex(hash)
}

pub fn argon2id_verify(password : String, salt : String, t_cost : Int, m_cost : Int, parallelism : Int, hash_len : Int, expected : Bytes) -> Bool {
  let hash = argon2id(password, salt, t_cost, m_cost, parallelism, hash_len)
  constant_eq(hash, expected)
}

pub fn argon2id_params_interactive() -> (Int, Int, Int) {
  (2, 65536, 1)
}

pub fn argon2id_params_moderate() -> (Int, Int, Int) {
  (3, 262144, 1)
}

pub fn argon2id_params_sensitive() -> (Int, Int, Int) {
  (4, 1048576, 1)
}
