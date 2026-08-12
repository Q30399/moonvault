// SHA-512 for MoonVault
// FIPS 180-4: Secure Hash Standard

// Initial hash values: first 64 bits of fractional parts of sqrt(2) through sqrt(23)
let h512_init : Array[UInt64] = [
  0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
  0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
  0x510e527fade682d1, 0x9b05688c2b3e6c1f,
  0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
]

// Round constants: first 64 bits of fractional parts of cube roots of first 80 primes
let k512_const : Array[UInt64] = [
  0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
  0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
  0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
  0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
  0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
  0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
  0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
  0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
  0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
  0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
  0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
  0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
  0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
  0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
  0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
  0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
  0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
  0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
  0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
  0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
]

fn rotr64_512(x : UInt64, n : Int) -> UInt64 {
  (x >> n) | (x << (64 - n))
}

fn big_sigma0(x : UInt64) -> UInt64 {
  rotr64_512(x, 28) ^ rotr64_512(x, 34) ^ rotr64_512(x, 39)
}

fn big_sigma1(x : UInt64) -> UInt64 {
  rotr64_512(x, 14) ^ rotr64_512(x, 18) ^ rotr64_512(x, 41)
}

fn small_sigma0(x : UInt64) -> UInt64 {
  rotr64_512(x, 1) ^ rotr64_512(x, 8) ^ (x >> 7)
}

fn small_sigma1(x : UInt64) -> UInt64 {
  rotr64_512(x, 19) ^ rotr64_512(x, 61) ^ (x >> 6)
}

fn ch(x : UInt64, y : UInt64, z : UInt64) -> UInt64 {
  (x & y) ^ (x.lnot() & z)
}

fn maj(x : UInt64, y : UInt64, z : UInt64) -> UInt64 {
  (x & y) ^ (x & z) ^ (y & z)
}

fn sha512_compress(state : Array[UInt64], block : Array[UInt64]) -> Array[UInt64] {
  let w : Array[UInt64] = Array::make(80, 0)
  let mut t = 0
  while t < 16 {
    w[t] = block[t]
    t = t + 1
  }
  while t < 80 {
    w[t] = small_sigma1(w[t - 2]) + w[t - 7] + small_sigma0(w[t - 15]) + w[t - 16]
    t = t + 1
  }

  let mut a = state[0]
  let mut b = state[1]
  let mut c = state[2]
  let mut d = state[3]
  let mut e = state[4]
  let mut f = state[5]
  let mut g = state[6]
  let mut h = state[7]

  t = 0
  while t < 80 {
    let t1 = h + big_sigma1(e) + ch(e, f, g) + k512_const[t] + w[t]
    let t2 = big_sigma0(a) + maj(a, b, c)
    h = g; g = f; f = e
    e = d + t1
    d = c; c = b; b = a
    a = t1 + t2
    t = t + 1
  }

  Array::makei(8, fn(i) { state[i] + [a, b, c, d, e, f, g, h][i] })
}

fn pad_message(msg : Bytes) -> Array[Byte] {
  let bit_len : UInt64 = (msg.length() * 8).to_uint64()
  let pad_zeroes = (128 - ((msg.length() + 1 + 16) % 128)) % 128
  let total = msg.length() + 1 + pad_zeroes + 16
  let padded : Array[Byte] = Array::make(total, b'\x00')

  let mut i = 0
  while i < msg.length() { padded[i] = msg[i]; i = i + 1 }

  padded[msg.length()] = b'\x80'

  // SHA-512 uses 128-bit length: upper 8 bytes = 0, lower 8 bytes = bit_len
  let offset = total - 16
  let mut j = 0
  while j < 8 {
    padded[offset + 8 + j] = ((bit_len >> (56 - j * 8)) & 0xFF).to_byte()
    j = j + 1
  }

  padded
}

fn bytes_to_uint64_be(data : Array[Byte], off : Int) -> UInt64 {
  let mut v : UInt64 = 0
  let mut i = 0
  while i < 8 {
    v = (v << 8) | data[off + i].to_uint64()
    i = i + 1
  }
  v
}

pub fn sha512(data : Bytes) -> Bytes {
  let padded = pad_message(data)
  let mut state : Array[UInt64] = Array::make(8, 0)
  let mut i = 0
  while i < 8 { state[i] = h512_init[i]; i = i + 1 }

  let mut off = 0
  while off < padded.length() {
    let block : Array[UInt64] = Array::make(16, 0)
    let mut j = 0
    while j < 16 {
      block[j] = bytes_to_uint64_be(padded, off + j * 8)
      j = j + 1
    }
    state = sha512_compress(state, block)
    off = off + 128
  }

  let result : Array[Byte] = Array::make(64, b'\x00')
  i = 0
  while i < 8 {
    let v = state[i]
    result[i * 8] = ((v >> 56) & 0xFF).to_byte()
    result[i * 8 + 1] = ((v >> 48) & 0xFF).to_byte()
    result[i * 8 + 2] = ((v >> 40) & 0xFF).to_byte()
    result[i * 8 + 3] = ((v >> 32) & 0xFF).to_byte()
    result[i * 8 + 4] = ((v >> 24) & 0xFF).to_byte()
    result[i * 8 + 5] = ((v >> 16) & 0xFF).to_byte()
    result[i * 8 + 6] = ((v >> 8) & 0xFF).to_byte()
    result[i * 8 + 7] = (v & 0xFF).to_byte()
    i = i + 1
  }

  Bytes::from_array(result)
}

pub fn sha512_hex(s : String) -> String {
  bytes_to_hex(sha512(str_to_utf8(s)))
}

// SHA-384: truncated SHA-512 with different initial values
let h384_init : Array[UInt64] = [
  0xcbbb9d5dc1059ed8, 0x629a292a367cd507,
  0x9159015a3070dd17, 0x152fecd8f70e5939,
  0x67332667ffc00b31, 0x8eb44a8768581511,
  0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4,
]

pub fn sha384(data : Bytes) -> Bytes {
  let padded = pad_message(data)
  let mut state : Array[UInt64] = Array::make(8, 0)
  let mut i = 0
  while i < 8 { state[i] = h384_init[i]; i = i + 1 }

  let mut off = 0
  while off < padded.length() {
    let block : Array[UInt64] = Array::make(16, 0)
    let mut j = 0
    while j < 16 {
      block[j] = bytes_to_uint64_be(padded, off + j * 8)
      j = j + 1
    }
    state = sha512_compress(state, block)
    off = off + 128
  }

  let result : Array[Byte] = Array::make(48, b'\x00')
  i = 0
  while i < 6 {
    let v = state[i]
    result[i * 8] = ((v >> 56) & 0xFF).to_byte()
    result[i * 8 + 1] = ((v >> 48) & 0xFF).to_byte()
    result[i * 8 + 2] = ((v >> 40) & 0xFF).to_byte()
    result[i * 8 + 3] = ((v >> 32) & 0xFF).to_byte()
    result[i * 8 + 4] = ((v >> 24) & 0xFF).to_byte()
    result[i * 8 + 5] = ((v >> 16) & 0xFF).to_byte()
    result[i * 8 + 6] = ((v >> 8) & 0xFF).to_byte()
    result[i * 8 + 7] = (v & 0xFF).to_byte()
    i = i + 1
  }

  Bytes::from_array(result)
}

pub fn sha384_hex(s : String) -> String {
  bytes_to_hex(sha384(str_to_utf8(s)))
}

// SHA-512/256: truncated SHA-512 with different initial values
let h512_256_init : Array[UInt64] = [
  0x22312194fc2bf72c, 0x9f555fa3c84c64c2,
  0x2393b86b6f53b151, 0x963877195940eabd,
  0x96283ee2a88effe3, 0xbe5e1e2553863992,
  0x2b0199fc2c85b8aa, 0x0eb72ddc81c52ca2,
]

pub fn sha512_256(data : Bytes) -> Bytes {
  let padded = pad_message(data)
  let mut state : Array[UInt64] = Array::make(8, 0)
  let mut i = 0
  while i < 8 { state[i] = h512_256_init[i]; i = i + 1 }

  let mut off = 0
  while off < padded.length() {
    let block : Array[UInt64] = Array::make(16, 0)
    let mut j = 0
    while j < 16 {
      block[j] = bytes_to_uint64_be(padded, off + j * 8)
      j = j + 1
    }
    state = sha512_compress(state, block)
    off = off + 128
  }

  let result : Array[Byte] = Array::make(32, b'\x00')
  i = 0
  while i < 4 {
    let v = state[i]
    result[i * 8] = ((v >> 56) & 0xFF).to_byte()
    result[i * 8 + 1] = ((v >> 48) & 0xFF).to_byte()
    result[i * 8 + 2] = ((v >> 40) & 0xFF).to_byte()
    result[i * 8 + 3] = ((v >> 32) & 0xFF).to_byte()
    result[i * 8 + 4] = ((v >> 24) & 0xFF).to_byte()
    result[i * 8 + 5] = ((v >> 16) & 0xFF).to_byte()
    result[i * 8 + 6] = ((v >> 8) & 0xFF).to_byte()
    result[i * 8 + 7] = (v & 0xFF).to_byte()
    i = i + 1
  }

  Bytes::from_array(result)
}

pub fn sha512_256_hex(s : String) -> String {
  bytes_to_hex(sha512_256(str_to_utf8(s)))
}
