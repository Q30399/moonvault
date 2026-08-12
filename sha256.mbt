// SHA-256 for MoonVault

// Convert MoonBit String (UTF-16) to UTF-8 Bytes
pub fn str_to_utf8(s : String) -> Bytes {
  let len = s.length()
  let result : Array[Byte] = Array::make(len * 3, b'\x00')
  let mut ri = 0
  let mut i = 0
  while i < len {
    let code = s[i].to_int()
    if code < 0x80 {
      result[ri] = code.to_byte()
      ri = ri + 1
    } else if code < 0x800 {
      result[ri] = (0xC0 | (code >> 6)).to_byte()
      result[ri + 1] = (0x80 | (code & 0x3F)).to_byte()
      ri = ri + 2
    } else {
      result[ri] = (0xE0 | (code >> 12)).to_byte()
      result[ri + 1] = (0x80 | ((code >> 6) & 0x3F)).to_byte()
      result[ri + 2] = (0x80 | (code & 0x3F)).to_byte()
      ri = ri + 3
    }
    i = i + 1
  }
  Bytes::from_array(result[0:ri])
}

let k_const : Array[UInt] = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]

struct Sha256 {
  state : Array[UInt]
  buf : Array[Byte]
  mut buf_len : Int
  mut total_len : Int64
}

fn rotr32(x : UInt, n : Int) -> UInt {
  (x >> n) | (x << (32 - n))
}

pub fn Sha256::new() -> Sha256 {
  {
    state: [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19],
    buf: Array::make(64, b'\x00'),
    buf_len: 0,
    total_len: 0L,
  }
}

fn Sha256::process_block(self : Sha256, block : Bytes) -> Sha256 {
  let w : Array[UInt] = Array::make(64, 0)
  let mut i = 0
  while i < 16 {
    let j = i * 4
    w[i] = (block[j].to_uint() << 24) | (block[j+1].to_uint() << 16) | (block[j+2].to_uint() << 8) | block[j+3].to_uint()
    i = i + 1
  }
  i = 16
  while i < 64 {
    let s0 = rotr32(w[i-15], 7) ^ rotr32(w[i-15], 18) ^ (w[i-15] >> 3)
    let s1 = rotr32(w[i-2], 17) ^ rotr32(w[i-2], 19) ^ (w[i-2] >> 10)
    w[i] = w[i-16] + s0 + w[i-7] + s1
    i = i + 1
  }
  let mut a = self.state[0]
  let mut b = self.state[1]
  let mut c = self.state[2]
  let mut d = self.state[3]
  let mut e = self.state[4]
  let mut f = self.state[5]
  let mut g = self.state[6]
  let mut h = self.state[7]
  i = 0
  while i < 64 {
    let se = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25)
    let ch = (e & f) ^ (e.lnot() & g)
    let t1 = h + se + ch + k_const[i] + w[i]
    let sa = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22)
    let maj = (a & b) ^ (a & c) ^ (b & c)
    let t2 = sa + maj
    h = g; g = f; f = e; e = d + t1
    d = c; c = b; b = a; a = t1 + t2
    i = i + 1
  }
  self.state[0] = self.state[0] + a
  self.state[1] = self.state[1] + b
  self.state[2] = self.state[2] + c
  self.state[3] = self.state[3] + d
  self.state[4] = self.state[4] + e
  self.state[5] = self.state[5] + f
  self.state[6] = self.state[6] + g
  self.state[7] = self.state[7] + h
  self
}

pub fn Sha256::write(self : Sha256, data : Bytes) -> Sha256 {
  let mut s = self
  s.total_len = s.total_len + data.length().to_int64()
  let mut offset = 0
  while offset < data.length() {
    let rem = 64 - s.buf_len
    let cl = if offset + rem <= data.length() { rem } else { data.length() - offset }
    let mut j = 0
    while j < cl { s.buf[s.buf_len + j] = data[offset + j]; j = j + 1 }
    s.buf_len = s.buf_len + cl
    offset = offset + cl
    if s.buf_len == 64 { s = s.process_block(Bytes::from_array(s.buf)); s.buf_len = 0 }
  }
  s
}

pub fn Sha256::write_string(self : Sha256, s : String) -> Sha256 {
  self.write(str_to_utf8(s))
}

pub fn Sha256::sum(self : Sha256) -> Bytes {
  let bit_len = self.total_len * 8L
  let rem = (self.total_len + 1L + 8L) % 64L
  let pad_len = if rem != 0L { 1 + (64L - rem).to_int() } else { 1 }
  let tp = pad_len + 8

  let padded : Array[Byte] = Array::make(tp, b'\x00')
  padded[0] = b'\x80'

  let hi = (bit_len >> 32).to_int()
  let lo = (bit_len & 0xFFFFFFFFL).to_int()

  padded[pad_len] = ((hi >> 24) & 0xFF).to_byte()
  padded[pad_len+1] = ((hi >> 16) & 0xFF).to_byte()
  padded[pad_len+2] = ((hi >> 8) & 0xFF).to_byte()
  padded[pad_len+3] = (hi & 0xFF).to_byte()

  padded[pad_len+4] = ((lo >> 24) & 0xFF).to_byte()
  padded[pad_len+5] = ((lo >> 16) & 0xFF).to_byte()
  padded[pad_len+6] = ((lo >> 8) & 0xFF).to_byte()
  padded[pad_len+7] = (lo & 0xFF).to_byte()

  let mut s = self
  let mut offset = 0
  while offset < tp {
    let rem = 64 - s.buf_len
    let cl = if offset + rem <= tp { rem } else { tp - offset }
    let mut j = 0
    while j < cl { s.buf[s.buf_len + j] = padded[offset + j]; j = j + 1 }
    s.buf_len = s.buf_len + cl
    offset = offset + cl
    if s.buf_len == 64 { s = s.process_block(Bytes::from_array(s.buf)); s.buf_len = 0 }
  }

  let digest : Array[Byte] = Array::make(32, b'\x00')
  let mut di = 0
  while di < 8 {
    let vi = s.state[di].reinterpret_as_int()
    digest[di*4] = ((vi >> 24) & 0xFF).to_byte()
    digest[di*4+1] = ((vi >> 16) & 0xFF).to_byte()
    digest[di*4+2] = ((vi >> 8) & 0xFF).to_byte()
    digest[di*4+3] = (vi & 0xFF).to_byte()
    di = di + 1
  }
  Bytes::from_array(digest)
}

pub fn sha256(data : Bytes) -> Bytes {
  let h = Sha256::new()
  let h = h.write(data)
  h.sum()
}

pub fn sha256_hex(s : String) -> String {
  let h = Sha256::new()
  let h = h.write_string(s)
  bytes_to_hex(h.sum())
}

let hex_digits : Array[String] = ["0","1","2","3","4","5","6","7","8","9","a","b","c","d","e","f"]

pub fn bytes_to_hex(b : Bytes) -> String {
  let mut result = ""
  let mut i = 0
  while i < b.length() {
    let v = b[i].to_int()
    result = result + hex_digits[v >> 4] + hex_digits[v & 0xF]
    i = i + 1
  }
  result
}
