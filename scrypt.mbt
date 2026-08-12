// scrypt password-based key derivation function for MoonVault
// RFC 7914: The scrypt Password-Based Key Derivation Function
// scrypt(P, S, N, r, p, dkLen) = PBKDF2(P, S, 1, p * MFLen)
// where MFLen = 128 * r, and MF = ROMix(BlockMix, Salsa20/8)

// Core Salsa20/8 quarter-round
fn salsa20_8(input : Array[UInt]) -> Array[UInt] {
  let x : Array[UInt] = Array::make(16, 0)
  let mut i = 0
  while i < 16 { x[i] = input[i]; i = i + 1 }

  i = 0
  while i < 4 {
    x[4] = x[4] ^ rotl(x[0] + x[12], 7)
    x[8] = x[8] ^ rotl(x[4] + x[0], 9)
    x[12] = x[12] ^ rotl(x[8] + x[4], 13)
    x[0] = x[0] ^ rotl(x[12] + x[8], 18)

    x[9] = x[9] ^ rotl(x[5] + x[1], 7)
    x[13] = x[13] ^ rotl(x[9] + x[5], 9)
    x[1] = x[1] ^ rotl(x[13] + x[9], 13)
    x[5] = x[5] ^ rotl(x[1] + x[13], 18)

    x[14] = x[14] ^ rotl(x[10] + x[6], 7)
    x[2] = x[2] ^ rotl(x[14] + x[10], 9)
    x[6] = x[6] ^ rotl(x[2] + x[14], 13)
    x[10] = x[10] ^ rotl(x[6] + x[2], 18)

    x[3] = x[3] ^ rotl(x[15] + x[11], 7)
    x[7] = x[7] ^ rotl(x[3] + x[15], 9)
    x[11] = x[11] ^ rotl(x[7] + x[3], 13)
    x[15] = x[15] ^ rotl(x[11] + x[7], 18)

    x[1] = x[1] ^ rotl(x[0] + x[3], 7)
    x[2] = x[2] ^ rotl(x[1] + x[0], 9)
    x[3] = x[3] ^ rotl(x[2] + x[1], 13)
    x[0] = x[0] ^ rotl(x[3] + x[2], 18)

    x[6] = x[6] ^ rotl(x[5] + x[4], 7)
    x[7] = x[7] ^ rotl(x[6] + x[5], 9)
    x[4] = x[4] ^ rotl(x[7] + x[6], 13)
    x[5] = x[5] ^ rotl(x[4] + x[7], 18)

    x[11] = x[11] ^ rotl(x[10] + x[9], 7)
    x[8] = x[8] ^ rotl(x[11] + x[10], 9)
    x[9] = x[9] ^ rotl(x[8] + x[11], 13)
    x[10] = x[10] ^ rotl(x[9] + x[8], 18)

    x[12] = x[12] ^ rotl(x[15] + x[14], 7)
    x[13] = x[13] ^ rotl(x[12] + x[15], 9)
    x[14] = x[14] ^ rotl(x[13] + x[12], 13)
    x[15] = x[15] ^ rotl(x[14] + x[13], 18)

    i = i + 1
  }

  let output : Array[UInt] = Array::make(16, 0)
  i = 0
  while i < 16 { output[i] = x[i] + input[i]; i = i + 1 }
  output
}

fn rotl(x : UInt, n : Int) -> UInt {
  (x << n) | (x >> (32 - n))
}

fn salsa20_8_core(block : Bytes) -> Bytes {
  let input : Array[UInt] = Array::make(16, 0)
  let mut i = 0
  while i < 16 {
    let off = i * 4
    input[i] = (uint_from_le_bytes(block, off))
    i = i + 1
  }

  let output = salsa20_8(input)

  let result : Array[Byte] = Array::make(64, b'\x00')
  i = 0
  while i < 16 {
    put_uint32_le(result, i * 4, output[i])
    i = i + 1
  }
  Bytes::from_array(result)
}

fn uint_from_le_bytes(b : Bytes, off : Int) -> UInt {
  let b0 = b[off].to_uint()
  let b1 = b[off + 1].to_uint()
  let b2 = b[off + 2].to_uint()
  let b3 = b[off + 3].to_uint()
  b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
}

fn put_uint32_le(arr : Array[Byte], off : Int, v : UInt) -> Unit {
  arr[off] = (v & 0xFF).to_byte()
  arr[off + 1] = ((v >> 8) & 0xFF).to_byte()
  arr[off + 2] = ((v >> 16) & 0xFF).to_byte()
  arr[off + 3] = ((v >> 24) & 0xFF).to_byte()
}

// BlockMix: mixes blocks of salsa20 output
fn blockmix_salsa8(b : Array[Byte], r : Int) -> Array[Byte] {
  let block_size = 128 * r
  let x_off = block_size - 64
  let result : Array[Byte] = Array::make(block_size, b'\x00')

  let x_data : Array[Byte] = Array::make(64, b'\x00')
  let mut i = 0
  while i < 64 { x_data[i] = b[x_off + i]; i = i + 1 }

  let mut j = 0
  while j < 2 * r {
    let mut k = 0
    while k < 64 { x_data[k] = x_data[k] ^ b[j * 64 + k]; k = k + 1 }

    let x_bytes = salsa20_8_core(Bytes::from_array(x_data))
    k = 0
    while k < 64 {
      x_data[k] = x_bytes[k]
      result[j * 64 + k] = x_bytes[k]
      k = k + 1
    }
    j = j + 1
  }

  let th = r * 64
  j = 0
  while j < r {
    let mut k = 0
    while k < 64 {
      let bi = 2 * j * 64
      result[th + k] = result[bi + k]
      result[bi + k] = result[(2 * j + 1) * 64 + k]
      k = k + 1
    }
    j = j + 1
  }

  result
}

// ROMix: memory-hard mixing function
fn romix(b : Array[Byte], r : Int, n : Int) -> Array[Byte] {
  let block_size = 128 * r
  let v : Array[Array[Byte]] = Array::make(n, [b'\x00'])

  let mut x = b
  let mut i = 0
  while i < n {
    v[i] = x
    x = blockmix_salsa8(x, r)
    i = i + 1
  }

  i = 0
  while i < n {
    let j = (integerify(x, r) % n.reinterpret_as_uint()).reinterpret_as_int()
    let t_arr : Array[Byte] = Array::make(block_size, b'\x00')
    let mut k = 0
    while k < block_size { t_arr[k] = x[k] ^ v[j][k]; k = k + 1 }
    x = blockmix_salsa8(t_arr, r)
    i = i + 1
  }
  x
}

fn integerify(b : Array[Byte], r : Int) -> UInt {
  let off = (2 * r - 1) * 64
  uint_from_le_bytes(Bytes::from_array(b), off)
}

// scrypt main function
pub fn scrypt(password : String, salt : String, n : Int, r : Int, p : Int, dk_len : Int) -> Bytes {
  let mflen = 128 * r
  let b_bytes = pbkdf2_raw(str_to_utf8(password), str_to_utf8(salt), 1, p * mflen)

  let b_fixed = b_bytes.to_fixedarray()
  let b : Array[Byte] = Array::make(b_bytes.length(), b'\x00')
  let mut bi = 0
  while bi < b_bytes.length() { b[bi] = b_fixed[bi]; bi = bi + 1 }

  bi = 0
  while bi < p {
    let block_size = 128 * r
    let block : Array[Byte] = Array::make(block_size, b'\x00')
    let mut k = 0
    while k < block_size { block[k] = b[bi * block_size + k]; k = k + 1 }

    let mixed = romix(block, r, n)

    k = 0
    while k < block_size { b[bi * block_size + k] = mixed[k]; k = k + 1 }
    bi = bi + 1
  }

  pbkdf2_raw(str_to_utf8(password), Bytes::from_array(b), 1, dk_len)
}

pub fn scrypt_simple(password : String, salt : String, n : Int, r : Int, p : Int, dk_len : Int) -> Bytes {
  scrypt(password, salt, n, r, p, dk_len)
}

pub fn scrypt_hex(password : String, salt : String, n : Int, r : Int, p : Int, dk_len : Int) -> String {
  bytes_to_hex(scrypt(password, salt, n, r, p, dk_len))
}

pub fn scrypt_verify(password : String, salt : String, n : Int, r : Int, p : Int, dk_len : Int, expected : Bytes) -> Bool {
  let dk = scrypt(password, salt, n, r, p, dk_len)
  constant_eq(dk, expected)
}

// scrypt recommended parameters
pub fn scrypt_params_interactive() -> (Int, Int, Int) {
  (16384, 8, 1)
}

pub fn scrypt_params_sensitive() -> (Int, Int, Int) {
  (1048576, 8, 1)
}

pub fn scrypt_params_paranoid() -> (Int, Int, Int) {
  (4194304, 8, 1)
}
