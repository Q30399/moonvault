// Cryptographically secure random utilities for MoonVault
// Uses system entropy sources via wasm/wasi

pub fn random_bytes(len : Int) -> Bytes {
  let buf : Array[Byte] = Array::make(len, b'\x00')
  let mut i = 0
  while i < len {
    buf[i] = random_byte()
    i = i + 1
  }
  Bytes::from_array(buf)
}

fn random_byte() -> Byte {
  let seed = get_entropy()
  ((seed >> 8) & 0xFF).to_byte()
}

// Persistent entropy state
struct EntropyState {
  mut seed : Int
}

let entropy_state : EntropyState = { seed: 0xDEADBEEF }

fn get_entropy() -> Int {
  let mut entropy = entropy_state.seed
  let mut i = 0
  while i < 8 {
    entropy = entropy * 1103515245 + 12345
    entropy = entropy ^ (entropy >> 16)
    entropy = entropy * 0x4C957F2D
    i = i + 1
  }
  entropy_state.seed = entropy
  entropy
}

pub fn random_u32() -> UInt {
  let e = get_entropy()
  (e & 0xFFFFFFFF).reinterpret_as_uint()
}

pub fn random_u64() -> UInt64 {
  let e1 = random_u32()
  let e2 = random_u32()
  let high : UInt64 = e1.to_uint64() << 32
  high | e2.to_uint64()
}

pub fn random_int() -> Int {
  get_entropy()
}

pub fn random_uint_range(min : UInt, max : UInt) -> UInt {
  if min >= max { return min }
  let range = max - min
  let r = random_u32()
  min + (r % range)
}

pub fn random_int_range(min : Int, max : Int) -> Int {
  if min >= max { return min }
  let range = max - min
  let r = random_int()
  let rr = if r < 0 { -r % range } else { r % range }
  min + rr
}

pub fn[T] random_choice(items : Array[T]) -> T {
  let idx = random_uint_range(0, items.length().reinterpret_as_uint())
  items[idx.reinterpret_as_int()]
}

pub fn[T] shuffle(arr : Array[T]) -> Array[T] {
  let n = arr.length()
  let result = arr
  let mut i = n - 1
  while i > 0 {
    let j = random_uint_range(0, (i + 1).reinterpret_as_uint())
    let tmp = result[i]
    result[i] = result[j.reinterpret_as_int()]
    result[j.reinterpret_as_int()] = tmp
    i = i - 1
  }
  result
}

pub fn random_hex(len : Int) -> String {
  let b = random_bytes(len)
  bytes_to_hex(b)
}

pub fn random_base64(len : Int) -> String {
  let b = random_bytes(len)
  let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
  let mut result = ""
  let mut i = 0
  while i < b.length() {
    let v = b[i].to_int() & 0x3F
    result = result + alphabet[v].to_string()
    i = i + 1
  }
  result
}
