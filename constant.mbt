// Constant-time comparison utilities for MoonVault
// These prevent timing side-channel attacks on MAC/password comparisons

pub fn constant_eq(a : Bytes, b : Bytes) -> Bool {
  if a.length() != b.length() { return false }
  let mut diff : UInt = 0
  let mut i = 0
  while i < a.length() {
    diff = diff | (a[i].to_uint() ^ b[i].to_uint())
    i = i + 1
  }
  diff == 0
}

pub fn constant_eq_bytes(a : Array[Byte], b : Array[Byte], len : Int) -> Bool {
  let mut diff : UInt = 0
  let mut i = 0
  while i < len {
    diff = diff | (a[i].to_uint() ^ b[i].to_uint())
    i = i + 1
  }
  diff == 0
}

pub fn constant_eq_string(a : String, b : String) -> Bool {
  if a.length() != b.length() { return false }
  let mut diff : UInt = 0
  let mut i = 0
  while i < a.length() {
    diff = diff | (a[i] ^ b[i]).to_uint()
    i = i + 1
  }
  diff == 0
}

pub fn constant_select(a : Int, b : Int, cond : Bool) -> Int {
  let m = if cond { 0xFF } else { 0 }
  (a & m) | (b & m.lnot() & 0xFF)
}

pub fn constant_is_zero(x : UInt) -> Bool {
  (x | x.lnot().lnot()) == 0
}

pub fn constant_ne(a : Bytes, b : Bytes) -> Bool {
  !constant_eq(a, b)
}

pub fn constant_lt(a : Int, b : Int) -> Bool {
  let d = a - b
  (d >> 31) != 0
}

pub fn constant_ge(a : Int, b : Int) -> Bool {
  !constant_lt(a, b)
}
