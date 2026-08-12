fn main {
  println("=== BCRYPT ROUNDTRIP DEBUG ===")
  
  let password = "mypassword"
  let salt = "saltsaltsaltsalt12"
  let cost = 4
  
  let hash1 = bcrypt_hash(password, cost, salt)
  let hash2 = bcrypt_hash(password, cost, salt)
  println("hash1: \{hash1}")
  println("hash2: \{hash2}")
  println("same:  \{hash1 == hash2}")
  println("")
  
  // Show salt roundtrip
  let salt_utf8 = str_to_utf8(salt)
  let salt_enc = bcrypt_encode64(salt_utf8, 16)
  println("salt_utf8 hex: \{bytes_to_hex(salt_utf8)}")
  println("salt_enc:      \{salt_enc} (len \{salt_enc.length()})")
  println("")
  
  // Decode and verify
  let decoded = bcrypt_decode_salt64(salt_enc)
  println("decoded hex:   \{bytes_to_hex(decoded)}")
  println("roundtrip ok:  \{salt_utf8.length() == decoded.length()}")
  println("")
  
  // Now verify
  println("verify result: \{bcrypt_verify(password, hash1)}")
}
