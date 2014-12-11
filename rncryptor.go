package rncryptor

import(
  "bytes"
  "log"
  "crypto/sha1"
  "crypto/sha256"
  "crypto/hmac"
  "crypto/aes"
  "crypto/cipher"
  "golang.org/x/crypto/pbkdf2"
)

func Decrypt(text, password []byte) ([]byte) {
  version         := text[:1]
  options         := text[1:2]
  encSalt         := text[2:10]
  hmacSalt        := text[10:18]
  iv              := text[18:34]
  cipherText      := text[34:(len(text)-66+34)]
  expectedHmac    := text[len(text)-32:len(text)]

  msg := make([]byte, 0)
  msg = append(msg, version...)
  msg = append(msg, options...)
  msg = append(msg, encSalt...)
  msg = append(msg, hmacSalt...)
  msg = append(msg, iv...)
  msg = append(msg, cipherText...)


  hmacKey := pbkdf2.Key(password, hmacSalt, 10000, 32, sha1.New)

  testHmac := hmac.New(sha256.New, hmacKey)
  testHmac.Write(msg)
  testHmacVal := testHmac.Sum(nil)

  verified := bytes.Equal(testHmacVal, expectedHmac)

  if !verified {
    log.Fatal("Password may be incorrect, or the data has been corrupted. (HMAC could not be verified)")
  }

  cipherKey := pbkdf2.Key(password, encSalt, 10000, 32, sha1.New)
  cipherBlock, err := aes.NewCipher(cipherKey)
  if err != nil {
    log.Fatal(err)
  }

  decrypter := cipher.NewCBCDecrypter(cipherBlock, iv)
  decrypter.CryptBlocks(cipherText, cipherText)

  return cipherText
}
