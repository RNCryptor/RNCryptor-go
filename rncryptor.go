package rncryptor

import(
  "bytes"
  "errors"
  "crypto/sha1"
  "crypto/sha256"
  "crypto/hmac"
  "crypto/aes"
  "crypto/cipher"
  "golang.org/x/crypto/pbkdf2"
)

func Decrypt(password string, data []byte) ([]byte, error) {
  version         := data[:1]
  options         := data[1:2]
  encSalt         := data[2:10]
  hmacSalt        := data[10:18]
  iv              := data[18:34]
  cipherText      := data[34:(len(data)-66+34)]
  expectedHmac    := data[len(data)-32:len(data)]

  msg := make([]byte, 0)
  msg = append(msg, version...)
  msg = append(msg, options...)
  msg = append(msg, encSalt...)
  msg = append(msg, hmacSalt...)
  msg = append(msg, iv...)
  msg = append(msg, cipherText...)

  hmacKey := pbkdf2.Key([]byte(password), hmacSalt, 10000, 32, sha1.New)
  testHmac := hmac.New(sha256.New, hmacKey)
  testHmac.Write(msg)
  testHmacVal := testHmac.Sum(nil)

  verified := bytes.Equal(testHmacVal, expectedHmac)

  if !verified {
    return nil, errors.New("Password may be incorrect, or the data has been corrupted. (HMAC could not be verified)")
  }

  cipherKey := pbkdf2.Key([]byte(password), encSalt, 10000, 32, sha1.New)
  cipherBlock, err := aes.NewCipher(cipherKey)
  if err != nil {
    return nil, err
  }

  decrypted := make([]byte, len(cipherText))
  copy(decrypted, cipherText)
  decrypter := cipher.NewCBCDecrypter(cipherBlock, iv)
  decrypter.CryptBlocks(decrypted, decrypted)

  length := len(decrypted)
  unpadding := int(decrypted[length-1])

  return decrypted[:(length - unpadding)], nil
}
