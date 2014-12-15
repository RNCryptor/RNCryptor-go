RNCryptor-go
============

Go implementation of [RNCryptor](http://rncryptor.github.io).

## Installation

```sh
go get github.com/stevenschobert/RNCryptor-go
```

## Example

```go
package main

import(
  "fmt"
  "github.com/stevenschobert/RNCryptor-go"
)

func main() {
  pass := "test"
  data := []byte("hello world")

  fmt.Printf("source: %v\n", string(data))

  encrypted, _ := rncryptor.Encrypt(pass, data)
  fmt.Printf("encrypted: %v\n", string(encrypted))

  // if you need to send the encrypted data across
  // the wire, you'll probably want to call
  // `base64.StdEncoding.EncodeToString(encrypted)`
  // to base64 the data rather than transmiting raw bytes

  decrypted, _ := rncryptor.Decrypt(pass, encrypted)
  fmt.Printf("decrypted: %v\n", string(decrypted))
}
```

## API

### Encrypt(password string, data []byte) ([]byte, error)

Encrypts `data` using `password`. Automatically handles salting, iv-generation, and hmac signing.
Returns the decrypted data, or an error, if encryption was unsuccessful.

- Password must be at least 1 character long.

```go
encrypted, err := rncryptor.Encrypt("securepassword", []byte("some bytes to encrypt"))
if err != nil {
  log.Printf("error encrypting data: %v", err)
}

// from here, you can encode `encrypted` however you want
// base64.StdEncoding.EncodeToString(encrypted)
```

### Decrypt(password string, data []byte) ([]byte, error)

Decrypts `data` using `password`. Returns un-encrypted data, or an error if decryption is
unsuccessful (e.g. password mismatch).

- Password must match the password used during encryption

```go
// if the encrypted data has been encoded, you'll need to decode it first
// base64.StdEncoding.DecodeString("base64data")

decrypted, err := rncryptor.Decrypt("securepassword", []byte("encrypted bytes here"))
if err != nil {
  log.Printf("error decrypting data: %v", err)
}
```

## Notes

If you'd like to help with any of the items below, send a pull-request!

- Only supports [version
  3](https://github.com/RNCryptor/RNCryptor-Spec/blob/0625abe597e67af4a9a40f460a10bc069b7caf48/RNCryptor-Spec-v3.md)
  of the RNCryptor spec.
- Lacks [consistent-time equality
  checking](https://github.com/RNCryptor/RNCryptor-Spec/blob/0625abe597e67af4a9a40f460a10bc069b7caf48/RNCryptor-Spec-v3.md#consistent-time-equality-checking).


## Contributing

Please read over [GitHub's guide on
contributing](https://guides.github.com/activities/contributing-to-open-source/) if you'd like to
lend a hand!

## Credits

Thanks to [Rob Napier](http://robnapier.net) and the maintainers of the various
[RNCryptor implementations](https://github.com/RNCryptor) for all their hard work!
