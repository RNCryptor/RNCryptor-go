package rncryptor

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

var (
	passwordCases = []struct{ title, password, plain, enc, encSalt, hmacSalt, iv string }{
		{"All fields empty or zero (with one-byte password)", "a", "", "03010000000000000000000000000000000000000000000000000000000000000000b3039be31cd7ece5e754f5c8da17003666313ae8a89ddcf8e3cb41fdc130b2329dbe07d6f4d32c34e050c8bd7e933b12", "0000000000000000", "0000000000000000", "00000000000000000000000000000000"},
		{"One byte", "thepassword", "01", "03010001020304050607010203040506070802030405060708090a0b0c0d0e0f0001a1f8730e0bf480eb7b70f690abf21e029514164ad3c474a51b30c7eaa1ca545b7de3de5b010acbad0a9a13857df696a8", "0001020304050607", "0102030405060708", "02030405060708090a0b0c0d0e0f0001"},
		{"Exactly one block", "thepassword", "0123456789abcdef", "030101020304050607000203040506070801030405060708090a0b0c0d0e0f0001020e437fe809309c03fd53a475131e9a1978b8eaef576f60adb8ce2320849ba32d742900438ba897d22210c76c35c849df", "0102030405060700", "0203040506070801", "030405060708090a0b0c0d0e0f000102"},
		{"More than one block", "thepassword", "0123456789abcdef01234567", "0301020304050607000103040506070801020405060708090a0b0c0d0e0f00010203e01bbda5df2ca8adace38f6c588d291e03f951b78d3417bc2816581dc6b767f1a2e57597512b18e1638f21235fa5928c", "0203040506070001", "0304050607080102", "0405060708090a0b0c0d0e0f00010203"},
		{"Multibyte password", "中文密码", "23456789abcdef0123456701", "03010304050607000102040506070801020305060708090a0b0c0d0e0f00010203048a9e08bdec1c4bfe13e81fb85f009ab3ddb91387e809c4ad86d9e8a6014557716657bd317d4bb6a7644615b3de402341", "0304050607000102", "0405060708010203", "05060708090a0b0c0d0e0f0001020304"},
		{"Longer text and password", "It was the best of times, it was the worst of times; it was the age of wisdom, it was the age of foolishness;", "697420776173207468652065706f6368206f662062656c6965662c20697420776173207468652065706f6368206f6620696e63726564756c6974793b206974207761732074686520736561736f6e206f66204c696768742c206974207761732074686520736561736f6e206f66204461726b6e6573733b206974207761732074686520737072696e67206f6620686f70652c20697420776173207468652077696e746572206f6620646573706169723b207765206861642065766572797468696e67206265666f72652075732c20776520686164206e6f7468696e67206265666f72652075733b207765207765726520616c6c20676f696e67206469726563746c7920746f2048656176656e2c207765207765726520616c6c20676f696e6720746865206f74686572207761792e0a0a", "030104050607000102030506070801020304060708090a0b0c0d0e0f000102030405d564c7a99da921a6e7c4078a82641d95479551283167a2c81f31ab80c9d7d8beb770111decd3e3d29bbdf7ebbfc5f10ac87e7e55bfb5a7f487bcd39835705e83b9c049c6d6952be011f8ddb1a14fc0c925738de017e62b1d621ccdb75f2937d0a1a70e44d843b9c61037dee2998b2bbd740b910232eea71961168838f6995b9964173b34c0bcd311a2c87e271630928bae301a8f4703ac2ae4699f3c285abf1c55ac324b073a958ae52ee8c3bd68f919c09eb1cd28142a1996a9e6cbff5f4f4e1dba07d29ff66860db9895a48233140ca249419d63046448db1b0f4252a6e4edb947fd0071d1e52bc15600622fa548a6773963618150797a8a80e592446df5926d0bfd32b544b796f3359567394f77e7b171b2f9bc5f2caf7a0fac0da7d04d6a86744d6e06d02fbe15d0f580a1d5bd16ad91348003611358dcb4ac9990955f6cbbbfb185941d4b4b71ce7f9ba6efc1270b7808838b6c7b7ef17e8db919b34fac", "0405060700010203", "0506070801020304", "060708090a0b0c0d0e0f000102030405"},
	}

	keyCases = []struct{ title, encKey, hmacKey, iv, plaintext, ciphertext string }{
		{"All fields empty or zero", "00000000000000000000000000000000", "00000000000000000000000000000000", "00000000000000000000000000000000", "", "03000000 00000000 00000000 00000000 00000143 db63ee66 b0cdff9f 69917680 151e0e67 e6f5aea8 30ced4af ef779fe7 e5b3767e b06ea81a 0bb8a7a0 bf62c6b0 0405"},
		{"One byte", "000102030405060708090a0b0c0d0e0f", "0102030405060708090a0b0c0d0e0f00", "02030405060708090a0b0c0d0e0f0001", "01", "03000203 04050607 08090a0b 0c0d0e0f 000198dc 7e36e7cc cb0cb7e8 2b048c46 0825ecd5 4ad9b093 3b236b74 8a1ce455 ee1ec4e9 3043f60b e2ed50dc cfb3c4b2 383c"},
		{"Exactly one block", "0102030405060708090a0b0c0d0e0f00", "02030405060708090a0b0c0d0e0f0001", "030405060708090a0b0c0d0e0f000102", "000102030405060708090a0b0c0d0e0f", "03000304 05060708 090a0b0c 0d0e0f00 01029228 f6538960 defc04a2 be30eee6 665ea738 f6c2f3fa 2b73c2ed bbe3a0d5 7f59d197 45313f9e a7ede5bb 6b1bd56f 2ff331dd d22f25dc 99bc11f3 d7ebbf49 14bc"},
		{"More than one block", "02030405060708090a0b0c0d0e0f0001", "030405060708090a0b0c0d0e0f000102", "0405060708090a0b0c0d0e0f00010203", "000102030405060708090a0b0c0d0e0f 000102030405060708", "03000405 06070809 0a0b0c0d 0e0f0001 0203a7c3 b4598b47 45fb62fb 266a54ee c7dcddc9 73d5ecb8 93586198 5407d656 2314d01f d9cddf52 859611d6 e917b6e2 40f82aa5 a508ddd8 8960df8b ceea3aeb e9de"},
	}
)

func TestDecrypt(t *testing.T) {
	for _, c := range passwordCases {
		enc, encErr := hex.DecodeString(c.enc)
		if encErr != nil {
			t.Errorf("Error decoding hex: %v, %v", c.enc, encErr)
		}
		plain, plainErr := hex.DecodeString(c.plain)
		if plainErr != nil {
			t.Errorf("Error decoding hex: %v, %v", c.plain, plainErr)
		}
		dec, decErr := Decrypt(c.password, enc)
		if decErr != nil {
			t.Errorf("Error decrypting: %v, %v", enc, decErr)
		}

		if !bytes.Equal(dec, plain) {
			t.Errorf("FAILED (%v) -> expected %v, got %v", c.title, plain, dec)
		}
	}
}

func TestEncrypt(t *testing.T) {
	for _, c := range passwordCases {
		enc, encErr := hex.DecodeString(c.enc)
		if encErr != nil {
			t.Errorf("Error decoding hex: %v, %v", c.enc, encErr)
		}
		plain, plainErr := hex.DecodeString(c.plain)
		if plainErr != nil {
			t.Errorf("Error decoding hex: %v, %v", c.plain, plainErr)
		}
		encSalt, encSaltErr := hex.DecodeString(c.encSalt)
		if encSaltErr != nil {
			t.Errorf("Error decoding hex: %v, %v", c.encSalt, encSaltErr)
		}
		hmacSalt, hmacSaltErr := hex.DecodeString(c.hmacSalt)
		if hmacSaltErr != nil {
			t.Errorf("Error decoding hex: %v, %v", c.hmacSalt, hmacSaltErr)
		}
		iv, ivErr := hex.DecodeString(c.iv)
		if ivErr != nil {
			t.Errorf("Error decoding hex: %v, %v", c.iv, ivErr)
		}

		testEnc, testEncError := EncryptWithOptions(c.password, plain, encSalt, hmacSalt, iv)
		if testEncError != nil {
			t.Errorf("Error encrypting: %v, %v", testEnc, testEncError)
		}

		if !bytes.Equal(testEnc, enc) {
			t.Errorf("FAILED (%v) -> expected %v, got %v", c.title, enc, testEnc)
		}
	}
}

func decodeHexOrError(s string, t *testing.T) []byte {
	result, err := hex.DecodeString(strings.Replace(s, " ", "", -1))
	if err != nil {
		t.Errorf("Error decoding hex: %v, %v", s, err)
	}
	return result
}

func TestRand(t *testing.T) {
	rand1, err1 := RandBytes(8)
	rand2, err2 := RandBytes(8)
	if err1 != nil {
		t.Error(err1)
	}
	if err2 != nil {
		t.Error(err2)
	}

	if bytes.Equal(rand1, rand2) {
		t.Errorf("RandBytes generated the same bytes -> %v -- %v", rand1, rand2)
	}
}

func TestEncryptWithKey(t *testing.T) {
	for _, c := range keyCases {

		encKey := decodeHexOrError(c.encKey, t)
		hmacKey := decodeHexOrError(c.hmacKey, t)
		iv := decodeHexOrError(c.iv, t)
		ciphertext := decodeHexOrError(c.ciphertext, t)
		plaintext := decodeHexOrError(c.plaintext, t)

		result, err := EncryptWithKeyAndIv(encKey, hmacKey, iv, plaintext)
		if err != nil {
			t.Errorf("Error encrypting: %v, %v", result, err)
		}

		if !bytes.Equal(result, ciphertext) {
			t.Errorf("FAILED (%v) -> expected %v, got %v", c.title, ciphertext, result)
		}
	}
}

func TestDecryptWithKey(t *testing.T) {
	for _, c := range keyCases {

		encKey := decodeHexOrError(c.encKey, t)
		hmacKey := decodeHexOrError(c.hmacKey, t)
		ciphertext := decodeHexOrError(c.ciphertext, t)
		plaintext := decodeHexOrError(c.plaintext, t)

		result, err := DecryptWithKey(encKey, hmacKey, ciphertext)
		if err != nil {
			t.Errorf("Error encrypting: %v, %v", result, err)
		}

		if !bytes.Equal(result, plaintext) {
			t.Errorf("FAILED (%v) -> expected %v, got %v", c.title, plaintext, result)
		}
	}
}

func TestEncryptDecrypt(t *testing.T) {
	const password = "secretsquirrel"

	plaintext := []byte("Hello, World!")

	ciphertext, err := Encrypt(password, plaintext)
	if err != nil {
		t.Errorf("Error encrypting: %v", err)
	}

	result, err := Decrypt(password, ciphertext)
	if err != nil {
		t.Errorf("Error decrypting: %v", err)
	}

	if !bytes.Equal(result, plaintext) {
		t.Errorf("FAILED -> expected %x, got %x", plaintext, result)
	}
}

func TestEncryptDecryptWithKey(t *testing.T) {
	encKey, err := RandBytes(32)
	if err != nil {
		t.Errorf("Error generating random number: %v", err)
	}

	hmacKey, err := RandBytes(32)
	if err != nil {
		t.Errorf("Error generating random number: %v", err)
	}

	plaintext := []byte("Hello, World!")

	ciphertext, err := EncryptWithKey(encKey, hmacKey, plaintext)
	if err != nil {
		t.Errorf("Error encrypting: %v", err)
	}

	result, err := DecryptWithKey(encKey, hmacKey, ciphertext)
	if err != nil {
		t.Errorf("Error decrypting: %v", err)
	}

	if !bytes.Equal(result, plaintext) {
		t.Errorf("FAILED -> expected %x, got %x", plaintext, result)
	}
}
