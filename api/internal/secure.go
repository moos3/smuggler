// internal/secure

package secure

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
)

// CipherData -- This generates a AES encrypted message and returns it as a string
func CipherData(text string) string {
	//cipher key
	dStr, _ := hex.DecodeString(os.Getenv("CRYPT_KEY"))
	plaintext := []byte(text)

	//*******************************
	/*This step can be removed or modified. I'm using sha512 to increase length of
	key and use part of hashed key as nonce and newKey. You can think of some other way or
	just remove sha512 and use your custom nonce and key as it is. The reason I'm doing this
	is to make nonce dynamic since key is known to both the parties.
	*/
	hasher := sha512.New()
	hasher.Write(dStr)
	out := hex.EncodeToString(hasher.Sum(nil))
	newKey, _ := hex.DecodeString(out[:64])
	nonce, _ := hex.DecodeString(out[64:(64 + 24)])
	//*******************************

	aData, _ := hex.DecodeString(os.Getenv("DECRYPT_KEY"))
	block, err := aes.NewCipher(newKey)
	if err != nil {
		panic(err.Error())
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	cipherText := aesgcm.Seal(nil, nonce, plaintext, aData)
	cT := fmt.Sprintf("%x", cipherText)
	return cT
}

// CheckSum -- generates a checksum fingerprint for a given string and sizes using SHA
func CheckSum(data string, size uint) (string, error) {
	switch size {
	case 256:
		h := sha256.New()
		h.Write([]byte(data))
		bs := h.Sum(nil)
		bytes := string(fmt.Sprintf("%x\n", bs))
		return bytes, nil
	case 512:
		h := sha512.New()
		h.Write([]byte(data))
		bs := h.Sum(nil)
		bytes := string(fmt.Sprintf("%x\n", bs))
		return bytes[:], nil
	default:
		return "", errors.New("unsupported sha size")
	}

}

// DecipherData -- decypts the string and requires the adata decryption string
func DecipherData(adata string, data string) string {
	dStr, _ := hex.DecodeString(os.Getenv("CRYPT_KEY"))

	//*******************************
	hasher := sha512.New()
	hasher.Write(dStr)
	out := hex.EncodeToString(hasher.Sum(nil))
	newKey, _ := hex.DecodeString(out[:64])
	nonce, _ := hex.DecodeString(out[64:(64 + 24)])
	//*******************************

	aData, _ := hex.DecodeString(adata)
	block, err := aes.NewCipher(newKey)
	if err != nil {
		panic(err.Error())
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	cipherText, _ := hex.DecodeString(data)
	output, _ := aesgcm.Open(nil, nonce, cipherText, aData)
	cT := fmt.Sprintf("%x", output)
	return cT
}
