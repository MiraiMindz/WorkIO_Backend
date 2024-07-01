package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/youmark/pkcs8"
	_ "github.com/joho/godotenv/autoload"
)

func LoadPrivateKey(keyName, password string) (*rsa.PrivateKey) {
	privateKeyPEM := os.Getenv(keyName)
	privBlock, _ := pem.Decode([]byte(privateKeyPEM))
	privKey, err := pkcs8.ParsePKCS8PrivateKeyRSA(privBlock.Bytes, []byte(password))
	if err != nil {
		fmt.Println(err.Error())
	}

	return privKey
}

func LoadPublicKey(keyName string) (*rsa.PublicKey) {
	publicKeyPEM := os.Getenv(keyName)
	pubBlock, _ := pem.Decode([]byte(publicKeyPEM))
	pubParseResult, _ := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	pubKey := pubParseResult.(*rsa.PublicKey)
	return pubKey
}

func Encrypt(publicKey *rsa.PublicKey, data []byte) []byte {
	cipherData, err := rsa.EncryptOAEP(sha512.New(), rand.Reader, publicKey, data, nil)
	if err != nil {
		fmt.Println(err.Error())
	}

	return cipherData
}

func Decrypt(privateKey *rsa.PrivateKey, encryptedData []byte) []byte {
	plainData, err := rsa.DecryptOAEP(sha512.New(), rand.Reader, privateKey, encryptedData, nil)
	if err != nil {
		fmt.Println(err.Error())
	}

	return plainData
}

func DecodeBase64(data string) []byte {
	decodedData, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		fmt.Println(err.Error())
	}

	return decodedData
}

func EncodeBase64(data []byte) string {
	encodedData := base64.StdEncoding.EncodeToString(data)

	return encodedData
}
