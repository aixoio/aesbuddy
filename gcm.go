package aesbuddy

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

// `key` is a 16, 24 or 32 byte slice of your encrpytion key
// `data` is slice of the data you are trying to encrpyt
func AesGCMEncrpyt(key []byte, data []byte) ([]byte, error) {
	aes, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, err
	}

	gcm, err := cipher.NewGCM(aes)
	if err != nil {
		return []byte{}, err
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		return []byte{}, err
	}

	cipherbytes := gcm.Seal(nonce, nonce, data, nil)

	return cipherbytes, nil
}

// `key` is a 16, 24 or 32 byte slice of your decrpytion key
// `data` is slice of the data you are trying to decrpyt
func AesGCMDecrpyt(key []byte, data []byte) ([]byte, error) {

	aes, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, err
	}

	gcm, err := cipher.NewGCM(aes)
	if err != nil {
		return []byte{}, err
	}

	nonceSize := gcm.NonceSize()
	nonce, cipherbytes := data[:nonceSize], data[nonceSize:]

	bytes, err := gcm.Open(nil, nonce, cipherbytes, nil)
	if err != nil {
		return []byte{}, err
	}

	return bytes, nil
}
