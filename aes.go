package aesbuddy

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

func Aes_GCM_Encrpyt(key []byte, data []byte) ([]byte, error) {
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

func Aes_GCM_Decrpyt(key []byte, data []byte) ([]byte, error) {

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
		return []byte{}, nil
	}

	return bytes, nil
}
