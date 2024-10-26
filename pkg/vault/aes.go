package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

func encrypt(secretKey []byte, plaintext []byte) ([]byte, error) {
    aes, err := aes.NewCipher([]byte(secretKey))
    if err != nil {
      return nil, err
    }

    gcm, err := cipher.NewGCM(aes)
    if err != nil {
      return nil, err
    }

    nonce := make([]byte, gcm.NonceSize())
    _, err = rand.Read(nonce)
    if err != nil {
      return nil, err
    }

    ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

    return ciphertext, err
}

func decrypt(secretKey []byte, ciphertext []byte) ([]byte, error) {
    aes, err := aes.NewCipher(secretKey)
    if err != nil {
      return nil, err
    }

    gcm, err := cipher.NewGCM(aes)
    if err != nil {
      return nil, err
    }

    nonceSize := gcm.NonceSize()
    nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

    plaintext, err := gcm.Open(nil, []byte(nonce), ciphertext, nil)
    if err != nil {
      return nil, err
    }

    return plaintext, nil
}
