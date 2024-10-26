package anonymize

import "crypto/rc4"

func encryptRC4(key []byte, plaintext []byte) ([]byte, error) {  
	if cipher, err := rc4.NewCipher(key); err != nil {
		return nil, err
	} else {
  	ciphertext := make([]byte, len(plaintext))
   	cipher.XORKeyStream(ciphertext, plaintext)
		return ciphertext, nil
	}
}  

func decryptRC4(key []byte, ciphertext []byte) ([]byte, error) {
  if cipher, err := rc4.NewCipher(key); err != nil {
		return nil, err
	} else { 
		plaintext := make([]byte, len(ciphertext))
   	cipher.XORKeyStream(plaintext, ciphertext)
		return plaintext, nil
	}
}