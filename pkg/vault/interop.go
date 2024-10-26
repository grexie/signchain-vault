package vault

import "github.com/grexie/signchain-vault/v2/pkg/storage/interfaces"

type EncryptRequest struct {
	Data []byte `json:"data"`
}

type EncryptResponse struct {
	KeyEncryptingKey interfaces.ID `json:"keyEncryptingKey"`
	EncryptedData []byte `json:"encryptedData"`
}

type DecryptRequest struct {
	KeyEncryptingKey interfaces.ID `json:"keyEncryptingKey"`
	EncryptedData []byte `json:"encryptedData"`
}

type DecryptResponse []byte