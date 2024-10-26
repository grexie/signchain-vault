package vault

import (
	"context"
	"crypto/rand"

	"github.com/grexie/signchain-vault/v2/pkg/api/interop"
	"github.com/grexie/signchain-vault/v2/pkg/storage/interfaces"
)

func (v *vault) CreateDataEncryptingKey(ctx context.Context) (interfaces.DataEncryptingKey, error) {
	var req EncryptRequest
	var res interop.APIResponse[EncryptResponse]
	req.Data = make([]byte, 32)

	if _, err := rand.Read(req.Data); err != nil {
		return nil, err
	} else if err := v.auth.Post("/vault/encrypt", &req, &res); err != nil {
		return nil, err
	} else {
		return v.storage.CreateDataEncryptingKey(ctx, res.Data.KeyEncryptingKey, res.Data.EncryptedData)
	}
}