package vault

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/grexie/signchain-vault/v2/pkg/api/interop"
	"github.com/grexie/signchain-vault/v2/pkg/storage/interfaces"
)

type Wallet interface {
	Account() interfaces.ID
	Address() common.Address
	PublicKey(ctx context.Context) (ecdsa.PublicKey, error)
	PrivateKey(ctx context.Context) (ecdsa.PrivateKey, error)

	interfaces.Wallet
}

type wallet struct {
	vault  *vault
	wallet interfaces.Wallet
}

var _ Wallet = &wallet{}
var _ json.Marshaler = &wallet{}

func (w *wallet) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{
		"id": w.ID(),
		"name": w.Name(),
		"address": w.Address(),
		"created": w.Created(),
		"updated": w.Updated(),
		"expires": w.Expires(),
	})
}

func (w *wallet) ID() interfaces.ID {
	return w.wallet.ID()
}

func (w *wallet) Name() string {
	return w.wallet.Name()
}

func (w *wallet) Account() interfaces.ID {
	return w.wallet.Account()
}

func (w *wallet) Address() common.Address {
	return w.wallet.Address()
}

func (w *wallet) DataEncryptingKey() interfaces.ID {
	return w.wallet.DataEncryptingKey()
}

func (w *wallet) EncryptedPrivateKey() []byte {
	return w.wallet.EncryptedPrivateKey()
}

func (w *wallet) Created() time.Time {
	return w.wallet.Created()
}

func (w *wallet) Updated() time.Time {
	return w.wallet.Updated()
}

func (w *wallet) Expires() *time.Time {
	return w.wallet.Expires()
}

func (w *wallet) PublicKey(ctx context.Context) (ecdsa.PublicKey, error) {
	if privateKey, err := w.PrivateKey(ctx); err != nil {
		return ecdsa.PublicKey{}, err
	} else {
		return privateKey.PublicKey, nil
	}
}

func (w *wallet) PrivateKey(ctx context.Context) (ecdsa.PrivateKey, error) {
	var req DecryptRequest
	var res interop.APIResponse[DecryptResponse]
	if dataEncryptingKey, err := w.vault.storage.GetDataEncryptingKey(ctx, w.wallet.DataEncryptingKey()); err != nil {
		return ecdsa.PrivateKey{}, err
	} else {
		req.KeyEncryptingKey = dataEncryptingKey.KeyEncryptingKey()
		req.EncryptedData = dataEncryptingKey.EncryptedKey()

		if err := w.vault.auth.Post("/vault/decrypt", &req, &res); err != nil {
			return ecdsa.PrivateKey{}, err
		} else if b, err := decrypt(res.Data, w.wallet.EncryptedPrivateKey()); err != nil {
			return ecdsa.PrivateKey{}, err
		} else if privateKey, err := crypto.ToECDSA(b); err != nil {
			return ecdsa.PrivateKey{}, err
		} else {
			return *privateKey, nil
		}
	}
}

type ListWalletsResult interface {
	Count() int64
	Page() []Wallet
}

type listWalletsResult struct {
	Count_ int64 `json:"count"`
	Page_ []*wallet `json:"page"`
}

var _ ListWalletsResult = &listWalletsResult{}

func (r *listWalletsResult) Count() int64 {
	return r.Count_
}

func (r *listWalletsResult) Page() []Wallet {
	out := make([]Wallet, len(r.Page_))
	for i, w := range r.Page_ {
		out[i] = w
	}
	return out
}

func (v *vault) CreateWallet(ctx context.Context, account string, name string) (Wallet, error) {
	if privateKey, err := crypto.GenerateKey(); err != nil {
		return nil, err
	} else {
		privateKeyBytes := crypto.FromECDSA(privateKey)

		var req DecryptRequest
		var res interop.APIResponse[DecryptResponse]
		if dataEncryptingKey, err := v.storage.GetOrCreateRandomKey(ctx, 1000); err != nil {
			return nil, err
		} else {
			req.KeyEncryptingKey = dataEncryptingKey.KeyEncryptingKey()
			req.EncryptedData = dataEncryptingKey.EncryptedKey()

			if err := v.auth.Post("/vault/decrypt", &req, &res); err != nil {
				return nil, err
			} else if b, err := encrypt(res.Data, privateKeyBytes); err != nil {
				return nil, err
			} else if w, err := v.storage.CreateWallet(ctx, account, name, crypto.PubkeyToAddress(privateKey.PublicKey), dataEncryptingKey.ID(), b); err != nil {
				return nil, err
			} else {
				w := wallet{
					vault:  v,
					wallet: w,
				}

				return &w, nil
			}
		}
	}
}

func (v *vault) GetWallet(ctx context.Context, account string, address common.Address) (Wallet, error) {
	if w, err := v.storage.GetWallet(ctx, account, address); err != nil {
		return nil, err
	} else {
		w := wallet{
			vault: v,
			wallet: w,
		}
		return &w, nil
	}
}

func (v *vault) storageWalletsToWallets(in []interfaces.Wallet) []*wallet {
	out := make([]*wallet, len(in))
	for i, w := range in {
		out[i] = &wallet{
			vault: v,
			wallet: w,
		}
	}
	return out
}

func (v *vault) ListWallets(ctx context.Context, account interfaces.ID, offset int64, count int64) (ListWalletsResult, error) {
	if r, err := v.storage.ListWallets(ctx, account, offset, count); err != nil {
		return nil, err
	} else {
		r := listWalletsResult{
			Count_: r.Count(),
			Page_: v.storageWalletsToWallets(r.Page()),
		}
		return &r, nil
	}
}

func (v *vault) UpdateWallet(ctx context.Context, account interfaces.ID, address common.Address, name string) (Wallet, error) {
	if w, err := v.storage.UpdateWallet(ctx, account, address, name); err != nil {
		return nil, err
	} else {
		w := wallet{
			vault: v,
			wallet: w,
		}
		return &w, nil
	}
}

func (v *vault) ExpireWallet(ctx context.Context, account interfaces.ID, address common.Address, ttl time.Duration) (Wallet, error) {
	if w, err := v.storage.ExpireWallet(ctx, account, address, ttl); err != nil {
		return nil, err
	} else {
		w := wallet{
			vault: v,
			wallet: w,
		}
		return &w, nil
	}
}

func (v *vault) UnexpireWallet(ctx context.Context, account interfaces.ID, address common.Address) (Wallet, error) {
	if w, err := v.storage.UnexpireWallet(ctx, account, address); err != nil {
		return nil, err
	} else {
		w := wallet{
			vault: v,
			wallet: w,
		}
		return &w, nil
	}
}
