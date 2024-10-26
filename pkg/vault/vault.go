package vault

import (
	"context"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/grexie/signchain-vault/v2/pkg/auth"
	"github.com/grexie/signchain-vault/v2/pkg/storage/interfaces"
)

type Vault interface {
	SetStorageBackend(storage interfaces.IStorageBackend) error
	interfaces.IVaultService

	CreateWallet(ctx context.Context, account interfaces.ID, name string) (Wallet, error)
	GetWallet(ctx context.Context, account interfaces.ID, address common.Address) (Wallet, error)
	ListWallets(ctx context.Context, account interfaces.ID, offset int64, count int64) (ListWalletsResult, error)
	UpdateWallet(ctx context.Context, account interfaces.ID, address common.Address, name string) (Wallet, error)
	ExpireWallet(ctx context.Context, account interfaces.ID, address common.Address, ttl time.Duration) (Wallet, error)
	UnexpireWallet(ctx context.Context, account interfaces.ID, address common.Address) (Wallet, error)
}

type vault struct {
	auth auth.Auth
	storage interfaces.IStorageBackend
}

var _ Vault = &vault{}

func NewVault(auth auth.Auth) (Vault, error) {
	v := vault{auth: auth}

	return &v, nil
}

func (v *vault) SetStorageBackend(storage interfaces.IStorageBackend) error {
	if v.storage != nil {
		return fmt.Errorf("storage backend already set")
	}
	v.storage = storage
	return nil
}


