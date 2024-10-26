package interfaces

import (
	"context"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

type ID = string

type IVaultService interface {
	CreateDataEncryptingKey(ctx context.Context) (DataEncryptingKey, error)
}

type IStorageBackend interface {
	CreateDataEncryptingKey(ctx context.Context, keyEncryptingKey ID, encryptedKey []byte) (DataEncryptingKey, error)
	GetDataEncryptingKey(ctx context.Context, id ID) (DataEncryptingKey, error)
	ListDataEncryptingKeys(ctx context.Context, offset int64, count int64) (ListDataEncryptingKeysResult, error)
	ExpireDataEncryptingKey(ctx context.Context, id ID, ttl time.Duration) (DataEncryptingKey, error)
	UnexpireDataEncryptingKey(ctx context.Context, id ID) (DataEncryptingKey, error)
	GetOrCreateRandomKey(ctx context.Context, maxRefCount int64) (DataEncryptingKey, error)

	CreateWallet(ctx context.Context, account ID, name string, address common.Address, dataEncryptingKey ID, encryptedPrivateKey []byte) (Wallet, error)
	GetWallet(ctx context.Context, account ID, address common.Address) (Wallet, error)
	ListWallets(ctx context.Context, account ID, offset int64, count int64) (ListWalletsResult, error)
	UpdateWallet(ctx context.Context, account ID, address common.Address, name string) (Wallet, error)
	ExpireWallet(ctx context.Context, account ID, address common.Address, ttl time.Duration) (Wallet, error)
	UnexpireWallet(ctx context.Context, account ID, address common.Address) (Wallet, error)
}

type ListDataEncryptingKeysResult interface {
	Count() int64
	Page() []DataEncryptingKey
}

type ListWalletsResult interface {
	Count() int64
	Page() []Wallet
}

type DataEncryptingKey interface {
	ID() ID
	KeyEncryptingKey() ID
	EncryptedKey() []byte
	Expires() *time.Time
	RefCount(ctx context.Context) (int64, error)
}

type Wallet interface {
	ID() ID
	Account() ID
	Name() string
	Address() common.Address
	DataEncryptingKey() ID
	EncryptedPrivateKey() []byte
	Created() time.Time
	Updated() time.Time
	Expires() *time.Time
}