package redis

import (
	"fmt"

	"github.com/grexie/signchain-vault/v2/pkg/storage/interfaces"
)

func NewRedisStorageBackend() (interfaces.IStorageBackend, error) {
	return nil, fmt.Errorf("not implemented")
}