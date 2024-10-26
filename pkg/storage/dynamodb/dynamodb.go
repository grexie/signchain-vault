package dynamodb

import (
	"fmt"

	"github.com/grexie/signchain-vault/v2/pkg/storage/interfaces"
)

func NewDynamoDBStorageBackend() (interfaces.IStorageBackend, error) {
	return nil, fmt.Errorf("not implemented")
}