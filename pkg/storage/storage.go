package storage

import (
	"fmt"
	"os"
	"strings"

	"github.com/grexie/signchain-vault/v2/pkg/storage/dynamodb"
	"github.com/grexie/signchain-vault/v2/pkg/storage/firebase"
	"github.com/grexie/signchain-vault/v2/pkg/storage/interfaces"
	"github.com/grexie/signchain-vault/v2/pkg/storage/mongo"
	"github.com/grexie/signchain-vault/v2/pkg/storage/redis"
)

func NewStorage(vault interfaces.IVaultService) (interfaces.IStorageBackend, error) {
	backend := strings.TrimSpace(os.Getenv("VAULT_STORAGE_BACKEND"))
	if backend == "" {
		return nil, fmt.Errorf("storage backend not configured, check online documentation for environment variable VAULT_STORAGE_BACKEND")
	}

	switch (backend) {
	case "mongo":
		return mongo.NewMongoStorageBackend(vault)
	case "redis":
		return redis.NewRedisStorageBackend()
	case "dynamodb":
		return dynamodb.NewDynamoDBStorageBackend()
	case "firebase":
		return firebase.NewFirebaseStorageBackend()
	default:
		return nil, fmt.Errorf("invalid storage backend: %s, check online documentation for environment variable VAULT_STORAGE_BACKEND", backend)
	}
}