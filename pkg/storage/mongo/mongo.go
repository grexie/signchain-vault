package mongo

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/grexie/signchain-vault/v2/pkg/storage/interfaces"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type mongoStorageBackend struct {
	db *mongo.Database
	vault interfaces.IVaultService
}

var _ interfaces.IStorageBackend = &mongoStorageBackend{}

func NewMongoStorageBackend(vault interfaces.IVaultService) (interfaces.IStorageBackend, error) {
	b := &mongoStorageBackend{vault: vault}

	if url, err := url.Parse(os.Getenv("VAULT_MONGO_URL")); err != nil {
		return nil, err
	} else if db, err := mongo.Connect(context.Background(), options.Client().ApplyURI(os.Getenv("VAULT_MONGO_URL"))); err != nil {
		return nil, err
	} else {
		b.db = db.Database(strings.TrimPrefix(url.Path, "/"))
	}

	if err := b.EnsureIndex(context.Background(), "wallets", mongo.IndexModel{
		Keys: bson.M{"expires": 1},
		Options: options.Index().SetName("expires").SetExpireAfterSeconds(1),
	}); err != nil {
		return nil, err
	}
	
	if err := b.EnsureIndex(context.Background(), "keys", mongo.IndexModel{
		Keys: bson.M{"expires": 1},
		Options: options.Index().SetName("expires").SetExpireAfterSeconds(1),
	}); err != nil {
		return nil, err
	}

	if err := b.EnsureIndex(context.Background(), "wallets", mongo.IndexModel{
		Keys: bson.M{"address": 1},
		Options: options.Index().SetName("address").SetUnique(true),
	}); err != nil {
		return nil, err
	}

	return b, nil
}

func (b *mongoStorageBackend) EnsureIndex(ctx context.Context, collectionName string, model mongo.IndexModel) error {
	c := b.db.Collection(collectionName)

	idxs := c.Indexes()

	v := model.Options.Name
	if v == nil {
		return fmt.Errorf("must provide a name for index")
	}
	expectedName := *v

	cur, err := idxs.List(ctx)
	if err != nil {
		return fmt.Errorf("unable to list indexes: %s", err)
	}

	found := false
	for cur.Next(ctx) {
		var d bson.M

		if err := cur.Decode(&d); err != nil {
			return fmt.Errorf("unable to decode bson index document: %s", err)
		}

		v := d["name"]
		if v != nil && v.(string) == expectedName {
			found = true
			break
		}
	}

	if found {
		return nil
	}

	_, err = idxs.CreateOne(ctx, model)
	return err
}