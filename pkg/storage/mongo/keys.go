package mongo

import (
	"context"
	"time"

	"github.com/grexie/signchain-vault/v2/pkg/storage/interfaces"
	"github.com/grexie/signchain-vault/v2/pkg/storage/mongo/anonymize"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/bsontype"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type DataEncryptingKeyID anonymize.ObjectID

var _ anonymize.Marshaller = &DataEncryptingKeyID{}

func (o DataEncryptingKeyID) MarshalJSON() ([]byte, error) {
	a := (*anonymize.ObjectID)(&o)
	return a.MarshalJSONWithPrefix("dek")
}

func (o *DataEncryptingKeyID) UnmarshalJSON(b []byte) error {
	a := (*anonymize.ObjectID)(o)
	return a.UnmarshalJSONWithPrefix("dek", b)
}

func (o DataEncryptingKeyID) MarshalBSONValue() (bsontype.Type, []byte, error) {
	return (*anonymize.ObjectID)(&o).MarshalBSONValue()
}

func (o *DataEncryptingKeyID) UnmarshalBSONValue(t bsontype.Type, b []byte) error {
	return (*anonymize.ObjectID)(o).UnmarshalBSONValue(t, b)
}

func (o DataEncryptingKeyID) ObjectID() primitive.ObjectID {
	return primitive.ObjectID(o)
}

func (o DataEncryptingKeyID) String() string {
	a := (*anonymize.ObjectID)(&o)
	return a.StringWithPrefix("dek")
}

func DataEncryptingKeyIDFromString(id string) (DataEncryptingKeyID, error) {
	if o, err := anonymize.ObjectIDFromStringWithPrefix("dek", id); err != nil {
		return DataEncryptingKeyID{}, err
	} else {
		return DataEncryptingKeyID(o), nil
	}
}

type dataEncryptingKey struct {
	backend *mongoStorageBackend
	ID_ DataEncryptingKeyID `bson:"_id"`
	KeyEncryptingKey_ interfaces.ID `bson:"keyEncryptingKey"`
	EncryptedKey_ []byte `bson:"encryptedKey"`
	Expires_ *time.Time `bson:"expires,omitempty"`
}

var _ interfaces.DataEncryptingKey = &dataEncryptingKey{}

func (k *dataEncryptingKey) ID() interfaces.ID {
	return interfaces.ID(k.ID_.String())
}

func (k *dataEncryptingKey) KeyEncryptingKey() interfaces.ID {
	return k.KeyEncryptingKey_
}

func (k *dataEncryptingKey) EncryptedKey() []byte {
	return k.EncryptedKey_
}

func (k *dataEncryptingKey) Expires() *time.Time {
	return k.Expires_
}

func (k *dataEncryptingKey) RefCount(ctx context.Context) (int64, error) {
	if count, err := k.backend.db.Collection("wallets").CountDocuments(ctx, bson.M{"dataEncryptingKey": k.ID_}); err != nil {
		return 0, err
	} else {
		return count, nil
	}
}

type listDataEncryptingKeysResult struct {
	Count_ int64
	Page_ []*dataEncryptingKey
}

var _ interfaces.ListDataEncryptingKeysResult = &listDataEncryptingKeysResult{}

func (r *listDataEncryptingKeysResult) Count() int64 {
	return r.Count_
}

func (r *listDataEncryptingKeysResult) Page() []interfaces.DataEncryptingKey {
	out := make([]interfaces.DataEncryptingKey, len(r.Page_))
	for i, k := range r.Page_ {
		out[i] = k
	}
	return out
}

type dataEncryptingKeyRefCount struct {
	ID DataEncryptingKeyID `bson:"_id"`
	Wallets struct{Count int64 `bson:"count"`} `bson:"wallets"`
}

func (m *mongoStorageBackend) GetOrCreateRandomKey(ctx context.Context, maxRefCount int64) (interfaces.DataEncryptingKey, error) {
	var r dataEncryptingKeyRefCount

	pipeline := bson.A{
		bson.M{
			"$lookup": bson.M{
				"from": "wallets",
				"let": bson.M{"dataEncryptingKey": "$_id"},
				"pipeline": bson.A{
					bson.M{"$match": bson.M{"$expr": bson.M{"$eq": bson.A{"$$dataEncryptingKey", "$dataEncryptingKey"}}}},
					bson.M{"$count": "count"},
				},
				"as": "wallets",
			},
		},
		bson.M{"$unwind": "$wallets"},
		bson.M{"$match": bson.M{"$expr": bson.M{"$lt": bson.A{"$wallets.count", maxRefCount}}}},
		bson.M{"$sample": bson.M{"size": 1}},
	}

	if cursor, err := m.db.Collection("keys").Aggregate(ctx, pipeline); err != nil {
		return nil, err
	} else if !cursor.Next(ctx) {
		return m.vault.CreateDataEncryptingKey(ctx)
	} else if err := cursor.Decode(&r); err != nil {
		return nil, err
	} else {
		return m.GetDataEncryptingKey(ctx, r.ID.String());
	}
}

func (m *mongoStorageBackend) CreateDataEncryptingKey(ctx context.Context, keyEncryptingKey interfaces.ID, encryptedKey []byte) (interfaces.DataEncryptingKey, error) {
	k := dataEncryptingKey{
		backend: m,
		ID_: DataEncryptingKeyID(primitive.NewObjectID()),
		KeyEncryptingKey_: keyEncryptingKey,
		EncryptedKey_: encryptedKey,
		Expires_: nil,
	}

	if _, err := m.db.Collection("keys").InsertOne(ctx, &k); err != nil {
		return nil, err
	} else {
		return &k, nil
	}
}

func (m *mongoStorageBackend) GetDataEncryptingKey(ctx context.Context, id interfaces.ID) (interfaces.DataEncryptingKey, error) {
	var k dataEncryptingKey

	if _id, err := DataEncryptingKeyIDFromString(id); err != nil {
		return nil, err
	} else if err := m.db.Collection("keys").FindOne(ctx, bson.M{"_id": _id}).Decode(&k); err != nil {
		return nil, err
	} else {
		k.backend = m
		return &k, nil
	}
}

func (m *mongoStorageBackend) ListDataEncryptingKeys(ctx context.Context, offset int64, count int64) (interfaces.ListDataEncryptingKeysResult, error) {
	var r listDataEncryptingKeysResult

	if count, err := m.db.Collection("keys").CountDocuments(ctx, bson.M{}); err != nil {
		return nil, err
	} else if cursor, err := m.db.Collection("keys").Find(ctx, bson.M{}, options.Find().SetSkip(offset).SetLimit(count)); err != nil {
		return nil, err
	} else if err := cursor.All(ctx, &r.Page_); err != nil {
		return nil, err
	} else {
		r.Count_ = count
		for _, k := range r.Page_ {
			k.backend = m
		}
		return &r, nil
	}
}

func (m *mongoStorageBackend) ExpireDataEncryptingKey(ctx context.Context, id interfaces.ID, ttl time.Duration) (interfaces.DataEncryptingKey, error) {
	if _id, err := DataEncryptingKeyIDFromString(id); err != nil {
		return nil, err
	} else if _, err := m.db.Collection("keys").UpdateByID(ctx, _id, bson.M{"$set": bson.M{"expires": time.Now().Add(ttl)}}); err != nil {
		return nil, err
	} else {
		return m.GetDataEncryptingKey(ctx, id)
	}
}

func (m *mongoStorageBackend) UnexpireDataEncryptingKey(ctx context.Context, id interfaces.ID) (interfaces.DataEncryptingKey, error) {
	if _id, err := DataEncryptingKeyIDFromString(id); err != nil {
		return nil, err
	} else if _, err := m.db.Collection("keys").UpdateByID(ctx, _id, bson.M{"$unset": bson.M{"expires": 1}}); err != nil {
		return nil, err
	} else {
		return m.GetDataEncryptingKey(ctx, id)
	}
}