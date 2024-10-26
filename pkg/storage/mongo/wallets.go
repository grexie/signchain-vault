package mongo

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/gofiber/fiber/v2"
	"github.com/grexie/signchain-vault/v2/pkg/storage/interfaces"
	"github.com/grexie/signchain-vault/v2/pkg/storage/mongo/anonymize"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/bsontype"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type WalletID anonymize.ObjectID

var _ anonymize.Marshaller = &WalletID{}

func (o WalletID) MarshalJSON() ([]byte, error) {
	a := (*anonymize.ObjectID)(&o)
	return a.MarshalJSONWithPrefix("wlt")
}

func (o *WalletID) UnmarshalJSON(b []byte) error {
	a := (*anonymize.ObjectID)(o)
	return a.UnmarshalJSONWithPrefix("wlt", b)
}

func (o WalletID) MarshalBSONValue() (bsontype.Type, []byte, error) {
	return (*anonymize.ObjectID)(&o).MarshalBSONValue()
}

func (o *WalletID) UnmarshalBSONValue(t bsontype.Type, b []byte) error {
	return (*anonymize.ObjectID)(o).UnmarshalBSONValue(t, b)
}

func (o WalletID) ObjectID() primitive.ObjectID {
	return primitive.ObjectID(o)
}

func (o WalletID) String() string {
	a := (*anonymize.ObjectID)(&o)
	return a.StringWithPrefix("wlt")
}

type wallet struct {
	ID_ WalletID `bson:"_id"`
	Account_ interfaces.ID `bson:"account"`
	Name_ string `bson:"name"`
	Address_ common.Address `bson:"address"`
	DataEncryptingKey_ DataEncryptingKeyID `bson:"dataEncryptingKey"`
	EncryptedPrivateKey_ []byte `bson:"encryptedPrivateKey"`
	Created_ time.Time `bson:"created"`
	Updated_ time.Time `bson:"updated"`
	Expires_ *time.Time `bson:"expires,omitempty"`
}

var _ interfaces.Wallet = &wallet{}

func (w *wallet) ID() interfaces.ID {
	return w.ID_.String()
}

func (w *wallet) Name() string {
	return w.Name_
}

func (w *wallet) Account() interfaces.ID {
	return w.Account_
}

func (w *wallet) Address() common.Address {
	return w.Address_
}

func (w *wallet) DataEncryptingKey() interfaces.ID {
	return w.DataEncryptingKey_.String()
}

func (w *wallet) EncryptedPrivateKey() []byte {
	return w.EncryptedPrivateKey_
}

func (w *wallet) Created() time.Time {
	return w.Created_
}

func (w *wallet) Updated() time.Time {
	return w.Updated_
}

func (w *wallet) Expires() *time.Time {
	return w.Expires_
}

type listWalletsResult struct {
	Count_ int64
	Page_ []*wallet
}

var _ interfaces.ListWalletsResult = &listWalletsResult{}

func (r *listWalletsResult) Count() int64 {
	return r.Count_
}

func (r *listWalletsResult) Page() []interfaces.Wallet {
	out := make([]interfaces.Wallet, len(r.Page_))
	for i, w := range r.Page_ {
		out[i] = w
	}
	return out
}

func WalletIDFromString(id string) (WalletID, error) {
	if o, err := anonymize.ObjectIDFromStringWithPrefix("wlt", id); err != nil {
		return WalletID{}, err
	} else {
		return WalletID(o), nil
	}
}

func (m *mongoStorageBackend) CreateWallet(ctx context.Context, account interfaces.ID, name string, address common.Address, dataEncryptingKey interfaces.ID, encryptedPrivateKey []byte) (interfaces.Wallet, error) {
	now := time.Now()

	if _dataEncryptingKey, err := DataEncryptingKeyIDFromString(dataEncryptingKey); err != nil {
		return nil, err
	} else {
		w := wallet{
			ID_: WalletID(primitive.NewObjectID()),
			Account_: account,
			Name_: name,
			Address_: address,
			DataEncryptingKey_: _dataEncryptingKey,
			EncryptedPrivateKey_: encryptedPrivateKey,
			Created_: now,
			Updated_: now,
			Expires_: nil,
		}

		if _, err := m.db.Collection("wallets").InsertOne(ctx, &w); err != nil {
			return nil, err
		} else {
			return &w, nil
		}
	}
}

func (m *mongoStorageBackend) GetWallet(ctx context.Context, account interfaces.ID, address common.Address) (interfaces.Wallet, error) {
	var w wallet

	if err := m.db.Collection("wallets").FindOne(ctx, bson.M{"account": account, "address": address}).Decode(&w); err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, fiber.NewError(fiber.StatusNotFound, fmt.Sprintf("wallet %s not found for account %s", address, account))
		}
		return nil, err
	} else {
		return &w, nil
	}
}

func (m *mongoStorageBackend) ListWallets(ctx context.Context, account interfaces.ID, offset int64, count int64) (interfaces.ListWalletsResult, error) {
	var r listWalletsResult

	filter := bson.M{}

	filter["account"] = account

	if count, err := m.db.Collection("wallets").CountDocuments(ctx, filter); err != nil {
		return nil, err
	} else if cursor, err := m.db.Collection("wallets").Find(ctx, filter, options.Find().SetSkip(offset).SetLimit(count)); err != nil {
		return nil, err
	} else if err := cursor.All(ctx, &r.Page_); err != nil {
		return nil, err
	} else {
		r.Count_ = count
		return &r, nil
	}
}

func (m *mongoStorageBackend) UpdateWallet(ctx context.Context, account interfaces.ID, address common.Address, name string) (interfaces.Wallet, error) {
	if _, err := m.db.Collection("wallets").UpdateOne(ctx, bson.M{"account": account, "address": address}, bson.M{"$set": bson.M{"updated": time.Now(), "name": name}}); err != nil {
		return nil, err
	} else {
		return m.GetWallet(ctx, account, address)
	}
}

func (m *mongoStorageBackend) ExpireWallet(ctx context.Context, account interfaces.ID, address common.Address, ttl time.Duration) (interfaces.Wallet, error) {
	if _, err := m.db.Collection("wallets").UpdateOne(ctx, bson.M{"account": account, "address": address}, bson.M{"$set": bson.M{"updated": time.Now(), "expires": time.Now().Add(ttl)}}); err != nil {
		return nil, err
	} else {
		return m.GetWallet(ctx, account, address)
	}
}

func (m *mongoStorageBackend) UnexpireWallet(ctx context.Context, account interfaces.ID, address common.Address) (interfaces.Wallet, error) {
	if _, err := m.db.Collection("wallets").UpdateOne(ctx, bson.M{"account": account, "address": address}, bson.M{"$set": bson.M{"updated": time.Now()}, "$unset": bson.M{"expires": 1}}); err != nil {
		return nil, err
	} else {
		return m.GetWallet(ctx, account, address)
	}
}
