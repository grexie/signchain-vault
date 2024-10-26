package anonymize

import (
	"encoding/base32"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/bsontype"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Marshaller interface {
	json.Marshaler
	json.Unmarshaler
	bson.ValueMarshaler
	bson.ValueUnmarshaler
	ObjectID() primitive.ObjectID
	String() string
}

type ObjectID primitive.ObjectID

var _ json.Marshaler = &ObjectID{}
var _ json.Unmarshaler = &ObjectID{}
var _ bson.ValueMarshaler = &ObjectID{}
var _ bson.ValueUnmarshaler = &ObjectID{}

func anonymizationKey() []byte {
	if k, ok := os.LookupEnv("VAULT_ANONYMIZATION_KEY"); ok {
		return []byte(k)
	} else {
		return []byte("ee63fc6f6f1e362f6f6a05977034ac9648cd9fde")
	}
}

func (o *ObjectID) UnmarshalJSON(b []byte) error {
	key := []byte(anonymizationKey())
	var id string
	if err := json.Unmarshal(b, &id); err != nil {
		return err
	} else if s, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(id)); err != nil {
		return err
	} else if plaintext, err := decryptRC4(key, []byte(s)); err != nil {
		return err
	} else {
		copy(o[:], plaintext)
		return nil
	}
}

func (o *ObjectID) MarshalJSON() ([]byte, error) {
	key := []byte(anonymizationKey())
	if ciphertext, err := encryptRC4(key, o[:]); err != nil {
		return nil, err
	} else {
		return json.Marshal(strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(ciphertext)))
	}
}

func (o *ObjectID) UnmarshalBSONValue(bsontype bsontype.Type, b []byte) error {
	p := (*primitive.ObjectID)(o)
	return bson.UnmarshalValue(bsontype, b, &p)
}

func (o *ObjectID) MarshalBSONValue() (bsontype.Type, []byte, error) {
	p := (*primitive.ObjectID)(o)
	return bson.MarshalValue(p)
}

func (o *ObjectID) UnmarshalJSONWithPrefix(prefix string, b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	} else {
		s = strings.TrimPrefix(s, fmt.Sprintf("%s-", prefix))
		if b, err := json.Marshal(s); err != nil {
			return err
		} else {
			return o.UnmarshalJSON(b)
		}
	}
}

func (o *ObjectID) MarshalJSONWithPrefix(prefix string) ([]byte, error) {
	var s string
	if b, err := o.MarshalJSON(); err != nil {
		return nil, err
	} else if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	} else {
		return json.Marshal(fmt.Sprintf("%s-%s", prefix, s))
	}
}

func (o ObjectID) ObjectID() primitive.ObjectID {
	return primitive.ObjectID(o)
}

func (o *ObjectID) StringWithPrefix(prefix string) string {
	key := []byte(anonymizationKey())
	if ciphertext, err := encryptRC4(key, o[:]); err != nil {
		return ""
	} else {
		return fmt.Sprintf("%s-%s", prefix, strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(ciphertext)))
	}
}

func ObjectIDFromStringWithPrefix(prefix string, id string) (ObjectID, error) {
	var o ObjectID
	key := []byte(anonymizationKey())
	id = strings.TrimPrefix(id, fmt.Sprintf("%s-", prefix))
	if s, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(id)); err != nil {
		return ObjectID{}, err
	} else if plaintext, err := decryptRC4(key, []byte(s)); err != nil {
		return ObjectID{}, err
	} else {
		copy(o[:], plaintext)
		return o, nil
	}
}
