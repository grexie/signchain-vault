package auth

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/log"
)

type Auth interface {
	VaultKeys() VaultKeyCollection

	RequireVaultKey(c *fiber.Ctx) error
	RequireAuthSignature(c *fiber.Ctx) error
	
	NewRequest(method string, url string, o any) (*http.Request, error)
	Get(url string, res any) error
	Post(url string, req any, res any) error
	Put(url string, req any, res any) error
	Delete(url string, req any) error
	Head(url string, res any) error
}

type auth struct {
	vaultKeys VaultKeyCollection
	authSecretKey *AuthSecretKey
}

var _ Auth = &auth{}

type AuthSecretKey string

// minimum length for 256-bit entropy (32 bytes)
const minAuthSecretKeyLength = 32

func calculateEntropy(s AuthSecretKey) float64 {
	freq := make(map[rune]float64)
	length := float64(utf8.RuneCountInString(string(s)))

	for _, char := range s {
		freq[char]++
	}

	entropy := 0.0
	for _, count := range freq {
		p := count / length
		entropy += -p * math.Log2(p)
	}

	return entropy
}

func (k AuthSecretKey) Validate() error {
	if len(k) < minAuthSecretKeyLength {
		return fmt.Errorf("VAULT_AUTH_SECRET_KEY is too short, must be at least %d characters", minAuthSecretKeyLength)
	}

	return nil
}

func (k AuthSecretKey) Verify(now time.Time, data []byte, signature VaultSignature) error {
	if nonce, timestamp, signatureHash, err := signature.Parse(); err != nil {
		return err
	} else if timestamp.Compare(now.Add(-2 * time.Minute)) < 0 {
		return fmt.Errorf("signature expired timestamp: %s current time: %s", timestamp, now)
	} else if timestamp.Compare(now.Add(2 * time.Minute)) > 0 {
		return fmt.Errorf("signature not yet valid timestamp: %s current time: %s", timestamp, now)
	} else {
		var tb [8]byte
		binary.PutVarint(tb[:], timestamp.UnixMicro())

		hash := sha256.New()
		hash.Write(data)
		hash.Write(nonce[:])
		hash.Write(tb[:])
		hash.Write([]byte(k))
		
		if hmac.Equal(hash.Sum(nil), signatureHash) {
			return nil
		} else {
			return fmt.Errorf("invalid signature for data: %s", signature)
		}
	}
}

type VaultSignature string

func (v VaultSignature) Parse() (nonce []byte, timestamp time.Time, hash []byte, err error)  {
	components := strings.Split(string(v), ".")
	var tb []byte

	if len(components) != 3 {
		err = fmt.Errorf("invalid signature: %s", v)
		return
	} else if nonce, err = base32.StdEncoding.DecodeString(strings.ToUpper(components[0])); err != nil {
		return
	} else if tb, err = base32.StdEncoding.DecodeString(strings.ToUpper(components[1])); err != nil {
		return
	} else if hash, err = base32.StdEncoding.DecodeString(strings.ToUpper(components[2])); err != nil {
		return
	} else if t, n := binary.Varint(tb); n != 8 {
		err = fmt.Errorf("invalid timestamp in signature: %s", v)
		return 
	} else {
		timestamp = time.UnixMicro(t)
		return
	}
}

func (s VaultSignature) String() string {
	return string(s)
}

type VaultKey string

func (v VaultKey) Hash() [32]byte {
	return sha256.Sum256([]byte(v))
}

func (v VaultKey) HashString() string {
	hash := v.Hash()
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(hash[:]))
}

func (v VaultKey) String() string {
	return string(v)
}

func (v VaultKey) Verify(now time.Time, data []byte, signature VaultSignature) error {
	if nonce, timestamp, signatureHash, err := signature.Parse(); err != nil {
		return err
	} else if timestamp.Compare(now.Add(-2 * time.Minute)) < 0 {
		return fmt.Errorf("signature expired timestamp: %s current time: %s", timestamp, now)
	} else if timestamp.Compare(now.Add(2 * time.Minute)) > 0 {
		return fmt.Errorf("signature not yet valid timestamp: %s current time: %s", timestamp, now)
	} else {
		var tb [8]byte
		binary.PutVarint(tb[:], timestamp.UnixMicro())

		hash := sha256.New()
		hash.Write(data)
		hash.Write(nonce[:])
		hash.Write(tb[:])
		hash.Write([]byte(v))
		
		if hmac.Equal(hash.Sum(nil), signatureHash) {
			return nil
		} else {
			return fmt.Errorf("invalid signature for data: %s", signature)
		}
	}
} 

func (v VaultKey) Sign(timestamp time.Time, data []byte) (VaultSignature, error) {
	var nonce [32]byte
	var tb [8]byte
	binary.PutVarint(tb[:], timestamp.UnixMicro())

	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	} else {
		hash := sha256.New()
		hash.Write(data)
		hash.Write(nonce[:])
		hash.Write(tb[:])
		hash.Write([]byte(v))
		
		signature := strings.ToLower(base32.StdEncoding.EncodeToString(nonce[:])) + "." + strings.ToLower(base32.StdEncoding.EncodeToString(tb[:])) + "." + strings.ToLower(base32.StdEncoding.EncodeToString(hash.Sum([]byte{})))
		
		return VaultSignature(signature), nil
	}
}

type VaultKeyCollection []VaultKey

func (c VaultKeyCollection) First() (VaultKey, error) {
	if len(c) < 1 {
		return "", fmt.Errorf("could not find a vault key, have you configured VAULT_KEYS environment variable?")
	}
	return c[0], nil
}

func (c VaultKeyCollection) GetKeyMatchingHash(hash string) (VaultKey, error) {
	if b, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(hash)); err != nil {
		return "", err
	} else if len(b) != 32 {
		return "", fmt.Errorf("invalid vault key hash size: %d", len(b))
	} else {
		var h [32]byte
		copy(h[:], b)
		for _, v := range c {
			if v.Hash() == h {
				return v, nil
			}
		}
		return "", fmt.Errorf("vault key for hash not configured: %s", hash)
	}
}

func (a *auth) NewRequest(method string, url string, o any) (*http.Request, error) {
	vaultKeys := a.vaultKeys
	baseUrl := "https://signchain.net"
	if u, ok := os.LookupEnv("API_URL"); ok {
		baseUrl = u
	}
	baseUrl = fmt.Sprintf("%s/api/v1", baseUrl)

	if json, err := json.Marshal(o); err != nil {
		return nil, err
	} else if vaultKey, err := vaultKeys.First(); err != nil {
		return nil, err
	} else if signature, err := vaultKey.Sign(time.Now(), json); err != nil {
		return nil, err
	} else if req, err := http.NewRequest(method, baseUrl + url, bytes.NewReader(json)); err != nil {
		return nil, err
	} else {
		req.Header.Add("X-Vault-Key-Hash", vaultKey.HashString())
		req.Header.Add("X-Vault-Signature", signature.String())
		req.Header.Add("Content-Type", "application/json")
		return req, nil
	}
}

func (a *auth) Get(url string, _res any) error {
	if req, err := a.NewRequest("GET", url, nil); err != nil {
		return err
	} else if res, err := http.DefaultClient.Do(req); err != nil {
		return err
	} else if b, err := io.ReadAll(res.Body); err != nil {
		return err
	} else if err := json.Unmarshal(b, _res); err != nil {
		return err
	} else {
		success := reflect.ValueOf(_res).Elem().FieldByName("Success").Bool()
		if !success {
			if errorValue := reflect.ValueOf(_res).Elem().FieldByName("Error"); errorValue.IsNil() {
				return fiber.NewError(res.StatusCode, "unknown error")
			} else {
				return fiber.NewError(res.StatusCode, errorValue.Elem().String())
			}
		}
		if res.StatusCode < 200 || res.StatusCode >= 400 {
			return fiber.NewError(res.StatusCode, res.Status)
		}
		return nil
	}
}

func (a *auth) Post(url string, req any, _res any) error {
	if req, err := a.NewRequest("POST", url, req); err != nil {
		return err
	} else if res, err := http.DefaultClient.Do(req); err != nil {
		return err
	} else if b, err := io.ReadAll(res.Body); err != nil {
		return err
	} else if err := json.Unmarshal(b, _res); err != nil {
		return err
	} else {
		success := reflect.ValueOf(_res).Elem().FieldByName("Success").Bool()
		if !success {
			if errorValue := reflect.ValueOf(_res).Elem().FieldByName("Error"); errorValue.IsNil() {
				return fiber.NewError(res.StatusCode, "unknown error")
			} else {
				return fiber.NewError(res.StatusCode, errorValue.Elem().String())
			}
		}
		if res.StatusCode < 200 || res.StatusCode >= 400 {
			return fiber.NewError(res.StatusCode, res.Status)
		}
		return nil
	}
}

func (a *auth) Put(url string, req any, _res any) error {
	if req, err := a.NewRequest("PUT", url, req); err != nil {
		return err
	} else if res, err := http.DefaultClient.Do(req); err != nil {
		return err
	} else if b, err := io.ReadAll(res.Body); err != nil {
		return err
	} else if err := json.Unmarshal(b, _res); err != nil {
		return err
	} else {
		success := reflect.ValueOf(_res).Elem().FieldByName("Success").Bool()
		if !success {
			if errorValue := reflect.ValueOf(_res).Elem().FieldByName("Error"); errorValue.IsNil() {
				return fiber.NewError(res.StatusCode, "unknown error")
			} else {
				return fiber.NewError(res.StatusCode, errorValue.Elem().String())
			}
		}
		if res.StatusCode < 200 || res.StatusCode >= 400 {
			return fiber.NewError(res.StatusCode, res.Status)
		}
		return nil
	}
}

func (a *auth) Delete(url string, req any) error {
	if req, err := a.NewRequest("DELETE", url, req); err != nil {
		return err
	} else if res, err := http.DefaultClient.Do(req); err != nil {
		return err
	} else {
		if res.StatusCode < 200 || res.StatusCode >= 400 {
			return fiber.NewError(res.StatusCode, res.Status)
		}
		return nil
	}
}

func (a *auth) Head(url string, _res any) error {
	if req, err := a.NewRequest("HEAD", url, nil); err != nil {
		return err
	} else if res, err := http.DefaultClient.Do(req); err != nil {
		return err
	} else if b, err := io.ReadAll(res.Body); err != nil {
		return err
	} else if err := json.Unmarshal(b, _res); err != nil {
		return err
	} else {
		success := reflect.ValueOf(_res).Elem().FieldByName("Success").Bool()
		if !success {
			if errorValue := reflect.ValueOf(_res).Elem().FieldByName("Error"); errorValue.IsNil() {
				return fiber.NewError(res.StatusCode, "unknown error")
			} else {
				return fiber.NewError(res.StatusCode, errorValue.Elem().String())
			}
		}
		if res.StatusCode < 200 || res.StatusCode >= 400 {
			return fiber.NewError(res.StatusCode, res.Status)
		}
		return nil
	}
}

func (a *auth) RequireVaultKey(c *fiber.Ctx) error {
	vaultKeys := a.vaultKeys

	if len(vaultKeys) == 0 {
		log.Warn("no VAULT_KEY configured, please follow online documentation")
	}

	vaultKeyHash := c.Get("X-Vault-Key-Hash")
	vaultSignature := c.Get("X-Vault-Signature")

	if vaultKeyHash == "" {
		log.Warn("received request with missing header X-Vault-Key-Hash")
		return fmt.Errorf("X-Vault-Key-Hash header not provided")
	} else if vaultSignature == "" {
		log.Warn("received request with missing header X-Vault-Signature")
		return fmt.Errorf("X-Vault-Signature header not provided")
	} else if v, err := vaultKeys.GetKeyMatchingHash(vaultKeyHash); err != nil {
		return err
	} else if err := v.Verify(time.Now(), c.BodyRaw(), VaultSignature(vaultSignature)); err != nil {
			return fmt.Errorf("invalid vault signature: %s for key hash: %s, %v", vaultSignature, vaultKeyHash, err)
	} else {
		return c.Next()
	}
}

func NewAuth() (Auth, error) {
	a := auth{}

	env := strings.TrimSpace(os.Getenv("VAULT_KEY"))
	if env == "" {
		return nil, fmt.Errorf("no VAULT_KEY configured, please follow online documentation")
	}

	authSecretKey := strings.TrimSpace(os.Getenv("VAULT_AUTH_SECRET_KEY"))
	if authSecretKey != "" {
		authSecretKey := AuthSecretKey(authSecretKey)
		if err := authSecretKey.Validate(); err != nil {
			log.Warn(err)
		}
		a.authSecretKey = &authSecretKey
	} else {
		log.Warn("VAULT_AUTH_SECRET_KEY not configured. It is recommended for self-hosted vaults to configure this.")
	}

	vaultKeys := strings.Split(env, ",")
	a.vaultKeys = make(VaultKeyCollection, len(vaultKeys))
	for i, k := range vaultKeys {
		a.vaultKeys[i] = VaultKey(strings.TrimSpace(k))
	}

	return &a, nil
}

func (a *auth) VaultKeys() VaultKeyCollection {
	return a.vaultKeys
}

func (a *auth) RequireAuthSignature(c *fiber.Ctx) error {
	authSignature := strings.TrimSpace(c.Get("X-Vault-Auth-Signature"))

	if authSignature != "" {
		if a.authSecretKey == nil {
			return fmt.Errorf("VAULT_AUTH_SECRET_KEY not configured, X-Vault-Auth-Signature not supported")
		} else if err := a.authSecretKey.Verify(time.Now(), c.BodyRaw(), VaultSignature(authSignature)); err != nil {
			return fmt.Errorf("X-Vault-Auth-Signature: %v", err)
		} else {
			return c.Next()
		}
	} else if a.authSecretKey != nil {
		return fmt.Errorf("VAULT_AUTH_SECRET_KEY configured, required X-Vault-Auth-Signature not provided")
	} else {
		return c.Next()
	}
}