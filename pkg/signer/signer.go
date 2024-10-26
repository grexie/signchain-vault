package signer

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"reflect"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/grexie/signchain-vault/v2/pkg/storage/interfaces"
	"github.com/grexie/signchain-vault/v2/pkg/vault"
	lru "github.com/hashicorp/golang-lru/v2"
)

type SignResult []any

type Signature interface {
	R() string
	S() string
	V() byte
	Nonce() string
}

type signature struct {
	Nonce_ string `json:"nonce"`
	R_ string `json:"r"`
	S_ string `json:"s"`
	V_ byte `json:"v"`
}

var _ Signature = &signature{}

type Signer interface {
	Sign(ctx context.Context, account interfaces.ID, sender common.Address, uniq string, signer common.Address, abi map[string]any, args []any) (SignResult, error)
}

type signer struct {
	vault vault.Vault
	cache *lru.Cache[cacheKey, ecdsa.PrivateKey]
}

var _ Signer = &signer{}

type cacheKey struct {
	Account string
	Signer common.Address
}

func NewSigner(vault vault.Vault) (Signer, error) {
	s := signer{vault: vault}
	
	if c, err := lru.New[cacheKey, ecdsa.PrivateKey](10 * 1024); err != nil {
		return nil, err
	} else {
		s.cache = c
	}

	return &s, nil
}

func packConvert(arg *abi.Type, param any) (any, error) {
	t := arg.GetType()
	if t.ConvertibleTo(reflect.TypeOf(&big.Int{})) {
		if s, ok := param.(string); ok {
			if strings.HasPrefix(s, "0x") {
				out, _ := new(big.Int).SetString(s[2:], 16)
				return out, nil
			} else {
				out, _ := new(big.Int).SetString(s, 10)
				return out, nil
			}
		} else if i, ok := param.(float64); ok {
			return new(big.Int).SetInt64(int64(i)), nil
		} else {
			return param, nil
		}
	} else if t.Kind() == reflect.Struct {
		p := param.(map[string]any)
		args := arg.TupleElems
		out := reflect.New(t).Elem()
		for i, a := range args {
			if v, err := packConvert(a, p[arg.TupleRawNames[i]]); err != nil {
				return nil, err
			} else {
				out.FieldByIndex([]int{i}).Set(reflect.ValueOf(v))
			}
		}
		return out.Interface(), nil
	} else if t.Kind() == reflect.Array {
		src := common.Hex2Bytes(param.(string)[2:])
		dst := reflect.New(t).Elem()
		reflect.Copy(dst, reflect.ValueOf(src))
		return dst.Interface(), nil
	} else if t.Kind() == reflect.Slice {
		return common.Hex2Bytes(param.(string)[2:]), nil
	} else {
		return param, nil
	}
}

func (s *signer) Sign(ctx context.Context, account interfaces.ID, sender common.Address, _uniq string, _signer common.Address, _abi map[string]any, _args []any) (SignResult, error) {
	if b, err := json.Marshal(_abi); err != nil {
		return nil, err
	} else if a, err := abi.JSON(bytes.NewReader([]byte("[" + string(b) + "]"))); err != nil {
		return nil, err
	} else {
		m := a.Methods[_abi["name"].(string)]
		bytes4, _ := abi.NewType("bytes4", "", nil)
		args := abi.Arguments{
			{ Type: bytes4 },
		}
		var id [4]byte
		copy(id[:], m.ID)
		p := []any{id}
		for i, arg := range m.Inputs {
			if i == len(m.Inputs) - 1 {
				break
			} else if param, err := packConvert(&arg.Type, _args[i]); err != nil {
				return nil, err
			} else {
				args = append(args, arg)
				p = append(p, param)
			}
		}

		if encodedParams, err := args.Pack(p...); err != nil {
			return nil, err
		} else {
			bytes32, _ := abi.NewType("bytes32", "", nil)
			address, _ := abi.NewType("address", "", nil)
			bytesTy, _ := abi.NewType("bytes", "", nil)

			args = abi.Arguments{
				{ Type: bytes32 },
				{ Type: bytes32 },
				{ Type: address },
				{ Type: bytesTy },
			}

			var nonce [32]byte
			rand.Read(nonce[:])

			var uniq [32]byte
			var signer common.Address

			copy(uniq[:], common.Hex2BytesFixed(_uniq, 32))
			signer = _signer
			
			buffer, err := args.Pack(uniq, nonce, sender, encodedParams)
			if err != nil {
				return nil, err
			}
			
			hash := crypto.Keccak256(buffer)
			
			var privateKey ecdsa.PrivateKey

			if pk, ok := s.cache.Get(cacheKey{Account: account, Signer: signer}); ok {
				privateKey = pk
			} else {
				wallet, err := s.vault.GetWallet(ctx, account, signer)
				if err != nil {
					return nil, err
				}

				if wallet.Address() != signer {
					return nil, fmt.Errorf("invalid signer: %s", signer)
				}

				pk, err := wallet.PrivateKey(ctx)
				if err != nil {
					return nil, err
				}

				privateKey = pk
				s.cache.Add(cacheKey{Account: account, Signer: signer}, pk)
			}

			signatureBytes, err := crypto.Sign(hash, &privateKey)
			if err != nil {
				return nil, err
			}

			var v byte
			var r [32]byte
			var s [32]byte

			v = signatureBytes[64] + 27
			copy(r[:], signatureBytes[:32])
			copy(s[:], signatureBytes[32:64])

			sig := signature{
				Nonce_: "0x" + common.Bytes2Hex(nonce[:]),
				R_: "0x" + common.Bytes2Hex(r[:]),
				S_: "0x" + common.Bytes2Hex(s[:]),
				V_: v,
			}

			out := SignResult{}

			for i := range _args {
				out = append(out, _args[i])
			}
			out = append(out, sig)

			return out, nil
		}
	}
}

func (s *signature) R() string {
	return s.R_
}

func (s *signature) S() string {
	return s.S_
}

func (s *signature) V() byte {
	return s.V_
}

func (s *signature) Nonce() string {
	return s.Nonce_
}