package api

import (
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/gofiber/fiber/v2"
	"github.com/grexie/signchain-vault/v2/pkg/api/interop"
	"github.com/grexie/signchain-vault/v2/pkg/storage/interfaces"
	"github.com/grexie/signchain-vault/v2/pkg/vault"
)

type CreateWalletRequest struct {
	Name string `json:"name"`
}

type CreateWalletResponse = vault.Wallet

func (a *api) CreateWallet(c *fiber.Ctx) error {
	account := interfaces.ID(c.Params("account"))
	var req CreateWalletRequest

	if err := c.BodyParser(&req); err != nil {
		return err
	} else if w, err := a.vault.CreateWallet(c.UserContext(), account, req.Name); err != nil {
		return err
	} else {
		return c.JSON(interop.NewResponse(w))
	}
}

func (a *api) GetWallet(c *fiber.Ctx) error {
	account := interfaces.ID(c.Params("account"))
	address := common.HexToAddress(c.Params("address"))

	if w, err := a.vault.GetWallet(c.UserContext(), account, address); err != nil {
		return err
	} else {
		return c.JSON(interop.NewResponse(w))
	}
}

func (a *api) ListWallets(c *fiber.Ctx) error {
	account := interfaces.ID(c.Params("account"))
	offset := int64(c.QueryInt("offset", 0))
	count := int64(c.QueryInt("count", 100))

	if r, err := a.vault.ListWallets(c.UserContext(), account, offset, count); err != nil {
		return err
	} else {
		return c.JSON(interop.NewResponse(r))
	}
}

type UpdateWalletRequest struct {
	Name string `json:"name"`
}

func (a *api) UpdateWallet(c *fiber.Ctx) error {
	account := interfaces.ID(c.Params("account"))
	address := common.HexToAddress(c.Params("address"))
	var req UpdateWalletRequest

	if err := c.BodyParser(&req); err != nil {
		return err
	} else if w, err := a.vault.UpdateWallet(c.UserContext(), account, address, req.Name); err != nil {
		return err
	} else {
		return c.JSON(interop.NewResponse(w))
	}
}

type ExpireWalletRequest struct {
	TTL time.Duration `json:"ttl"`
}

func (a *api) ExpireWallet(c *fiber.Ctx) error {
	account := interfaces.ID(c.Params("account"))
	address := common.HexToAddress(c.Params("address"))
	var req ExpireWalletRequest

	if err := c.BodyParser(&req); err != nil {
		return err
	} else if w, err := a.vault.ExpireWallet(c.UserContext(), account, address, req.TTL * time.Second); err != nil {
		return err
	} else {
		return c.JSON(interop.NewResponse(w))
	}
}

type UnexpireWalletRequest struct {

}

func (a *api) UnexpireWallet(c *fiber.Ctx) error {
	account := interfaces.ID(c.Params("account"))
	address := common.HexToAddress(c.Params("address"))
	var req UnexpireWalletRequest

	if err := c.BodyParser(&req); err != nil {
		return err
	} else if w, err := a.vault.UnexpireWallet(c.UserContext(), account, address); err != nil {
		return err
	} else {
		return c.JSON(interop.NewResponse(w))
	}
}