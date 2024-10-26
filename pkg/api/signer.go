package api

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/gofiber/fiber/v2"
	"github.com/grexie/signchain-vault/v2/pkg/api/interop"
	"github.com/grexie/signchain-vault/v2/pkg/signer"
	"github.com/grexie/signchain-vault/v2/pkg/storage/interfaces"
)

type SignRequest struct {
	Sender common.Address `json:"sender"`
	Uniq string `json:"uniq"`
	ABI map[string]any `json:"abi"`
	Args []any `json:"args"`
}

type SignResponse = signer.SignResult

func (a *api) Sign(c *fiber.Ctx) error {
	account := interfaces.ID(c.Params("account"))
	address := common.HexToAddress(c.Params("address"))

	var req SignRequest

	if err := c.BodyParser(&req); err != nil {
		return err
	} else if res, err := a.signer.Sign(c.UserContext(), account, req.Sender, req.Uniq, address, req.ABI, req.Args); err != nil {
		return err
	} else {
		return c.JSON(interop.NewResponse(res))
	}
}