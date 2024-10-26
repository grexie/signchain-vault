package api

import (
	"github.com/gofiber/fiber/v2"
	"github.com/grexie/signchain-vault/v2/pkg/api/interop"
	"github.com/grexie/signchain-vault/v2/pkg/storage/interfaces"
	"github.com/carlmjohnson/versioninfo"
)

type StatusResponse struct {
	VaultKeys int `json:"vaultKeys"`
	Wallets int64 `json:"wallets"`
	Version string `json:"version"`
}

func (a *api) Status(c *fiber.Ctx) error {
	account := interfaces.ID(c.Params("account"))

	if r, err := a.vault.ListWallets(c.UserContext(), account, 0, 0); err != nil {
		return err
	} else {
		vaultKeys := len(a.auth.VaultKeys())

		return c.JSON(interop.NewResponse(StatusResponse{
			VaultKeys: vaultKeys,
			Wallets: r.Count(),
			Version: versioninfo.Short(),
		}))
	}
}