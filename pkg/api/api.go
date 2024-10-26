package api

import (
	"errors"
	"fmt"

	"github.com/gofiber/fiber/v2"
	"github.com/grexie/signchain-vault/v2/pkg/api/interop"
	"github.com/grexie/signchain-vault/v2/pkg/auth"
	"github.com/grexie/signchain-vault/v2/pkg/signer"
	"github.com/grexie/signchain-vault/v2/pkg/vault"
)

type API interface {
	App() *fiber.App
}

type api struct {
	app *fiber.App
	auth auth.Auth
	vault vault.Vault
	signer signer.Signer
}

var _ API = &api{}

func NewAPI(auth auth.Auth, vault vault.Vault, signer signer.Signer) (API, error) {
	a := api{auth: auth, vault: vault, signer: signer}

	a.app = fiber.New(fiber.Config{
		DisableStartupMessage: true,
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			code := fiber.StatusInternalServerError

			var e *fiber.Error
			if errors.As(err, &e) {
				code = e.Code
			}

			err = c.Status(code).JSON(interop.NewErrorResponse(err))
			if err != nil {
				return c.Status(code).JSON(interop.NewErrorResponse(fmt.Errorf("internal server error")))
			}

			return nil
		},
	})

	a.app.Post("/accounts/:account/wallets/:address/sign", a.auth.RequireVaultKey, a.auth.RequireAuthSignature, a.Sign)

	a.app.Post("/accounts/:account/wallets", a.auth.RequireVaultKey, a.CreateWallet)
	a.app.Get("/accounts/:account/wallets/:address", a.auth.RequireVaultKey, a.GetWallet)
	a.app.Get("/accounts/:account/wallets", a.auth.RequireVaultKey, a.ListWallets)
	a.app.Put("/accounts/:account/wallets/:address", a.auth.RequireVaultKey, a.UpdateWallet)
	a.app.Post("/accounts/:account/wallets/:address/expire", a.auth.RequireVaultKey, a.ExpireWallet)
	a.app.Post("/accounts/:account/wallets/:address/unexpire", a.auth.RequireVaultKey, a.UnexpireWallet)
	a.app.Get("/accounts/:account/status", a.auth.RequireVaultKey, a.Status)

	return &a, nil
}

func (a *api) App() *fiber.App {
	return a.app
}
