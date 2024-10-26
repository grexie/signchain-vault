package main

import (
	"fmt"
	"log"
	"os"

	"github.com/carlmjohnson/versioninfo"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/grexie/signchain-vault/v2/pkg/api"
	"github.com/grexie/signchain-vault/v2/pkg/auth"
	"github.com/grexie/signchain-vault/v2/pkg/signer"
	"github.com/grexie/signchain-vault/v2/pkg/storage"
	"github.com/grexie/signchain-vault/v2/pkg/tls"
	"github.com/grexie/signchain-vault/v2/pkg/vault"
	"github.com/joho/godotenv"
)

func loadEnv(filenames ...string) {
	for _, filename := range filenames {
		if s, err := os.Stat(filename); err == nil && !s.IsDir() {
			godotenv.Load(filename)
		}
	}
}

func main() {
	if _, ok := os.LookupEnv("ENV"); !ok {
		env := "development"
		os.Setenv("ENV", env)
	}
	loadEnv(".env." + os.Getenv("ENV") + ".local", ".env." + os.Getenv("ENV"), ".env.local", ".env")

	port := "443"
	if p, ok := os.LookupEnv("PORT"); ok {
		port = p
	}

	if auth, err := auth.NewAuth(); err != nil {
		log.Fatal(err)
	} else if vault, err := vault.NewVault(auth); err != nil {
		log.Fatal(err)
	} else if storage, err := storage.NewStorage(vault); err != nil {
		log.Fatal(err)
	} else if err := vault.SetStorageBackend(storage); err != nil {
		log.Fatal(err)
	} else if signer, err := signer.NewSigner(vault); err != nil {
		log.Fatal(err)
	} else if api, err := api.NewAPI(auth, vault, signer); err != nil {
		log.Fatal(err)
	} else {
		app := fiber.New(fiber.Config{
			DisableStartupMessage: true,
		})

		app.Use(logger.New())

		app.Mount("/api/v1", api.App())

		if os.Getenv("VAULT_INSECURE_HTTP") == "true" {
			log.Printf("🚀 started signchain vault on port %s", port)
			log.Fatal(app.Listen(fmt.Sprintf(":%s", port)))
		} else {
			if cert, err := tls.CreateServerCert(); err != nil {
				log.Fatal(fmt.Errorf("error creating tls certificate: %v", err))
			} else {
				log.Printf("🚀 started signchain vault %s on port %s", versioninfo.Short(), port)
				log.Fatal(app.ListenTLSWithCertificate(fmt.Sprintf(":%s", port), cert))
			}
		}
		
	}
}