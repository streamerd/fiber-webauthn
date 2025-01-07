package main

import (
	"log"
	"os"

	"example/store"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/template/html/v2"
	"github.com/streamerd/fiber-webauthn"
)

func main() {
	// Initialize SQLite store
	store, err := store.NewSQLiteStore("webauthn.db")
	if err != nil {
		log.Fatal(err)
	}

	// Initialize template engine
	engine := html.New("./views", ".html")

	// Initialize Fiber
	app := fiber.New(fiber.Config{
		Views: engine,
	})

	// Serve static files
	app.Static("/", "./views")

	// Initialize WebAuthn middleware
	webAuthnMiddleware := webauthn.New(webauthn.Config{
		RPDisplayName:   "WebAuthn Example",
		RPID:            "localhost",
		RPOrigins:       []string{"http://localhost:3000"},
		CredentialStore: store,
	})

	// Routes
	app.Get("/", func(c *fiber.Ctx) error {
		return c.Render("index", fiber.Map{
			"Title": "WebAuthn Example",
		})
	})

	// WebAuthn endpoints
	auth := app.Group("/auth/passkey")
	auth.Post("/register/begin", webAuthnMiddleware.BeginRegistration())
	auth.Post("/register/finish", webAuthnMiddleware.FinishRegistration())
	auth.Post("/login/begin", webAuthnMiddleware.BeginAuthentication())
	auth.Post("/login/finish", webAuthnMiddleware.FinishAuthentication())

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}
	log.Fatal(app.Listen(":" + port))
}
