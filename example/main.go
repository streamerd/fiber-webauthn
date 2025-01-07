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
	// Get port from environment or use default
	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}

	// Initialize SQLite store
	store, err := store.NewSQLiteStore("webauthn.db")
	if err != nil {
		log.Fatal(err)
	}

	// Initialize template engine
	engine := html.New("./views", ".html")

	// Initialize Fiber
	app := fiber.New(fiber.Config{
		Views:                 engine,
		DisableStartupMessage: true,
	})

	// Add proxy configuration
	app.Use(func(c *fiber.Ctx) error {
		c.Set("X-Forwarded-Proto", "http")
		c.Set("X-Forwarded-Host", "localhost:3000")
		return c.Next()
	})

	// Serve static files
	app.Static("/", "./views")

	// Add redirect middleware FIRST
	app.Use(func(c *fiber.Ctx) error {
		if c.Hostname() == "127.0.0.1" {
			originalURL := c.OriginalURL()
			if originalURL == "" {
				originalURL = "/"
			}
			return c.Redirect("http://localhost:3000" + originalURL)
		}
		return c.Next()
	})

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
			"Title": "WebAuthn Demo",
		}, "")
	})

	// WebAuthn endpoints
	auth := app.Group("/auth/passkey")
	auth.Post("/register/begin", webAuthnMiddleware.BeginRegistration())
	auth.Post("/register/finish", webAuthnMiddleware.FinishRegistration())
	auth.Post("/login/begin", webAuthnMiddleware.BeginAuthentication())
	auth.Post("/login/finish", webAuthnMiddleware.FinishAuthentication())

	log.Printf("Server started at http://localhost:%s\n", port)
	log.Fatal(app.Listen("localhost:" + port))
}
