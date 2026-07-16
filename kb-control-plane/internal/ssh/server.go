package ssh

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/charmbracelet/ssh"
	"github.com/charmbracelet/wish"
)

type Service struct {
	server *ssh.Server
	config *Config
}

// NewService instantiates a new SSH service using Wish.
func NewService() (*Service, error) {
	cfg, err := LoadConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load SSH config: %w", err)
	}

	// Ensure host key exists (will generate if not present)
	if err := EnsureHostKeyExists(cfg.HostKeyPath); err != nil {
		return nil, fmt.Errorf("host key verification/generation failed: %w", err)
	}

	// Ensure authorized keys file exists (create empty one in dev mode as a fallback)
	if _, err := os.Stat(cfg.AuthorizedKeysPath); os.IsNotExist(err) {
		log.Printf("[SSH] Warning: Authorized keys file %s does not exist. Public key auth will fail.", cfg.AuthorizedKeysPath)
		if cfg.DevMode {
			_ = os.WriteFile(cfg.AuthorizedKeysPath, []byte("# Add operator public keys here\n"), 0600)
		}
	}

	ws, err := wish.NewServer(
		wish.WithAddress(cfg.BindAddr),
		wish.WithHostKeyPath(cfg.HostKeyPath),
		wish.WithPublicKeyAuth(func(ctx ssh.Context, key ssh.PublicKey) bool {
			return ValidatePublicKey(cfg.AuthorizedKeysPath, key)
		}),
		wish.WithMiddleware(
			func(h ssh.Handler) ssh.Handler {
				return func(s ssh.Session) {
					handleSession(s)
				}
			},
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create wish server: %w", err)
	}

	return &Service{
		server: ws,
		config: cfg,
	}, nil
}

// Start runs the SSH server in a background goroutine.
func (s *Service) Start() error {
	log.Printf("[SSH] Starting SSH service on %s", s.config.BindAddr)
	go func() {
		if err := s.server.ListenAndServe(); err != nil && err != ssh.ErrServerClosed {
			log.Printf("[SSH] SSH service ListenAndServe error: %v", err)
		}
	}()
	return nil
}

// Stop gracefully shuts down the SSH server.
func (s *Service) Stop() error {
	log.Printf("[SSH] Stopping SSH service...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.server.Shutdown(ctx)
}
