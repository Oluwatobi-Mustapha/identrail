package runtime

import (
	"fmt"

	"github.com/Oluwatobi-Mustapha/identrail/internal/api"
	"github.com/Oluwatobi-Mustapha/identrail/internal/app"
	"github.com/Oluwatobi-Mustapha/identrail/internal/config"
	"github.com/Oluwatobi-Mustapha/identrail/internal/db"
	awsprovider "github.com/Oluwatobi-Mustapha/identrail/internal/providers/aws"
)

// BuildScanService constructs store + scanner + API service from runtime config.
func BuildScanService(cfg config.Config) (*api.Service, func() error, error) {
	store, err := NewStore(cfg.DatabaseURL)
	if err != nil {
		return nil, nil, err
	}

	scanner := app.Scanner{
		Collector:            awsprovider.NewFixtureCollector(cfg.AWSFixturePath),
		Normalizer:           awsprovider.NewRoleNormalizer(),
		PermissionResolver:   awsprovider.NewPolicyPermissionResolver(),
		RelationshipResolver: awsprovider.NewRelationshipBuilder(),
		RiskRuleSet:          awsprovider.NewRuleSet(),
	}

	svc := api.NewService(store, scanner, cfg.Provider)
	return svc, store.Close, nil
}

// NewStore returns memory store by default, Postgres when database URL is provided.
func NewStore(databaseURL string) (db.Store, error) {
	if databaseURL == "" {
		return db.NewMemoryStore(), nil
	}
	store, err := db.NewPostgresStore(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("initialize postgres store: %w", err)
	}
	return store, nil
}
