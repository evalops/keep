package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/rs/zerolog"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"

	"github.com/EvalOps/keep/pkg/logging"
	"github.com/EvalOps/keep/pkg/secrets"
)

func main() {
	logging.Initialize("migrate-cli", logLevel())
	cliLogger = logging.NewServiceLogger("cmd")

	if err := run(); err != nil {
		cliLogger.Fatal().Err(err).Msg("migrate command failed")
	}
}

const (
	allSteps     = 0
	noForceValue = -1
)

var cliLogger zerolog.Logger

func logLevel() string {
	if level := os.Getenv("LOG_LEVEL"); level != "" {
		return level
	}
	return "info"
}

func run() error {
	var (
		direction     = flag.String("direction", "up", "Migration direction: up, down")
		steps         = flag.Int("steps", allSteps, "Number of migration steps (0 = all)")
		migrationsDir = flag.String("migrations-dir", "file://migrations", "Path to migrations directory")
		force         = flag.Int("force", noForceValue, "Force set migration version (use with caution)")
		showVersion   = flag.Bool("version", false, "Show current migration version")
	)
	flag.Parse()

	secretHelper := secrets.NewHelperFromEnv()

	dbConfig := secretHelper.LoadDatabaseConfig()
	databaseURL, err := secrets.BuildDSN(dbConfig)
	if err != nil {
		return fmt.Errorf("build DSN: %w", err)
	}

	m, err := migrate.New(*migrationsDir, databaseURL)
	if err != nil {
		return fmt.Errorf("init migrator: %w", err)
	}
	defer func() {
		sourceErr, dbErr := m.Close()
		if sourceErr != nil && !errors.Is(sourceErr, migrate.ErrNoChange) {
			cliLogger.Warn().Err(sourceErr).Msg("migrate source close")
		}
		if dbErr != nil && !errors.Is(dbErr, migrate.ErrNoChange) {
			cliLogger.Warn().Err(dbErr).Msg("migrate database close")
		}
	}()

	switch {
	case *showVersion:
		return showCurrentVersion(m)
	case *force >= allSteps:
		return forceVersion(m, *force)
	case *direction == "up":
		if *steps > allSteps {
			return migrateSteps(m, *steps)
		}
		return migrateUp(m)
	case *direction == "down":
		if *steps > allSteps {
			return migrateSteps(m, -*steps)
		}
		return migrateDown(m)
	default:
		return fmt.Errorf("invalid direction: %s (use 'up' or 'down')", *direction)
	}
}

func showCurrentVersion(m *migrate.Migrate) error {
	version, dirty, err := m.Version()
	if err != nil {
		return fmt.Errorf("get migration version: %w", err)
	}

	cliLogger.Info().Uint64("version", uint64(version)).Msg("current migration version")
	if dirty {
		cliLogger.Warn().Msg("migration state is dirty (incomplete migration)")
	} else {
		cliLogger.Info().Msg("migration state is clean")
	}
	return nil
}

func forceVersion(m *migrate.Migrate, version int) error {
	cliLogger.Info().Int("version", version).Msg("forcing migration version")
	if err := m.Force(version); err != nil {
		return fmt.Errorf("force version: %w", err)
	}
	cliLogger.Info().Int("version", version).Msg("migration version forced")
	return nil
}

func migrateUp(m *migrate.Migrate) error {
	cliLogger.Info().Msg("running all pending migrations")
	if err := m.Up(); err != nil {
		if errors.Is(err, migrate.ErrNoChange) {
			cliLogger.Info().Msg("no pending migrations")
			return nil
		}
		return fmt.Errorf("migration up: %w", err)
	}
	cliLogger.Info().Msg("all migrations completed successfully")
	return nil
}

func migrateDown(m *migrate.Migrate) error {
	cliLogger.Info().Msg("rolling back all migrations")
	if err := m.Down(); err != nil {
		if errors.Is(err, migrate.ErrNoChange) {
			cliLogger.Info().Msg("no migrations to roll back")
			return nil
		}
		return fmt.Errorf("migration down: %w", err)
	}
	cliLogger.Info().Msg("all migrations rolled back successfully")
	return nil
}

func migrateSteps(m *migrate.Migrate, steps int) error {
	if steps > allSteps {
		cliLogger.Info().Int("steps", steps).Msg("running migration steps")
	} else {
		cliLogger.Info().Int("steps", -steps).Msg("rolling back migration steps")
	}

	if err := m.Steps(steps); err != nil {
		if errors.Is(err, migrate.ErrNoChange) {
			cliLogger.Info().Msg("no migration changes to apply")
			return nil
		}
		return fmt.Errorf("migration steps: %w", err)
	}
	cliLogger.Info().Int("steps", steps).Msg("migration completed")
	return nil
}
