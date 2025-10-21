package main

import (
	"errors"
	"flag"
	"fmt"
	"log"

	"github.com/EvalOps/keep/pkg/secrets"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("migrate: %v", err)
	}
}

const (
	allSteps     = 0
	noForceValue = -1
)

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
			log.Printf("migrate source close: %v", sourceErr)
		}
		if dbErr != nil && !errors.Is(dbErr, migrate.ErrNoChange) {
			log.Printf("migrate db close: %v", dbErr)
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

	log.Printf("Current migration version: %d", version)
	if dirty {
		log.Printf("Migration state is dirty (incomplete migration)")
	} else {
		log.Printf("Migration state is clean")
	}
	return nil
}

func forceVersion(m *migrate.Migrate, version int) error {
	log.Printf("Forcing migration version to %d...", version)
	if err := m.Force(version); err != nil {
		return fmt.Errorf("force version: %w", err)
	}
	log.Printf("Migration version forced to %d", version)
	return nil
}

func migrateUp(m *migrate.Migrate) error {
	log.Println("Running all pending migrations...")
	if err := m.Up(); err != nil {
		if errors.Is(err, migrate.ErrNoChange) {
			log.Println("No pending migrations")
			return nil
		}
		return fmt.Errorf("migration up: %w", err)
	}
	log.Println("All migrations completed successfully")
	return nil
}

func migrateDown(m *migrate.Migrate) error {
	log.Println("Rolling back all migrations...")
	if err := m.Down(); err != nil {
		if errors.Is(err, migrate.ErrNoChange) {
			log.Println("No migrations to roll back")
			return nil
		}
		return fmt.Errorf("migration down: %w", err)
	}
	log.Println("All migrations rolled back successfully")
	return nil
}

func migrateSteps(m *migrate.Migrate, steps int) error {
	if steps > allSteps {
		log.Printf("Running %d migration steps...", steps)
	} else {
		log.Printf("Rolling back %d migration steps...", -steps)
	}

	if err := m.Steps(steps); err != nil {
		if errors.Is(err, migrate.ErrNoChange) {
			log.Println("No migration changes to apply")
			return nil
		}
		return fmt.Errorf("migration steps: %w", err)
	}
	log.Printf("Migration completed: %d steps", steps)
	return nil
}
