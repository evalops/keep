package main

import (
	"flag"
	"log"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"

	"github.com/EvalOps/keep/pkg/secrets"
)

func main() {
	var (
		direction     = flag.String("direction", "up", "Migration direction: up, down")
		steps         = flag.Int("steps", 0, "Number of migration steps (0 = all)")
		migrationsDir = flag.String("migrations-dir", "file://migrations", "Path to migrations directory")
		force         = flag.Int("force", -1, "Force set migration version (use with caution)")
		showVersion   = flag.Bool("version", false, "Show current migration version")
	)
	flag.Parse()

	// Initialize secret management
	secretHelper := secrets.NewHelperFromEnv()

	// Load database configuration
	dbConfig := secretHelper.LoadDatabaseConfig()
	databaseURL := secretHelper.BuildDSN(dbConfig)

	// Create migrator instance
	m, err := migrate.New(*migrationsDir, databaseURL)
	if err != nil {
		log.Fatalf("Migration initialization failed: %v", err)
	}
	defer m.Close()

	// Handle different commands
	switch {
	case *showVersion:
		showCurrentVersion(m)

	case *force >= 0:
		forceVersion(m, *force)

	case *direction == "up":
		if *steps > 0 {
			migrateSteps(m, *steps)
		} else {
			migrateUp(m)
		}

	case *direction == "down":
		if *steps > 0 {
			migrateSteps(m, -*steps)
		} else {
			migrateDown(m)
		}

	default:
		log.Fatalf("Invalid direction: %s (use 'up' or 'down')", *direction)
	}
}

func showCurrentVersion(m *migrate.Migrate) {
	version, dirty, err := m.Version()
	if err != nil {
		log.Fatalf("Failed to get migration version: %v", err)
	}

	log.Printf("Current migration version: %d", version)
	if dirty {
		log.Printf("Migration state is dirty (incomplete migration)")
	} else {
		log.Printf("Migration state is clean")
	}
}

func forceVersion(m *migrate.Migrate, version int) {
	log.Printf("Forcing migration version to %d...", version)
	if err := m.Force(version); err != nil {
		log.Fatalf("Failed to force migration version: %v", err)
	}
	log.Printf("Migration version forced to %d", version)
}

func migrateUp(m *migrate.Migrate) {
	log.Println("Running all pending migrations...")
	if err := m.Up(); err != nil {
		if err == migrate.ErrNoChange {
			log.Println("No pending migrations")
		} else {
			log.Fatalf("Migration failed: %v", err)
		}
	} else {
		log.Println("All migrations completed successfully")
	}
}

func migrateDown(m *migrate.Migrate) {
	log.Println("Rolling back all migrations...")
	if err := m.Down(); err != nil {
		if err == migrate.ErrNoChange {
			log.Println("No migrations to roll back")
		} else {
			log.Fatalf("Rollback failed: %v", err)
		}
	} else {
		log.Println("All migrations rolled back successfully")
	}
}

func migrateSteps(m *migrate.Migrate, steps int) {
	if steps > 0 {
		log.Printf("Running %d migration steps...", steps)
	} else {
		log.Printf("Rolling back %d migration steps...", -steps)
	}

	if err := m.Steps(steps); err != nil {
		if err == migrate.ErrNoChange {
			log.Println("No migration changes to apply")
		} else {
			log.Fatalf("Migration failed: %v", err)
		}
	} else {
		log.Printf("Migration completed: %d steps", steps)
	}
}
