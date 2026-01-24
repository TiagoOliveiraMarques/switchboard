package migrations

import "errors"

var (
	// ErrDriverCreation is returned when the postgres driver cannot be created.
	ErrDriverCreation = errors.New("failed to create postgres driver")

	// ErrSourceCreation is returned when the migration source driver cannot be created.
	ErrSourceCreation = errors.New("failed to create source driver")

	// ErrMigrateInstance is returned when the migrate instance cannot be created.
	ErrMigrateInstance = errors.New("failed to create migrate instance")

	// ErrMigrationFailed is returned when migrations fail to run.
	ErrMigrationFailed = errors.New("failed to run migrations")
)
