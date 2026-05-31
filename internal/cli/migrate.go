package cli

import (
	"fmt"

	"github.com/rafabd1/ZERO/internal/db"
	"github.com/spf13/cobra"
)

func newMigrateCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "migrate up",
		Short: "Apply database migrations to Supabase/Postgres.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if args[0] != "up" {
				return fmt.Errorf("unsupported migration direction %q", args[0])
			}
			ctx := commandContext()
			cfg := loadConfig()
			if cfg.DatabaseURL == "" {
				return fmt.Errorf("ZERO_DATABASE_URL is required")
			}
			return db.Migrate(ctx, cfg.DatabaseURL)
		},
	}
}
