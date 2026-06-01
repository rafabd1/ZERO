package cli

import (
	"fmt"

	"github.com/rafabd1/ZERO/internal/notify"
	"github.com/spf13/cobra"
)

func newNotifyCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "notify",
		Short: "Send deduplicated notifications for new findings.",
	}

	var limit int
	var dryRun bool
	cmd.AddCommand(&cobra.Command{
		Use:   "discord",
		Short: "Send new report notifications to Discord.",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := commandContext()
			cfg := loadConfig()
			repo := openRepository(ctx, cfg)
			defer repo.Close()

			result, err := notify.NewDiscordNotifier(repo, cfg.Notify.DiscordWebhookURL).
				WithLimit(limit).
				WithDryRun(dryRun).
				Run(ctx)
			if err != nil {
				return err
			}
			state := ""
			if result.Disabled {
				state = " (disabled: ZERO_DISCORD_WEBHOOK_URL is empty)"
			}
			fmt.Fprintf(cmd.OutOrStdout(), "discord notifications checked %d reports, sent %d, skipped %d, failed %d%s\n", result.Reports, result.Sent, result.Skipped, result.Failed, state)
			return nil
		},
	})
	cmd.Commands()[0].Flags().IntVar(&limit, "limit", 25, "maximum reports to notify")
	cmd.Commands()[0].Flags().BoolVar(&dryRun, "dry-run", false, "inspect pending reports without sending or recording notifications")

	return cmd
}
