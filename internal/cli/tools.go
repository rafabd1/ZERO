package cli

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/spf13/cobra"
)

func newToolsCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tools",
		Short: "Manage external tool caches used by Zero.",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "nuclei-update",
		Short: "Update nuclei-templates in the configured template directory.",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := loadConfig()
			templateDir := cfg.Tools.NucleiTemplateDir
			if templateDir == "" {
				templateDir = "nuclei-templates"
			}
			if err := os.MkdirAll(templateDir, 0o755); err != nil {
				return err
			}
			update := exec.CommandContext(commandContext(), cfg.Tools.NucleiBin, "-update-templates", "-update-template-dir", templateDir, "-silent")
			update.Stdout = cmd.OutOrStdout()
			update.Stderr = cmd.ErrOrStderr()
			if err := update.Run(); err != nil {
				return fmt.Errorf("update nuclei templates: %w", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "nuclei templates updated in %s\n", templateDir)
			return nil
		},
	})
	return cmd
}
