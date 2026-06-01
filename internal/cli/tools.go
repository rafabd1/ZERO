package cli

import (
	"context"
	"fmt"
	"os"
	"os/exec"

	"github.com/rafabd1/ZERO/internal/config"
	toolrunner "github.com/rafabd1/ZERO/internal/tools"
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
			ctx := commandContext()
			return updateNucleiTemplates(ctx, cmd, cfg)
		},
	})
	return cmd
}

func updateNucleiTemplates(ctx context.Context, cmd *cobra.Command, cfg config.Config) error {
	templateDir := cfg.Tools.NucleiTemplateDir
	if templateDir == "" {
		templateDir = "nuclei-templates"
	}
	if err := os.MkdirAll(templateDir, 0o755); err != nil {
		return err
	}
	runCtx := ctx
	cancel := func() {}
	if cfg.Tools.ToolTimeout > 0 {
		runCtx, cancel = context.WithTimeout(ctx, cfg.Tools.ToolTimeout)
	}
	defer cancel()

	update := exec.CommandContext(runCtx, cfg.Tools.NucleiBin, "-update-templates", "-update-template-dir", templateDir, "-silent")
	update.Stdout = cmd.OutOrStdout()
	update.Stderr = cmd.ErrOrStderr()
	if err := update.Run(); err != nil {
		if runCtx.Err() == context.DeadlineExceeded {
			timeoutErr := toolrunner.TimeoutError{Bin: cfg.Tools.NucleiBin, Args: []string{"-update-templates", "-update-template-dir", templateDir, "-silent"}, Timeout: cfg.Tools.ToolTimeout}
			alertOnTimeout(ctx, cmd, cfg, "", "", []string{"tools", "nuclei-update"}, timeoutErr)
			return timeoutErr
		}
		return fmt.Errorf("update nuclei templates: %w", err)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "nuclei templates updated in %s\n", templateDir)
	return nil
}
