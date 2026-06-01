package cli

import (
	"context"
	"fmt"

	"github.com/rafabd1/ZERO/internal/config"
	"github.com/rafabd1/ZERO/internal/notify"
	"github.com/rafabd1/ZERO/internal/tools"
	"github.com/spf13/cobra"
)

func alertOnTimeout(ctx context.Context, cmd *cobra.Command, cfg config.Config, programID, programHandle string, step []string, err error) {
	if err == nil || !tools.IsTimeout(err) {
		return
	}
	alert := notify.OperationalAlert{
		Kind:          "tool_timeout",
		Title:         "Zero tool timeout",
		ProgramID:     programID,
		ProgramHandle: programHandle,
		Step:          step,
		Error:         err.Error(),
		Timeout:       cfg.Tools.ToolTimeout.String(),
	}
	if sendErr := notify.SendOperationalAlert(ctx, cfg.Notify.DiscordAlertWebhookURL, alert); sendErr != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "failed to send operational alert: %v\n", sendErr)
	}
}
