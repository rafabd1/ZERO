package cli

import (
	"context"
	"fmt"
	"strings"

	"github.com/rafabd1/ZERO/internal/config"
	"github.com/rafabd1/ZERO/internal/notify"
	"github.com/rafabd1/ZERO/internal/tools"
	"github.com/rafabd1/ZERO/internal/validate"
	"github.com/spf13/cobra"
)

func alertOnTimeout(ctx context.Context, cmd *cobra.Command, cfg config.Config, programID, programHandle string, step []string, err error) {
	if err == nil || !tools.IsTimeout(err) {
		return
	}
	timeout := cfg.Tools.ToolTimeout
	if actual, ok := tools.TimeoutDuration(err); ok {
		timeout = actual
	}
	alert := notify.OperationalAlert{
		Kind:          "tool_timeout",
		Title:         "Zero tool timeout",
		ProgramID:     programID,
		ProgramHandle: programHandle,
		Step:          step,
		Error:         err.Error(),
		Timeout:       timeout.String(),
	}
	if sendErr := notify.SendOperationalAlert(ctx, cfg.Notify.DiscordAlertWebhookURL, alert); sendErr != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "failed to send operational alert: %v\n", sendErr)
	}
}

func alertOnWAF(ctx context.Context, cmd *cobra.Command, cfg config.Config, programID, programHandle string, step []string, diag validate.WAFDiagnostic) {
	if !diag.Enabled || !diag.Suspected || diag.Confidence < 70 {
		return
	}
	alert := notify.OperationalAlert{
		Kind:          "waf_suspected",
		Title:         "Zero WAF interference suspected",
		ProgramID:     programID,
		ProgramHandle: programHandle,
		Step:          step,
		Error: fmt.Sprintf(
			"confidence=%d reason=%s baseline_blocked=%d post_blocked=%d indicators=%s",
			diag.Confidence,
			diag.Reason,
			diag.BaselineBlocked,
			diag.PostBlocked,
			strings.Join(diag.Indicators, ","),
		),
	}
	if sendErr := notify.SendOperationalAlert(ctx, cfg.Notify.DiscordAlertWebhookURL, alert); sendErr != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "failed to send WAF alert: %v\n", sendErr)
	}
}
