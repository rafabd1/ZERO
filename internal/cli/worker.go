package cli

import (
	"fmt"
	"time"

	"github.com/robfig/cron/v3"
	"github.com/spf13/cobra"
)

func newWorkerCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "worker",
		Short: "Run scheduled monitoring tasks.",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := loadConfig()
			c := cron.New(cron.WithSeconds())

			addJob := func(name, spec string, fn func()) error {
				_, err := c.AddFunc(spec, func() {
					fmt.Fprintf(cmd.OutOrStdout(), "[%s] starting %s\n", time.Now().UTC().Format(time.RFC3339), name)
					fn()
					fmt.Fprintf(cmd.OutOrStdout(), "[%s] finished %s\n", time.Now().UTC().Format(time.RFC3339), name)
				})
				return err
			}

			if err := addJob("scope-sync", cfg.Schedule.ScopeSync, func() { runChild(cmd, "sync", "h1") }); err != nil {
				return err
			}
			if err := addJob("enum", cfg.Schedule.Enum, func() { runChild(cmd, "enum", "subfinder") }); err != nil {
				return err
			}
			if err := addJob("probe", cfg.Schedule.Probe, func() { runChild(cmd, "probe", "httpx") }); err != nil {
				return err
			}
			if err := addJob("cve", cfg.Schedule.CVE, func() { runChild(cmd, "analyze", "cves") }); err != nil {
				return err
			}
			if err := addJob("nuclei", cfg.Schedule.Nuclei, func() { runChild(cmd, "analyze", "nuclei") }); err != nil {
				return err
			}

			c.Start()
			<-commandContext().Done()
			ctx := c.Stop()
			<-ctx.Done()
			return nil
		},
	}
}

func runChild(parent *cobra.Command, args ...string) {
	child := newRootCommand()
	child.SetArgs(args)
	child.SetOut(parent.OutOrStdout())
	child.SetErr(parent.ErrOrStderr())
	if err := child.Execute(); err != nil {
		fmt.Fprintf(parent.ErrOrStderr(), "task %v failed: %v\n", args, err)
	}
}
