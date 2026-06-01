package cli

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/rafabd1/ZERO/internal/db"
	"github.com/rafabd1/ZERO/internal/sanitize"
	"github.com/spf13/cobra"
)

func newDevCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:    "dev",
		Short:  "Development and lab helpers.",
		Hidden: true,
	}
	var labURL string
	var techName string
	var techVersion string
	seedLab := &cobra.Command{
		Use:   "seed-lab",
		Short: "Seed a local lab service into the database for end-to-end validation.",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := commandContext()
			cfg := loadConfig()
			repo := openRepository(ctx, cfg)
			defer repo.Close()
			u, err := url.Parse(labURL)
			if err != nil || u.Hostname() == "" {
				return fmt.Errorf("invalid --url %q", labURL)
			}
			host, ok := sanitize.CanonicalDomain(u.Hostname())
			if !ok {
				host = strings.ToLower(u.Hostname())
			}
			programID, err := repo.UpsertProgram(ctx, "lab", "zero-lab", "https://example.invalid/zero-lab", map[string]any{"lab": true})
			if err != nil {
				return err
			}
			_, err = repo.UpsertScopeAsset(ctx, db.ScopeAsset{
				ProgramID:         programID,
				Platform:          "lab",
				Handle:            "zero-lab",
				AssetType:         "url",
				TargetRaw:         labURL,
				TargetNormalized:  db.NormalizeTarget(labURL),
				InScope:           true,
				EligibleForBounty: true,
				Source:            "lab",
				Metadata:          map[string]any{"lab": true},
			})
			if err != nil {
				return err
			}
			serviceID, err := repo.UpsertHTTPService(ctx, db.HTTPService{
				ProgramID:    programID,
				URL:          labURL,
				Scheme:       firstNonEmpty(u.Scheme, "http"),
				Host:         host,
				Webserver:    techName,
				Technologies: []string{techName},
			})
			if err != nil {
				return err
			}
			if techVersion != "" {
				_, _, err = repo.UpsertTechnologyObservation(ctx, db.TechnologyObservation{
					ProgramID:     programID,
					HTTPServiceID: serviceID,
					Name:          techName,
					Version:       techVersion,
					Source:        "lab",
					Confidence:    100,
					Evidence: map[string]any{
						"url": labURL,
						"lab": true,
					},
				})
				if err != nil {
					return err
				}
			}
			fmt.Fprintf(cmd.OutOrStdout(), "seeded lab program %s for %s (%s %s)\n", programID, labURL, techName, techVersion)
			return nil
		},
	}
	seedLab.Flags().StringVar(&labURL, "url", "http://lab-apache", "lab service URL")
	seedLab.Flags().StringVar(&techName, "tech", "Apache HTTP Server", "technology name to seed")
	seedLab.Flags().StringVar(&techVersion, "version", "2.4.49", "technology version to seed")
	cmd.AddCommand(seedLab)
	cmd.AddCommand(&cobra.Command{
		Use:   "disable-lab",
		Short: "Disable the seeded lab program and related active entities.",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := commandContext()
			cfg := loadConfig()
			repo := openRepository(ctx, cfg)
			defer repo.Close()

			rows, err := repo.QueryJSONRows(ctx, `
				WITH target AS (
					SELECT id
					FROM zero_programs
					WHERE platform = 'lab'
					  AND handle = 'zero-lab'
				), programs AS (
					UPDATE zero_programs
					SET active = false,
						metadata = metadata || jsonb_build_object(
							'disabled_reason', 'lab program excluded before real execution',
							'disabled_at', now()
						)
					WHERE id IN (SELECT id FROM target)
					RETURNING id
				), assets AS (
					UPDATE zero_scope_assets
					SET active = false,
						metadata = metadata || jsonb_build_object(
							'disabled_reason', 'lab program excluded before real execution',
							'disabled_at', now()
						)
					WHERE program_id IN (SELECT id FROM target)
					  AND active = true
					RETURNING id
				), subdomains AS (
					UPDATE zero_subdomains
					SET active = false,
						metadata = metadata || jsonb_build_object(
							'disabled_reason', 'lab program excluded before real execution',
							'disabled_at', now()
						)
					WHERE program_id IN (SELECT id FROM target)
					  AND active = true
					RETURNING id
				), services AS (
					UPDATE zero_http_services
					SET active = false,
						raw = raw || jsonb_build_object(
							'disabled_reason', 'lab program excluded before real execution',
							'disabled_at', now()
						)
					WHERE program_id IN (SELECT id FROM target)
					  AND active = true
					RETURNING id
				), technologies AS (
					UPDATE zero_technology_observations
					SET active = false,
						evidence = evidence || jsonb_build_object(
							'disabled_reason', 'lab program excluded before real execution',
							'disabled_at', now()
						)
					WHERE program_id IN (SELECT id FROM target)
					  AND active = true
					RETURNING id
				)
				SELECT jsonb_build_object(
					'programs', (SELECT count(*) FROM programs),
					'assets', (SELECT count(*) FROM assets),
					'subdomains', (SELECT count(*) FROM subdomains),
					'services', (SELECT count(*) FROM services),
					'technologies', (SELECT count(*) FROM technologies)
				)
			`)
			if err != nil {
				return err
			}
			if len(rows) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "lab program not found")
				return nil
			}
			fmt.Fprintf(cmd.OutOrStdout(), "disabled lab entities: %s\n", rows[0])
			return nil
		},
	})
	return cmd
}
