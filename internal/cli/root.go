package cli

import (
	"fmt"
	"io"

	"github.com/Oluwatobi-Mustapha/aurelius/internal/config"
	"github.com/spf13/cobra"
)

// BuildRootCmd creates the command tree with injected config and output writer.
func BuildRootCmd(cfg config.Config, out io.Writer) *cobra.Command {
	root := &cobra.Command{
		Use:   "aurelius",
		Short: "Machine identity security scanner",
		Long:  "Aurelius scans machine identities and reports typed cloud identity risks.",
	}

	root.SetOut(out)
	root.SetErr(out)

	root.AddCommand(&cobra.Command{
		Use:   "scan",
		Short: "Run a read-only scan",
		RunE: func(_ *cobra.Command, _ []string) error {
			_, err := fmt.Fprintf(out, "Starting scan with service %s on %s\n", cfg.ServiceName, cfg.Provider)
			return err
		},
	})

	root.AddCommand(&cobra.Command{
		Use:   "findings",
		Short: "List current findings",
		RunE: func(_ *cobra.Command, _ []string) error {
			_, err := fmt.Fprintln(out, "No findings available yet. Run `aurelius scan` first.")
			return err
		},
	})

	return root
}

// Execute runs the root command with externalized args for testability.
func Execute(cfg config.Config, args []string, out io.Writer) error {
	cmd := BuildRootCmd(cfg, out)
	cmd.SetArgs(args)
	return cmd.Execute()
}
