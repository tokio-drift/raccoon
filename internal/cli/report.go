package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/tokio-drift/raccoon/internal/casedir"
	"github.com/tokio-drift/raccoon/internal/report"
)

func newReportCommand(stdout io.Writer) *cobra.Command {
	var (
		format string
		out    string
	)
	cmd := &cobra.Command{
		Use:   "report <case>",
		Short: "Write a report for an existing case",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			f, err := report.ParseFormat(format)
			if err != nil {
				return badInput(err)
			}
			path := args[0]
			if _, err := os.Stat(path); err != nil {
				base, err := filepath.Abs(out)
				if err != nil {
					return internal(fmt.Errorf("resolve case directory: %w", err))
				}
				path = filepath.Join(base, args[0])
			}
			if _, err := casedir.Open(path); err != nil {
				return badInput(fmt.Errorf("open case %q: %w", args[0], err))
			}
			dst, err := report.Write(path, f)
			if err != nil {
				if report.IsUnsupported(err) {
					return badInput(err)
				}
				return internal(err)
			}
			fmt.Fprintf(stdout, "Report: %s\n", dst)
			return nil
		},
	}
	cmd.Flags().StringVar(&format, "format", "html", "report format: html, json or pdf")
	cmd.Flags().StringVar(&out, "out", defaultBaseDir(), "case directory base")
	return cmd
}
