package cli

import (
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cobra"
)

func newRootCommand(stdout, stderr io.Writer) *cobra.Command {
	root := &cobra.Command{
		Use:           "raccoon",
		Short:         "RACCOON network forensics",
		Long:          "RACCOON analyses captured network traffic and serves a local investigation UI.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.AddCommand(
		newAnalyzeCommand(stdout, stderr),
		newServeCommand(stdout, stderr),
		newReportCommand(stdout),
		newVersionCommand(stdout),
		newDoctorCommand(stdout),
		newDebugCommand(stdout),
	)
	return root
}

func runCLI(args []string, stdout, stderr io.Writer) int {
	cmd := newRootCommand(stdout, stderr)
	cmd.SetArgs(args)
	err := cmd.Execute()
	if err == nil {
		return 0
	}
	code := 2
	var ee *exitError
	if errors.As(err, &ee) {
		code = ee.code
	}
	fmt.Fprintf(stderr, "raccoon: %v\n", err)
	return code
}

func newVersionCommand(stdout io.Writer) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the RACCOON version",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintln(stdout, versionString())
		},
	}
}
