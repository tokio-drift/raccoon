package cli

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/spf13/cobra"
)

func newDoctorCommand(stdout io.Writer) *cobra.Command {
	var out string
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Check the local RACCOON environment",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			base, err := filepath.Abs(out)
			if err != nil {
				return internal(fmt.Errorf("resolve case directory: %w", err))
			}
			if yara, err := exec.LookPath("yara"); err != nil {
				fmt.Fprintln(stdout, "yara: not found (YARA scanning will be disabled)")
			} else {
				fmt.Fprintf(stdout, "yara: %s\n", yara)
			}
			if err := os.MkdirAll(base, 0o700); err != nil {
				fmt.Fprintf(stdout, "case directory: not writable (%v)\n", err)
			} else {
				f, err := os.CreateTemp(base, ".doctor-*")
				if err != nil {
					fmt.Fprintf(stdout, "case directory: not writable (%v)\n", err)
				} else {
					name := f.Name()
					f.Close()
					os.Remove(name)
					fmt.Fprintf(stdout, "case directory: writable (%s)\n", base)
				}
			}
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				fmt.Fprintf(stdout, "localhost: not listening (%v)\n", err)
			} else {
				fmt.Fprintf(stdout, "localhost: listening (%s)\n", ln.Addr())
				ln.Close()
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&out, "out", defaultBaseDir(), "case directory base")
	return cmd
}
