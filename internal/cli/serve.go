package cli

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/tokio-drift/raccoon/internal/casedir"
	"github.com/tokio-drift/raccoon/internal/logging"
	"github.com/tokio-drift/raccoon/internal/server"
	"github.com/tokio-drift/raccoon/web"
)

type serveOptions struct {
	port      int
	noBrowser bool
	out       string
	verbose   bool
}

// shutdownGrace is the time the server gets to finish open streams and
// background analyses before it is closed.
const shutdownGrace = 15 * time.Second

func newServeCommand(stdout, stderr io.Writer) *cobra.Command {
	opts := serveOptions{out: defaultBaseDir()}
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Serve the investigation UI for existing cases",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			logging.Setup(opts.verbose)
			if opts.port < 0 || opts.port > 65535 {
				return badInput(fmt.Errorf("invalid --port %d", opts.port))
			}
			base, err := filepath.Abs(opts.out)
			if err != nil {
				return internal(fmt.Errorf("resolve case directory: %w", err))
			}
			if err := os.MkdirAll(base, 0o700); err != nil {
				return internal(fmt.Errorf("create case directory: %w", err))
			}
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			return serveCase(ctx, base, opts.port, opts.noBrowser, stdout, stderr)
		},
	}
	f := cmd.Flags()
	f.IntVar(&opts.port, "port", 0, "listen port (default: random free port)")
	f.BoolVar(&opts.noBrowser, "no-browser", false, "do not open a browser")
	f.StringVar(&opts.out, "out", opts.out, "case directory base")
	f.BoolVarP(&opts.verbose, "verbose", "v", false, "enable debug logging")
	return cmd
}

func serveCase(ctx context.Context, base string, port int, noBrowser bool, stdout, stderr io.Writer) error {
	token, err := newToken()
	if err != nil {
		return internal(err)
	}
	addr := ""
	if port != 0 {
		addr = fmt.Sprintf("127.0.0.1:%d", port)
	}
	dist, err := fs.Sub(web.Dist, "dist")
	if err != nil {
		return internal(fmt.Errorf("open embedded UI: %w", err))
	}
	s, err := server.New(server.Config{
		Token:   token,
		DataDir: base,
		Dist:    dist,
		Addr:    addr,
	})
	if err != nil {
		return internal(fmt.Errorf("start server: %w", err))
	}
	if err := s.Start(); err != nil {
		return internal(fmt.Errorf("listen: %w", err))
	}
	defer s.Close()

	if cases, err := casedir.List(base); err == nil {
		fmt.Fprintf(stdout, "Cases: %d\n", len(cases))
	}
	writeDashboard(stdout, s)

	url := dashboardFullURL(s)
	if !noBrowser && url != "" {
		if err := openBrowserFn(url); err != nil {
			fmt.Fprintf(stderr, "warning: could not open a browser: %v\n", err)
			fmt.Fprintf(stderr, "open %s manually\n", url)
		}
	}

	<-ctx.Done()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	if err := s.Shutdown(shutdownCtx); err != nil {
		return internal(fmt.Errorf("shutdown: %w", err))
	}
	if pending := s.PendingAnalyses(); pending > 0 {
		fmt.Fprintf(stderr, "warning: %d analysis(es) were still running; the case is kept on disk\n", pending)
	}
	fmt.Fprintf(stdout, "Stopped. Cases are kept in %s\n", base)
	return nil
}
