package cli

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/tokio-drift/raccoon/internal/capture"
	"github.com/tokio-drift/raccoon/internal/casedir"
	"github.com/tokio-drift/raccoon/internal/intel"
	"github.com/tokio-drift/raccoon/internal/limits"
	"github.com/tokio-drift/raccoon/internal/logging"
	"github.com/tokio-drift/raccoon/internal/model"
	"github.com/tokio-drift/raccoon/internal/pipeline"
	"github.com/tokio-drift/raccoon/internal/report"
	"github.com/tokio-drift/raccoon/internal/resource"
	"github.com/tokio-drift/raccoon/internal/store"
)

type analyzeOptions struct {
	port        int
	noBrowser   bool
	out         string
	offline     bool
	vtKey       string
	vtRate      int
	rules       string
	maxFileSize string
	maxMem      string
	maxDisk     string
	workers     int
	report      string
	verbose     bool
}

func newAnalyzeCommand(stdout, stderr io.Writer) *cobra.Command {
	opts := analyzeOptions{
		out:         defaultBaseDir(),
		vtKey:       os.Getenv("RACCOON_VT_API_KEY"),
		vtRate:      limits.VTRatePerMinute,
		maxFileSize: "200MB",
		maxMem:      "2GB",
		workers:     defaultWorkers(),
	}
	cmd := &cobra.Command{
		Use:   "analyze <pcap>",
		Short: "Analyze a capture and serve the investigation UI",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := runAnalyze(args[0], opts, stdout, stderr); err != nil {
				return err
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.IntVar(&opts.port, "port", 0, "listen port (default: random free port)")
	f.BoolVar(&opts.noBrowser, "no-browser", false, "do not open a browser")
	f.StringVar(&opts.out, "out", opts.out, "case directory base")
	f.BoolVar(&opts.offline, "offline", false, "disable VirusTotal lookups")
	f.StringVar(&opts.vtKey, "vt-key", opts.vtKey, "VirusTotal API key (env RACCOON_VT_API_KEY)")
	f.IntVar(&opts.vtRate, "vt-rate", opts.vtRate, "VirusTotal requests per minute")
	f.StringVar(&opts.rules, "rules", "", "YARA rules directory (default: embedded rules)")
	f.StringVar(&opts.maxFileSize, "max-file-size", opts.maxFileSize, "maximum carved file size")
	f.StringVar(&opts.maxMem, "max-mem", opts.maxMem, "memory budget (minimum 256MB)")
	f.StringVar(&opts.maxDisk, "max-disk", "", "maximum disk use (default: unlimited)")
	f.IntVar(&opts.workers, "workers", opts.workers, "worker goroutines")
	f.StringVar(&opts.report, "report", "", "write a report and exit (html, json)")
	f.BoolVarP(&opts.verbose, "verbose", "v", false, "enable debug logging")
	return cmd
}

func runAnalyze(input string, opts analyzeOptions, stdout, stderr io.Writer) error {
	logging.Setup(opts.verbose)

	if opts.port < 0 || opts.port > 65535 {
		return badInput(fmt.Errorf("invalid --port %d", opts.port))
	}
	if opts.vtRate < 0 {
		return badInput(fmt.Errorf("invalid --vt-rate %d", opts.vtRate))
	}
	maxMem, err := resource.ParseSize(opts.maxMem)
	if err != nil {
		return badInput(fmt.Errorf("invalid --max-mem: %w", err))
	}
	budget, err := resource.NewBudget(maxMem, 0, opts.workers)
	if err != nil {
		return badInput(fmt.Errorf("invalid resource flags: %w", err))
	}
	if cmd := opts.maxDisk; cmd != "" {
		budget.MaxDisk, err = resource.ParseSize(cmd)
		if err != nil {
			return badInput(fmt.Errorf("invalid --max-disk: %w", err))
		}
	} else {
		fmt.Fprintln(stderr, "warning: --max-disk is not set; disk use is unlimited")
	}
	maxFileSize, err := resource.ParseSize(opts.maxFileSize)
	if err != nil {
		return badInput(fmt.Errorf("invalid --max-file-size: %w", err))
	}
	if opts.rules != "" {
		st, err := os.Stat(opts.rules)
		if err != nil {
			return badInput(fmt.Errorf("rules directory: %w", err))
		}
		if !st.IsDir() {
			return badInput(fmt.Errorf("rules path %q is not a directory", opts.rules))
		}
	}
	var reportFormat report.Format
	if opts.report != "" {
		reportFormat, err = report.ParseFormat(opts.report)
		if err != nil {
			return badInput(err)
		}
	}

	st, err := os.Stat(input)
	if err != nil {
		return badInput(fmt.Errorf("cannot read input %q: %w", input, err))
	}
	if st.IsDir() {
		return badInput(fmt.Errorf("input %q is a directory", input))
	}
	if _, err := capture.Validate(input); err != nil {
		return badInput(fmt.Errorf("invalid capture %q: %w", input, err))
	}

	base, err := filepath.Abs(opts.out)
	if err != nil {
		return internal(fmt.Errorf("resolve case directory: %w", err))
	}
	src, err := filepath.Abs(input)
	if err != nil {
		return internal(fmt.Errorf("resolve input: %w", err))
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	c, err := casedir.Create(base, casedir.Options{
		PCAP: src,
		Extra: map[string]any{
			"max_mem":       budget.MaxMem,
			"max_disk":      budget.MaxDisk,
			"workers":       budget.Workers,
			"max_file_size": maxFileSize,
			"offline":       opts.offline,
		},
	})
	if err != nil {
		return internal(fmt.Errorf("create case: %w", err))
	}
	db, err := store.Open(c.DB())
	if err != nil {
		return internal(fmt.Errorf("open case database: %w", err))
	}

	svc, err := newIntelService(ctx, db, c, opts)
	if err != nil {
		db.Close()
		return internal(err)
	}
	progress := newProgressPrinter(stdout)
	result, runErr := pipeline.Run(ctx, pipeline.Options{
		PCAPPath:    src,
		Case:        c,
		Budget:      budget,
		Store:       db,
		Progress:    pipeline.NewProgress(),
		OnProgress:  progress.Update,
		MaxFileSize: maxFileSize,
		Hooks:       intelHooks(db, svc, c),
	})
	svc.Close()
	closeErr := db.Close()
	if runErr != nil {
		return internal(fmt.Errorf("analysis failed: %w", runErr))
	}
	if closeErr != nil {
		return internal(fmt.Errorf("close case database: %w", closeErr))
	}

	fmt.Fprintf(stdout, "Case: %s\n", c.Dir)
	fmt.Fprintf(stdout, "Analyzed %d packets, %d bytes, %d streams, %d carved files in %s\n",
		result.Packets, result.Bytes, result.Streams, result.Files, result.Duration.Round(time.Millisecond))

	if opts.report != "" {
		dst, err := report.Write(c.Dir, reportFormat)
		if err != nil {
			return internal(err)
		}
		fmt.Fprintf(stdout, "Report: %s\n", dst)
		return nil
	}
	return serveCase(ctx, base, opts.port, opts.noBrowser, stdout, stderr)
}

func newIntelService(ctx context.Context, db *store.DB, c *casedir.Case, opts analyzeOptions) (*intel.Service, error) {
	engine, err := intel.NewSubprocessEngine(opts.rules)
	if err != nil {
		return nil, fmt.Errorf("initialize YARA: %w", err)
	}
	var vt intel.VTClient
	if !opts.offline && opts.vtKey != "" {
		vt = intel.NewVTClient(opts.vtKey)
	}
	return intel.NewService(ctx, intel.ServiceConfig{
		Store:           db,
		YARA:            engine,
		VTClient:        vt,
		Cache:           intel.NewCache(db, limits.VerdictCacheTTL),
		Offline:         opts.offline,
		VTRatePerMinute: opts.vtRate,
	}), nil
}

func intelHooks(db *store.DB, svc *intel.Service, c *casedir.Case) pipeline.Hooks {
	return pipeline.Hooks{
		IntelEnqueue: func(ctx context.Context, file *model.CarvedFile) error {
			info := intel.FileInfo{
				FileID:   file.ID,
				SHA256:   file.SHA256,
				AbsPath:  filepath.Join(c.Dir, filepath.FromSlash(file.Path)),
				StreamID: file.StreamID,
			}
			if stream, err := db.StreamByID(file.StreamID); err == nil {
				info.Src = net.JoinHostPort(stream.SrcIP, fmt.Sprint(stream.SrcPort))
				info.Dst = net.JoinHostPort(stream.DstIP, fmt.Sprint(stream.DstPort))
				info.Proto = stream.Proto
				info.TS = stream.StartTS
				info.PacketNo = stream.FirstPacket
			}
			svc.ProcessFile(info)
			return nil
		},
	}
}

type progressPrinter struct {
	out       io.Writer
	lastStage string
}

func newProgressPrinter(out io.Writer) *progressPrinter {
	return &progressPrinter{out: out}
}

func (p *progressPrinter) Update(s pipeline.ProgressSnapshot) {
	if s.Stage == p.lastStage {
		return
	}
	p.lastStage = s.Stage
	pct := 0
	switch s.Stage {
	case "read":
		pct = 15
	case "process":
		pct = 80
	case "done":
		pct = 100
	}
	fmt.Fprintf(p.out, "%-8s %3d%%  packets=%d bytes=%d streams=%d files=%d\n",
		s.Stage, pct, s.PacketsRead, s.BytesRead, s.Streams, s.Files)
}
