package logging

import (
	"log/slog"
	"os"
)

// Setup configures the default slog logger. The default level is warn; when
// verbose is true the level is debug. Logs are written to stderr as text.
func Setup(verbose bool) {
	level := slog.LevelWarn
	if verbose {
		level = slog.LevelDebug
	}
	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	slog.SetDefault(slog.New(handler))
}
