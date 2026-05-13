package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/RowanDark/draugr/internal/config"
	"github.com/RowanDark/draugr/internal/crawler"
	"github.com/RowanDark/draugr/internal/patterns"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var validFormats = map[string]bool{
	"stream": true,
	"json":   true,
	"csv":    true,
	"html":   true,
}

func main() {
	cfg := &config.Config{}
	var patternsRaw string

	root := &cobra.Command{
		Use:   "draugr",
		Short: "Draugr — web crawler and secret scanner",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if !validFormats[cfg.Format] {
				return fmt.Errorf("invalid format %q: must be one of stream|json|csv|html", cfg.Format)
			}
			if patternsRaw != "" {
				cfg.Patterns = strings.Split(patternsRaw, ",")
			}
			return nil
		},
	}

	scan := &cobra.Command{
		Use:   "scan",
		Short: "Crawl a target URL and scan for secrets",
		RunE: func(cmd *cobra.Command, args []string) error {
			var logger *zap.Logger
			var err error
			if cfg.Silent {
				logger = zap.NewNop()
			} else {
				logger, err = zap.NewProduction()
				if err != nil {
					return fmt.Errorf("failed to initialise logger: %w", err)
				}
			}
			defer logger.Sync() //nolint:errcheck

			logger.Info("resolved config",
				zap.String("url", cfg.URL),
				zap.Int("depth", cfg.Depth),
				zap.Int("max_pages", cfg.MaxPages),
				zap.Duration("delay", cfg.Delay),
				zap.Int("workers", cfg.Workers),
				zap.Int("js_workers", cfg.JSWorkers),
				zap.Bool("use_js", cfg.UseJS),
				zap.Strings("patterns", cfg.Patterns),
				zap.String("custom_file", cfg.CustomFile),
				zap.String("output", cfg.Output),
				zap.String("format", cfg.Format),
				zap.Bool("quiet", cfg.Quiet),
				zap.Bool("silent", cfg.Silent),
				zap.Bool("no_robots", cfg.NoRobots),
				zap.Bool("use_db", cfg.UseDB),
				zap.String("db_path", cfg.DBPath),
			)

			ctx, cancel := signal.NotifyContext(context.Background(),
				syscall.SIGINT, syscall.SIGTERM)
			defer cancel()

			c := crawler.New(cfg, logger)

			// Build and load pattern registry
			reg := patterns.New(logger)
			if err := reg.Load(cfg.Patterns); err != nil {
				return fmt.Errorf("patterns: %w", err)
			}
			logger.Info("patterns loaded", zap.Int("count", reg.Count()))

			// findings channel — Issue #5 will replace the consumer below
			findings := make(chan crawler.Finding, 200)

			// Matcher goroutine: reads pages, runs patterns, emits findings
			go func() {
				defer close(findings)
				for page := range c.Pages() {
					for _, f := range reg.Match(page) {
						findings <- f
					}
				}
			}()

			// Temporary findings consumer — replaced in Issue #5
			go func() {
				for f := range findings {
					logger.Info("finding",
						zap.String("pattern", f.Pattern),
						zap.String("severity", f.Severity),
						zap.String("url", f.PageURL),
						zap.String("match", f.Match),
					)
				}
			}()

			if err := c.Run(ctx); err != nil {
				return fmt.Errorf("crawler: %w", err)
			}

			// Wait for pages channel to close (crawl complete or ctx cancelled)
			for range c.Pages() {}

			return nil
		},
	}

	f := scan.Flags()
	f.StringVar(&cfg.URL, "url", "", "Target URL to crawl (required)")
	f.IntVar(&cfg.Depth, "depth", 3, "Max crawl depth")
	f.IntVar(&cfg.MaxPages, "pages", 100, "Max pages to visit")
	f.DurationVar(&cfg.Delay, "delay", 500_000_000, "Delay between requests")
	f.IntVar(&cfg.Workers, "workers", 10, "Concurrent HTTP workers")
	f.IntVar(&cfg.JSWorkers, "js-workers", 3, "Concurrent browser slots")
	f.BoolVar(&cfg.UseJS, "js", false, "Enable headless browser rendering")
	f.StringVar(&patternsRaw, "patterns", "", "Pattern kit names to load, comma-separated (api-keys,credentials,endpoints,financial,javascript,headers,cloud,all)")
	f.StringVar(&cfg.CustomFile, "custom", "", "Path to custom patterns YAML file")
	f.StringVar(&cfg.Output, "output", "", "Output file path (default: stdout)")
	f.StringVar(&cfg.Format, "format", "stream", "Output format: stream|json|csv|html")
	f.BoolVar(&cfg.Quiet, "quiet", false, "Suppress live streaming; print summary only")
	f.BoolVar(&cfg.Silent, "silent", false, "No output except fatal errors")
	f.BoolVar(&cfg.NoRobots, "no-robots", false, "Ignore robots.txt")
	f.BoolVar(&cfg.UseDB, "db", false, "Enable SQLite persistence")
	f.StringVar(&cfg.DBPath, "db-path", "draugr.db", "SQLite file path")
	f.StringVar(&cfg.ChromePath, "chrome-path", "/usr/bin/google-chrome",
		"Path to Chrome or Chromium binary for JS rendering")

	cobra.MarkFlagRequired(f, "url") //nolint:errcheck

	root.AddCommand(scan)

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}
