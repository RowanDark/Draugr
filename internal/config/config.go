package config

import "time"

type Config struct {
	URL        string
	Depth      int
	MaxPages   int
	Delay      time.Duration
	Workers    int
	JSWorkers  int
	UseJS      bool
	Patterns   []string
	CustomFile string
	Output     string
	Format     string
	Quiet      bool
	Silent     bool
	NoRobots   bool
	UseDB      bool
	DBPath     string
	ChromePath string  // path to Chrome/Chromium binary
}
