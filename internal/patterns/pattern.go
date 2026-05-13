package patterns

import "regexp"

// Pattern is a single named regex rule with metadata.
type Pattern struct {
	Name     string `yaml:"name"`
	Regex    string `yaml:"regex"`
	Category string `yaml:"category"`
	Severity string `yaml:"severity"` // high | medium | low
	compiled *regexp.Regexp            // populated by Registry.Load()
}

// kitFile is the top-level structure of each YAML kit file.
type kitFile struct {
	Kit      string    `yaml:"kit"`
	Patterns []Pattern `yaml:"patterns"`
}
