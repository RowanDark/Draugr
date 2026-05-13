package crawler

import "time"

type Finding struct {
	URL        string    // URL where the pattern matched (may include " (headers)" suffix)
	PageURL    string    // canonical page URL that was crawled
	Pattern    string    // pattern name that matched
	Category   string    // pattern category
	Severity   string    // high | medium | low
	Match      string    // matched text, truncated to 200 chars
	Context    string    // up to 100 chars before and after match
	StatusCode int       // HTTP status of the source page
	Timestamp  time.Time
	FromJS     bool // true if content came from browser render (Issue #4)
}
