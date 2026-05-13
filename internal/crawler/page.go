package crawler

// Page holds the raw fetched content of a single URL.
// Pattern matching (Issue #3) reads from this.
type Page struct {
	URL        string
	Body       string
	Headers    map[string]string
	StatusCode int
	Depth      int
	FromJS     bool
}
