package patterns

import (
	"fmt"
	"strings"
	"time"

	"github.com/RowanDark/draugr/internal/crawler"
)

// Match runs all loaded patterns against the page body and headers.
// It returns one Finding per match. A single pattern may produce
// multiple findings if it matches more than once on the page.
func (r *Registry) Match(page *crawler.Page) []crawler.Finding {
	var findings []crawler.Finding

	// Build header string once for matching
	var headerLines strings.Builder
	for k, v := range page.Headers {
		fmt.Fprintf(&headerLines, "%s: %s\n", k, v)
	}
	headerStr := headerLines.String()

	for _, p := range r.patterns {
		// Match against body
		findings = append(findings,
			r.matchContent(p, page.Body, page.URL, page)...)

		// Match against headers (separate URL suffix for clarity)
		findings = append(findings,
			r.matchContent(p, headerStr, page.URL+" (headers)", page)...)
	}

	return findings
}

// matchContent runs a single compiled pattern against a content string.
func (r *Registry) matchContent(
	p Pattern,
	content string,
	sourceURL string,
	page *crawler.Page,
) []crawler.Finding {
	var findings []crawler.Finding

	matches := p.compiled.FindAllStringIndex(content, -1)
	for _, loc := range matches {
		start, end := loc[0], loc[1]

		// Extract match text, capped at 200 chars
		matchText := content[start:end]
		if len(matchText) > 200 {
			matchText = matchText[:200]
		}

		// Extract context: up to 100 chars before and after
		ctxStart := start - 100
		if ctxStart < 0 {
			ctxStart = 0
		}
		ctxEnd := end + 100
		if ctxEnd > len(content) {
			ctxEnd = len(content)
		}
		context := strings.Join(
			strings.Fields(content[ctxStart:ctxEnd]), " ")

		findings = append(findings, crawler.Finding{
			URL:        sourceURL,
			PageURL:    page.URL,
			Pattern:    p.Name,
			Category:   p.Category,
			Severity:   p.Severity,
			Match:      matchText,
			Context:    context,
			StatusCode: page.StatusCode,
			Timestamp:  time.Now(),
			FromJS:     page.FromJS,
		})
	}

	return findings
}
