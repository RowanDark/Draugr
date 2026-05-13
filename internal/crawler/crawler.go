package crawler

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/html"

	"github.com/RowanDark/draugr/internal/config"
	"go.uber.org/zap"
)

type Crawler struct {
	cfg       *config.Config
	log       *zap.Logger
	client    *http.Client
	domain    string
	visited   sync.Map
	queue     chan queueItem
	pages     chan *Page
	done      chan struct{}
	wg        sync.WaitGroup // tracks in-flight queue items
	pageCount atomic.Int64
	pool      *BrowserPool // nil when --js is not set
}

type queueItem struct {
	url   string
	depth int
}

// New constructs a Crawler. Does not start crawling.
func New(cfg *config.Config, log *zap.Logger) *Crawler {
	c := &Crawler{
		cfg:   cfg,
		log:   log,
		queue: make(chan queueItem, 1000),
		pages: make(chan *Page, 100),
		done:  make(chan struct{}),
	}
	c.client = &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			if c.domain != "" && req.URL.Host != c.domain {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	return c
}

// Pages returns the read-only channel of fetched pages.
// The channel is closed when crawling is complete.
func (c *Crawler) Pages() <-chan *Page {
	return c.pages
}

// Run starts the worker pool and blocks until crawling is complete or ctx is cancelled.
func (c *Crawler) Run(ctx context.Context) error {
	baseURL, err := url.Parse(c.cfg.URL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	c.domain = baseURL.Host

	if c.cfg.UseJS {
		pool, err := NewBrowserPool(ctx, c.cfg.JSWorkers, c.cfg.ChromePath, c.log)
		if err != nil {
			return fmt.Errorf("browser pool: %w", err)
		}
		c.pool = pool
		defer c.pool.Close()
	}

	var workerWg sync.WaitGroup
	for i := 0; i < c.cfg.Workers; i++ {
		workerWg.Add(1)
		go func() {
			defer workerWg.Done()
			c.worker(ctx)
		}()
	}

	// Coordinator: close queue when all in-flight items are processed.
	go func() {
		c.wg.Wait()
		close(c.queue)
	}()

	// Seed the queue.
	c.wg.Add(1)
	c.queue <- queueItem{url: c.cfg.URL, depth: 0}

	// Wait for all workers to finish or context cancellation.
	workerDone := make(chan struct{})
	go func() {
		workerWg.Wait()
		close(workerDone)
	}()

	select {
	case <-workerDone:
	case <-ctx.Done():
		workerWg.Wait()
	}

	close(c.pages)
	return nil
}

func (c *Crawler) worker(ctx context.Context) {
	for item := range c.queue {
		c.processItem(ctx, item)
	}
}

func (c *Crawler) processItem(ctx context.Context, item queueItem) {
	defer c.wg.Done()

	if ctx.Err() != nil {
		return
	}

	if _, loaded := c.visited.LoadOrStore(item.url, struct{}{}); loaded {
		return
	}

	if c.pageCount.Add(1) > int64(c.cfg.MaxPages) {
		c.pageCount.Add(-1)
		return
	}

	page, err := c.fetch(ctx, item.url)
	if err != nil {
		c.log.Warn("fetch failed", zap.String("url", item.url), zap.Error(err))
		return
	}
	page.Depth = item.depth

	if c.pool != nil {
		rendered, err := c.pool.Render(ctx, item.url)
		if err != nil {
			c.log.Warn("browser render failed",
				zap.String("url", item.url),
				zap.Error(err),
			)
			// fall through: send the HTTP-fetched page as-is
		} else {
			page.Body = rendered
			page.FromJS = true
		}
	}

	select {
	case c.pages <- page:
	case <-ctx.Done():
		return
	}

	if item.depth < c.cfg.Depth {
		base, err := url.Parse(item.url)
		if err == nil {
			for _, link := range extractLinks(page.Body, base, c.domain) {
				c.wg.Add(1)
				select {
				case c.queue <- queueItem{url: link, depth: item.depth + 1}:
				default:
					c.wg.Done()
				}
			}
		}
	}

	if c.cfg.Delay > 0 {
		select {
		case <-time.After(c.cfg.Delay):
		case <-ctx.Done():
		}
	}
}

func (c *Crawler) fetch(ctx context.Context, rawURL string) (*Page, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "draugr/2.0")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return nil, err
	}

	headers := make(map[string]string, len(resp.Header))
	for k, vs := range resp.Header {
		if len(vs) > 0 {
			headers[k] = vs[0]
		}
	}

	return &Page{
		URL:        rawURL,
		Body:       string(bodyBytes),
		Headers:    headers,
		StatusCode: resp.StatusCode,
		FromJS:     false,
	}, nil
}

func extractLinks(body string, base *url.URL, domain string) []string {
	tokenizer := html.NewTokenizer(strings.NewReader(body))
	seen := make(map[string]struct{})
	var result []string

	for {
		tt := tokenizer.Next()
		if tt == html.ErrorToken {
			break
		}
		if tt != html.StartTagToken && tt != html.SelfClosingTagToken {
			continue
		}

		token := tokenizer.Token()
		var href string
		switch token.Data {
		case "a":
			for _, attr := range token.Attr {
				if attr.Key == "href" {
					href = attr.Val
					break
				}
			}
		case "form":
			for _, attr := range token.Attr {
				if attr.Key == "action" {
					href = attr.Val
					break
				}
			}
		default:
			continue
		}

		if href == "" {
			continue
		}

		parsed, err := base.Parse(href)
		if err != nil {
			continue
		}

		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			continue
		}

		if parsed.Host != domain {
			continue
		}

		parsed.Fragment = ""
		link := parsed.String()

		if _, exists := seen[link]; !exists {
			seen[link] = struct{}{}
			result = append(result, link)
		}
	}

	if result == nil {
		return []string{}
	}
	return result
}
