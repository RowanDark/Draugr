package crawler

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/html"
	"go.uber.org/zap"

	"github.com/RowanDark/draugr/internal/config"
)

type Crawler struct {
	cfg    *config.Config
	log    *zap.Logger
	client *http.Client
	pool   *BrowserPool
	pages  chan *Page
}

type queueItem struct {
	url   string
	depth int
}

func New(cfg *config.Config, log *zap.Logger) *Crawler {
	return &Crawler{
		cfg:   cfg,
		log:   log,
		pages: make(chan *Page, 100),
		client: &http.Client{
			Timeout: 15 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
	}
}

func (c *Crawler) Pages() <-chan *Page {
	return c.pages
}

func (c *Crawler) Run(ctx context.Context) error {
	base, err := url.Parse(c.cfg.URL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	domain := base.Host

	if c.cfg.UseJS {
		pool, err := NewBrowserPool(ctx, c.cfg.JSWorkers, c.cfg.ChromePath, c.log)
		if err != nil {
			return fmt.Errorf("browser pool: %w", err)
		}
		c.pool = pool
	}

	go func() {
		if c.pool != nil {
			defer c.pool.Close()
		}
		defer close(c.pages)

		visited := make(map[string]struct{})
		queue := []queueItem{{url: c.cfg.URL, depth: 0}}
		pageCount := 0

		for len(queue) > 0 {
			select {
			case <-ctx.Done():
				return
			default:
			}

			item := queue[0]
			queue = queue[1:]

			if _, seen := visited[item.url]; seen {
				continue
			}
			visited[item.url] = struct{}{}

			if pageCount >= c.cfg.MaxPages {
				continue
			}
			pageCount++

			page, err := c.fetch(ctx, item.url)
			if err != nil {
				c.log.Warn("fetch failed",
					zap.String("url", item.url),
					zap.Error(err),
				)
				continue
			}
			page.Depth = item.depth

			if c.pool != nil {
				rendered, err := c.pool.Render(ctx, item.url)
				if err != nil {
					c.log.Warn("browser render failed",
						zap.String("url", item.url),
						zap.Error(err),
					)
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
					for _, link := range extractLinks(page.Body, base, domain) {
						if _, seen := visited[link]; !seen {
							queue = append(queue, queueItem{
								url:   link,
								depth: item.depth + 1,
							})
						}
					}
				}
			}

			if c.cfg.Delay > 0 {
				select {
				case <-time.After(c.cfg.Delay):
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	return nil
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
