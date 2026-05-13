package crawler

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/chromedp/chromedp"
	"go.uber.org/zap"
)

// BrowserPool manages a semaphore-limited pool of chromedp browser slots.
// A single browser process is shared; slots control tab concurrency.
type BrowserPool struct {
	slots     chan struct{}
	allocator context.Context
	cancel    context.CancelFunc
	log       *zap.Logger
}

// NewBrowserPool creates and starts a shared headless Chrome instance.
// slots is cfg.JSWorkers (default 3).
func NewBrowserPool(ctx context.Context, slots int, execPath string, log *zap.Logger) (*BrowserPool, error) {
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.ExecPath(execPath),
		chromedp.NoFirstRun,
		chromedp.NoDefaultBrowserCheck,
		chromedp.Headless,
		chromedp.DisableGPU,
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("disable-extensions", true),
		chromedp.Flag("blink-settings", "imagesEnabled=false"),
		chromedp.UserAgent("draugr/2.0"),
	)

	allocCtx, cancel := chromedp.NewExecAllocator(ctx, opts...)

	p := &BrowserPool{
		slots:     make(chan struct{}, slots),
		allocator: allocCtx,
		cancel:    cancel,
		log:       log,
	}
	for i := 0; i < slots; i++ {
		p.slots <- struct{}{}
	}

	log.Info("browser pool initialised", zap.Int("slots", slots))
	return p, nil
}

// Render navigates to url in a new tab, waits for the page to settle,
// extracts enriched content, and returns it as a single string.
// Blocks until a slot is available or ctx is cancelled.
func (p *BrowserPool) Render(ctx context.Context, url string) (string, error) {
	select {
	case <-p.slots:
		defer func() { p.slots <- struct{}{} }()
	case <-ctx.Done():
		return "", ctx.Err()
	}

	tabCtx, cancel := chromedp.NewContext(p.allocator)
	defer cancel()
	tabCtx, cancelTimeout := context.WithTimeout(tabCtx, 30*time.Second)
	defer cancelTimeout()

	var renderedHTML string
	var globalVars string
	var localStore string
	var sessionStore string

	err := chromedp.Run(tabCtx,
		chromedp.Navigate(url),
		chromedp.WaitReady("body", chromedp.ByQuery),
		chromedp.OuterHTML("html", &renderedHTML, chromedp.ByQuery),
		chromedp.Evaluate(`
			(function() {
				var vars = {};
				for (var k in window) {
					try {
						var v = window[k];
						if (typeof v === 'string' && v.length > 0 && v.length < 500) {
							vars[k] = v;
						}
					} catch(e) {}
				}
				return JSON.stringify(vars);
			})()
		`, &globalVars),
		chromedp.Evaluate(`JSON.stringify(Object.fromEntries(
			Object.keys(localStorage).map(k => [k, localStorage.getItem(k)])
		))`, &localStore),
		chromedp.Evaluate(`JSON.stringify(Object.fromEntries(
			Object.keys(sessionStorage).map(k => [k, sessionStorage.getItem(k)])
		))`, &sessionStore),
	)
	if err != nil {
		p.log.Warn("browser render failed", zap.String("url", url), zap.Error(err))
		return "", err
	}

	var sb strings.Builder
	sb.WriteString(renderedHTML)
	if globalVars != "" && globalVars != "null" && globalVars != "{}" {
		fmt.Fprintf(&sb, "\n\n%s", globalVars)
	}
	if localStore != "" && localStore != "null" && localStore != "{}" {
		fmt.Fprintf(&sb, "\n\n%s", localStore)
	}
	if sessionStore != "" && sessionStore != "null" && sessionStore != "{}" {
		fmt.Fprintf(&sb, "\n\n%s", sessionStore)
	}
	return sb.String(), nil
}

// Close shuts down the browser and releases all resources.
func (p *BrowserPool) Close() {
	if p.cancel != nil {
		p.cancel()
	}
}
