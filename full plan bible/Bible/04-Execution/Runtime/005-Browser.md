# AIOS Bible — Execution
## 005 — Browser Automation Provider

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Execution/Runtime |
| Document ID | AIOS-BBL-004-RTM-005 |
| Source Laws | Law 2 — Law of Non-Execution, Law 7 — Law of Capability Bounds |
| Source Physics | Physics/010-Execution.md, Physics/007-Capabilities.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Browser Provider executes browser automation actions using Playwright (primary) with Puppeteer (fallback). It enables AIOS entities to navigate web pages, extract content, fill forms, take screenshots, and execute JavaScript within an isolated, bounded browser environment. Every browser session is ephemeral, capability-bounded, and fully recorded.

## Capability Declaration

| Property | Value |
|----------|-------|
| provider_id | `aios.provider.browser` |
| action_types | `browser.navigate`, `browser.extract`, `browser.screenshot`, `browser.evaluate`, `browser.form`, `browser.session` |
| max_parallelism | 20 concurrent browser contexts |
| default_timeout_ms | 60000 (1 minute) |
| supported_autonomy_levels | L0, L1, L2 |

## Action Types

| Action Type | Description | Parameters |
|-------------|-------------|------------|
| `browser.navigate` | Navigate to a URL and wait for page load | url, wait_until (load/domcontentloaded/networkidle), timeout |
| `browser.extract` | Extract content from the current page | selectors (CSS/XPath), extract_type (text/html/attribute/all) |
| `browser.screenshot` | Capture a screenshot of the viewport or full page | format (png/jpeg), full_page, quality, selector |
| `browser.evaluate` | Execute JavaScript in the page context | script, args, return_type |
| `browser.form` | Fill and submit a form | fields (selector → value map), submit_selector, wait_for_navigation |
| `browser.session` | Create or manage a browsing session | action (create/close/reset), cookies, localStorage |

## Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| browser_engine | `playwright` | Browser automation engine (playwright or puppeteer) |
| headless | `true` | Run browser in headless mode |
| viewport_width | 1280 | Default viewport width in pixels |
| viewport_height | 720 | Default viewport height in pixels |
| max_page_size_bytes | 10485760 | Maximum page size (10 MB) |
| max_screenshot_dimension | 4096 | Maximum screenshot dimension in pixels |
| navigation_timeout_ms | 30000 | Default navigation timeout |
| resource_blocklist | `[font, media, stylesheet]` | Resource types to block for performance |

## Edge Cases

| Scenario | Handling |
|----------|----------|
| Page redirects to a blocked domain | Terminate navigation; return RedirectBlocked error with final URL |
| CAPTCHA or bot detection triggered | Return BotDetection error; suggest manual intervention |
| Infinite scroll page with dynamic content | Extract visible content only; warn about truncated output |
| WebSocket or service worker connections | Block all non-HTTP connections at the browser process level |
| Page requires authentication (login form) | Deny; credential submission requires explicit form-fill capability |

## Integration Patterns

The Browser Provider is typically chained with a model provider in a perceive-reason-act loop: the entity uses a model to decide what to navigate to, then invokes the browser to navigate and extract content, then feeds extracted content back to the model for analysis. This pattern is used for web research, data extraction, and form automation workflows. The provider supports session persistence for multi-step workflows — a browser session can be created once and used across multiple executions within the same entity's mission scope, subject to capability bounds on session duration and page count.

## Isolation Model

Every execution receives a fresh browser context within an isolated, headless Chromium instance. Contexts are destroyed after execution completes. Cookies, localStorage, and sessionStorage are scoped to the execution context and are not shared across executions. Screenshots and extracted data are returned through the `ExecutionResult` and are not persisted in the browser sandbox.

## Navigation Restrictions

The provider enforces URL allow-list and block-list policies from the capability bounds. By default, only HTTPS URLs are allowed. Navigation to internal network addresses (10.x, 172.16-31.x, 192.168.x, localhost) is blocked unless explicitly authorized in the capability declaration. File protocol URLs are always blocked.

## Error Handling

| Error Code | Condition | Action |
|------------|-----------|--------|
| BRW-0001 | URL not in allowed scope | Deny with blocked category; log attempted URL |
| BRW-1001 | Navigation timeout | Return partial DOM state; suggest increasing timeout bound |
| BRW-2001 | Page load error (HTTP 4xx/5xx) | Return HTTP status and error body |
| BRW-3001 | Script evaluation blocked by CSP | Return CSP violation details; deny execution |
| BRW-4001 | Selector not found | Return NotFound error with available selector suggestions |
| BRW-5001 | Browser engine not available | Return Unhealthy; trigger Playwright/Puppeteer reinstall |

## Events

| Event Type | Fields |
|------------|--------|
| `Provider.Browser.NavigateStarted` | execution_id, url, navigation_id |
| `Provider.Browser.PageLoaded` | execution_id, url, status_code, dom_size_bytes, load_time_ms |
| `Provider.Browser.ExtractCompleted` | execution_id, selector_count, extracted_size_bytes |
| `Provider.Browser.ScreenshotCaptured` | execution_id, format, dimensions, file_size_bytes |
| `Provider.Browser.EvaluateCompleted` | execution_id, return_type, result_size_bytes |
| `Provider.Browser.FormSubmitted` | execution_id, field_count, submit_url, navigation_occurred |
| `Provider.Browser.NavigateFailed` | execution_id, url, error_code, error_message |

## Cross-Cutting Concerns

### Security

The browser runs in a sandboxed headless process with no access to the host filesystem, clipboard, or native APIs. Navigation is restricted by URL policy. JavaScript evaluation is scoped to the page origin. Screenshots are sanitized to remove EXIF data. The provider enforces a maximum page size (DOM tree depth, resource count, total bytes).

### Evidence

Every browser action produces an Event chain: navigation start → page load → action execution → result. Screenshots are included as result data but are not retained after the Event is processed. Navigation URLs are logged for audit.

### Lifecycle

The provider manages a pool of Chromium instances. On `initialize()`, it installs or validates the Playwright browser binary. On `shutdown()`, it closes all browser contexts and kills browser processes. Health checks verify browser binary availability and launch capability.

### Capability Bounds

The provider enforces: allowed URL patterns, blocked URL patterns, max page size, max screenshot resolution, max script execution time, max navigation time, max extracted content size, and max number of selector queries per execution.

### Communication

The provider communicates with the Chromium browser over the Chrome DevTools Protocol (CDP) via Playwright's internal connection. No external network communication occurs beyond the browser's HTTP requests, which are monitored and bounded.

### Design DNA

| Rule | Assessment |
|------|------------|
| R1 | Provider handles only browser automation — no data processing, no model inference |
| R5 | Playwright and Puppeteer are interchangeable backends via the same provider interface |
| R10 | Browser actions are simple command → navigate → extract → return sequences |
| R12 | All browser errors map to BRW-NNNN codes with DOM context |
| R13 | Navigation timeouts fail closed; browser crashes trigger context pool refresh |
| R14 | Paved path: validate URL → create context → execute action → extract result → destroy context |
| R15 | New browser actions extend the action type list without modifying the core isolation logic |

## Performance Characteristics

| Metric | Target | Notes |
|--------|--------|-------|
| Page load time | < 3s | Up to networkidle wait state |
| Screenshot capture | < 500ms | Viewport-only capture |
| Content extraction (100 selectors) | < 200ms | Parallel selector evaluation |
| JavaScript evaluation | < 100ms | Simple return-value scripts |
| Browser context creation | < 300ms | New incognito context in Chromium |
| Form submission | < 2s | Includes navigation wait after submit |

## Autonomy Level Behavior

| Level | Behavior |
|-------|----------|
| L0 | Every navigation requires human URL approval; screenshots require approval before capture |
| L1 | Navigation auto-proceeds; extracted content is flagged for human review |
| L2 | Navigation, extraction, and form submission are fully autonomous within URL scope bounds |
| L3 | Not supported — browser automation requires human oversight at all levels above L2 |
| L4 | Not supported — browser automation cannot operate at full autonomy |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Bible/04-Execution/Runtime/000-Overview.md | Runtime Engine architecture |
| Bible/04-Execution/Runtime/001-SDK.md | Provider SDK used to build this provider |
| Physics/010-Execution.md | Execution invariants for tool execution |
| Physics/007-Capabilities.md | Capability bounds for URL scope and browser resources |
