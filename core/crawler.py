"""
Web Crawler Module v5.0
Discovers URLs and forms in the target application.

Two crawlers are provided:
  WebCrawler       — fast, zero-dependency HTML-only crawler (requests + BeautifulSoup).
                     Works on any server-rendered site. Misses JS-rendered routes.
  PlaywrightCrawler — headless-browser crawler that executes JavaScript before
                     extracting links and forms. Discovers SPA routes, JS-rendered
                     menus, hash-router paths (#/admin/users), and API calls made
                     by the page. Falls back to WebCrawler if Playwright is not
                     installed (import-guarded, never crashes the scanner).

Key accuracy fixes vs original:
  - JS-redirect link extraction removed: window.location patterns in page JS
    are NOT reliable page links — they are mostly event handlers, cookie
    banners, and "back" buttons that have nothing to do with site navigation,
    and feeding them to the scanner produces broken/false-positive test URLs.
  - URL normalisation: query params sorted so ?a=1&b=2 and ?b=2&a=1 are
    deduplicated to the same URL.
  - follow_redirects respects scanner config.
  - Respects max_urls hard cap to avoid runaway crawls.
"""

import logging
import time
from typing import Dict, List, Set
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from xml.etree import ElementTree

import requests
from bs4 import BeautifulSoup
from colorama import Fore, Style

from config import SCANNER_CONFIG

logger = logging.getLogger(__name__)


try:
    from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False


class WebCrawler:

    SKIP_EXTENSIONS = {
        '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
        '.zip', '.tar', '.gz', '.rar', '.7z', '.exe', '.dmg',
        '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.ico', '.webp',
        '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv', '.webm',
        '.css', '.map', '.woff', '.woff2', '.ttf', '.eot',
    }

    def __init__(self, base_url: str, session: requests.Session, config: Dict):
        self.base_url  = base_url.rstrip('/')
        self.session   = session
        self.config    = config

        # Bug 3 fix: track ALL domains seen after redirects so
        # www.example.com links are not dropped when base is example.com
        parsed = urlparse(base_url)
        self.domain  = parsed.netloc
        self._allowed_domains: Set[str] = {
            self.domain,
            self.domain.lstrip('www.'),
            'www.' + self.domain.lstrip('www.'),
        }

        self.visited_urls:    Set[str]              = set()
        self.discovered_urls: Set[str]              = set()
        self.forms_data:      Dict[str, List[Dict]] = {}

    # ── URL helpers ────────────────────────────────────────────────────────

    def is_same_domain(self, url: str) -> bool:
        try:
            netloc = urlparse(url).netloc
            return netloc in self._allowed_domains
        except Exception:
            return False

    def _register_redirect_domain(self, final_url: str) -> None:
        """Add domain seen after redirect so links from it are accepted."""
        netloc = urlparse(final_url).netloc
        if netloc:
            self._allowed_domains.add(netloc)
            self._allowed_domains.add(netloc.lstrip('www.'))
            self._allowed_domains.add('www.' + netloc.lstrip('www.'))

    def is_valid_url(self, url: str) -> bool:
        try:
            parsed = urlparse(url)
            if parsed.scheme not in ('http', 'https'):
                return False
            path = parsed.path.lower()
            for ext in self.SKIP_EXTENSIONS:
                if path.endswith(ext):
                    return False
            if not self.is_same_domain(url):
                return False
            return True
        except Exception:
            return False

    @staticmethod
    def normalise_url(url: str) -> str:
        """Normalise URL so ?b=2&a=1 and ?a=1&b=2 are the same."""
        try:
            p = urlparse(url.split('#')[0])   # strip fragment
            qs = urlencode(sorted(parse_qs(p.query).items()), doseq=True)
            return urlunparse((p.scheme, p.netloc, p.path, p.params, qs, ''))
        except Exception:
            return url.split('#')[0]

    # ── Extraction ──────────────────────────────────────────────────────────

    def extract_links(self, html: str, base_url: str) -> List[str]:
        """
        Extract navigable links from HTML.

        Only <a href="..."> links are extracted. JavaScript redirect patterns
        (window.location, location.href) were removed because they are not
        reliable navigation links — they appear in event handlers, cookie
        banners, and utility scripts throughout the page and feeding them to
        the scanner produced meaningless / broken probe URLs.
        """
        links = []
        try:
            soup = BeautifulSoup(html, 'html.parser')
            for tag in soup.find_all('a', href=True):
                href = tag['href'].strip()
                if not href or href.startswith(('mailto:', 'tel:', 'javascript:')):
                    continue
                full_url = urljoin(base_url, href)
                full_url = self.normalise_url(full_url)
                if self.is_valid_url(full_url):
                    links.append(full_url)
        except Exception as exc:
            logger.debug("Link extraction error: %s", exc)
        return list(set(links))

    def extract_forms(self, html: str, url: str) -> List[Dict]:
        """Extract all forms from HTML."""
        forms = []
        try:
            soup = BeautifulSoup(html, 'html.parser')
            for form in soup.find_all('form'):
                action = form.get('action', '')
                form_data = {
                    'action': urljoin(url, action) if action else url,
                    'method': form.get('method', 'GET').upper(),
                    'inputs': [],
                }
                for tag in form.find_all(['input', 'textarea', 'select']):
                    name = tag.get('name')
                    if name:
                        form_data['inputs'].append({
                            'name':  name,
                            'type':  tag.get('type', 'text').lower(),
                            'value': tag.get('value', ''),
                        })
                forms.append(form_data)
        except Exception as exc:
            logger.debug("Form extraction error: %s", exc)
        self.forms_data[url] = forms
        return forms

    # ── Discovery seeding (robots.txt / sitemap.xml) ────────────────────────
    #
    # Accuracy/coverage fix: link-following alone misses pages that exist
    # but aren't linked from anywhere the crawler visits (orphaned admin
    # panels, old paths still live, staging routes) — exactly the pages an
    # attacker would find first, and exactly what "crawl ALL pages" needs.
    # robots.txt and sitemap.xml are the two standard, low-cost sources of
    # such URLs, so we seed the frontier with them before the BFS starts.
    # These are *discovery* seeds only — normal detectors still run their
    # own checks (baseline, auth, etc.) on whatever is fetched.

    def _seed_from_robots_and_sitemap(self) -> List[str]:
        seeds: Set[str] = set()
        parsed_base = urlparse(self.base_url)
        origin = f"{parsed_base.scheme}://{parsed_base.netloc}"
        timeout = self.config.get('request_timeout', 30)

        # -- robots.txt: Sitemap: lines + Disallow/Allow paths --------------
        sitemap_urls: List[str] = [urljoin(origin, "/sitemap.xml")]
        try:
            resp = self.session.get(urljoin(origin, "/robots.txt"), timeout=timeout)
            if resp.status_code == 200 and resp.text:
                for raw_line in resp.text.splitlines():
                    line = raw_line.strip()
                    if not line or line.startswith('#') or ':' not in line:
                        continue
                    directive, _, value = line.partition(':')
                    directive = directive.strip().lower()
                    value = value.strip()
                    if not value:
                        continue
                    if directive == 'sitemap':
                        sitemap_urls.append(value)
                    elif directive in ('disallow', 'allow'):
                        # Disallowed paths are real attack surface for an
                        # authorized scan — a crawler that only follows
                        # links would never find them, yet they're
                        # frequently where sensitive functionality lives.
                        if value in ('/', '*', ''):
                            continue
                        candidate = urljoin(origin, value.split('*')[0])
                        full = self.normalise_url(candidate)
                        if self.is_valid_url(full):
                            seeds.add(full)
        except Exception as exc:
            logger.debug("robots.txt fetch failed for %s: %s", origin, exc)

        # -- sitemap.xml (and sitemap-index files, recursively) -------------
        seen_sitemaps: Set[str] = set()
        to_fetch = list(dict.fromkeys(sitemap_urls))  # de-dup, preserve order
        while to_fetch and len(seen_sitemaps) < 20:   # cap: avoid sitemap-bomb DoS
            sm_url = to_fetch.pop(0)
            if sm_url in seen_sitemaps:
                continue
            seen_sitemaps.add(sm_url)
            try:
                resp = self.session.get(sm_url, timeout=timeout)
                if resp.status_code != 200 or not resp.text.strip():
                    continue
                root = ElementTree.fromstring(resp.content)
                tag = root.tag.lower()
                # Namespaces vary across sitemap generators; match on the
                # local tag name only, ignoring the xmlns prefix.
                for child in root.iter():
                    local = child.tag.rsplit('}', 1)[-1].lower()
                    if local != 'loc' or not (child.text or '').strip():
                        continue
                    loc = child.text.strip()
                    if 'sitemapindex' in tag:
                        if loc not in seen_sitemaps:
                            to_fetch.append(loc)
                    else:
                        full = self.normalise_url(loc)
                        if self.is_valid_url(full):
                            seeds.add(full)
                        if len(seeds) >= self.config.get('max_urls', 500) * 2:
                            break
            except ElementTree.ParseError:
                logger.debug("Sitemap at %s is not valid XML — skipped", sm_url)
            except Exception as exc:
                logger.debug("Sitemap fetch failed for %s: %s", sm_url, exc)

        if seeds:
            print(f"{Fore.CYAN}[*] Discovered {len(seeds)} additional URL(s) "
                  f"from robots.txt/sitemap.xml{Style.RESET_ALL}")
        return list(seeds)

    # ── Crawl ───────────────────────────────────────────────────────────────

    def crawl(self, start_url: str = None, max_depth: int = None) -> List[str]:
        start     = start_url or self.base_url
        # Bug 4 fix: use explicit None check — `max_depth or N` treats 0 as falsy
        max_depth = max_depth if max_depth is not None else self.config.get('max_depth', 3)
        max_urls  = self.config.get('max_urls', 500)

        urls_to_visit = [(start, 0)]

        # Seed the frontier with robots.txt/sitemap.xml URLs at depth 1 so
        # they're subject to the normal max_depth/max_urls bookkeeping but
        # don't require being linked from the homepage to be reached.
        if self.config.get('crawl_robots_sitemap', True):
            for seed_url in self._seed_from_robots_and_sitemap():
                norm = self.normalise_url(seed_url)
                if norm not in self.visited_urls:
                    self.discovered_urls.add(seed_url)
                    urls_to_visit.append((seed_url, 1))

        print(f"{Fore.CYAN}[*] Starting crawl from: {start}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Max depth: {max_depth}, Max URLs: {max_urls}{Style.RESET_ALL}")

        while urls_to_visit and len(self.visited_urls) < max_urls:
            current_url, depth = urls_to_visit.pop(0)
            normalised = self.normalise_url(current_url)

            if normalised in self.visited_urls or depth > max_depth:
                continue

            try:
                print(f"{Fore.BLUE}[*] Crawling: {current_url}{Style.RESET_ALL}", end='\r')

                response = self.session.get(
                    current_url,
                    timeout=self.config.get('request_timeout', 30),
                    allow_redirects=True,
                )

                # Bug 1 fix: mark visited immediately — before any processing
                # so a failed parse never leaves the URL in an unvisited state
                self.visited_urls.add(normalised)

                # Bug 3 fix: register the domain we actually landed on after
                # redirects (e.g. example.com → www.example.com) so links
                # from the redirected page are not rejected as "wrong domain"
                if response.url != current_url:
                    self._register_redirect_domain(response.url)
                    self.visited_urls.add(self.normalise_url(response.url))

                # Bug 2 fix: do not require exact 'text/html' content-type.
                # Some servers return empty content-type or 'application/xhtml+xml'.
                # Fall back to a quick HTML sniff when content-type is missing.
                ct = response.headers.get('content-type', '').lower()
                is_html = (
                    'text/html' in ct
                    or 'xhtml' in ct
                    or (not ct and response.text.lstrip().startswith('<'))
                )

                if is_html:
                    # Use response.url (after redirect) as base for link resolution
                    links = self.extract_links(response.text, response.url)
                    for link in links:
                        norm_link = self.normalise_url(link)
                        if norm_link not in self.visited_urls:
                            self.discovered_urls.add(link)
                            urls_to_visit.append((link, depth + 1))
                    forms = self.extract_forms(response.text, response.url)

                    # Coverage fix: a GET form's action is itself a navigable
                    # page (search results, filtered listings) that may not
                    # be linked anywhere else. Queue it like a normal link so
                    # the crawl doesn't stop at the form.
                    for form in forms:
                        if form.get('method', 'GET').upper() != 'GET':
                            continue
                        action = self.normalise_url(form.get('action', ''))
                        if action and self.is_valid_url(action) and action not in self.visited_urls:
                            self.discovered_urls.add(action)
                            urls_to_visit.append((action, depth + 1))

                time.sleep(self.config.get('delay', 0.2))

            except Exception as exc:
                logger.debug("Crawl error for %s: %s", current_url, exc)
                # Bug 1 fix: mark failed URLs as visited too — prevents
                # infinite retry of permanently unreachable pages
                self.visited_urls.add(normalised)
                continue

        all_urls = list(self.discovered_urls.union(self.visited_urls))
        print(f"\n{Fore.GREEN}[+] Crawl complete. "
              f"Visited {len(self.visited_urls)} URLs, "
              f"discovered {len(all_urls)} total{Style.RESET_ALL}")
        return all_urls

    def get_forms(self, url: str) -> List[Dict]:
        """Get forms for a specific URL."""
        norm = self.normalise_url(url)
        return self.forms_data.get(norm, self.forms_data.get(url, []))

    def get_all_forms(self) -> Dict[str, List[Dict]]:
        return self.forms_data


class PlaywrightCrawler(WebCrawler):
    """
    Headless-browser crawler for JavaScript-heavy SPAs.

    Solves Problem 1: React/Vue/Angular apps that render routes entirely
    in JavaScript — the standard HTML crawler only ever sees the SPA shell
    (1 URL), missing all the routes behind #/ hash fragments or client-side
    routing. This crawler actually EXECUTES the page's JavaScript via a
    headless Chromium instance before extracting links and forms, so every
    route the app renders is discovered.

    How it works
    ────────────
    1. Opens each URL in a headless Chromium page.
    2. Waits for "networkidle" (no network requests for 500 ms) so
       lazy-loaded components and API calls complete.
    3. Extracts <a href> links from the fully-rendered DOM, including any
       injected by JS frameworks after initial load.
    4. Captures every fetch()/XHR URL the page calls from JavaScript via a
       network-request interceptor — these become API endpoint candidates
       for injection testing even if they have no <a> link.
    5. Handles hash-router SPAs (#/admin/users) by normalising the fragment
       back into a path so the rest of the scanner sees it as a real URL.
    6. Falls back to the standard HTML crawler if Playwright is not
       installed (graceful degradation, zero crash risk).

    Auth cookie passthrough
    ───────────────────────
    Cookies from the requests.Session are copied to the Playwright browser
    context, so any auth the scanner obtained during form-based login (see
    AuthHandler) is automatically carried into the SPA crawl.

    Installation (one-time, only needed for SPA crawling)
    ─────────────────────────────────────────────────────
      pip install playwright
      playwright install chromium
    """

    def __init__(self, base_url: str, session: requests.Session, config: Dict):
        super().__init__(base_url, session, config)
        self._api_endpoints: Set[str] = set()

    @property
    def api_endpoints(self) -> List[str]:
        """XHR/fetch URLs captured during the crawl — injection candidates."""
        return list(self._api_endpoints)

    def _session_cookies_for_playwright(self) -> List[Dict]:
        """Convert requests.Session cookies to Playwright cookie dicts."""
        parsed = urlparse(self.base_url)
        cookies = []
        for c in self.session.cookies:
            cookies.append({
                "name":   c.name,
                "value":  c.value,
                "domain": c.domain or parsed.netloc,
                "path":   c.path or "/",
            })
        return cookies

    def _extract_from_page(self, page, url: str) -> List[str]:
        """
        Extract all navigable links from a fully-rendered Playwright page,
        including hash-router fragments treated as separate paths.
        """
        links = []
        try:
            hrefs = page.eval_on_selector_all(
                "a[href]",
                "els => els.map(e => e.getAttribute('href'))"
            )
            for href in (hrefs or []):
                if not href or href.startswith(('mailto:', 'tel:', 'javascript:')):
                    continue
                # Normalise hash-router fragments: #/admin/users → /admin/users
                if href.startswith('#/'):
                    parsed = urlparse(url)
                    href = f"{parsed.scheme}://{parsed.netloc}{href[1:]}"
                full = urljoin(url, href)
                full = self.normalise_url(full)
                if self.is_valid_url(full):
                    links.append(full)
        except Exception as exc:
            logger.debug("Playwright link extraction error: %s", exc)
        return list(set(links))

    def _extract_forms_from_page(self, page, url: str) -> List[Dict]:
        """
        Extract forms from the rendered DOM — captures dynamically-injected
        forms that never appear in the original HTML source.
        """
        forms = []
        try:
            raw = page.evaluate("""() => {
                return Array.from(document.querySelectorAll('form')).map(f => ({
                    action: f.action || '',
                    method: (f.method || 'GET').toUpperCase(),
                    inputs: Array.from(f.querySelectorAll('input,textarea,select'))
                        .filter(i => i.name)
                        .map(i => ({
                            name:  i.name,
                            type:  (i.type || 'text').toLowerCase(),
                            value: i.value || ''
                        }))
                }));
            }""")
            for f in (raw or []):
                action = f.get("action", "")
                forms.append({
                    "action": self.normalise_url(action) if action else url,
                    "method": f.get("method", "GET"),
                    "inputs": f.get("inputs", []),
                })
        except Exception as exc:
            logger.debug("Playwright form extraction error: %s", exc)
        self.forms_data[url] = forms
        return forms

    def crawl(self, start_url: str = None, max_depth: int = None) -> List[str]:
        if not PLAYWRIGHT_AVAILABLE:
            logger.warning(
                "Playwright not installed — falling back to HTML-only crawler. "
                "Install with: pip install playwright && playwright install chromium"
            )
            return super().crawl(start_url, max_depth)

        start     = start_url or self.base_url
        max_depth = max_depth or self.config.get('max_depth', 3)
        max_urls  = self.config.get('max_urls', 500)
        timeout   = int(self.config.get('request_timeout', 30) * 1000)  # ms

        print(f"{Fore.CYAN}[*] Starting Playwright SPA crawl from: {start}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Max depth: {max_depth}, Max URLs: {max_urls}{Style.RESET_ALL}")

        urls_to_visit = [(start, 0)]

        # Same robots.txt/sitemap.xml seeding as WebCrawler — SPA routing
        # means sitemap-listed routes are often the ONLY way to reach pages
        # that require deep client-side navigation to expose otherwise.
        if self.config.get('crawl_robots_sitemap', True):
            for seed_url in self._seed_from_robots_and_sitemap():
                norm = self.normalise_url(seed_url)
                if norm not in self.visited_urls:
                    self.discovered_urls.add(seed_url)
                    urls_to_visit.append((seed_url, 1))

        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            context = browser.new_context(
                ignore_https_errors=not self.config.get("verify_ssl", True),
                user_agent=self.config.get(
                    "user_agent",
                    "Mozilla/5.0 (compatible; VulnScanner/5.0)"
                ),
            )
            # Forward auth cookies from the requests session
            cookies = self._session_cookies_for_playwright()
            if cookies:
                context.add_cookies(cookies)

            while urls_to_visit and len(self.visited_urls) < max_urls:
                current_url, depth = urls_to_visit.pop(0)
                normalised = self.normalise_url(current_url)

                if normalised in self.visited_urls or depth > max_depth:
                    continue

                page = context.new_page()
                api_calls_on_page: List[str] = []

                # Intercept XHR/fetch to discover API endpoints not linked
                # by any <a href> — these are common injection targets in SPAs.
                def on_request(req):
                    rtype = req.resource_type
                    if rtype in ("xhr", "fetch"):
                        norm = self.normalise_url(req.url)
                        if self.is_valid_url(req.url):
                            api_calls_on_page.append(norm)
                            self._api_endpoints.add(norm)

                page.on("request", on_request)

                try:
                    print(f"{Fore.BLUE}[*] Playwright crawling: {current_url}{Style.RESET_ALL}", end='\r')
                    page.goto(current_url, timeout=timeout, wait_until="networkidle")
                    self.visited_urls.add(normalised)

                    links = self._extract_from_page(page, current_url)
                    self._extract_forms_from_page(page, current_url)

                    for link in links:
                        norm_link = self.normalise_url(link)
                        if norm_link not in self.visited_urls:
                            self.discovered_urls.add(link)
                            urls_to_visit.append((link, depth + 1))

                    # Also queue API endpoints discovered on this page for
                    # parameter injection testing — they won't be crawled
                    # recursively (no HTML to follow) but will be scanned.
                    for api_url in api_calls_on_page:
                        if api_url not in self.visited_urls:
                            self.discovered_urls.add(api_url)

                    time.sleep(self.config.get('delay', 0.3))

                except PWTimeout:
                    logger.debug("Playwright timeout on %s", current_url)
                    self.visited_urls.add(normalised)
                except Exception as exc:
                    logger.debug("Playwright crawl error for %s: %s", current_url, exc)
                finally:
                    page.close()

            browser.close()

        all_urls = list(self.discovered_urls.union(self.visited_urls))
        print(f"\n{Fore.GREEN}[+] Playwright crawl complete. "
              f"Visited {len(self.visited_urls)} URLs, "
              f"captured {len(self._api_endpoints)} API endpoints{Style.RESET_ALL}")
        return all_urls


def make_crawler(base_url: str, session: requests.Session,
                 config: Dict) -> WebCrawler:
    """
    Factory: returns a PlaywrightCrawler if --browser-crawl is set AND
    Playwright is installed, otherwise the standard WebCrawler.
    This is the single construction point used by core/scanner.py so
    the rest of the scanner is completely unaware of which crawler is
    in use — both expose the same .crawl(), .get_forms(),
    .get_all_forms() interface.
    """
    if config.get("browser_crawl") and PLAYWRIGHT_AVAILABLE:
        logger.info("Using Playwright browser crawler (SPA mode)")
        return PlaywrightCrawler(base_url, session, config)
    if config.get("browser_crawl") and not PLAYWRIGHT_AVAILABLE:
        logger.warning(
            "--browser-crawl requested but Playwright is not installed. "
            "Install with: pip install playwright && playwright install chromium  "
            "Falling back to HTML-only crawler."
        )
    return WebCrawler(base_url, session, config)
