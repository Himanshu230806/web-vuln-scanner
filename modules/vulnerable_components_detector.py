"""
Vulnerable & Outdated Components Detector
OWASP A06:2021 – Vulnerable and Outdated Components

Checks:
  - Server/X-Powered-By header version fingerprinting vs known CVEs
  - Outdated JS libraries (jQuery, Bootstrap, Angular, React, Vue, lodash)
    cross-referenced against the OSV.dev vulnerability database (live CVE
    lookup, not just a small hardcoded table) with graceful fallback to
    the local table if OSV is unreachable.
  - Outdated CMS signatures (WordPress, Drupal, Joomla)
  - Exposed package files (package.json, composer.json, requirements.txt)
    parsed and EVERY listed dependency checked against OSV.dev
  - Exposed version disclosure endpoints
"""

import json
import logging
import re
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlparse

import requests

from modules.scan_utils import get_baseline, matches_baseline
from modules.verification_engine import VerifiedFinding, Evidence

logger = logging.getLogger(__name__)

# npm/PyPI ecosystem name for OSV.dev lookups, keyed by our internal lib name
OSV_ECOSYSTEM_MAP = {
    "jQuery":    ("jquery",    "npm"),
    "Bootstrap": ("bootstrap", "npm"),
    "AngularJS": ("angular",   "npm"),
    "lodash":    ("lodash",    "npm"),
    "moment.js": ("moment",    "npm"),
    "Vue.js":    ("vue",       "npm"),
    "React":     ("react",     "npm"),
}


class VulnerableComponentsDetector:

    # Known vulnerable version ranges: (library, regex_to_find_version, min_safe_version, cve_note)
    JS_LIBRARIES = [
        ("jQuery",    r"jquery[./\-](\d+\.\d+\.?\d*)",    "3.7.0",  "CVE-2020-11022/23 XSS in jQuery < 3.5.0"),
        ("Bootstrap", r"bootstrap[./\-](\d+\.\d+\.?\d*)", "5.3.0",  "Various XSS in Bootstrap < 4.3.1"),
        ("AngularJS", r"angular[./\-](\d+\.\d+\.?\d*)",   "1.8.3",  "CVE-2022-25844 ReDoS in AngularJS < 1.8.3"),
        ("lodash",    r"lodash[./\-](\d+\.\d+\.?\d*)",    "4.17.21","CVE-2021-23337 prototype pollution < 4.17.21"),
        ("moment.js", r"moment[./\-](\d+\.\d+\.?\d*)",    "2.29.4", "CVE-2022-24785 path traversal < 2.29.2"),
        ("Vue.js",    r"vue[./\-](\d+\.\d+\.?\d*)",       "3.3.0",  "XSS in Vue < 2.7.14 / 3.3.0"),
        ("React",     r"react[./\-](\d+\.\d+\.?\d*)",     "18.0.0", "Various issues in React < 16.9.0"),
    ]

    # Accuracy fix (round 2): the earlier fix that restricted the inline
    # search to <script>...</script> BODIES (instead of the whole page)
    # stopped matching plain page copy directly, but it does NOT stop
    # matching that same copy once a server-rendered framework (Next.js,
    # Nuxt, etc.) serialises the page's own text into a JSON hydration
    # blob sitting inside a <script type="application/json"> tag — which
    # is still a "<script>...</script> body" by the old regex's
    # definition. An education/course site whose page text says "Learn
    # Bootstrap 3.3.7 fundamentals" reproduces the exact false positive
    # this way even though nothing on the site is actually running that
    # version. Requiring one of these library-specific code-shaped
    # patterns (minified license banners, VERSION assignments, the
    # library's own CDN domain, etc.) makes an inline (non-src) match only
    # count when it looks like real bundled code, not prose that happens
    # to mention a library name and a number.
    INLINE_CODE_CONTEXT_PATTERNS = {
        "jQuery":    [r"/\*!\s*jquery", r"jquery\.fn\.jquery\s*=", r"jquery\.min\.js",
                      r"jquery-\d+\.\d+\.\d+\.(?:min\.)?js"],
        "Bootstrap": [r"/\*!\s*bootstrap", r"bootstrap\.min\.(?:js|css)", r"getbootstrap\.com",
                      r"bootstrap-\d+\.\d+\.\d+[./\-]"],
        "AngularJS": [r"/\*!\s*angularjs", r"angular\.version\s*=", r"angular\.min\.js"],
        "lodash":    [r"/\*!\s*lodash", r"lodash\.min\.js", r"_\.VERSION\s*="],
        "moment.js": [r"/\*!\s*moment\.js", r"moment\.version\s*=", r"moment\.min\.js"],
        "Vue.js":    [r"/\*!\s*vue\.js", r"vue\.version\s*=", r"vue(?:\.runtime)?\.min\.js"],
        "React":     [r"/\*!\s*react", r"react\.version\s*=", r"react\.min\.js",
                      r"react(?:-dom)?\.production\.min\.js"],
    }

    # <script> tags with these `type` values (or these hydration-data ids)
    # hold serialized page DATA, not executable code — the framework dumps
    # the rendered page's own text/props in here for client-side hydration.
    NON_CODE_SCRIPT_TYPE_RE = re.compile(
        r'type\s*=\s*["\'](?:application/(?:json|ld\+json)|text/template)["\']'
        r'|id\s*=\s*["\'](?:__NEXT_DATA__|__NUXT__|__remix|__APOLLO_STATE__)["\']',
        re.IGNORECASE,
    )

    SERVER_CVE_MAP = {
        "apache": [
            ("2.4.49", "CVE-2021-41773 Path Traversal / RCE — upgrade immediately"),
            ("2.4.50", "CVE-2021-42013 Path Traversal / RCE — upgrade immediately"),
            ("2.4.51", "Multiple CVEs — upgrade to 2.4.57+"),
        ],
        "nginx": [
            ("1.20", "CVE-2022-41741/42 memory corruption — upgrade to 1.22.1+"),
            ("1.18", "Multiple CVEs — upgrade to 1.22+"),
        ],
        "php": [
            ("7.",  "PHP 7.x is end-of-life since Nov 2022 — upgrade to 8.2+"),
            ("8.0", "PHP 8.0 EOL Dec 2023 — upgrade to 8.2+"),
            ("8.1", "PHP 8.1 EOL Nov 2024 — upgrade to 8.2+"),
        ],
        "iis": [
            ("7.",  "IIS 7.x is end-of-life — upgrade to IIS 10+"),
            ("8.",  "IIS 8.x is end-of-life — upgrade to IIS 10+"),
        ],
    }

    # Paths that expose dependency/version files
    SENSITIVE_PATHS = [
        "/package.json",
        "/composer.json",
        "/requirements.txt",
        "/Gemfile",
        "/Gemfile.lock",
        "/pom.xml",
        "/build.gradle",
        "/yarn.lock",
        "/package-lock.json",
        "/CHANGELOG.txt",
        "/CHANGELOG.md",
    ]
    # NOTE: /robots.txt and /sitemap.xml were removed from this list — they
    # are INTENDED to be publicly accessible on virtually every website and
    # do not expose dependency versions. Flagging them as a "Vulnerable
    # Component" finding was simply incorrect. CMS-specific paths
    # (/wp-login.php, /administrator/index.php, etc.) were also removed —
    # CMS detection is handled separately by _check_cms() and being
    # reachable is not itself a vulnerability.

    def __init__(self, session: requests.Session, config: Dict):
        self.session = session
        self.config  = config
        self._osv_cache: Dict[str, List[Dict]] = {}
        self._osv_available: Optional[bool] = None   # None = not yet tested

    # ── public API ────────────────────────────────────────────────────────────

    def scan(self, base_url: str, crawled_urls: List[str]) -> List[Dict]:
        findings = []
        findings.extend(self._check_server_headers(base_url))
        findings.extend(self._check_js_libraries(crawled_urls))
        findings.extend(self._check_exposed_files(base_url))
        findings.extend(self._check_cms(base_url))
        findings.extend(self._check_manifest_dependencies_via_osv(base_url))
        return findings

    # ── OSV.dev live CVE lookup ────────────────────────────────────────────────

    def _osv_query(self, package: str, ecosystem: str, version: str) -> List[Dict]:
        """
        Query the OSV.dev vulnerability database for known CVEs affecting
        this exact package+version. Returns a list of vuln dicts (possibly
        empty). Results are cached per (package, ecosystem, version) for
        the life of the scan to avoid redundant API calls.

        OSV.dev is a free, no-API-key-required aggregator covering npm,
        PyPI, RubyGems, Maven, Go, crates.io, and more — pulling from NVD,
        GHSA, and ecosystem-specific advisories.
        """
        cache_key = f"{ecosystem}:{package}:{version}"
        if cache_key in self._osv_cache:
            return self._osv_cache[cache_key]

        if self._osv_available is False:
            return []   # already confirmed unreachable this scan, don't retry every call

        try:
            resp = requests.post(
                "https://api.osv.dev/v1/query",
                json={"package": {"name": package, "ecosystem": ecosystem}, "version": version},
                timeout=self.config.get("request_timeout", 10),
            )
            self._osv_available = True
            if resp.status_code != 200:
                self._osv_cache[cache_key] = []
                return []
            data = resp.json()
            vulns = data.get("vulns", [])
            self._osv_cache[cache_key] = vulns
            return vulns
        except Exception as exc:
            logger.debug(f"OSV.dev query failed for {package}@{version}: {exc}")
            self._osv_available = False
            self._osv_cache[cache_key] = []
            return []

    @staticmethod
    def _summarize_osv_vuln(vuln: Dict) -> str:
        vuln_id  = vuln.get("id", "UNKNOWN")
        summary  = vuln.get("summary", "") or vuln.get("details", "")[:150]
        severity = ""
        for sev in vuln.get("severity", []):
            if sev.get("type") == "CVSS_V3":
                severity = f" (CVSS: {sev.get('score','?')})"
                break
        return f"{vuln_id}{severity}: {summary}"

    # ── manifest file dependency scanning via OSV ──────────────────────────────

    def _check_manifest_dependencies_via_osv(self, base_url: str) -> List[Dict]:
        """
        If package.json / requirements.txt / composer.json / Gemfile.lock
        is exposed (already detected by _check_exposed_files), parse EVERY
        listed dependency and check it against OSV.dev — not just the
        ~7 libraries in our hardcoded JS_LIBRARIES table. This is the fix
        for "surface-level component analysis": previously only a handful
        of well-known frontend libraries were checked; now any dependency
        in an exposed manifest gets a real CVE lookup.
        """
        findings = []
        parsed = urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        manifest_parsers = [
            ("/package.json",      "npm",   self._parse_package_json),
            ("/requirements.txt",  "PyPI",  self._parse_requirements_txt),
            ("/composer.json",     "Packagist", self._parse_composer_json),
        ]

        for path, ecosystem, parser_fn in manifest_parsers:
            url = origin + path
            try:
                resp = self.session.get(url, timeout=self.config.get("request_timeout", 10))
                if resp.status_code != 200:
                    continue
                deps = parser_fn(resp.text)
            except Exception:
                continue

            for pkg_name, version in deps.items():
                if not version or version in ("*", "latest"):
                    continue
                clean_version = re.sub(r'^[\^~>=<\s]+', '', version).strip()
                if not clean_version:
                    continue

                vulns = self._osv_query(pkg_name, ecosystem, clean_version)
                if not vulns:
                    continue

                most_severe = vulns[0]
                cve_summary = self._summarize_osv_vuln(most_severe)
                cve_ids = [v.get("id") for v in vulns[:5]]

                finding = VerifiedFinding(
                    vuln_type   = "Vulnerable Component",
                    url         = url,
                    parameter   = "",
                    severity    = "High" if len(vulns) > 0 else "Medium",
                    confidence  = 90,
                    owasp       = "A06 – Vulnerable Components",
                    description = (
                        f"Dependency '{pkg_name}@{clean_version}' ({ecosystem}) has "
                        f"{len(vulns)} known vulnerabilit{'y' if len(vulns)==1 else 'ies'} "
                        f"in the OSV.dev database. Most relevant: {cve_summary}"
                    ),
                    evidence = Evidence(
                        probe_url        = url,
                        probe_payload    = f"{pkg_name}@{clean_version}",
                        response_excerpt = cve_summary[:200],
                        matched_pattern  = ", ".join(cve_ids),
                        verification_note= f"Live lookup against OSV.dev — {len(vulns)} matching advisory(ies)",
                    ),
                )
                findings.append(finding.to_dict())

        return findings

    @staticmethod
    def _parse_package_json(text: str) -> Dict[str, str]:
        try:
            data = json.loads(text)
        except Exception:
            return {}
        deps = {}
        for key in ("dependencies", "devDependencies"):
            deps.update(data.get(key, {}) or {})
        return deps

    @staticmethod
    def _parse_requirements_txt(text: str) -> Dict[str, str]:
        deps = {}
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = re.match(r'^([A-Za-z0-9_\-\.]+)\s*(==|>=|<=|~=)\s*([\d.]+)', line)
            if m:
                deps[m.group(1)] = m.group(3)
        return deps

    @staticmethod
    def _parse_composer_json(text: str) -> Dict[str, str]:
        try:
            data = json.loads(text)
        except Exception:
            return {}
        deps = {}
        for key in ("require", "require-dev"):
            for pkg, ver in (data.get(key, {}) or {}).items():
                if pkg != "php":
                    deps[pkg] = ver
        return deps

    def _check_server_headers(self, url: str) -> List[Dict]:
        findings = []
        try:
            resp = self.session.get(url, timeout=self.config.get("request_timeout", 15))
        except Exception:
            return findings

        for header in ("Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"):
            value = resp.headers.get(header, "")
            if not value:
                continue

            value_lower = value.lower()
            for product, versions in self.SERVER_CVE_MAP.items():
                if product in value_lower:
                    for ver_str, cve_note in versions:
                        if ver_str in value_lower:
                            findings.append({
                                "type": "Vulnerable Component",
                                "subtype": "Outdated Server Software",
                                "url": url,
                                "severity": "High",
                                "description": (
                                    f"Server header reveals '{value}' which matches a known "
                                    f"vulnerable version. {cve_note}"
                                ),
                                "recommendation": f"Upgrade {product} and suppress version disclosure in server headers.",
                                "evidence": f"{header}: {value}",
                            })

        return findings

    # ── JS library version detection ─────────────────────────────────────────

    def _check_js_libraries(self, urls: List[str]) -> List[Dict]:
        findings = []
        checked_scripts: set = set()
        # Tracks the strongest (script-src-based) version seen per library
        # across the whole site, so an inline "match" that contradicts real
        # evidence found elsewhere (e.g. an actual <script src=".../
        # bootstrap@5.3.3/..."> reference) can be recognised as almost
        # certainly a false positive rather than a second, older copy.
        src_confirmed_versions: Dict[str, set] = {}

        for url in urls:
            try:
                resp = self.session.get(url, timeout=self.config.get("request_timeout", 15))
                html = resp.text

                # Find all <script src="..."> references
                script_urls = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE)
                for script_src in script_urls:
                    full_src = script_src if script_src.startswith("http") else urljoin(url, script_src)
                    if full_src in checked_scripts:
                        continue
                    checked_scripts.add(full_src)

                    for lib_name, pattern, min_safe, cve_note in self.JS_LIBRARIES:
                        # Check URL itself for version — this is hard
                        # evidence (an actual file reference), so no
                        # corroborating-context check is needed here.
                        match = re.search(pattern, full_src, re.IGNORECASE)
                        if match:
                            version = match.group(1)
                            src_confirmed_versions.setdefault(lib_name, set()).add(version)
                            if self._is_outdated(version, min_safe):
                                findings.append(self._js_finding(lib_name, version, min_safe, cve_note, full_src))

                # Also search inline <script>...</script> CODE content —
                # deliberately NOT the full page HTML/visible text. This
                # site is an educational platform whose course pages
                # legitimately contain plain-text mentions of "Bootstrap
                # 3.3.7", "React", "Vue.js", "Angular" etc. as curriculum
                # copy — searching the whole page for these library-name
                # regexes matched that prose text and reported courses
                # describing OLD library versions as if the scanned page
                # itself were RUNNING that vulnerable version. Restricting
                # the search to actual <script> code bodies (version
                # banners like `/*! bootstrap v3.3.7 */` or inline JS like
                # `Bootstrap.VERSION = "3.3.7"`) keeps the real detection
                # capability (self-hosted/bundled libraries with an
                # embedded version string) while eliminating false matches
                # against ordinary page copy.
                #
                # Round-2 accuracy fix: that alone still isn't enough for
                # server-rendered frameworks (Next.js/Nuxt/etc.) that dump
                # the page's own visible text into a JSON hydration blob
                # sitting *inside* a <script> tag — which still counts as
                # a "<script> body" by the round-1 fix. Two more checks:
                #   (a) skip <script> tags that hold serialized DATA
                #       (application/json, __NEXT_DATA__, etc.), not code;
                #   (b) require a library-specific code-shaped pattern
                #       (minified banner, VERSION assignment, own CDN
                #       domain) to corroborate the match — plain prose
                #       mentioning "Bootstrap 3.3.7" won't have one.
                script_tag_re = re.compile(
                    r"<script(?![^>]*\bsrc=)([^>]*)>(.*?)</script>",
                    re.IGNORECASE | re.DOTALL
                )
                inline_js_parts = [
                    body for attrs, body in script_tag_re.findall(html)
                    if not self.NON_CODE_SCRIPT_TYPE_RE.search(attrs)
                ]
                inline_js = "\n".join(inline_js_parts)
                for lib_name, pattern, min_safe, cve_note in self.JS_LIBRARIES:
                    match = re.search(pattern, inline_js, re.IGNORECASE)
                    if not match:
                        continue
                    version = match.group(1)

                    context_patterns = self.INLINE_CODE_CONTEXT_PATTERNS.get(lib_name, [])
                    has_context = any(
                        re.search(p, inline_js, re.IGNORECASE) for p in context_patterns
                    )
                    if not has_context:
                        logger.debug(
                            "Skipping inline %s v%s match at %s — no corroborating "
                            "code-shaped context, likely page prose rather than "
                            "an actual bundled library", lib_name, version, url
                        )
                        continue

                    # If we've already seen this exact library referenced
                    # via a real <script src> elsewhere on the site with a
                    # safe (non-vulnerable) version, an inline match for an
                    # older version is far more likely a false positive
                    # (prose, comment, changelog snippet) than genuine
                    # evidence of a second, outdated bundled copy.
                    safe_versions_seen = {
                        v for v in src_confirmed_versions.get(lib_name, set())
                        if not self._is_outdated(v, min_safe)
                    }
                    if safe_versions_seen and self._is_outdated(version, min_safe):
                        logger.debug(
                            "Skipping inline %s v%s match at %s — contradicts "
                            "confirmed safe version(s) %s found via real "
                            "<script src> elsewhere on the site",
                            lib_name, version, url, safe_versions_seen
                        )
                        continue

                    if self._is_outdated(version, min_safe):
                        findings.append(self._js_finding(lib_name, version, min_safe, cve_note, url))

            except Exception as e:
                logger.debug(f"VulnComponents JS check error for {url}: {e}")

        # Deduplicate by (lib, version, url)
        seen = set()
        unique = []
        for f in findings:
            key = (f.get("subtype"), f.get("evidence","")[:60], f.get("url"))
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

    # ── exposed dependency files ──────────────────────────────────────────────

    def _check_exposed_files(self, base_url: str) -> List[Dict]:
        """
        Probe for exposed dependency manifest files.

        Same accuracy fix as elsewhere: compare against this origin's
        baseline "soft 404" / SPA-catch-all response, and verify the body
        actually looks like the manifest format we're probing for (JSON
        for package.json/composer.json, plain text for requirements.txt,
        XML for pom.xml, etc.) rather than an HTML page returned for any path.
        """
        findings = []
        parsed = urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        baseline = get_baseline(self.session, base_url, self.config)

        for path in self.SENSITIVE_PATHS:
            test_url = origin + path
            try:
                resp = self.session.get(
                    test_url,
                    timeout=self.config.get("request_timeout", 10),
                    allow_redirects=False,
                )
                if resp.status_code != 200 or len(resp.text) <= 50:
                    continue

                if matches_baseline(resp, baseline):
                    continue

                if not self._looks_like_manifest(path, resp.text):
                    continue

                findings.append({
                    "type": "Vulnerable Component",
                    "subtype": "Exposed Dependency File",
                    "url": test_url,
                    "severity": "Medium",
                    "description": (
                        f"Sensitive file '{path}' is publicly accessible. "
                        "Dependency files expose exact library versions, helping "
                        "attackers identify known CVEs for your stack."
                    ),
                    "recommendation": f"Block public access to {path} via server config.",
                    "evidence": f"HTTP 200 from {test_url} ({len(resp.text)} bytes)",
                })
            except Exception:
                continue
        return findings

    @staticmethod
    def _looks_like_manifest(path: str, body: str) -> bool:
        """Verify the response body actually looks like the manifest format
        we probed for, not an HTML page returned for any path."""
        lower = body.lower().strip()

        # HTML pages are never a real dependency manifest
        if lower.startswith(("<!doctype html", "<html")) or "<head" in lower[:500]:
            return False

        if path.endswith((".json", ".lock")):
            stripped = body.strip()
            return stripped.startswith("{") or stripped.startswith("[")
        if path == "/requirements.txt":
            # Typical lines: "flask>=3.0.0", "requests==2.31.0"
            return bool(re.search(r"^[A-Za-z0-9_\-\.]+\s*(==|>=|<=|~=|>|<)?\s*[\d.]*\s*$",
                                  body.splitlines()[0].strip() if body.splitlines() else ""))
        if path == "/Gemfile":
            return "gem " in lower or "source " in lower
        if path in ("/pom.xml", "/build.gradle"):
            return "<project" in lower or "dependencies" in lower or "implementation" in lower

        return True

    # ── CMS detection ─────────────────────────────────────────────────────────

    def _check_cms(self, base_url: str) -> List[Dict]:
        findings = []
        try:
            resp = self.session.get(base_url, timeout=self.config.get("request_timeout", 15))
            html = resp.text.lower()

            if "wp-content" in html or "wp-includes" in html:
                version_match = re.search(r'wordpress[/ ](\d+\.\d+\.?\d*)', html)
                ver = version_match.group(1) if version_match else "unknown"
                findings.append({
                    "type": "Vulnerable Component",
                    "subtype": "CMS Detected",
                    "url": base_url,
                    "severity": "Info",
                    "description": f"WordPress CMS detected (version: {ver}). Ensure all plugins, themes, and core are up to date.",
                    "recommendation": "Keep WordPress, plugins, and themes updated. Use a WAF.",
                    "evidence": f"WordPress v{ver} fingerprint in HTML",
                })

            if 'content="drupal' in html or "/sites/default/files" in html:
                findings.append({
                    "type": "Vulnerable Component",
                    "subtype": "CMS Detected",
                    "url": base_url,
                    "severity": "Info",
                    "description": "Drupal CMS detected. Ensure core and modules are fully patched.",
                    "recommendation": "Apply all Drupal security advisories promptly.",
                    "evidence": "Drupal fingerprint in HTML",
                })

            if "joomla" in html or "/media/jui/" in html:
                findings.append({
                    "type": "Vulnerable Component",
                    "subtype": "CMS Detected",
                    "url": base_url,
                    "severity": "Info",
                    "description": "Joomla CMS detected. Ensure core and extensions are up to date.",
                    "recommendation": "Apply all Joomla security updates promptly.",
                    "evidence": "Joomla fingerprint in HTML",
                })

        except Exception as e:
            logger.debug(f"CMS check error: {e}")
        return findings

    # ── helpers ───────────────────────────────────────────────────────────────

    def _js_finding(self, lib, version, min_safe, cve_note, url) -> Dict:
        # Cross-reference against the live OSV.dev database for this exact
        # detected version. If OSV confirms specific CVEs, use that (more
        # authoritative and current); otherwise fall back to our local
        # hardcoded note, which may be stale.
        osv_pkg = OSV_ECOSYSTEM_MAP.get(lib)
        osv_vulns = []
        if osv_pkg:
            pkg_name, ecosystem = osv_pkg
            osv_vulns = self._osv_query(pkg_name, ecosystem, version)

        if osv_vulns:
            cve_summary = self._summarize_osv_vuln(osv_vulns[0])
            cve_ids = [v.get("id") for v in osv_vulns[:5]]
            return {
                "type": "Vulnerable Component",
                "subtype": f"Outdated JS Library: {lib}",
                "url": url,
                "severity": "High",
                "confidence": 92,
                "confidence_label": "High",
                "description": (
                    f"{lib} v{version} has {len(osv_vulns)} known vulnerabilit"
                    f"{'y' if len(osv_vulns)==1 else 'ies'} confirmed via OSV.dev. "
                    f"Most relevant: {cve_summary}"
                ),
                "recommendation": f"Upgrade {lib} to v{min_safe} or later.",
                "evidence": f"{lib} v{version} found at {url}; OSV match: {', '.join(cve_ids)}",
                "owasp": "A06 – Vulnerable Components",
            }

        # Fallback: local hardcoded table (OSV unreachable or no match)
        return {
            "type": "Vulnerable Component",
            "subtype": f"Outdated JS Library: {lib}",
            "url": url,
            "severity": "Medium",
            "confidence": 55,
            "confidence_label": "Medium",
            "description": (
                f"{lib} v{version} is outdated (safe version: {min_safe}+). {cve_note} "
                "(local reference table — live OSV.dev lookup unavailable or found no match)."
            ),
            "recommendation": f"Upgrade {lib} to v{min_safe} or later.",
            "evidence": f"{lib} v{version} found at {url}",
            "owasp": "A06 – Vulnerable Components",
        }

    @staticmethod
    def _is_outdated(version_str: str, min_safe: str) -> bool:
        try:
            def parse(v):
                parts = v.split(".")
                return tuple(int(x) for x in parts[:3] + ["0"] * (3 - len(parts)))
            return parse(version_str) < parse(min_safe)
        except Exception:
            return False
