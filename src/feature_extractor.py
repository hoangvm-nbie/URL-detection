from __future__ import annotations
import contextlib
import io
import math
import re
import socket
import ssl
import urllib.parse
import warnings
from datetime import datetime
from urllib.parse import urljoin, urlparse
import requests
import whois
from bs4 import BeautifulSoup
warnings.filterwarnings("ignore")
# ══════════════════════════════════════════════════════════════════════════════
# SECTION 1 — ENHANCED FEATURE HELPERS
# ══════════════════════════════════════════════════════════════════════════════
# ── The Threshold ───────────────────────────────────
TYPO_THRESHOLDS      = (0.0, 0.40)   # typosquatting score [0,1]
ENTROPY_THRESHOLDS   = (3.5, 3.8)    # Shannon entropy (bits)
SENSITIVE_THRESHOLDS = (0, 2)        # số từ nhạy cảm
# ── Popular domains list (global + Vietnam) ───────────────────────────────────
_POPULAR_DOMAINS: list[str] = [
    # Global
    "google", "facebook", "youtube", "microsoft", "apple", "amazon",
    "paypal", "netflix", "twitter", "instagram", "tiktok", "linkedin",
    "github", "cloudflare", "dropbox", "adobe", "spotify", "yahoo",
    "bing", "wikipedia",
    # VN e-commerce
    "shopee", "lazada", "tiki", "sendo", "thegioididong", "fptshop",
    # VN payment & banking
    "vnpay", "momo", "zalopay", "nganluong", "vietcombank", "techcombank",
    "mbbank", "agribank", "bidv", "vpbank", "hdbank", "tpbank",
    "sacombank", "acb", "ocb", "vib", "msb", "seabank",
    # VN telecoms
    "viettel", "mobifone", "vinaphone",
    # VN news portals
    "vnexpress", "tuoitre", "dantri", "baomoi", "zingnews",
]
# ── Homoglyph / leet-speak substitution tables ────────────────────────────────
_HOMOGLYPHS: dict[str, str] = {
    "0": "o", "1": "l", "3": "e", "4": "a",
    "5": "s", "6": "b", "7": "t", "8": "b",
    "@": "a", "$": "s",
}
_MULTI_CHAR_GLYPHS: dict[str, str] = {
    "rn": "m",
    "vv": "w",
    "cl": "d",
}
# ── Sensitive words (EN + VI) ─────────────────────────────────────────────────
_SENSITIVE_EN: list[str] = [
    "login", "signin", "sign-in", "signup", "register",
    "secure", "security", "verify", "verification",
    "account", "password", "passwd", "credential",
    "banking", "ebanking", "online-banking",
    "update", "upgrade", "confirm", "confirmation",
    "paypal", "payment", "checkout", "invoice",
    "credit", "debit", "card", "wallet",
    "free", "gift", "bonus", "reward", "offer", "promo", "promotion",
    "prize", "winner", "lucky", "claim",
    "admin", "webmail", "cpanel",
    "support", "helpdesk", "service", "customer",
    "alert", "warning", "suspend", "suspended", "limit",
    "recover", "recovery", "reset",
]
_SENSITIVE_VI: list[str] = [
    "thanhtoan", "thanhtown", "giaodich", "naptien", "rutien",
    "chuyentien", "taikhoan", "matkhau",
    "nganhang", "nganluong", "internetbanking",
    "khuyenmai", "giamdoc", "mienphi", "tangqua", "quangcao",
    "trungtuong", "thuong", "uu-dai", "uudai",
    "xacnhan", "xacthuc", "capnhat", "dangky", "dangnhap",
    "vnpay", "momo", "zalopay", "vietcombank", "techcombank",
    "mbbank", "agribank", "bidv", "vpbank", "viettel",
    "shopee", "lazada", "tiki",
]
_ALL_SENSITIVE: list[str] = _SENSITIVE_EN + _SENSITIVE_VI
# ── Internal utility ──────────────────────────────────────────────────────────
def _levenshtein(s1: str, s2: str) -> int:
    """Compute the Levenshtein edit distance between two strings."""
    m, n = len(s1), len(s2)
    dp = list(range(n + 1))
    for i in range(1, m + 1):
        prev, dp[0] = dp[0], i
        for j in range(1, n + 1):
            temp = dp[j]
            dp[j] = prev if s1[i - 1] == s2[j - 1] else 1 + min(prev, dp[j], dp[j - 1])
            prev = temp
    return dp[n]
def _normalize_homoglyph(name: str) -> str:
    """Replace common homoglyph/leet-speak characters with their originals."""
    name = name.lower()
    for fake, real in _MULTI_CHAR_GLYPHS.items():
        name = name.replace(fake, real)
    for fake, real in _HOMOGLYPHS.items():
        name = name.replace(fake, real)
    return name
# ══════════════════════════════════════════════════════════════════════════════
# SECTION 2 — SIDE FEATURE CLASSES
# ══════════════════════════════════════════════════════════════════════════════
class TyposquattingChecker:
    def __init__(
        self,
        popular_domains: list[str] | None = None,
        thresholds: tuple[float, float] | None = None,
    ):
        self._domains = [d.lower() for d in (popular_domains or _POPULAR_DOMAINS)]
        legit_max, sus_max = thresholds or TYPO_THRESHOLDS
        self._legit_max = legit_max
        self._sus_max   = sus_max

    def _extract_main_name(self, url: str) -> str:
        """Extract the registrable domain label (no TLD, no www)."""
        try:
            host = urlparse(url).hostname or url
        except Exception:
            host = url
        host = re.sub(r"^www\d*\.", "", host.lower())
        return host.split(".")[0]
    def _homoglyph_count(self, name: str) -> int:
        count  = sum(1 for fake in _HOMOGLYPHS       if fake in name)
        count += sum(1 for fake in _MULTI_CHAR_GLYPHS if fake in name)
        return count
    def _score_float(self, url: str) -> float:
        """Raw typosquatting score in [0.0, 1.0] (for debugging/inspection)."""
        name = self._extract_main_name(url)
        if len(name) < 3:
            return 0.0
        try:
            host = urlparse(url).hostname or name
        except Exception:
            host = name
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
            return 0.0
        homoglyph_bonus = min(0.5, self._homoglyph_count(name) * 0.25)
        normalized = _normalize_homoglyph(name)
        distances = [
            min(_levenshtein(name, d), _levenshtein(normalized, d))
            for d in self._domains
        ]
        min_dist = min(distances)
        if min_dist == 0:
            lev_bonus = 0.0      
        elif min_dist == 1 and len(name) >= 4:
            lev_bonus = 0.6
        elif min_dist == 2 and len(name) >= 5:
            lev_bonus = 0.4
        else:
            lev_bonus = 0.0
        return round(min(1.0, homoglyph_bonus + lev_bonus), 4)

    def score(self, url: str) -> int:
        raw = self._score_float(url)
        if raw <= self._legit_max:
            return 1
        if raw <= self._sus_max:
            return 0
        return -1
    
class URLEntropyScorer:
    def __init__(self ):
        legit_max, sus_max = ENTROPY_THRESHOLDS
        self._legit_max = legit_max
        self._sus_max   = sus_max

    @staticmethod
    def _shannon_entropy(text: str) -> float:
        if not text:
            return 0.0
        freq: dict[str, int] = {}
        for ch in text:
            freq[ch] = freq.get(ch, 0) + 1
        n = len(text)
        return -sum((f / n) * math.log2(f / n) for f in freq.values())
    
    def _score_float(self, url: str) -> float:
        """Raw Shannon entropy of URL in bits (scheme stripped). For debugging."""
        clean = re.sub(r"^https?://", "", url.lower())
        return round(self._shannon_entropy(clean), 4)
    
    def path_entropy(self, url: str) -> float:
        """Entropy of the path component only (debug/analysis helper)."""
        try:
            path = urlparse(url).path or ""
        except Exception:
            path = ""
        return round(self._shannon_entropy(path), 4)

    def score(self, url: str) -> int:
        raw = self._score_float(url)
        if raw <= self._legit_max:
            return 1
        if raw <= self._sus_max:
            return 0
        return -1
    
class SensitiveWordCounter:
    def __init__(self, extra_words: list[str] | None = None):
        words = _ALL_SENSITIVE + (extra_words or [])
        # Sort longest-first so longer phrases match before sub-phrases
        self._words: list[str] = sorted(
            [w.lower().replace("-", "").replace("_", "") for w in words],
            key=len,
            reverse=True,
        )
        legit_max, sus_max = SENSITIVE_THRESHOLDS
        self._legit_max = legit_max
        self._sus_max   = sus_max

    def _normalize_url(self, url: str) -> str:
        url = url.lower()
        url = re.sub(r"^https?://", "", url)
        url = re.sub(r"[^a-z0-9]", "", url)
        return url
    
    def _count_raw(self, url: str) -> int:
        """Raw count of unique sensitive words found in the URL. For debugging."""
        normalized = self._normalize_url(url)
        return sum(1 for word in self._words if word in normalized)
    
    def get_found_words(self, url: str) -> list[str]:
        """Debug helper: return all sensitive words detected in the URL."""
        normalized = self._normalize_url(url)
        return [w for w in self._words if w in normalized]

    def count(self, url: str) -> int:
        raw = self._count_raw(url)
        if raw <= self._legit_max:
            return 1
        if raw <= self._sus_max:
            return 0
        return -1
# ══════════════════════════════════════════════════════════════════════════════
# SECTION 3 — MAIN FEATURE EXTRACTOR  
FEATURE_NAMES: list[str] = [
    "having_IP_Address",           #  1
    "URL_Length",                  #  2
    "Shortining_Service",          #  3
    "having_At_Symbol",            #  4
    "double_slash_redirecting",    #  5
    "Prefix_Suffix",               #  6
    "having_Sub_Domain",           #  7
    "SSLfinal_State",              #  8
    "Domain_registeration_length", #  9
    "HTTPS_token",                 # 10
    "Abnormal_URL",                # 11
    "port",                        # 12
    "Favicon",                     # 13
    "Request_URL",                 # 14
    "URL_of_Anchor",               # 15
    "Links_in_tags",               # 16
    "SFH",                         # 17
    "Submitting_to_email",         # 18
    "Redirect",                    # 19
    "on_mouseover",                # 20
    "RightClick",                  # 21
    "popUpWindow",                 # 22
    "Iframe",                      # 23
    "Links_pointing_to_page",      # 24
    "age_of_domain",               # 25
    "dns_record",                  # 26
    "web_traffic",                 # 27
    "Google_Index",                # 28
    "Statistical_report",          # 29
    "url_entropy",                 # 30  
    "typosquatting_score",         # 31  
    "sensitive_word_count",        # 32  
]
class URLFeatureExtractor:
    def __init__(self, top_domains_file: str = "top_10000_domains.csv"):
        self.shortening_services = (
            r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|"
            r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|"
            r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|"
            r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.ny|lnkd\.in|db\.tt|"
            r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|"
            r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|"
            r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|"
            r"tr\.im|link\.zip\.net"
        )
        self.THRESHOLDS = {
            'request_url':   (22, 61),
            'url_of_anchor': (31, 67),
            'links_in_tags': (17, 81),
            'redirect':      (1, 3),
        }
        self.top_domains = self._load_top_domains(top_domains_file)
        # ── Side feature helpers ──────────────────────────────────────────
        self._typo_checker   = TyposquattingChecker()
        self._entropy_scorer = URLEntropyScorer()
        self._sensitive_ctr  = SensitiveWordCounter()
    # ──────────────────────────────────────────────
    # Internal helpers
    # ──────────────────────────────────────────────
    def _load_top_domains(self, file_path: str) -> set[str]:
        domains: set[str] = set()
        try:
            with open(file_path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    domain = line.split(",")[-1] if "," in line else line
                    domain = domain.lower().lstrip("www.")
                    domains.add(domain)
        except FileNotFoundError:
            pass
        return domains
    def get_base_domain(self, url: str) -> str:
        netloc = urlparse(url).netloc.lower()
        return netloc.replace("www.", "")
    def _safe_whois(self, domain: str):
        try:
            with contextlib.redirect_stderr(io.StringIO()), \
                 contextlib.redirect_stdout(io.StringIO()):
                return whois.whois(domain)
        except Exception:
            return None
    # ──────────────────────────────────────────────
    # Feature 8 — SSLfinal_State
    # ──────────────────────────────────────────────
    TRUSTED_ISSUERS = {
        "geotrust", "godaddy", "network solutions", "thawte",
        "comodo", "doster", "verisign", "digicert", "sectigo",
        "let's encrypt", "amazon", "globalsign",
    }
    def check_ssl(self, hostname: str) -> int:
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(
                socket.create_connection((hostname, 443), timeout=5),
                server_hostname=hostname,
            ) as ssock:
                cert = ssock.getpeercert()
            issuer_fields = dict(x[0] for x in cert.get("issuer", []))
            org = issuer_fields.get("organizationName", "").lower()
            trusted = any(t in org for t in self.TRUSTED_ISSUERS)
            not_before_str = cert.get("notBefore", "")
            not_before = datetime.strptime(not_before_str, "%b %d %H:%M:%S %Y %Z")
            age_days = (datetime.utcnow() - not_before).days
            if trusted and age_days >= 365:
                return 1   
            return 0        
        except Exception:
            return -1       
    # ──────────────────────────────────────────────
    # Feature 27 — web_traffic
    # ──────────────────────────────────────────────
    def get_web_traffic(self, domain: str) -> int:
        if not self.top_domains:
            return 0   # File not loaded → suspicious
        return 1 if domain in self.top_domains else 0
    # ──────────────────────────────────────────────
    # Feature 29 — statistical_report
    # ──────────────────────────────────────────────
    def check_statistical_report(self, url: str, hostname: str) -> int:
        """Query PhishTank API to check if URL is a known phishing site."""
        try:
            encoded_url = urllib.parse.quote(url, safe="")
            response = requests.post(
                "https://checkurl.phishtank.com/checkurl/",
                data={
                    "url":    encoded_url,
                    "format": "json",
                },
                headers={"User-Agent": "phishtank/YourAppName"},
                timeout=5,
            )
            data = response.json()
            results = data.get("results", {})
            if results.get("in_database") and results.get("valid"):
                return -1   # Confirmed phishing
            return 1
        except Exception:
            return 1        # Default: assume legitimate if API unreachable
    # ──────────────────────────────────────────────
    # All feature extraction  (returns 32 features)
    def extract_features(self, url: str, timeout: int = 5) -> list:
        features = []
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname or ""
        # 1. having_IP_Address
        ip_pattern = (
            r'(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}'
            r'([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])|'
            r'0x[0-9a-fA-F]+\.0x[0-9a-fA-F]+\.0x[0-9a-fA-F]+\.0x[0-9a-fA-F]+'
        )
        features.append(-1 if re.search(ip_pattern, url) else 1)
        # 2. URL_Length
        length = len(url)
        features.append(1 if length < 54 else (0 if length <= 75 else -1))
        # 3. Shortining_Service
        features.append(-1 if re.search(self.shortening_services, url) else 1)
        # 4. having_At_Symbol
        features.append(-1 if "@" in url else 1)
        # 5. double_slash_redirecting
        features.append(-1 if url.rfind('//') > 7 else 1)
        # 6. Prefix_Suffix
        features.append(-1 if '-' in hostname else 1)
        # 7. having_Sub_Domain
        dot_count = hostname.replace("www.", "").count('.')
        features.append(1 if dot_count == 1 else (0 if dot_count == 2 else -1))
        # 8. SSLfinal_State
        features.append(self.check_ssl(hostname))
        # 9. Domain_registeration_length
        try:
            domain_info = self._safe_whois(hostname)
            expiration_date = domain_info.expiration_date if domain_info else None
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]
            days_left = (expiration_date - datetime.now()).days if expiration_date else None
            features.append(1 if days_left and days_left > 365 else -1)
        except Exception:
            features.append(-1)
        # 10. HTTPS_token
        features.append(-1 if "https" in hostname.lower() else 1)
        # 11. Abnormal_URL
        features.append(1 if hostname in url else -1)
        # 12. port
        features.append(
            -1 if (parsed_url.port and parsed_url.port not in [80, 443]) else 1
        )
        # ── HTML / JS features (13–24) ───────────────────────────────────────
        html_features = self.extract_html_js_features_robust(url, timeout)
        features.append(html_features['Favicon'])                # 13
        features.append(html_features['Request_URL'])            # 14
        features.append(html_features['URL_of_Anchor'])          # 15
        features.append(html_features['Links_in_tags'])          # 16
        features.append(html_features['SFH'])                    # 17
        features.append(html_features['Submitting_to_email'])    # 18
        features.append(html_features['Redirect'])               # 19
        features.append(html_features['on_mouseover'])           # 20
        features.append(html_features['RightClick'])             # 21
        features.append(html_features['popUpWindow'])            # 22
        features.append(html_features['Iframe'])                 # 23
        features.append(html_features['Links_pointing_to_page']) # 24
        # 25. age_of_domain
        domain_age_days = self.get_domain_age(self.get_base_domain(url))
        features.append(1 if (domain_age_days and domain_age_days > 180) else -1)
        # 26. dns_record
        features.append(self.has_dns_record(self.get_base_domain(url)))
        # 27. web_traffic
        features.append(self.get_web_traffic(self.get_base_domain(url)))
        # 28. google_index
        features.append(self.is_google_indexed(self.get_base_domain(url)))
        # 29. statistical_report
        features.append(self.check_statistical_report(url, hostname))
        # ── Enhanced features — thứ tự khớp dataset training ─────────────────
        # 30. url_entropy          (Shannon entropy của URL)
        features.append(self._entropy_scorer.score(url))
        # 31. typosquatting_score  (điểm giả mạo domain)
        features.append(self._typo_checker.score(url))
        # 32. sensitive_word_count (số từ nhạy cảm)
        features.append(self._sensitive_ctr.count(url))
        return features

    def extract_features_labeled(self, url: str, timeout: int = 5) -> dict:
        """Trả về dict {feature_name: value} theo đúng thứ tự dataset."""
        return dict(zip(FEATURE_NAMES, self.extract_features(url, timeout)))
    # ──────────────────────────────────────────────
    # Domain helpers
    # ──────────────────────────────────────────────
    def get_domain_age(self, domain: str):
        try:
            w = self._safe_whois(domain)
            creation = w.creation_date if w else None
            if isinstance(creation, list):
                creation = creation[0]
            return (datetime.now() - creation).days if creation else None
        except Exception:
            return None
    def has_dns_record(self, domain: str) -> int:
        try:
            socket.gethostbyname(domain)
            return 1
        except Exception:
            return -1
    def is_google_indexed(self, domain: str) -> int:
        try:
            headers = {"User-Agent": "Mozilla/5.0"}
            resp = requests.get(
                f"https://www.google.com/search?q=site:{domain}",
                headers=headers, timeout=5,
            )
            return -1 if "did not match any documents" in resp.text.lower() else 1
        except Exception:
            return 1
    def get_redirect_chain_length(self, url: str, timeout: int = 10) -> int:
        try:
            resp = requests.Session().get(url, timeout=timeout, allow_redirects=True)
            return len(resp.history)
        except Exception:
            return -1
    # ──────────────────────────────────────────────
    # HTML / JS feature extraction
    # ──────────────────────────────────────────────
    def extract_html_js_features_robust(self, url: str, timeout: int = 10) -> dict:
        features = {
            "Favicon": 1, "Request_URL": 1, "URL_of_Anchor": 1,
            "Links_in_tags": 1, "SFH": 1, "Submitting_to_email": 1,
            "Redirect": 1, "on_mouseover": 1, "RightClick": 1,
            "popUpWindow": 1, "Iframe": 1, "Links_pointing_to_page": 1,
        }
        try:
            response = requests.get(
                url, timeout=timeout,
                headers={'User-Agent': 'Mozilla/5.0'},
                allow_redirects=True,
            )
            if response.status_code != 200:
                return features
            try:
                soup = BeautifulSoup(response.content, 'lxml')
            except Exception:
                soup = BeautifulSoup(response.content, 'html.parser')
            base_domain  = self.get_base_domain(response.url)
            html_content = response.text
            # 13. Favicon
            link_icon = soup.find('link', rel=re.compile("icon", re.I))
            if link_icon and link_icon.get('href'):
                favicon_url = urljoin(response.url, link_icon['href'])
                features['Favicon'] = (
                    1 if self.get_base_domain(favicon_url) == base_domain else -1
                )
            # 14. Request_URL
            media_tags = soup.find_all(['img', 'video', 'audio'])
            if media_tags:
                mismatch = sum(
                    1 for tag in media_tags
                    if tag.get('src') and
                    self.get_base_domain(urljoin(response.url, tag['src'])) != base_domain
                )
                perc = mismatch / len(media_tags) * 100
                lo, hi = self.THRESHOLDS['request_url']
                features['Request_URL'] = 1 if perc < lo else (0 if perc <= hi else -1)
            # 15. URL_of_Anchor
            anchors = soup.find_all('a')
            if anchors:
                unsafe = 0
                for a in anchors:
                    href = a.get('href', '').strip()
                    if not href:
                        continue
                    if href.startswith('#') or 'javascript:' in href.lower():
                        unsafe += 1
                    elif self.get_base_domain(urljoin(response.url, href)) != base_domain:
                        unsafe += 1
                perc = unsafe / len(anchors) * 100
                lo, hi = self.THRESHOLDS['url_of_anchor']
                features['URL_of_Anchor'] = 1 if perc < lo else (0 if perc <= hi else -1)
            # 16. Links_in_tags
            link_tags = soup.find_all(
                ['meta', 'script', 'link', 'iframe', 'embed', 'object', 'source']
            )
            valid_count = mismatch = 0
            for tag in link_tags:
                link = tag.get('href') or tag.get('src') or tag.get('data')
                if link:
                    valid_count += 1
                    if self.get_base_domain(urljoin(response.url, link)) != base_domain:
                        mismatch += 1
            if valid_count:
                perc = mismatch / valid_count * 100
                lo, hi = self.THRESHOLDS['links_in_tags']
                features['Links_in_tags'] = 1 if perc < lo else (0 if perc <= hi else -1)
            # 17. SFH
            forms = soup.find_all('form')
            if forms:
                has_empty = has_external = False
                for form in forms:
                    action = form.get('action', '').strip().lower()
                    if action in ['', 'about:blank']:
                        has_empty = True
                    elif self.get_base_domain(urljoin(response.url, action)) != base_domain:
                        has_external = True
                features['SFH'] = -1 if has_empty else (0 if has_external else 1)
            # 18. Submitting_to_email
            features['Submitting_to_email'] = (
                -1 if re.search(r"mailto:|mail\(", html_content, re.I) else 1
            )
            # 19. Redirect
            n_redirects = len(response.history) + len(
                re.findall(r"window\.location\.(?:replace|href)\s*=", html_content)
            )
            lo, hi = self.THRESHOLDS['redirect']
            features['Redirect'] = 1 if n_redirects <= lo else (0 if n_redirects <= hi else -1)
            # 20. on_mouseover
            features['on_mouseover'] = (
                -1 if re.search(
                    r"onmouseover\s*=\s*['\"].*window\.status.*['\"]",
                    html_content, re.I,
                ) else 1
            )
            # 21. RightClick
            features['RightClick'] = (
                -1 if (
                    "event.button==2" in html_content.replace(" ", "") or
                    "contextmenu" in html_content.lower()
                ) else 1
            )
            # 22. popUpWindow
            if re.search(r"window\.open\s*\(", html_content):
                popup_with_input = re.search(
                    r"window\.open[^;]{0,300}(input|password|text|form)",
                    html_content, re.I | re.S,
                )
                features['popUpWindow'] = -1 if popup_with_input else 0
            else:
                features['popUpWindow'] = 1
            # 23. Iframe
            iframe = soup.find('iframe')
            if iframe:
                src = iframe.get('src')
                features['Iframe'] = (
                    -1 if src and
                    self.get_base_domain(urljoin(response.url, src)) != base_domain
                    else 1
                )
            # 24. Links_pointing_to_page
            domain       = self.get_base_domain(url)
            redirect_cnt = self.get_redirect_chain_length(url, timeout)
            age          = self.get_domain_age(domain)
            shortened    = bool(re.search(self.shortening_services, url))
            risk = 0
            if redirect_cnt != -1 and redirect_cnt > 2: risk += 1
            if age is not None and age < 30:             risk += 1
            if shortened:                                risk += 1
            features['Links_pointing_to_page'] = (
                -1 if risk >= 2 else (0 if risk == 1 else 1)
            )
        except Exception:
            pass
        return features
