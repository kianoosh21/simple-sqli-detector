#!/usr/bin/env python3
"""
SQL Injection Detection Tool - Full Featured (curl-based)
Detects error-based SQLi hints using 500 -> non-500 status transitions

Features:
- Auto-detect JSON bodies (no need -json)
- Optional -json to FORCE JSON mode
- Strips Content-Length so curl recalculates after mutations (prevents JSON truncation/corruption)
- Safe multi-request splitting (won't collide with header/body blank line)

Scope flags:
- Default: test GET + POST params only
- -c / --cookie-only : test COOKIE params ONLY
- -f / --full        : test GET + POST + COOKIE together
    + ALSO tests headers: User-Agent, Referer, X-Forwarded-For
      (adds them if missing), appends ' and then '' and checks 500 -> non-500

Report wording:
- Uses "PROBABLE" / "Highly probable vulnerable parameters"
"""

import argparse
import subprocess
import sys
import json
import re
from urllib.parse import urlparse, urlunparse
from typing import Dict, List, Tuple, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

print_lock = threading.Lock()


class CurlParser:
    """Parse curl commands from Burp Suite OR raw HTTP request"""

    __slots__ = ('curl_cmd', 'method', 'url', 'headers', 'cookies', 'body', 'extra_flags')

    def __init__(self, curl_cmd: str):
        self.curl_cmd = curl_cmd.strip()
        self.method = "GET"
        self.url = ""
        self.headers: List[str] = []
        self.cookies: List[str] = []
        self.body: Optional[str] = None
        self.extra_flags: List[str] = []

    def parse(self) -> Dict:
        if not self.curl_cmd.startswith('curl'):
            return self._parse_raw_request()

        cmd = self.curl_cmd.replace('\\\n', ' ').replace('\\\r\n', ' ')
        tokens = self._tokenize(cmd)

        i = 0
        while i < len(tokens):
            tok = tokens[i]

            if tok == 'curl':
                i += 1
                continue

            if tok in ('-X', '--request'):
                i += 1
                if i < len(tokens):
                    self.method = tokens[i]
                i += 1
                continue

            if tok in ('-H', '--header'):
                i += 1
                if i < len(tokens):
                    h = tokens[i]
                    # IMPORTANT: drop Content-Length so curl recalculates correctly after mutation
                    if not h.lower().startswith('content-length:'):
                        self.headers.append(h)
                i += 1
                continue

            if tok in ('-b', '--cookie'):
                i += 1
                if i < len(tokens):
                    self.cookies.append(tokens[i])
                i += 1
                continue

            if tok in ('-d', '--data', '--data-raw', '--data-binary'):
                i += 1
                if i < len(tokens):
                    self.body = tokens[i]
                i += 1
                continue

            if tok in ('--path-as-is', '-k', '--insecure', '-s', '--silent',
                       '--compressed', '-L', '--location'):
                self.extra_flags.append(tok)
                i += 1
                continue

            if tok in ('-i', '--include'):
                i += 1
                continue

            if not tok.startswith('-'):
                self.url = tok

            i += 1

        return {
            'method': self.method,
            'url': self.url,
            'headers': self.headers,
            'cookies': self.cookies,
            'body': self.body,
            'extra_flags': self.extra_flags
        }

    def _parse_raw_request(self) -> Dict:
        lines = self.curl_cmd.replace('\r\n', '\n').replace('\r', '\n').split('\n')
        if not lines:
            return self._empty_result()

        parts = lines[0].strip().split(' ')
        if len(parts) >= 2:
            self.method = parts[0]
            path = parts[1]
        else:
            return self._empty_result()

        body_start = len(lines)
        host = None
        cookie_header = None

        for i, line in enumerate(lines[1:], 1):
            raw = line
            line = line.strip()
            if not line:
                body_start = i + 1
                break

            if ':' in raw:
                key, _, value = raw.partition(':')
                key = key.strip()
                value = value.strip()

                if key.lower() == 'host':
                    host = value
                elif key.lower() == 'cookie':
                    cookie_header = value
                elif key.lower() == 'content-length':
                    # IMPORTANT: drop it so curl recalculates correctly after mutation
                    continue
                else:
                    self.headers.append(f"{key}: {value}")

        if host:
            self.url = f"https://{host}{path}"
        else:
            self.url = path

        if cookie_header:
            self.cookies.append(cookie_header)

        if body_start < len(lines):
            self.body = '\n'.join(lines[body_start:]).strip() or None

        # Keep previous behavior
        self.extra_flags.append('-k')

        return {
            'method': self.method,
            'url': self.url,
            'headers': self.headers,
            'cookies': self.cookies,
            'body': self.body,
            'extra_flags': self.extra_flags
        }

    def _empty_result(self) -> Dict:
        return {
            'method': 'GET',
            'url': '',
            'headers': [],
            'cookies': [],
            'body': None,
            'extra_flags': []
        }

    def _tokenize(self, cmd: str) -> List[str]:
        tokens = []
        current = []
        i = 0
        cmd_len = len(cmd)

        while i < cmd_len:
            c = cmd[i]

            if c in ' \t\n\r' and not current:
                i += 1
                continue

            if cmd[i:i+2] == "$'":
                if current:
                    tokens.append(''.join(current))
                    current = []
                j = i + 2
                while j < cmd_len:
                    if cmd[j] == "'":
                        tokens.append(cmd[i:j+1])
                        i = j + 1
                        break
                    if cmd[j] == '\\' and j + 1 < cmd_len:
                        j += 2
                    else:
                        j += 1
                else:
                    i = j
                continue

            if c == "'" and not current:
                j = i + 1
                while j < cmd_len and cmd[j] != "'":
                    j += 1
                tokens.append(cmd[i+1:j])
                i = j + 1
                continue

            if c == '"' and not current:
                j = i + 1
                while j < cmd_len:
                    if cmd[j] == '"':
                        break
                    if cmd[j] == '\\' and j + 1 < cmd_len:
                        j += 2
                    else:
                        j += 1
                tokens.append(cmd[i+1:j])
                i = j + 1
                continue

            if c in ' \t\n\r':
                if current:
                    tokens.append(''.join(current))
                    current = []
                i += 1
                continue

            current.append(c)
            i += 1

        if current:
            tokens.append(''.join(current))

        return tokens


class SQLiDetector:
    """Detect SQL injection vulnerabilities"""

    __slots__ = ('debug', 'proxy', 'max_workers', 'mode', 'scope', 'force_json')

    def __init__(self, debug: bool = False, proxy: Optional[str] = None,
                 max_workers: int = 10, mode: str = 'single',
                 scope: str = 'params',
                 force_json: bool = False):
        self.debug = debug
        self.proxy = proxy
        self.max_workers = max_workers
        self.mode = mode  # 'single', 'faster', 'fastest'
        self.scope = scope  # 'params' | 'cookie' | 'full'
        self.force_json = force_json  # legacy -json: force JSON mode for all requests

    # ---------------- Auto JSON detection ----------------

    @staticmethod
    def _headers_have_json(headers: List[str]) -> bool:
        for h in headers:
            if ':' not in h:
                continue
            k, _, v = h.partition(':')
            if k.strip().lower() == 'content-type' and 'application/json' in v.lower():
                return True
        return False

    @staticmethod
    def _body_is_valid_json(body: Optional[str]) -> bool:
        if not body:
            return False
        s = body.lstrip()
        if not (s.startswith('{') or s.startswith('[')):
            return False
        try:
            json.loads(body)
            return True
        except Exception:
            return False

    def _json_enabled_for_request(self, base_cmd: Dict) -> bool:
        if self.force_json:
            return True
        if self._headers_have_json(base_cmd['headers']):
            return True
        if self._body_is_valid_json(base_cmd.get('body')):
            return True
        return False

    # ---------------- Header helpers (for -f/--full) ----------------

    @staticmethod
    def _get_header_index_and_value(headers: List[str], header_name: str) -> Tuple[Optional[int], Optional[str]]:
        target = header_name.lower()
        for i, h in enumerate(headers):
            if ':' not in h:
                continue
            k, _, v = h.partition(':')
            if k.strip().lower() == target:
                return i, v.lstrip()
        return None, None

    @staticmethod
    def _set_or_add_header(headers: List[str], header_name: str, value: str) -> List[str]:
        # replace if exists (case-insensitive), otherwise append
        out = list(headers)
        idx, _ = SQLiDetector._get_header_index_and_value(out, header_name)
        line = f"{header_name}: {value}"
        if idx is None:
            out.append(line)
        else:
            out[idx] = line
        return out

    def _default_header_value(self, header_name: str, base_url: str) -> str:
        hn = header_name.lower()
        if hn == "user-agent":
            return "Mozilla/5.0"
        if hn == "referer":
            try:
                p = urlparse(base_url)
                if p.scheme and p.netloc:
                    return f"{p.scheme}://{p.netloc}/"
            except Exception:
                pass
            return "https://example.com/"
        if hn == "x-forwarded-for":
            return "127.0.0.1"
        return "x"

    def _ensure_header_present(self, base_cmd: Dict, header_name: str) -> List[str]:
        headers = list(base_cmd.get('headers', []))
        idx, val = self._get_header_index_and_value(headers, header_name)
        if idx is None:
            headers = self._set_or_add_header(headers, header_name, self._default_header_value(header_name, base_cmd.get('url', '')))
        elif val is None or val.strip() == "":
            headers = self._set_or_add_header(headers, header_name, self._default_header_value(header_name, base_cmd.get('url', '')))
        return headers

    def _mutate_header_value(self, headers: List[str], header_name: str, suffix: str, base_url: str) -> List[str]:
        # headers ALWAYS use literal quotes (NOT %27)
        out = list(headers)
        idx, val = self._get_header_index_and_value(out, header_name)
        if idx is None:
            base_val = self._default_header_value(header_name, base_url)
        else:
            base_val = val if val is not None else self._default_header_value(header_name, base_url)
        return self._set_or_add_header(out, header_name, f"{base_val}{suffix}")

    # ----------------------------------------------------

    def build_curl_cmd(self, base_cmd: Dict, url: str, body: Optional[str] = None,
                       cookies: Optional[List[str]] = None,
                       headers_override: Optional[List[str]] = None) -> List[str]:
        cmd = ['curl']

        if base_cmd['method'] != 'GET':
            cmd.extend(['-X', base_cmd['method']])

        # Choose headers (base or overridden)
        headers_src = headers_override if headers_override is not None else base_cmd['headers']

        # Safety filter: ensure Content-Length never gets forwarded
        safe_headers = [h for h in headers_src if not h.lower().startswith('content-length:')]
        cmd.extend(sum((['-H', h] for h in safe_headers), []))

        cookie_list = cookies if cookies is not None else base_cmd['cookies']
        cmd.extend(sum((['-b', c] for c in cookie_list), []))

        if body is not None:
            cmd.extend(['--data-raw', body])

        cmd.extend(base_cmd['extra_flags'])

        if self.proxy:
            cmd.extend(['-x', self.proxy])

        cmd.extend(['-o', '/dev/null', '-w', '%{http_code}'])
        cmd.append(url)

        return cmd

    def execute_curl(self, cmd: List[str]) -> Optional[int]:
        if self.debug:
            with print_lock:
                print(f"[DEBUG] {' '.join(cmd[:10])} ...", file=sys.stderr)

        try:
            full_cmd = ' '.join(self._escape_for_bash(t) for t in cmd)
            result = subprocess.run(
                ['bash', '-c', full_cmd],
                capture_output=True,
                text=True,
                timeout=30
            )

            status_code = result.stdout.strip()
            if self.debug:
                with print_lock:
                    print(f"[DEBUG] Status: {status_code}", file=sys.stderr)

            return int(status_code) if status_code.isdigit() else None

        except subprocess.TimeoutExpired:
            if self.debug:
                with print_lock:
                    print("[DEBUG] Request timed out", file=sys.stderr)
            return None
        except Exception as e:
            if self.debug:
                with print_lock:
                    print(f"[DEBUG] Error: {e}", file=sys.stderr)
            return None

    @staticmethod
    def _escape_for_bash(token: str) -> str:
        if token.startswith("$'") and token.endswith("'"):
            return token

        needs_escape = ' $&|;<>(){}[]?~`"\'\\\n\r\t'
        if not any(c in token for c in needs_escape):
            return token

        return f"'{token.replace(chr(39), chr(39) + chr(92) + chr(39) + chr(39))}'"

    @staticmethod
    def _normalize_json_suffix(suffix: str) -> str:
        # for JSON, use literal quotes not %27
        if suffix == '%27':
            return "'"
        if suffix == '%27%27':
            return "''"
        return suffix

    # --------- Mutation helpers (JSON-aware via runtime flag) ---------

    def _mutate_all_url_params(self, url: str, suffix: str) -> str:
        clean_url = url[2:-1] if url.startswith("$'") and url.endswith("'") else url
        parsed = urlparse(clean_url)
        if not parsed.query:
            return url

        parts = []
        for param in parsed.query.split('&'):
            if '=' in param:
                key, _, value = param.partition('=')
                parts.append(f"{key}={value}{suffix}")
            else:
                parts.append(param)

        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, '&'.join(parts), parsed.fragment))

    def _mutate_all_body_params(self, body: str, suffix: str, json_enabled: bool) -> str:
        if not body:
            return body

        if json_enabled and body.strip().startswith(('{', '[')):
            try:
                data = json.loads(body)
                js_suffix = self._normalize_json_suffix(suffix)
                mutated = self._mutate_json_recursive(data, js_suffix)
                return json.dumps(mutated, ensure_ascii=False)
            except Exception:
                return body

        if '=' in body:
            parts = []
            for param in body.split('&'):
                if '=' in param:
                    key, _, value = param.partition('=')
                    parts.append(f"{key}={value}{suffix}")
                else:
                    parts.append(param)
            return '&'.join(parts)

        return body

    def _mutate_json_recursive(self, data, suffix: str):
        if isinstance(data, dict):
            return {k: self._mutate_json_recursive(v, suffix) for k, v in data.items()}
        if isinstance(data, list):
            return [self._mutate_json_recursive(item, suffix) for item in data]
        if isinstance(data, str):
            return data + suffix
        return data

    def _mutate_all_cookies(self, cookies: List[str], suffix: str) -> List[str]:
        mutated = []
        for cookie in cookies:
            parts = []
            for part in cookie.split(';'):
                part = part.strip()
                if '=' in part:
                    key, _, value = part.partition('=')
                    parts.append(f"{key}={value}{suffix}")
                else:
                    parts.append(part)
            mutated.append('; '.join(parts))
        return mutated

    def mutate_all_params(self, base_cmd: Dict, suffix: str, json_enabled: bool) -> Tuple[str, Optional[str], Optional[List[str]]]:
        mutated_url = self._mutate_all_url_params(base_cmd['url'], suffix)
        mutated_body = self._mutate_all_body_params(base_cmd['body'], suffix, json_enabled) if base_cmd.get('body') else base_cmd.get('body')

        mutated_cookies = None
        if base_cmd.get('cookies'):
            mutated_cookies = self._mutate_all_cookies(base_cmd['cookies'], suffix)

        return mutated_url, mutated_body, mutated_cookies

    def mutate_only_cookies(self, base_cmd: Dict, suffix: str) -> Tuple[str, Optional[str], Optional[List[str]]]:
        mutated_cookies = None
        if base_cmd.get('cookies'):
            mutated_cookies = self._mutate_all_cookies(base_cmd['cookies'], suffix)
        return base_cmd['url'], base_cmd.get('body'), mutated_cookies

    # ---------------- Extraction + single param mutation ----------------

    def extract_params(self, url: str, body: Optional[str], json_enabled: bool) -> Tuple[Dict[str, List[str]], Dict[str, List[str]]]:
        get_params: Dict[str, List[str]] = {}
        post_params: Dict[str, List[str]] = {}

        clean_url = url[2:-1] if url.startswith("$'") and url.endswith("'") else url
        parsed = urlparse(clean_url)

        if parsed.query:
            for param in parsed.query.split('&'):
                if '=' in param:
                    key, _, value = param.partition('=')
                    get_params.setdefault(key, []).append(value)
                else:
                    get_params.setdefault(param, []).append('')

        if body:
            if json_enabled and body.strip().startswith(('{', '[')):
                try:
                    data = json.loads(body)
                    json_params = self._extract_json_params(data)
                    for key, value in json_params:
                        post_params.setdefault(key, []).append(value)
                except Exception:
                    pass
            elif '=' in body and not body.strip().startswith(('{', '[')):
                for param in body.split('&'):
                    if '=' in param:
                        key, _, value = param.partition('=')
                        post_params.setdefault(key, []).append(value)
                    else:
                        post_params.setdefault(param, []).append('')

        return get_params, post_params

    def _extract_json_params(self, data, prefix='') -> List[Tuple[str, str]]:
        params = []
        if isinstance(data, dict):
            for k, v in data.items():
                key = f"{prefix}.{k}" if prefix else k
                if isinstance(v, (dict, list)):
                    params.extend(self._extract_json_params(v, key))
                else:
                    params.append((key, str(v)))
        elif isinstance(data, list):
            for i, item in enumerate(data):
                params.extend(self._extract_json_params(item, f"{prefix}[{i}]"))
        return params

    def extract_cookie_params(self, cookies: List[str]) -> Dict[str, List[str]]:
        cookie_params: Dict[str, List[str]] = {}
        for cookie in cookies:
            for part in cookie.split(';'):
                part = part.strip()
                if '=' in part:
                    key, _, value = part.partition('=')
                    cookie_params.setdefault(key, []).append(value)
        return cookie_params

    def mutate_url_param(self, url: str, param_name: str, param_idx: int, suffix: str) -> str:
        clean_url = url[2:-1] if url.startswith("$'") and url.endswith("'") else url
        parsed = urlparse(clean_url)
        if not parsed.query:
            return clean_url

        parts = []
        current_idx: Dict[str, int] = {}

        for param in parsed.query.split('&'):
            if '=' in param:
                key, _, value = param.partition('=')
                idx = current_idx.get(key, 0)
                if key == param_name and idx == param_idx:
                    value += suffix
                current_idx[key] = idx + 1
                parts.append(f"{key}={value}")
            else:
                parts.append(param)

        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, '&'.join(parts), parsed.fragment))

    def mutate_body_param(self, body: str, param_name: str, param_idx: int, suffix: str, json_enabled: bool) -> str:
        if not body:
            return body

        if json_enabled and body.strip().startswith(('{', '[')):
            try:
                data = json.loads(body)
                js_suffix = self._normalize_json_suffix(suffix)
                mutated = self._mutate_json_param(data, param_name, js_suffix)
                return json.dumps(mutated, ensure_ascii=False)
            except Exception:
                return body

        parts = []
        current_idx: Dict[str, int] = {}

        for param in body.split('&'):
            if '=' in param:
                key, _, value = param.partition('=')
                idx = current_idx.get(key, 0)
                if key == param_name and idx == param_idx:
                    value += suffix
                current_idx[key] = idx + 1
                parts.append(f"{key}={value}")
            else:
                parts.append(param)

        return '&'.join(parts)

    def _mutate_json_param(self, data, param_name: str, suffix: str):
        if isinstance(data, dict):
            result = {}
            for k, v in data.items():
                if k == param_name or param_name.startswith(f"{k}."):
                    if isinstance(v, str):
                        result[k] = v + suffix
                    elif isinstance(v, (dict, list)):
                        result[k] = self._mutate_json_param(v, param_name, suffix)
                    else:
                        result[k] = v
                else:
                    result[k] = v
            return result
        if isinstance(data, list):
            return [self._mutate_json_param(item, param_name, suffix) for item in data]
        return data

    def mutate_cookie_param(self, cookies: List[str], param_name: str, param_idx: int, suffix: str) -> List[str]:
        mutated = []
        current_idx: Dict[str, int] = {}

        for cookie in cookies:
            parts = []
            for part in cookie.split(';'):
                part = part.strip()
                if '=' in part:
                    key, _, value = part.partition('=')
                    idx = current_idx.get(key, 0)
                    if key == param_name and idx == param_idx:
                        value += suffix
                    current_idx[key] = idx + 1
                    parts.append(f"{key}={value}")
                else:
                    parts.append(part)
            mutated.append('; '.join(parts))

        return mutated

    # ---------------- Header-only tests (for -f/--full) ----------------

    def scan_headers_only(self, base_cmd: Dict) -> List[Dict]:
        """
        Tests headers (User-Agent, Referer, X-Forwarded-For) ONLY.
        Logic:
          baseline with ensured header -> append ' -> expect 500 -> append '' -> expect non-500
        """
        header_names = ["User-Agent", "Referer", "X-Forwarded-For"]
        findings: List[Dict] = []
        tasks = [(base_cmd, hn) for hn in header_names]

        with ThreadPoolExecutor(max_workers=min(self.max_workers, 3) or 1) as executor:
            future_to_task = {executor.submit(self.test_header, *task): task for task in tasks}
            for future in as_completed(future_to_task):
                result = future.result()
                if result:
                    findings.append(result)

        return findings

    def test_header(self, base_cmd: Dict, header_name: str) -> Optional[Dict]:
        # Ensure header exists for baseline/consistency
        base_headers = self._ensure_header_present(base_cmd, header_name)

        baseline_cmd = self.build_curl_cmd(base_cmd, base_cmd['url'], base_cmd.get('body'), base_cmd.get('cookies'), headers_override=base_headers)
        baseline_status = self.execute_curl(baseline_cmd)
        if baseline_status is None:
            return None

        # Single quote
        quote_headers = self._mutate_header_value(base_headers, header_name, "'", base_cmd.get('url', ''))
        quote_cmd = self.build_curl_cmd(base_cmd, base_cmd['url'], base_cmd.get('body'), base_cmd.get('cookies'), headers_override=quote_headers)
        quote_status = self.execute_curl(quote_cmd)
        if quote_status is None or quote_status != 500:
            return None

        # Two quotes (''), should "fix" and become non-500
        dquote_headers = self._mutate_header_value(base_headers, header_name, "''", base_cmd.get('url', ''))
        dquote_cmd = self.build_curl_cmd(base_cmd, base_cmd['url'], base_cmd.get('body'), base_cmd.get('cookies'), headers_override=dquote_headers)
        dquote_status = self.execute_curl(dquote_cmd)
        if dquote_status is None or dquote_status == 500:
            return None

        return {
            'param': header_name,
            'type': 'HEADER',
            'baseline': baseline_status,
            'quote': quote_status,
            'dquote': dquote_status,
            'quote_cmd': ' '.join(self._escape_for_bash(t) for t in quote_cmd),
            'dquote_cmd': ' '.join(self._escape_for_bash(t) for t in dquote_cmd),
            'url': base_cmd['url']
        }

    # ---------------- Scanning modes ----------------

    def scan_faster(self, base_cmd: Dict, json_enabled: bool) -> List[Dict]:
        print("Mode: FASTER (batch test with single-recursive fallback)")

        if self.scope == 'cookie':
            mut_url, mut_body, mut_cookies = self.mutate_only_cookies(base_cmd, '%27')
        else:
            mut_url, mut_body, mut_cookies = self.mutate_all_params(base_cmd, '%27', json_enabled)

        cmd = self.build_curl_cmd(base_cmd, mut_url, mut_body, mut_cookies)
        status = self.execute_curl(cmd)

        if status == 500:
            print("  → Got 500, switching to single-recursive mode")
            return self.scan_single_recursive(base_cmd, json_enabled)

        print(f"  → Got {status}, skipping")
        return []

    def scan_fastest(self, base_cmd: Dict, json_enabled: bool) -> List[Dict]:
        print("Mode: FASTEST (batch test with double-quote verification)")

        if self.scope == 'cookie':
            mut_url1, mut_body1, mut_cookies1 = self.mutate_only_cookies(base_cmd, '%27')
        else:
            mut_url1, mut_body1, mut_cookies1 = self.mutate_all_params(base_cmd, '%27', json_enabled)

        cmd1 = self.build_curl_cmd(base_cmd, mut_url1, mut_body1, mut_cookies1)
        status1 = self.execute_curl(cmd1)

        if status1 != 500:
            print(f"  → Got {status1}, skipping")
            return []

        print("  → Got 500 with single quote")

        if self.scope == 'cookie':
            mut_url2, mut_body2, mut_cookies2 = self.mutate_only_cookies(base_cmd, '%27%27')
        else:
            mut_url2, mut_body2, mut_cookies2 = self.mutate_all_params(base_cmd, '%27%27', json_enabled)

        cmd2 = self.build_curl_cmd(base_cmd, mut_url2, mut_body2, mut_cookies2)
        status2 = self.execute_curl(cmd2)

        if status2 != 500:
            print(f"  → Got {status2} with double quote, fallback to identify probable vulnerable param")
            return self.scan_single_recursive(base_cmd, json_enabled)

        print("  → Still 500 with double quote, skipping")
        return []

    def scan_single_recursive(self, base_cmd: Dict, json_enabled: bool) -> List[Dict]:
        get_params, post_params = self.extract_params(base_cmd['url'], base_cmd['body'], json_enabled)
        cookie_params = self.extract_cookie_params(base_cmd['cookies']) if base_cmd.get('cookies') else {}

        # Scope behavior
        if self.scope == 'cookie':
            get_params = {}
            post_params = {}
        elif self.scope == 'params':
            cookie_params = {}

        get_count = sum(len(v) for v in get_params.values())
        post_count = sum(len(v) for v in post_params.values())
        cookie_count = sum(len(v) for v in cookie_params.values())

        print(f"Found {get_count} GET, {post_count} POST, {cookie_count} COOKIE parameter(s)")

        tasks = []
        for param_name, values in get_params.items():
            for idx in range(len(values)):
                tasks.append((base_cmd, param_name, idx, 'GET', json_enabled))

        for param_name, values in post_params.items():
            for idx in range(len(values)):
                tasks.append((base_cmd, param_name, idx, 'POST', json_enabled))

        for param_name, values in cookie_params.items():
            for idx in range(len(values)):
                tasks.append((base_cmd, param_name, idx, 'COOKIE', json_enabled))

        findings = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_task = {executor.submit(self.test_parameter, *task): task for task in tasks}
            for future in as_completed(future_to_task):
                result = future.result()
                if result:
                    findings.append(result)

        return findings

    def test_parameter(self, base_cmd: Dict, param_name: str, param_idx: int, param_type: str, json_enabled: bool) -> Optional[Dict]:
        baseline_cmd = self.build_curl_cmd(base_cmd, base_cmd['url'], base_cmd.get('body'), base_cmd.get('cookies'))
        baseline_status = self.execute_curl(baseline_cmd)
        if baseline_status is None:
            return None

        # single quote probe
        if param_type == 'GET':
            mut_url = self.mutate_url_param(base_cmd['url'], param_name, param_idx, '%27')
            mut_body = base_cmd.get('body')
            mut_cookies = base_cmd.get('cookies')
        elif param_type == 'POST':
            mut_url = base_cmd['url']
            mut_body = self.mutate_body_param(base_cmd.get('body') or '', param_name, param_idx, '%27', json_enabled)
            mut_cookies = base_cmd.get('cookies')
        else:  # COOKIE
            mut_url = base_cmd['url']
            mut_body = base_cmd.get('body')
            mut_cookies = self.mutate_cookie_param(base_cmd.get('cookies') or [], param_name, param_idx, '%27')

        quote_cmd = self.build_curl_cmd(base_cmd, mut_url, mut_body, mut_cookies)
        quote_status = self.execute_curl(quote_cmd)
        if quote_status is None or quote_status != 500:
            return None

        # two single quotes probe
        if param_type == 'GET':
            mut_url2 = self.mutate_url_param(base_cmd['url'], param_name, param_idx, '%27%27')
            mut_body2 = base_cmd.get('body')
            mut_cookies2 = base_cmd.get('cookies')
        elif param_type == 'POST':
            mut_url2 = base_cmd['url']
            mut_body2 = self.mutate_body_param(base_cmd.get('body') or '', param_name, param_idx, '%27%27', json_enabled)
            mut_cookies2 = base_cmd.get('cookies')
        else:  # COOKIE
            mut_url2 = base_cmd['url']
            mut_body2 = base_cmd.get('body')
            mut_cookies2 = self.mutate_cookie_param(base_cmd.get('cookies') or [], param_name, param_idx, '%27%27')

        dquote_cmd = self.build_curl_cmd(base_cmd, mut_url2, mut_body2, mut_cookies2)
        dquote_status = self.execute_curl(dquote_cmd)
        if dquote_status is None or dquote_status == 500:
            return None

        return {
            'param': f"{param_name}[{param_idx}]",
            'type': param_type,
            'baseline': baseline_status,
            'quote': quote_status,
            'dquote': dquote_status,
            'quote_cmd': ' '.join(self._escape_for_bash(t) for t in quote_cmd),
            'dquote_cmd': ' '.join(self._escape_for_bash(t) for t in dquote_cmd),
            'url': base_cmd['url']
        }

    def scan(self, content: str) -> List[Dict]:
        parser = CurlParser(content)
        base_cmd = parser.parse()

        if not base_cmd.get('url'):
            print("Error: No URL found in request", file=sys.stderr)
            return []

        json_enabled = self._json_enabled_for_request(base_cmd)
        if json_enabled:
            print(f"\nTarget: {base_cmd['method']} {base_cmd['url']} (auto-detected JSON body)")
        else:
            print(f"\nTarget: {base_cmd['method']} {base_cmd['url']}")

        # Run main scan (params/cookies based on scope & mode)
        if self.mode == 'faster':
            findings = self.scan_faster(base_cmd, json_enabled)
        elif self.mode == 'fastest':
            findings = self.scan_fastest(base_cmd, json_enabled)
        else:
            findings = self.scan_single_recursive(base_cmd, json_enabled)

        # In FULL scope, ALWAYS also test headers (even if batch mode "skipped")
        if self.scope == 'full':
            header_findings = self.scan_headers_only(base_cmd)
            if header_findings:
                findings.extend(header_findings)

        return findings


def split_requests(content: str) -> List[str]:
    """
    Safe splitter for multiple raw Burp requests in one file.
    - Allows ONE blank line inside a request (headers/body separator)
    - Splits on TWO consecutive blank lines OR a new request-line after a blank line
    """
    content = content.replace('\r\n', '\n').replace('\r', '\n')
    lines = content.split('\n')

    request_line_re = re.compile(
        r'^(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD|TRACE|CONNECT)\s+\S+\s+HTTP/\d(\.\d)?\s*$'
    )

    requests = []
    current = []
    blank_run = 0

    def flush():
        nonlocal current
        while current and not current[-1].strip():
            current.pop()
        if current:
            req = '\n'.join(current).strip('\n')
            if req.strip():
                requests.append(req)
        current = []

    for line in lines:
        if not line.strip():
            blank_run += 1
            current.append(line)
            if blank_run >= 2:
                flush()
                blank_run = 0
            continue

        if current and blank_run >= 1 and request_line_re.match(line):
            flush()

        current.append(line)
        blank_run = 0

    flush()
    return requests


def url_to_request(url: str) -> str:
    parsed = urlparse(url)
    path = parsed.path or '/'
    if parsed.query:
        path += '?' + parsed.query
    return f"GET {path} HTTP/1.1\nHost: {parsed.netloc}\n"


def main():
    parser = argparse.ArgumentParser(
        description='SQLi Detection Tool - Error-based SQLi scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Scope:
  (default)           Test GET + POST params only
  -c, --cookie-only   Test COOKIE params ONLY
  -f, --full          Test GET + POST + COOKIE together
                      + also tests headers: User-Agent, Referer, X-Forwarded-For

Modes:
  -sr, --singleRecursive  Default mode (tests params one by one)
  -faster                 Batch test, fallback to single if 500
  -fastest                Fastest mode with minimal requests

Examples:
  python3 test.py -r packet.txt
  python3 test.py -r packet.txt --proxy http://127.0.0.1:8080
  python3 test.py -r packet.txt -c                    # cookie-only
  python3 test.py -r packet.txt -f                    # full (params + cookies + headers)
  python3 test.py -r packet.txt -fastest -f
        """
    )

    # Input options
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('-r', '--request', help='File with curl/raw HTTP request(s)')
    input_group.add_argument('-u', '--url', help='Single URL to test')
    input_group.add_argument('-ul', '--url-list', help='File with URLs (one per line)')

    # Mode options
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument('-sr', '--singleRecursive', action='store_true', help='Single recursive mode (default)')
    mode_group.add_argument('-faster', action='store_true', help='Faster batch mode')
    mode_group.add_argument('-fastest', action='store_true', help='Fastest mode')

    # Scope options
    scope_group = parser.add_mutually_exclusive_group()
    scope_group.add_argument('-c', '--cookie-only', action='store_true',
                             help='Test COOKIE parameters ONLY (skip GET/POST)')
    scope_group.add_argument('-f', '--full', action='store_true',
                             help='Test GET+POST+COOKIE together + header tests')

    # Other options
    parser.add_argument('--debug', action='store_true', help='Debug mode')
    parser.add_argument('--proxy', help='Proxy URL (e.g., http://127.0.0.1:8080)')
    parser.add_argument('-t', '--threads', type=int, help='Number of threads (default: 1 for single URL, 5 for -ul)')

    # Optional legacy switch: force JSON mode even if not detected
    parser.add_argument('-json', action='store_true', help='FORCE JSON body mode (otherwise auto-detected)')

    args = parser.parse_args()

    if args.fastest:
        mode = 'fastest'
    elif args.faster:
        mode = 'faster'
    else:
        mode = 'single'

    if args.threads:
        threads = args.threads
    elif args.url_list:
        threads = 5
    else:
        threads = 1

    if args.full:
        scope = 'full'
    elif args.cookie_only:
        scope = 'cookie'
    else:
        scope = 'params'

    # Prepare requests
    requests: List[str] = []

    if args.request:
        try:
            with open(args.request, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()

            if content.lstrip().startswith("curl"):
                requests = [content.strip()]
            else:
                requests = split_requests(content)

        except Exception as e:
            print(f"Error reading file: {e}", file=sys.stderr)
            sys.exit(1)

    elif args.url:
        requests = [url_to_request(args.url)]

    elif args.url_list:
        try:
            with open(args.url_list, 'r', encoding='utf-8', errors='replace') as f:
                urls = [line.strip() for line in f if line.strip()]
            requests = [url_to_request(url) for url in urls]
        except Exception as e:
            print(f"Error reading URL list: {e}", file=sys.stderr)
            sys.exit(1)

    if not requests:
        print("Error: No requests to process", file=sys.stderr)
        sys.exit(1)

    print(f"\n{'='*70}")
    print("SQLi Detection Scanner")
    print(f"Mode: {mode.upper()} | Scope: {scope.upper()} | Threads: {threads} | Requests: {len(requests)}")
    print(f"{'='*70}")

    detector = SQLiDetector(
        debug=args.debug,
        proxy=args.proxy,
        max_workers=threads,
        mode=mode,
        scope=scope,
        force_json=args.json
    )

    all_findings: List[Dict] = []

    for idx, req in enumerate(requests, 1):
        print(f"\n[{idx}/{len(requests)}] Scanning...")
        findings = detector.scan(req)
        if findings:
            all_findings.extend(findings)

    if all_findings:
        print(f"\n\n{'='*70}")
        print(f"⚠️  PROBABLE VULNERABILITY REPORT - {len(all_findings)} FINDING(S)")
        print(f"{'='*70}\n")

        by_url: Dict[str, List[Dict]] = {}
        for finding in all_findings:
            by_url.setdefault(finding.get('url', 'Unknown'), []).append(finding)

        for url, findings in by_url.items():
            print(f"URL: {url}")
            print(f"Highly probable vulnerable parameters: {len(findings)}")
            for finding in findings:
                print(f"  • {finding['param']} ({finding['type']}) - baseline={finding['baseline']}, quote={finding['quote']}, doublequote={finding['dquote']}")
            print()

        print(f"{'='*70}")
        print("DETAILED REPRODUCTION COMMANDS (HEURISTIC)")
        print(f"{'='*70}\n")

        for idx, finding in enumerate(all_findings, 1):
            print(f"[{idx}] {finding['param']} at {finding.get('url', 'Unknown')}")
            print("Single quote probe (triggers 500):")
            print(f"{finding['quote_cmd']}\n")
            print("Two single quotes probe (fixes error):")
            print(f"{finding['dquote_cmd']}\n")
    else:
        print(f"\n{'='*70}")
        print("✓ No SQL injection vulnerabilities detected")
        print(f"{'='*70}\n")


if __name__ == '__main__':
    main()
