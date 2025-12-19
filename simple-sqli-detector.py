#!/usr/bin/env python3
"""
simple-sqli-scanner.py
Heuristic SQLi scanner that looks for the pattern:
  baseline (any) -> append quote -> 500 -> append double quote -> non-500
Supports:
- Raw Burp request(s) in a file (-r). Multiple requests must be separated by TWO empty lines.
- curl commands exported from Burp (also via -r)
- Single URL (-u) and URL list (-ul)
- Form bodies (x-www-form-urlencoded) and JSON bodies (including NESTED JSON)
- Cookie-only mode (-c)
- Full mode (-f): params + cookies + header probes (User-Agent / Referer / X-Forwarded-For)
JSON handling:
- Auto-detect JSON when Content-Type is JSON OR body parses as JSON
- Optional force JSON mode: -json (kept for README compatibility)
Transport:
- Uses curl for sending requests (curl recalculates Content-Length; Content-Length header is stripped when parsing raw requests).
NOTE:
This is a heuristic scanner. It reports "probable/highly probable" signals, not guaranteed SQL injection.
"""
import re
import argparse
import subprocess
import sys
import json
import threading
from typing import Dict, List, Tuple, Optional, Any, Union
from urllib.parse import urlparse, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed

print_lock = threading.Lock()
RED = "\033[0;31m"
NC = "\033[0m"


# ---------------------------
# Curl / raw request parsing
# ---------------------------
class CurlParser:
    """Parse curl commands OR raw HTTP request from Burp copy-as-text."""
    __slots__ = ('curl_cmd', 'method', 'url', 'headers', 'cookies', 'body', 'extra_flags')

    def __init__(self, curl_cmd: str):
        self.curl_cmd = curl_cmd.strip()
        self.method = "GET"
        self.url = ""
        self.headers: List[str] = []
        self.cookies: List[str] = []
        self.body: Optional[str] = None
        self.extra_flags: List[str] = []

    def parse(self) -> Dict[str, Any]:
        """Parse curl command into components; if not curl, parse raw request."""
        if not self.curl_cmd:
            return self._empty_result()
        if not self.curl_cmd.lstrip().startswith('curl'):
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
                    if not h.lower().startswith("content-length:"):
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

    def _parse_raw_request(self) -> Dict[str, Any]:
        """Parse raw HTTP request from Burp (copy/paste)."""
        lines = self.curl_cmd.split('\n')
        if not lines:
            return self._empty_result()
        parts = lines[0].strip().split(' ')
        if len(parts) < 2:
            return self._empty_result()
        self.method = parts[0].strip()
        path = parts[1].strip()
        host = None
        cookie_header = None
        body_start = len(lines)
        for i, line in enumerate(lines[1:], 1):
            line = line.rstrip('\r').strip('\n')
            if not line.strip():
                body_start = i + 1
                break
            if ':' in line:
                key, _, value = line.partition(':')
                key = key.strip()
                value = value.strip()
                if key.lower() == 'host':
                    host = value
                elif key.lower() == 'cookie':
                    cookie_header = value
                else:
                    if key.lower() != 'content-length':
                        self.headers.append(f"{key}: {value}")
        if host:
            if path.startswith("http://") or path.startswith("https://"):
                self.url = path
            else:
                self.url = f"https://{host}{path}"
        else:
            self.url = path
        if cookie_header:
            self.cookies.append(cookie_header)
        if body_start < len(lines):
            self.body = '\n'.join(lines[body_start:]).strip() or None
        self.extra_flags.append('-k')
        return {
            'method': self.method,
            'url': self.url,
            'headers': self.headers,
            'cookies': self.cookies,
            'body': self.body,
            'extra_flags': self.extra_flags
        }

    def _empty_result(self) -> Dict[str, Any]:
        return {'method': 'GET', 'url': '', 'headers': [], 'cookies': [], 'body': None, 'extra_flags': []}

    def _tokenize(self, cmd: str) -> List[str]:
        """Tokenize command respecting quotes."""
        tokens: List[str] = []
        current: List[str] = []
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


# ---------------------------
# SQLi Detector
# ---------------------------
class SQLiDetector:
    """Detect SQL injection vulnerabilities via 500 -> non-500 transition heuristics."""
    __slots__ = ('debug', 'proxy', 'max_workers', 'mode', 'cookie_only', 'full_mode', 'force_json', 'silent')

    def __init__(
        self,
        debug: bool = False,
        proxy: Optional[str] = None,
        max_workers: int = 10,
        mode: str = 'single',
        cookie_only: bool = False,
        full_mode: bool = False,
        force_json: bool = False,
        silent: bool = False,
    ):
        self.debug = debug
        self.proxy = proxy
        self.max_workers = max_workers
        self.mode = mode
        self.cookie_only = cookie_only
        self.full_mode = full_mode
        self.force_json = force_json
        self.silent = silent

    def build_curl_cmd(
        self,
        base_cmd: Dict[str, Any],
        url: str,
        body: Optional[str] = None,
        cookies: Optional[List[str]] = None,
        headers: Optional[List[str]] = None
    ) -> List[str]:
        cmd = ['curl']
        if base_cmd['method'].upper() != 'GET':
            cmd.extend(['-X', base_cmd['method']])
        hdrs = headers if headers is not None else base_cmd['headers']
        cmd.extend(sum((['-H', h] for h in hdrs), []))
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
        needs_escape = ' $&|;<>(){}[]?~`"\'\\'
        if not any(c in token for c in needs_escape):
            return token
        return "'" + token.replace("'", "'\\''") + "'"

    def is_json_body(self, headers: List[str], body: Optional[str]) -> bool:
        if not body:
            return False
        b = body.strip()
        if self.force_json:
            try:
                json.loads(b)
                return True
            except Exception:
                return False
        ct = None
        for h in headers:
            if h.lower().startswith("content-type:"):
                ct = h.split(":", 1)[1].strip().lower()
                break
        if ct and "application/json" in ct:
            return True
        if b.startswith("{") or b.startswith("["):
            try:
                json.loads(b)
                return True
            except Exception:
                return False
        return False

    @staticmethod
    def _normalize_json_suffix(suffix: str) -> str:
        if suffix == "%27":
            return "'"
        if suffix == "%27%27":
            return "''"
        return suffix

    def extract_params(
        self,
        url: str,
        body: Optional[str],
        headers: List[str]
    ) -> Tuple[Dict[str, List[str]], Dict[str, List[str]], List[str], bool]:
        get_params: Dict[str, List[str]] = {}
        post_params: Dict[str, List[str]] = {}
        json_paths: List[str] = []
        clean_url = url[2:-1] if url.startswith("$'") and url.endswith("'") else url
        parsed = urlparse(clean_url)
        if parsed.query:
            for param in parsed.query.split('&'):
                if '=' in param:
                    key, _, value = param.partition('=')
                    get_params.setdefault(key, []).append(value)
                else:
                    get_params.setdefault(param, []).append('')
        is_json = self.is_json_body(headers, body)
        if body:
            if is_json:
                try:
                    data = json.loads(body)
                    json_paths = self._extract_json_paths(data)
                except Exception:
                    json_paths = []
                    is_json = False
            if not is_json and '=' in body and not body.strip().startswith('{'):
                for param in body.split('&'):
                    if '=' in param:
                        key, _, value = param.partition('=')
                        post_params.setdefault(key, []).append(value)
                    else:
                        post_params.setdefault(param, []).append('')
        return get_params, post_params, json_paths, is_json

    def extract_cookie_params(self, cookies: List[str]) -> Dict[str, List[str]]:
        cookie_params: Dict[str, List[str]] = {}
        for cookie in cookies:
            for part in cookie.split(';'):
                part = part.strip()
                if '=' in part:
                    key, _, value = part.partition('=')
                    cookie_params.setdefault(key, []).append(value)
        return cookie_params

    def _extract_json_paths(self, data: Any, prefix: str = "") -> List[str]:
        paths: List[str] = []
        if isinstance(data, dict):
            for k, v in data.items():
                p = f"{prefix}.{k}" if prefix else k
                paths.extend(self._extract_json_paths(v, p))
        elif isinstance(data, list):
            for i, v in enumerate(data):
                p = f"{prefix}[{i}]" if prefix else f"[{i}]"
                paths.extend(self._extract_json_paths(v, p))
        else:
            if isinstance(data, str) and prefix:
                paths.append(prefix)
        return paths

    @staticmethod
    def _parse_json_path(path: str) -> List[Union[str, int]]:
        tokens: List[Union[str, int]] = []
        buf = ''
        i = 0
        n = len(path)
        while i < n:
            c = path[i]
            if c == '.':
                if buf:
                    tokens.append(buf)
                    buf = ''
                i += 1
                continue
            if c == '[':
                if buf:
                    tokens.append(buf)
                    buf = ''
                j = path.find(']', i + 1)
                if j == -1:
                    break
                idx_str = path[i + 1:j]
                try:
                    tokens.append(int(idx_str))
                except ValueError:
                    tokens.append(idx_str)
                i = j + 1
                continue
            buf += c
            i += 1
        if buf:
            tokens.append(buf)
        return tokens

    def _mutate_json_at_path(self, data: Any, tokens: List[Union[str, int]], suffix: str) -> Any:
        if not tokens:
            if isinstance(data, str):
                return data + suffix
            return data
        head, *tail = tokens
        if isinstance(head, int) and isinstance(data, list):
            new_list = list(data)
            if 0 <= head < len(new_list):
                new_list[head] = self._mutate_json_at_path(new_list[head], tail, suffix)
            return new_list
        if isinstance(head, str) and isinstance(data, dict):
            new_obj = dict(data)
            if head in new_obj:
                new_obj[head] = self._mutate_json_at_path(new_obj[head], tail, suffix)
            return new_obj
        return data

    def mutate_url_param(self, url: str, param_name: str, param_idx: int, suffix: str) -> str:
        clean_url = url[2:-1] if url.startswith("$'") and url.endswith("'") else url
        parsed = urlparse(clean_url)
        parts = []
        current_idx: Dict[str, int] = {}
        for param in parsed.query.split('&') if parsed.query else []:
            if '=' in param:
                key, _, value = param.partition('=')
                idx = current_idx.get(key, 0)
                if key == param_name and idx == param_idx:
                    value += suffix
                current_idx[key] = idx + 1
                parts.append(f"{key}={value}")
            else:
                parts.append(param)
        return urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, '&'.join(parts), parsed.fragment
        ))

    def mutate_body_param(
        self,
        body: str,
        param_name: str,
        param_idx: int,
        suffix: str,
        json_enabled: bool
    ) -> str:
        if not body:
            return body
        if json_enabled and body.strip().startswith(('{', '[')):
            try:
                data = json.loads(body)
                js_suffix = self._normalize_json_suffix(suffix)
                path_tokens = self._parse_json_path(param_name)
                mutated = self._mutate_json_at_path(data, path_tokens, js_suffix)
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

    @staticmethod
    def _get_header(headers: List[str], name: str) -> Optional[Tuple[int, str]]:
        ln = name.lower()
        for i, h in enumerate(headers):
            if ':' not in h:
                continue
            k, _, v = h.partition(':')
            if k.strip().lower() == ln:
                return i, v.strip()
        return None

    @staticmethod
    def _set_header(headers: List[str], name: str, value: str) -> List[str]:
        out = list(headers)
        found = False
        ln = name.lower()
        for i, h in enumerate(out):
            if ':' not in h:
                continue
            k, _, _ = h.partition(':')
            if k.strip().lower() == ln:
                out[i] = f"{name}: {value}"
                found = True
                break
        if not found:
            out.append(f"{name}: {value}")
        return out

    def scan_faster(self, base_cmd: Dict[str, Any]) -> List[Dict[str, Any]]:
        if not self.silent:
            print("Mode: FASTER (batch test with single-recursive fallback)")
        json_enabled = self.is_json_body(base_cmd['headers'], base_cmd.get('body'))
        mut_url = self._mutate_all_url_params(base_cmd['url'], '%27')
        mut_body = self._mutate_all_body(base_cmd.get('body'), '%27', json_enabled)
        mut_cookies = self._mutate_all_cookies(base_cmd.get('cookies', []), "'") if base_cmd.get('cookies') else None
        cmd = self.build_curl_cmd(base_cmd, mut_url, mut_body, mut_cookies)
        status = self.execute_curl(cmd)
        if status == 500:
            if not self.silent:
                print(" → Got 500, switching to single-recursive mode")
            return self.scan_single_recursive(base_cmd)
        else:
            if not self.silent:
                print(f" → Got {status}, skipping")
            return []

    def scan_fastest(self, base_cmd: Dict[str, Any]) -> List[Dict[str, Any]]:
        if not self.silent:
            print("Mode: FASTEST (batch test with double-quote verification)")
        json_enabled = self.is_json_body(base_cmd['headers'], base_cmd.get('body'))
        mut_url1 = self._mutate_all_url_params(base_cmd['url'], '%27')
        mut_body1 = self._mutate_all_body(base_cmd.get('body'), '%27', json_enabled)
        mut_cookies1 = self._mutate_all_cookies(base_cmd.get('cookies', []), "'") if base_cmd.get('cookies') else None
        cmd1 = self.build_curl_cmd(base_cmd, mut_url1, mut_body1, mut_cookies1)
        status1 = self.execute_curl(cmd1)
        if status1 != 500:
            if not self.silent:
                print(f" → Got {status1}, skipping")
            return []
        if not self.silent:
            print(" → Got 500 with single quote")
        mut_url2 = self._mutate_all_url_params(base_cmd['url'], '%27%27')
        mut_body2 = self._mutate_all_body(base_cmd.get('body'), '%27%27', json_enabled)
        mut_cookies2 = self._mutate_all_cookies(base_cmd.get('cookies', []), "''") if base_cmd.get('cookies') else None
        cmd2 = self.build_curl_cmd(base_cmd, mut_url2, mut_body2, mut_cookies2)
        status2 = self.execute_curl(cmd2)
        if status2 != 500:
            if not self.silent:
                print(f" → Got {status2} with double quote, fallback to identify probable input")
            return self.scan_single_recursive(base_cmd)
        else:
            if not self.silent:
                print(" → Still 500 with double quote, skipping")
            return []

    @staticmethod
    def _mutate_all_url_params(url: str, suffix: str) -> str:
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
        return urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, '&'.join(parts), parsed.fragment
        ))

    def _mutate_all_body(self, body: Optional[str], suffix: str, json_enabled: bool) -> Optional[str]:
        if body is None:
            return None
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

    @staticmethod
    def _mutate_json_recursive(data: Any, suffix: str) -> Any:
        if isinstance(data, dict):
            return {k: SQLiDetector._mutate_json_recursive(v, suffix) for k, v in data.items()}
        if isinstance(data, list):
            return [SQLiDetector._mutate_json_recursive(v, suffix) for v in data]
        if isinstance(data, str):
            return data + suffix
        return data

    @staticmethod
    def _mutate_all_cookies(cookies: List[str], suffix: str) -> List[str]:
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

    def scan_single_recursive(self, base_cmd: Dict[str, Any]) -> List[Dict[str, Any]]:
        headers = base_cmd['headers']
        json_enabled = self.is_json_body(headers, base_cmd.get('body'))
        get_params, post_params, json_paths, is_json = self.extract_params(
            base_cmd['url'], base_cmd.get('body'), headers
        )
        cookie_params = self.extract_cookie_params(base_cmd.get('cookies', [])) if base_cmd.get('cookies') else {}
        do_params = not self.cookie_only
        do_cookies = self.cookie_only or self.full_mode
        do_headers = self.full_mode

        get_count = sum(len(v) for v in get_params.values())
        post_count = sum(len(v) for v in post_params.values())
        json_count = len(json_paths) if is_json else 0
        cookie_count = sum(len(v) for v in cookie_params.values())

        if not self.silent:
            if self.cookie_only:
                print(f"Found {cookie_count} COOKIE parameter(s) (cookie-only mode)")
            else:
                if is_json:
                    print(f"Found {get_count} GET, {json_count} JSON string-leaf parameter(s)")
                else:
                    print(f"Found {get_count} GET, {post_count} POST, {cookie_count} COOKIE parameter(s)")

        findings: List[Dict[str, Any]] = []
        tasks: List[Tuple[Any, ...]] = []

        if do_params:
            for param_name, values in get_params.items():
                for idx in range(len(values)):
                    tasks.append((base_cmd, param_name, idx, 'GET', json_enabled))
            if is_json:
                for path in json_paths:
                    tasks.append((base_cmd, path, 0, 'JSON', json_enabled))
            else:
                for param_name, values in post_params.items():
                    for idx in range(len(values)):
                        tasks.append((base_cmd, param_name, idx, 'POST', json_enabled))

        if do_cookies:
            for param_name, values in cookie_params.items():
                for idx in range(len(values)):
                    tasks.append((base_cmd, param_name, idx, 'COOKIE', json_enabled))

        if do_headers:
            base_headers = list(base_cmd['headers'])
            if self._get_header(base_headers, "User-Agent") is None:
                base_headers = self._set_header(base_headers, "User-Agent", "Mozilla/5.0")
            if self._get_header(base_headers, "Referer") is None:
                try:
                    p = urlparse(base_cmd['url'])
                    base_headers = self._set_header(base_headers, "Referer", f"{p.scheme}://{p.netloc}/")
                except Exception:
                    base_headers = self._set_header(base_headers, "Referer", "https://example.com/")
            if self._get_header(base_headers, "X-Forwarded-For") is None:
                base_headers = self._set_header(base_headers, "X-Forwarded-For", "127.0.0.1")
            base_cmd = dict(base_cmd)
            base_cmd['headers'] = base_headers
            tasks.append((base_cmd, "User-Agent", 0, "HEADER", json_enabled))
            tasks.append((base_cmd, "Referer", 0, "HEADER", json_enabled))
            tasks.append((base_cmd, "X-Forwarded-For", 0, "HEADER", json_enabled))

        if not tasks:
            if not self.silent:
                print("Nothing to test with selected flags.")
            return []

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_task = {executor.submit(self.test_parameter, *task): task for task in tasks}
            for future in as_completed(future_to_task):
                result = future.result()
                if result:
                    findings.append(result)
        return findings

    def test_parameter(
        self,
        base_cmd: Dict[str, Any],
        param_name: str,
        param_idx: int,
        param_type: str,
        json_enabled: bool
    ) -> Optional[Dict[str, Any]]:
        if self.debug:
            with print_lock:
                print(f" Testing {param_type}: {param_name}[{param_idx}]")

        baseline_cmd = self.build_curl_cmd(base_cmd, base_cmd['url'], base_cmd.get('body'), base_cmd.get('cookies'), base_cmd.get('headers'))
        baseline_status = self.execute_curl(baseline_cmd)
        if baseline_status is None:
            return None

        if param_type == 'JSON':
            s1, s2 = "%27", "%27%27"
        elif param_type in ('COOKIE', 'HEADER'):
            s1, s2 = "'", "''"
        else:
            s1, s2 = "%27", "%27%27"

        def run_mutation(suffix: str) -> Tuple[Optional[int], List[str]]:
            if param_type == 'GET':
                mut_url = self.mutate_url_param(base_cmd['url'], param_name, param_idx, suffix)
                mut_body = base_cmd.get('body')
                mut_cookies = base_cmd.get('cookies')
                mut_headers = base_cmd.get('headers')
            elif param_type == 'POST':
                mut_url = base_cmd['url']
                mut_body = self.mutate_body_param(base_cmd.get('body') or "", param_name, param_idx, suffix, False)
                mut_cookies = base_cmd.get('cookies')
                mut_headers = base_cmd.get('headers')
            elif param_type == 'JSON':
                mut_url = base_cmd['url']
                mut_body = self.mutate_body_param(base_cmd.get('body') or "", param_name, param_idx, suffix, True)
                mut_cookies = base_cmd.get('cookies')
                mut_headers = base_cmd.get('headers')
            elif param_type == 'COOKIE':
                mut_url = base_cmd['url']
                mut_body = base_cmd.get('body')
                mut_cookies = self.mutate_cookie_param(base_cmd.get('cookies', []), param_name, param_idx, suffix)
                mut_headers = base_cmd.get('headers')
            else:  # HEADER
                mut_url = base_cmd['url']
                mut_body = base_cmd.get('body')
                mut_cookies = base_cmd.get('cookies')
                found = self._get_header(base_cmd.get('headers', []), param_name)
                current_val = found[1] if found else ""
                mut_headers = self._set_header(base_cmd.get('headers', []), param_name, current_val + suffix)
            cmd = self.build_curl_cmd(base_cmd, mut_url, mut_body, mut_cookies, mut_headers)
            st = self.execute_curl(cmd)
            return st, cmd

        quote_status, quote_cmd = run_mutation(s1)
        if quote_status is None or quote_status != 500:
            return None
        dquote_status, dquote_cmd = run_mutation(s2)
        if dquote_status is None or dquote_status == 500:
            return None

        label = param_name if param_type == 'JSON' else f"{param_name}[{param_idx}]"
        return {
            'param': label,
            'type': param_type,
            'baseline': baseline_status,
            'quote': quote_status,
            'dquote': dquote_status,
            'quote_cmd': ' '.join(self._escape_for_bash(t) for t in quote_cmd),
            'dquote_cmd': ' '.join(self._escape_for_bash(t) for t in dquote_cmd),
            'url': base_cmd['url']
        }

    def scan(self, content: str) -> List[Dict[str, Any]]:
        parser = CurlParser(content)
        base_cmd = parser.parse()
        if not base_cmd['url']:
            if not self.silent:
                print("Error: No URL found in request", file=sys.stderr)
            return []
        if not self.silent:
            print(f"\nTarget: {base_cmd['method']} {base_cmd['url']}")
        if self.mode == 'faster':
            return self.scan_faster(base_cmd)
        elif self.mode == 'fastest':
            return self.scan_fastest(base_cmd)
        else:
            return self.scan_single_recursive(base_cmd)


# ---------------------------
# Request preparation
# ---------------------------
def url_to_request(url: str) -> str:
    parsed = urlparse(url)
    path = parsed.path or '/'
    if parsed.query:
        path += '?' + parsed.query
    return f"GET {path} HTTP/1.1\nHost: {parsed.netloc}\n\n"


def split_requests(content: str) -> List[str]:
    lines = content.split('\n')
    requests: List[str] = []
    cur: List[str] = []
    blank_run = 0
    for line in lines:
        if not line.strip():
            blank_run += 1
            cur.append(line)
            if blank_run >= 2:
                while cur and not cur[-1].strip():
                    cur.pop()
                if cur:
                    requests.append('\n'.join(cur).strip('\n'))
                cur = []
                blank_run = 0
            continue
        else:
            blank_run = 0
            cur.append(line)
    while cur and not cur[-1].strip():
        cur.pop()
    if cur:
        requests.append('\n'.join(cur).strip('\n'))
    return [r for r in requests if r.strip()]


# ---------------------------
# Display helpers
# ---------------------------
def _display_hit_name(ftype: str, raw_param: str) -> str:
    if not raw_param:
        return "Unknown"
    if ftype == "JSON":
        leaf = raw_param.rsplit(".", 1)[-1]
        leaf = re.sub(r"\[\d+\]", "", leaf)
        return leaf or raw_param
    if ftype in ("GET", "POST", "COOKIE") and "[" in raw_param and raw_param.endswith("]"):
        return raw_param.split("[", 1)[0]
    return raw_param


# ---------------------------
# Main
# ---------------------------
def main():
    parser = argparse.ArgumentParser(
        description='simple-sqli-scanner.py - Error-heuristic SQLi scanner (500 -> non-500)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes:
  -sr, --singleRecursive   Default mode (tests inputs one by one)
  -faster                  Faster batch mode
  -fastest                 Fastest mode with minimal requests

Input:
  -r/--request FILE        Raw Burp or curl requests (multiple separated by two blank lines)
  -u/--url URL             Single URL
  -ul/--url-list FILE      List of URLs

Scope:
  -c/--cookie-only         Test only cookies
  -f/--full                Test params + cookies + common headers

Other:
  --debug                  Show debug output
  --proxy URL              Use proxy
  -t/--threads N           Threads (default: 1 or 5 for -ul)
  -json                    Force JSON body parsing
  -s/--silent              Only show output if vulnerabilities found
  -o/--output FILE         Save report to file (only if hits found in silent mode)

Examples:
  python3 simple-sqli-scanner.py -r requests.txt
  python3 simple-sqli-scanner.py -ul urls.txt -t 20 -s -o results.txt
  python3 simple-sqli-scanner.py -r burp.txt -f -s -o vulns.txt
        """
    )
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('-r', '--request', help='File with curl/raw HTTP request(s)')
    input_group.add_argument('-u', '--url', help='Single URL to test')
    input_group.add_argument('-ul', '--url-list', help='File with URLs (one per line)')

    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument('-sr', '--singleRecursive', action='store_true', help='Single recursive mode (default)')
    mode_group.add_argument('-faster', action='store_true', help='Faster batch mode')
    mode_group.add_argument('-fastest', action='store_true', help='Fastest mode')

    scope_group = parser.add_mutually_exclusive_group()
    scope_group.add_argument('-c', '--cookie-only', action='store_true', help='ONLY test cookie parameters')
    scope_group.add_argument('-f', '--full', action='store_true', help='Test params + cookies + header probes')

    parser.add_argument('--debug', action='store_true', help='Debug mode')
    parser.add_argument('--proxy', help='Proxy URL (e.g., http://127.0.0.1:8080)')
    parser.add_argument('-t', '--threads', type=int, help='Number of threads')
    parser.add_argument('-json', action='store_true', help='Force JSON mode')
    parser.add_argument('-s', '--silent', action='store_true', help='Silent mode: only output on findings')
    parser.add_argument('-o', '--output', help='Save final report to file')

    args = parser.parse_args()

    mode = 'fastest' if args.fastest else 'faster' if args.faster else 'single'
    threads = args.threads or (5 if args.url_list else 1)

    requests: List[str] = []
    if args.request:
        with open(args.request, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
        requests = split_requests(content)
    elif args.url:
        requests = [url_to_request(args.url)]
    elif args.url_list:
        with open(args.url_list, 'r', encoding='utf-8', errors='replace') as f:
            urls = [line.strip() for line in f if line.strip()]
        requests = [url_to_request(url) for url in urls]

    if not requests:
        print("Error: No requests to process", file=sys.stderr)
        sys.exit(1)

    if not args.silent:
        print(f"\n{'='*70}")
        print("SQLi Detection Scanner (heuristic)")
        print(f"Mode: {mode.upper()} | Threads: {threads} | Requests: {len(requests)} | "
              f"Scope: {'COOKIE-ONLY' if args.cookie_only else 'FULL' if args.full else 'PARAMS'}")
        print(f"{'='*70}")

    detector = SQLiDetector(
        debug=args.debug,
        proxy=args.proxy,
        max_workers=threads,
        mode=mode,
        cookie_only=args.cookie_only,
        full_mode=args.full,
        force_json=args.json,
        silent=args.silent
    )

    all_findings: List[Dict[str, Any]] = []
    for idx, req in enumerate(requests, 1):
        if not args.silent:
            print(f"\n[{idx}/{len(requests)}] Scanning...")
        findings = detector.scan(req)
        all_findings.extend(findings)

    # Generate report only if there are findings (or always in non-silent)
    if all_findings:
        report_lines = []
        report_lines.append(f"\n{'='*70}")
        report_lines.append(f"⚠️ PROBABLE SQLi SIGNAL(S) FOUND - {len(all_findings)} HIT(S)")
        report_lines.append(f"{'='*70}\n")

        by_url: Dict[str, List[Dict[str, Any]]] = {}
        hit_summary: Dict[str, Dict[str, set]] = {}
        for finding in all_findings:
            url = finding.get('url', 'Unknown')
            by_url.setdefault(url, []).append(finding)
            ftype = finding['type']
            raw_param = finding['param']
            key_name = _display_hit_name(ftype, raw_param)
            hit_summary.setdefault(url, {}).setdefault(ftype, set()).add(key_name)

        report_lines.append("HIT SUMMARY (inputs matching 500 → non-500 pattern):\n")
        for url in sorted(hit_summary):
            report_lines.append(f"URL: {url}")
            for ftype in sorted(hit_summary[url]):
                keys = ", ".join(sorted(f"{RED}{k}{NC}" for k in hit_summary[url][ftype]))
                report_lines.append(f" {ftype}: {keys}")
            report_lines.append("")

        report_lines.append(f"{'='*70}")
        report_lines.append("DETAILS (per-hit entries)")
        report_lines.append(f"{'='*70}\n")
        for url, findings in by_url.items():
            report_lines.append(f"URL: {url}")
            report_lines.append(f"Probable vulnerable inputs: {len(findings)}")
            for f in findings:
                report_lines.append(f" • {f['param']} ({f['type']}) - baseline={f['baseline']}, quote={f['quote']}, doublequote={f['dquote']}")
            report_lines.append("")

        report_lines.append(f"{'='*70}")
        report_lines.append("DETAILED REPRODUCTION COMMANDS")
        report_lines.append(f"{'='*70}\n")
        for i, f in enumerate(all_findings, 1):
            report_lines.append(f"[{i}] {f['param']} ({f['type']}) at {f.get('url', 'Unknown')}")
            report_lines.append("Single quote (triggers 500):")
            report_lines.append(f"{f['quote_cmd']}\n")
            report_lines.append("Double quote (removes 500):")
            report_lines.append(f"{f['dquote_cmd']}\n")

        report = "\n".join(report_lines)

        # Always print when findings exist
        print(report)

        # Save to file if -o specified
        if args.output:
            try:
                with open(args.output, 'w', encoding='utf-8') as f:
                    f.write(report)
                if not args.silent:
                    print(f"\nReport saved to: {args.output}")
            except Exception as e:
                print(f"Error saving report: {e}", file=sys.stderr)
    else:
        if not args.silent:
            print(f"\n{'='*70}")
            print("✓ No SQLi signals detected (heuristic)")
            print(f"{'='*70}\n")
        # In silent mode with no findings and -o: optionally create empty file
        if args.output:
            try:
                with open(args.output, 'w', encoding='utf-8') as f:
                    f.write("No SQLi signals detected.\n")
                if not args.silent:
                    print(f"Empty report saved to: {args.output}")
            except Exception as e:
                print(f"Error saving empty report: {e}", file=sys.stderr)


if __name__ == '__main__':
    main()
