import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional

import requests

from .models import FetchResult


_HTML_PREFIX_RE = re.compile(r"^(?:<!doctype\s+html|<html|<head|<body)(?:\s|>)", re.IGNORECASE)


def validate_response_content(content: str, content_type: str = "") -> Optional[str]:
    """Return an error when a successful HTTP response is not usable rule content."""
    if not content or not content.strip():
        return "empty response body"

    if "text/html" in content_type.lower() or _HTML_PREFIX_RE.match(content.lstrip()):
        return "HTML response instead of rule list"

    return None


def fetch_url(url: str, timeout: int = 15, retries: int = 2) -> FetchResult:
    attempts = retries + 1
    last_error = None

    for attempt in range(attempts):
        try:
            response = requests.get(url, timeout=timeout)
            if response.status_code == 200:
                content = response.text
                content_error = validate_response_content(
                    content,
                    response.headers.get("Content-Type", ""),
                )
                if content_error is None:
                    return FetchResult(
                        url=url,
                        success=True,
                        status_code=response.status_code,
                        content=content,
                    )
                last_error = content_error
            else:
                last_error = f"HTTP {response.status_code}"
        except Exception as exc:
            last_error = str(exc)

        if attempt < attempts - 1:
            backoff_seconds = 0.5 * (2**attempt)
            time.sleep(backoff_seconds)

    return FetchResult(url=url, success=False, error=last_error)


def fetch_many(urls: List[str], timeout: int = 15, retries: int = 2) -> List[FetchResult]:
    if not urls:
        return []

    max_workers = min(8, len(urls))
    results: List[FetchResult] = [FetchResult(url=url, success=False, error="not started") for url in urls]

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_index = {
            executor.submit(fetch_url, url, timeout, retries): idx for idx, url in enumerate(urls)
        }
        for future in as_completed(future_to_index):
            idx = future_to_index[future]
            try:
                results[idx] = future.result()
            except Exception as exc:
                results[idx] = FetchResult(url=urls[idx], success=False, error=str(exc))

    return results
