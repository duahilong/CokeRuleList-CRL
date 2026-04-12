from typing import List

import requests

from .models import FetchResult


def fetch_url(url: str, timeout: int = 15, retries: int = 2) -> FetchResult:
    attempts = retries + 1
    last_error = None

    for _ in range(attempts):
        try:
            response = requests.get(url, timeout=timeout)
            if response.status_code == 200:
                return FetchResult(
                    url=url,
                    success=True,
                    status_code=response.status_code,
                    content=response.text,
                )
            last_error = f"HTTP {response.status_code}"
        except Exception as exc:
            last_error = str(exc)

    return FetchResult(url=url, success=False, error=last_error)


def fetch_many(urls: List[str], timeout: int = 15, retries: int = 2) -> List[FetchResult]:
    return [fetch_url(url, timeout=timeout, retries=retries) for url in urls]
