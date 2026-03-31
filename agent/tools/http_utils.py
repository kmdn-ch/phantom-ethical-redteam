"""HTTP utilities — retry with exponential backoff + stealth integration."""

import time
import logging
import requests

logger = logging.getLogger(__name__)

try:
    from .rate_limiter import limiter as _global_limiter
except ImportError:
    _global_limiter = None


def retry_request(
    url: str,
    *,
    method: str = "GET",
    max_retries: int = 3,
    backoff_factor: float = 2.0,
    timeout: int = 15,
    **kwargs,
) -> requests.Response:
    """Execute an HTTP request with exponential backoff on failure.

    Automatically applies stealth headers and proxy if stealth module is loaded
    and no explicit headers/proxies are provided.
    """
    # Integrate stealth headers if not explicitly provided
    try:
        from .stealth import stealth_headers, get_proxy

        if "headers" not in kwargs:
            kwargs["headers"] = stealth_headers()
        proxies = get_proxy()
        if proxies and "proxies" not in kwargs:
            kwargs["proxies"] = proxies
    except ImportError:
        pass

    # Default verify=False for pentesting (self-signed certs are common)
    verify = kwargs.pop("verify", False)

    last_exc = None
    for attempt in range(max_retries + 1):
        # Enforce global rate limit before every request
        if _global_limiter is not None:
            _global_limiter.wait()

        try:
            resp = requests.request(
                method, url, timeout=timeout, verify=verify, **kwargs
            )

            # 429 Too Many Requests — retryable; honour Retry-After header
            if resp.status_code == 429:
                if _global_limiter is not None:
                    _global_limiter.on_rate_limited()
                retry_after = resp.headers.get("Retry-After")
                if retry_after:
                    try:
                        wait = float(retry_after)
                    except ValueError:
                        wait = backoff_factor**attempt
                else:
                    wait = backoff_factor**attempt
                logger.warning(
                    "HTTP %s %s — 429 rate limited (attempt %d/%d), waiting %.1fs",
                    method,
                    url,
                    attempt + 1,
                    max_retries + 1,
                    wait,
                )
                if attempt < max_retries:
                    time.sleep(wait)
                    last_exc = requests.exceptions.HTTPError(response=resp)
                    continue
                resp.raise_for_status()

            # Other client errors (4xx) are permanent — never retry them
            if 400 <= resp.status_code < 500:
                logger.error(
                    "HTTP %s %s — client error %d (not retryable): %s",
                    method,
                    url,
                    resp.status_code,
                    f"{resp.status_code} Client Error for url: {url}",
                )
                resp.raise_for_status()

            # Server errors (5xx) are transient — retry them
            if resp.status_code >= 500:
                resp.raise_for_status()

            return resp
        except requests.exceptions.HTTPError as exc:
            # 4xx (non-429): permanent failure, raise immediately without retry
            if (
                exc.response is not None
                and 400 <= exc.response.status_code < 500
                and exc.response.status_code != 429
            ):
                raise
            # 5xx: transient, fall through to retry logic
            last_exc = exc
            if attempt < max_retries:
                wait = backoff_factor**attempt
                logger.warning(
                    "HTTP %s %s failed (attempt %d/%d): %s — retrying in %.1fs",
                    method,
                    url,
                    attempt + 1,
                    max_retries + 1,
                    exc,
                    wait,
                )
                time.sleep(wait)
            else:
                logger.error(
                    "HTTP %s %s failed after %d attempts: %s",
                    method,
                    url,
                    max_retries + 1,
                    exc,
                )
        except (requests.ConnectionError, requests.Timeout) as exc:
            # Connection/timeout errors are transient — retry
            last_exc = exc
            if attempt < max_retries:
                wait = backoff_factor**attempt
                logger.warning(
                    "HTTP %s %s failed (attempt %d/%d): %s — retrying in %.1fs",
                    method,
                    url,
                    attempt + 1,
                    max_retries + 1,
                    exc,
                    wait,
                )
                time.sleep(wait)
            else:
                logger.error(
                    "HTTP %s %s failed after %d attempts: %s",
                    method,
                    url,
                    max_retries + 1,
                    exc,
                )
        except requests.RequestException as exc:
            # Other request errors — not retryable
            logger.error(
                "HTTP %s %s — request error (not retryable): %s", method, url, exc
            )
            raise
    raise last_exc
