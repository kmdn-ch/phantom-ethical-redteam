"""Web page screenshot capture for evidence collection."""

import logging
import subprocess
from datetime import datetime

from .scope_checker import scope_guard
from .logs_helper import log_path

logger = logging.getLogger(__name__)


def run(url: str, full_page: bool = False) -> str:
    guard = scope_guard(url)
    if guard:
        return guard

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = log_path(f"screenshot_{ts}.png")

    # Try playwright first
    try:
        cmd = ["python", "-m", "playwright", "screenshot"]
        if full_page:
            cmd.append("--full-page")
        cmd += [url, output_path]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            logger.info("Screenshot captured via Playwright: %s", output_path)
            return f"Screenshot saved: {output_path}"
    except FileNotFoundError:
        pass
    except Exception as e:
        logger.debug("Playwright screenshot failed: %s", e)

    # Try wkhtmltoimage
    try:
        cmd = ["wkhtmltoimage", "--quality", "80"]
        if not full_page:
            cmd += ["--height", "900", "--crop-h", "900"]
        cmd += [url, output_path]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            logger.info("Screenshot captured via wkhtmltoimage: %s", output_path)
            return f"Screenshot saved: {output_path}"
    except FileNotFoundError:
        pass
    except Exception as e:
        logger.debug("wkhtmltoimage screenshot failed: %s", e)

    # Try chromium headless
    try:
        for browser in ["chromium", "google-chrome", "chrome"]:
            try:
                cmd = [
                    browser, "--headless", "--disable-gpu",
                    f"--screenshot={output_path}",
                    "--window-size=1280,900", "--no-sandbox",
                    url,
                ]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                if result.returncode == 0:
                    logger.info("Screenshot captured via %s: %s", browser, output_path)
                    return f"Screenshot saved: {output_path}"
            except FileNotFoundError:
                continue
    except Exception:
        pass

    return (
        "[TOOL OK, BINARY MISSING] take_screenshot tool is available but no screenshot backend is installed. Install one of:\n"
        "  pip install playwright && playwright install chromium\n"
        "  apt install wkhtmltopdf  (includes wkhtmltoimage)\n"
        "  apt install chromium-browser\n"
        "The take_screenshot tool will work once any backend is installed."
    )


TOOL_SPEC = {
    "name": "take_screenshot",
    "description": (
        "Capture a screenshot of a web page for evidence. "
        "Tries Playwright, wkhtmltoimage, or Chromium headless."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "URL to screenshot"},
            "full_page": {
                "type": "boolean",
                "description": "Capture full scrollable page (default: viewport only)",
            },
        },
        "required": ["url"],
    },
}
