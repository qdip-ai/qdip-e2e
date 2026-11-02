"""#407 real Chromium preview smoke; not a substitute for admin login E2E.

Runs against the immutable Vercel PR preview. Never bypasses authentication,
creates a user, or fabricates a session. Screenshots remain in the QA container.
"""
from __future__ import annotations

import base64
import os
from pathlib import Path
from urllib.parse import urlsplit

from playwright.sync_api import sync_playwright

URL = os.environ.get("QDIP_P1_PREVIEW_URL", "").rstrip("/")
SIZES = (
    ("desktop", 1440, 900),
    ("mobile-portrait", 390, 844),
    ("mobile-landscape", 844, 390),
)
OUTPUT = Path("/tmp/qdip-sdk-p1-browser")


def main() -> None:
    parsed = urlsplit(URL)
    if parsed.scheme != "https" or not parsed.hostname:
        raise RuntimeError("QDIP_P1_PREVIEW_URL must be an HTTPS deployment URL")
    OUTPUT.mkdir(parents=True, exist_ok=True)
    blocked_viewports = []
    with sync_playwright() as browser_driver:
        browser = browser_driver.chromium.launch(
            executable_path="/usr/bin/chromium", headless=True, args=["--no-sandbox"]
        )
        try:
            for label, width, height in SIZES:
                context = browser.new_context(
                    viewport={"width": width, "height": height},
                    device_scale_factor=1,
                )
                page = context.new_page()
                try:
                    response = page.goto(
                        URL + "/uk/admin/plugins",
                        wait_until="domcontentloaded", timeout=30000,
                    )
                    if response is None:
                        raise AssertionError("Browser received no page response")
                    final = urlsplit(page.url)
                    page.screenshot(path=str(OUTPUT / (label + ".png")), full_page=True)
                    # Capture actual browser pixels for evidence; no real
                    # authenticated sessions or credentials are involved.
                    screenshot = page.screenshot(
                        type="jpeg", quality=45, full_page=False,
                    )
                    print(
                        "SDK_P1_BROWSER_JPEG_" + label + "="
                        + base64.b64encode(screenshot).decode("ascii"),
                        flush=True,
                    )
                    print(
                        "SDK_P1_BROWSER_VIEWPORT=" + label
                        + " http=" + str(response.status)
                        + " final_host=" + str(final.hostname)
                        + " screenshot=" + str(OUTPUT / (label + ".png")),
                        flush=True,
                    )
                    if response.status >= 500:
                        raise AssertionError("Preview server error")
                    if (
                        final.hostname != parsed.hostname
                        and "vercel" in (final.hostname or "")
                    ) or "Vercel Authentication" in page.title():
                        blocked_viewports.append(label)
                        print("SDK_P1_BROWSER_BLOCKED=" + label
                              + ":Vercel deployment protection", flush=True)
                        continue
                    # No logged-in admin in this run. This is a negative
                    # authorization smoke only; the full panel E2E remains open.
                    visible_review = page.locator(
                        'section[aria-label="Заявки сторонніх розробників"]'
                    ).count()
                    if visible_review:
                        raise AssertionError("Anonymous session reached admin review UI")
                    result = context.request.get(
                        URL + "/api/observatory/admin/plugin-publication-submissions",
                        timeout=15000,
                    )
                    content_type = result.headers.get("content-type", "")
                    if "application/json" not in content_type:
                        blocked_viewports.append(label)
                        print("SDK_P1_BROWSER_BLOCKED=" + label
                              + ":BFF not reachable as JSON", flush=True)
                        continue
                    if result.status not in (401, 403):
                        raise AssertionError(
                            "Unauthorized queue returned HTTP " + str(result.status)
                        )
                    print(
                        "SDK_P1_BROWSER_ANON_QUEUE_DENIED=" + label
                        + " http=" + str(result.status),
                        flush=True,
                    )
                finally:
                    context.close()
            if blocked_viewports:
                print("QDIP_SDK_P1_BROWSER_PREVIEW=BLOCKED viewports="
                      + ",".join(blocked_viewports), flush=True)
                raise RuntimeError("Real QDIP browser E2E blocked by preview protection")
            print("QDIP_SDK_P1_BROWSER_ANONYMOUS=PASS viewports=3", flush=True)
            print("QDIP_SDK_P1_BROWSER_REAL_ZITADEL_ADMIN=NOT_TESTED", flush=True)
        finally:
            browser.close()


if __name__ == "__main__":
    main()
