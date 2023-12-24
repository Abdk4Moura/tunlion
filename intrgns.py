#!/usr/bin/env python3

# assuming a testing framework like pytest and a
# browser automation library like Playwright

import os
import pytest
from playwright.sync_api import sync_playwright

config = {
    "test_page": "tests/index.html?hidepassed",
    "disable_watching": True,
    "launch_in_ci": ["chromium"],  # Adjusted for Playwright's browser names
    "launch_in_dev": ["chromium"],
    "browser_start_timeout": 120,
    "browser_args": {
        "chromium": {
            "ci": [
                "--no-sandbox" if os.environ.get("CI") else None,
                "--headless",
                "--disable-dev-shm-usage",
                "--disable-software-rasterizer",
                "--mute-audio",
                "--remote-debugging-port=0",
                "--window-size=1440,900",
            ],
        },
    },
}

# Example usage in a pytest fixture
@pytest.fixture(scope="session")
def playwright():
    with sync_playwright() as p:
        browser = p.chromium.launch(**config["browser_args"]["chromium"]["ci"])
        yield browser
        browser.close()
