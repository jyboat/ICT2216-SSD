import os
import time
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.remote.webdriver import WebDriver
from selenium.common.exceptions import WebDriverException

def test_login_page_loads():
    options = Options()
    options.add_argument("--headless")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")

    # Selenium container exposed to localhost:4444
    selenium_host = "localhost"
    remote_url = f'http://{selenium_host}:4444/wd/hub'

    # Retry logic: wait up to 30 seconds for WebDriver to be ready
    driver = None
    for attempt in range(6):  # try every 5 seconds up to 30s
        try:
            driver: WebDriver = webdriver.Remote(command_executor=remote_url, options=options)
            break
        except WebDriverException:
            print(f"[Attempt {attempt + 1}] Selenium not ready, retrying...")
            time.sleep(5)

    if driver is None:
        raise RuntimeError("Selenium server not reachable after retries.")

    try:
        time.sleep(2)  # give Flask some time to boot
        driver.get("http://127.0.0.1:5000/login")
        assert "Login" in driver.title
    finally:
        driver.quit()
