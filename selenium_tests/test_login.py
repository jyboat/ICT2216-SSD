import os
import time
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.remote.webdriver import WebDriver

def test_login_page_loads():
    # Set up Chrome options
    options = Options()
    options.add_argument("--headless")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")

    selenium_host = "localhost"
    
    # Use remote WebDriver for GitHub Actions and local
    driver: WebDriver = webdriver.Remote(
        command_executor=f'http://{selenium_host}:4444/wd/hub',
        options=options
    )

    try:
        # Wait for Flask app to be ready
        time.sleep(5)

        # Visit the login page
        driver.get("http://127.0.0.1:5000/login")
        assert "Login" in driver.title
    finally:
        driver.quit()
