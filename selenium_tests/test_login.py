import os
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.remote.webdriver import WebDriver

def test_login_page_loads():
    # Set up Chrome options
    options = Options()
    options.add_argument("--headless")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")

    # Detect if running in GitHub Actions
    selenium_host = "localhost"
    if os.getenv("GITHUB_ACTIONS") == "true":
        selenium_host = "selenium"

    # Connect to the correct WebDriver endpoint
    driver: WebDriver = webdriver.Remote(
        command_executor=f'http://{selenium_host}:4444/wd/hub',
        options=options
    )

    # Load login page
    driver.get("http://localhost/login")
    assert "StudyNest Login" in driver.title

    # Check for essential elements
    assert driver.find_element(By.NAME, "email")
    assert driver.find_element(By.NAME, "password")
    assert driver.find_element(By.ID, "signInBtn")

    driver.quit()
