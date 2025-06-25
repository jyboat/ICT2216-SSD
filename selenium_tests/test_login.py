from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
from selenium.webdriver.remote.webdriver import WebDriver

def test_login_page_loads():
    options = Options()
    options.add_argument("--headless")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")

    # Use remote WebDriver to connect to the Docker container
    driver: WebDriver = webdriver.Remote(
        command_executor='http://localhost:4444/wd/hub',
        options=options,
        desired_capabilities=DesiredCapabilities.CHROME
    )

    driver.get("http://localhost/login")
    assert "StudyNest Login" in driver.title

    # Optional: check for form fields
    assert driver.find_element(By.NAME, "email")
    assert driver.find_element(By.NAME, "password")
    assert driver.find_element(By.ID, "signInBtn")

    driver.quit()
