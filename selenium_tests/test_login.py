from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.remote.webdriver import WebDriver

def test_login_page_loads():
    options = Options()
    options.add_argument("--headless")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")

    driver: WebDriver = webdriver.Remote(
        command_executor='http://localhost:4444/wd/hub',
        options=options
    )

    driver.get("http://localhost/login")
    assert "StudyNest Login" in driver.title

    assert driver.find_element(By.NAME, "email")
    assert driver.find_element(By.NAME, "password")
    assert driver.find_element(By.ID, "signInBtn")

    driver.quit()
