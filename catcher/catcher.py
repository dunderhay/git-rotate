import os
import threading
import logging
from datetime import datetime
from colorama import Fore, Style
from flask import Flask, request, jsonify


app = Flask(__name__)

log_directory = "output"
if not os.path.exists(log_directory):
    os.makedirs(log_directory)

logging.basicConfig(filename=os.path.join(log_directory, 'full.log'), level=logging.INFO, format='[%(asctime)s %(levelname)s] %(message)s')

def log_message(message, color=None):
    timestamp = datetime.now().strftime("%d-%m-%Y %H:%M:%S")
    if color:
        print(f"[{timestamp}] {color}{message}{Style.RESET_ALL}")
    else:
        print(f"[{timestamp}] {message}")

    logging.info(f"{message}")


# When a POST message is received by web server, process the data
def process_response(username, password, response_code, response):
    if response_code == 200:
        log_message(
            f"[+] {username} : {password}",
            color=Fore.GREEN,
        )
    else:
        # Check for error codes in response
        # List of Entra ID error codes - https://learn.microsoft.com/en-us/entra/identity-platform/reference-error-codes
        if "AADSTS50126" in response:
            # Standard invalid password
            log_message(
                f"[*] Valid user, but invalid password {username} : {password}",
                color=Fore.YELLOW,
            )
        elif "AADSTS50055" in response:
            # User password is expired
            log_message(
                f"[+] {username} : {password} - NOTE: The user's password is expired.",
                color=Fore.GREEN,
            )
        elif "AADSTS50079" in response or "AADSTS50076" in response:
            # Microsoft MFA response
            log_message(
                f"[+] {username} : {password} - NOTE: The response indicates MFA (Microsoft) is in use.",
                color=Fore.GREEN,
            )
        elif "AADSTS50158" in response:
            # Conditional Access response (Based off of limited testing this seems to be the repsonse to DUO MFA)
            log_message(
                f"[+] {username} : {password} - NOTE: Conditional access policy (MFA: DUO or other) is in use.",
                color=Fore.GREEN,
            )
        elif "AADSTS53003" in response:
            # Conditional Access response - access policy blocks token issuance
            log_message(
                f"[+] {username} : {password} - NOTE: Conditional access policy is in place and blocks token issuance.",
                color=Fore.GREEN,
            )
        elif "AADSTS53000" in response:
            # Conditional Access response - access policy requires a compliant device
            log_message(
                f"[+] {username} : {password} - NOTE: Conditional access policy is in place and requires a compliant device, and the device isn't compliant.",
                color=Fore.GREEN,
            )
        elif "AADSTS530035" in response:
            # Access block by security defaults
            log_message(
                f"[+] {username} : {password} - NOTE: Access has been blocked by security defaults. The request is deemed unsafe by security defaults policies",
                color=Fore.GREEN,
            )
        elif "AADSTS50128" in response or "AADSTS50059" in response:
            # Invalid Tenant Response
            log_message(
                f"[-] Tenant for account {username} doesn't exist. Check the domain to make sure they are using Azure/O365 services.",
                color=Fore.YELLOW,
            )
        elif "AADSTS50034" in response:
            # Invalid Username
            log_message(
                f"[-] The user {username} doesn't exist.",
                color=Fore.YELLOW,
            )

        elif "AADSTS50053" in response:
            # Locked out account or Smart Lockout in place
            log_message(
                f"[!] The account {username} appears to be locked.",
                color=Fore.RED,
            )
        elif "AADSTS50057" in response:
            # Disabled account
            log_message(
                f"[!] The account {username} appears to be disabled.",
                color=Fore.YELLOW,
            )
        else:
            # Unknown errors
            log_message(
                f"[*] Got an error we haven't seen yet for user {username}",
            )
            log_message(response)


@app.route("/wow-amazing", methods=["POST"])
def handle_post_data():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    login_response_code = data.get("status_code")
    login_response = data.get("response")

    # Start a new thread to process the response asynchronously
    threading.Thread(
        target=process_response,
        args=(
            username,
            password,
            login_response_code,
            login_response,
        ),
    ).start()

    result = {"message": "Data received and processed successfully"}
    return jsonify(result)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=20005)
