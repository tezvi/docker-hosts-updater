#!/usr/bin/env python3
"""
Copyright (c) 2025 Andrej Vitez

This software is released under the MIT License.
See the LICENSE file for more details.

Description:
    This script updates the /etc/hosts file with the IP addresses and hostnames of currently running Docker containers.
    It ensures that a designated block (between "# BEGIN DOCKER CONTAINERS" and "# END DOCKER CONTAINERS") exists in /etc/hosts
    and is kept up-to-date by monitoring Docker events such as container start and network disconnect.

Usage:
    Run the script with elevated privileges, for example:
        sudo ./docker-update-hosts

Author: Andrej Vitez <andrejvitez@gmail.com>
Date: 2025-02-25
"""

import subprocess
import re
import os
import json
import tempfile
import logging
import argparse

DEFAULT_LOG_LEVEL = logging.INFO
HOSTS_FILE = "/etc/hosts"
BEGIN_BLOCK = "# BEGIN DOCKER CONTAINERS"
END_BLOCK = "# END DOCKER CONTAINERS"
DOMAIN_SUFFIX = '.docker'

def setup_logging(log_level):
    """
    Configures the logging system with the specified log level.
    """
    logger = logging.getLogger(__name__)
    logger.setLevel(log_level)

    handler = logging.StreamHandler()  # Logs to stderr
    formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    handler.setFormatter(formatter)

    # Avoid duplicate handlers
    if not logger.handlers:
        logger.addHandler(handler)

    logger.debug(f"Logging level set to: {logging.getLevelName(log_level)}")
    return logger

def ensure_block_exists(logger):
    """
    Ensure that /etc/hosts contains the BEGIN_BLOCK and END_BLOCK lines.
    If not present, append them.
    """
    logger.debug("Ensuring block exists in /etc/hosts")
    try:
        with open(HOSTS_FILE, "r") as f:
            contents = f.read()
    except FileNotFoundError:
        logger.error(f"Hosts file not found: {HOSTS_FILE}")
        return

    if BEGIN_BLOCK not in contents:
        logger.info(f"Block not found in {HOSTS_FILE}, appending it.")
        with open(HOSTS_FILE, "a") as f:
            f.write(f"\n{BEGIN_BLOCK}\n{END_BLOCK}\n")
    else:
        logger.debug(f"Block already exists in {HOSTS_FILE}")

def generate_docker_hosts_lines(logger):
    """
    1. Get the list of running container IDs.
    2. Inspect containers via Docker to retrieve their IP addresses and names.
    3. Transform each container's name and IP into lines of the form:
       [IP or "# no ip address:"] [transformed_container_name]
    4. Return a list of those lines.
    """
    logger.debug("Generating Docker hosts lines")
    try:
        # Get container IDs
        logger.debug("Getting container IDs")
        container_ids = subprocess.check_output(
            ["docker", "container", "ls", "-q"],
            text=True
        ).strip().split()
        logger.debug(f"Found container IDs: {container_ids}")
    except subprocess.CalledProcessError as e:
        logger.error(f"Error getting container IDs: {e}")
        # If for some reason the 'docker' command fails, just return empty
        return []

    if not container_ids:
        logger.info("No running containers found.")
        return []

    # Inspect all containers at once
    try:
        logger.debug(f"Inspecting containers: {container_ids}")
        inspect_output = subprocess.check_output(
            ["docker", "container", "inspect"] + container_ids,
            text=True
        )
        logger.debug("Container inspection successful.")
    except subprocess.CalledProcessError as e:
        logger.error(f"Error inspecting containers: {e}")
        return []

    try:
        data = json.loads(inspect_output)
    except json.JSONDecodeError as e:
        logger.error(f"Error decoding JSON output from docker inspect: {e}")
        return []

    result_lines = []
    for container in data:
        container_name = container.get("Name", "")
        hostname = generate_hostname(container_name, logger)
        networks = container.get("NetworkSettings", {}).get("Networks", {})
        ip_found = False
        logger.debug(f"Processing container: {container_name}")

        for net_key, net_info in networks.items():
            ip = net_info.get("IPAddress", "")
            network_hostname=hostname
            if ip:
                # If we already have an IP address for this container append the network name to get unique DNS record
                if ip_found:
                    network_hostname = generate_hostname(net_key, logger)
                else:
                    ip_found = True

                result_lines.append(f"{ip} {network_hostname}")
                logger.debug(f"  Found IP: {ip} for hostname: {network_hostname}")

        if not ip_found:
            # If no IP addresses were found, mimic the "# no ip address:" line
            result_lines.append(f"# no ip address detected: {hostname}")
            logger.warning(f"  No IP address found for container: {container_name}")

    logger.debug(f"Generated Docker hosts lines: {result_lines}")
    return result_lines


def generate_hostname(name, logger):
    # Transform name according to rules:
    #  - Remove leading "/"
    #  - Remove trailing "_1"
    #  - Replace "_" with "-"
    #  - Append ".docker"
    logger.debug(f"Generating hostname for: {name}")
    if name.startswith("/"):
        name = name[1:]
    if name.endswith("_1"):
        name = name[:-2]
    name = name.replace("_", "-")
    hostname = name + (".docker" if DOMAIN_SUFFIX and DOMAIN_SUFFIX not in name else "")
    logger.debug(f"Generated hostname: {hostname}")
    return hostname


def update_hosts(logger):
    """
    Regenerate the block between BEGIN_BLOCK and END_BLOCK in /etc/hosts
    with the current container IP/name mappings.
    """
    logger.info("Updating /etc/hosts")
    docker_lines = generate_docker_hosts_lines(logger)

    # Read the current /etc/hosts
    try:
        with open(HOSTS_FILE, "r") as f:
            content = f.read()
    except FileNotFoundError:
        logger.error(f"Hosts file not found: {HOSTS_FILE}")
        return

    # Use a regex to replace everything between BEGIN_BLOCK and END_BLOCK
    pattern = re.compile(
        rf"({re.escape(BEGIN_BLOCK)})(.*?)({re.escape(END_BLOCK)})",
        re.DOTALL
    )
    new_block_content = (
        BEGIN_BLOCK + "\n" +
        "\n".join(docker_lines) + "\n" +
        END_BLOCK
    )

    new_content = re.sub(pattern, new_block_content, content)

    # Write out to a temporary file, then move it into place
    with tempfile.NamedTemporaryFile("w", delete=False) as tmpf:
        tmpf.write(new_content)
        tmp_name = tmpf.name
        logger.debug(f"Wrote new content to temporary file: {tmp_name}")

    os.chmod(tmp_name, 0o644)
    logger.debug(f"Changed permissions of temporary file to 0o644")
    os.replace(tmp_name, HOSTS_FILE)
    logger.info(f"Updated {HOSTS_FILE} successfully.")

def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Update /etc/hosts with Docker container IPs.")
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Set the logging level (default: INFO)",
    )
    parser.set_defaults(log_level=logging.getLevelName(DEFAULT_LOG_LEVEL))
    args = parser.parse_args()

    # Set up logging based on the command-line argument
    log_level = getattr(logging, args.log_level.upper())
    logger = setup_logging(log_level)

    # 1. Ensure the block is present in /etc/hosts
    ensure_block_exists(logger)

    # 2. Initialize /etc/hosts with current container data
    logger.info("Initializing /etc/hosts with current container data")
    update_hosts(logger)

    # 3. Stream Docker events in a loop; update /etc/hosts on 'container start' or 'network disconnect' events.
    logger.info("Starting to monitor Docker events.")
    process = subprocess.Popen(["docker", "events"], stdout=subprocess.PIPE, text=True)

    for line in process.stdout:
        if " container start " in line or " network disconnect " in line:
            logger.info("Detected container start or network disconnect event; updating /etc/hosts")
            update_hosts(logger)
        logger.debug(f"Docker event: {line.strip()}")

if __name__ == "__main__":
    main()
