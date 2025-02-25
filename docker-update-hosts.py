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

HOSTS_FILE = "/etc/hosts"
BEGIN_BLOCK = "# BEGIN DOCKER CONTAINERS"
END_BLOCK = "# END DOCKER CONTAINERS"
DOMAIN_SUFFIX = '.docker'

def ensure_block_exists():
    """
    Ensure that /etc/hosts contains the BEGIN_BLOCK and END_BLOCK lines.
    If not present, append them.
    """
    with open(HOSTS_FILE, "r") as f:
        contents = f.read()

    if BEGIN_BLOCK not in contents:
        with open(HOSTS_FILE, "a") as f:
            f.write(f"\n{BEGIN_BLOCK}\n{END_BLOCK}\n")

def generate_docker_hosts_lines():
    """
    1. Get the list of running container IDs.
    2. Inspect containers via Docker to retrieve their IP addresses and names.
    3. Transform each container's name and IP into lines of the form:
       [IP or "# no ip address:"] [transformed_container_name]
    4. Return a list of those lines.
    """
    try:
        # Get container IDs
        container_ids = subprocess.check_output(
            ["docker", "container", "ls", "-q"],
            text=True
        ).strip().split()
    except subprocess.CalledProcessError:
        # If for some reason the 'docker' command fails, just return empty
        return []

    if not container_ids:
        return []

    # Inspect all containers at once
    try:
        inspect_output = subprocess.check_output(
            ["docker", "container", "inspect"] + container_ids,
            text=True
        )
    except subprocess.CalledProcessError:
        return []

    data = json.loads(inspect_output)

    result_lines = []
    for container in data:
        container_name = container.get("Name", "")
        hostname = generate_hostname(container_name)
        networks = container.get("NetworkSettings", {}).get("Networks", {})
        ip_found = False

        for net_key, net_info in networks.items():
            ip = net_info.get("IPAddress", "")
            network_hostname=hostname
            if ip:
                # If we already have an IP address for this container append the network name to get unique DNS record
                if ip_found:
                    network_hostname = generate_hostname(net_key)
                else:
                    ip_found = True

                result_lines.append(f"{ip} {network_hostname}")

        if not ip_found:
            # If no IP addresses were found, mimic the "# no ip address:" line
            result_lines.append(f"# no ip address detected: {hostname}")

    return result_lines


def generate_hostname(name):
    # Transform name according to rules:
    #  - Remove leading "/"
    #  - Remove trailing "_1"
    #  - Replace "_" with "-"
    #  - Append ".docker"
    if name.startswith("/"):
        name = name[1:]
    if name.endswith("_1"):
        name = name[:-2]
    name = name.replace("_", "-")
    hostname = name + (".docker" if DOMAIN_SUFFIX and DOMAIN_SUFFIX not in name else "")
    return hostname


def update_hosts():
    """
    Regenerate the block between BEGIN_BLOCK and END_BLOCK in /etc/hosts
    with the current container IP/name mappings.
    """
    docker_lines = generate_docker_hosts_lines()

    # Read the current /etc/hosts
    with open(HOSTS_FILE, "r") as f:
        content = f.read()

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

    os.chmod(tmp_name, 0o644)
    os.replace(tmp_name, HOSTS_FILE)

def main():
    # 1. Ensure the block is present in /etc/hosts
    ensure_block_exists()

    # 2. Initialize /etc/hosts with current container data
    print("Initializing /etc/hosts with current container data")
    update_hosts()

    # 3. Stream Docker events in a loop; update /etc/hosts on 'container start' or 'network disconnect' events.
    process = subprocess.Popen(["docker", "events"], stdout=subprocess.PIPE, text=True)

    for line in process.stdout:
        if " container start " in line or " network disconnect " in line:
            print("Detected container start or network disconnect event; updating /etc/hosts")
            update_hosts()

if __name__ == "__main__":
    main()
