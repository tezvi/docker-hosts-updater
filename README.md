# Docker Hosts Updater

This project contains a Python script that updates your system's `/etc/hosts` file with the IP addresses and hostnames of your running Docker containers. It is designed to be used both manually and as a continuously running service via systemd.

## Overview

The script performs the following tasks:
- **Hosts File Management:**  
  It ensures that `/etc/hosts` contains a designated block marked by `# BEGIN DOCKER CONTAINERS` and `# END DOCKER CONTAINERS`. This block is used to store Docker container IP/hostname mappings.
- **Container Data Retrieval:**  
  It uses Docker commands to list running containers and inspect them to retrieve IP addresses and container names.
- **Dynamic Hostname Generation:**  
  Container names are transformed to be DNS-friendly by removing unwanted characters and appending a `.docker` domain suffix.
- **Real-Time Updates:**  
  The script continuously monitors Docker events (such as container start and network disconnect) and automatically updates `/etc/hosts` to reflect changes.

## Why This is Useful

Developers often work with multiple Docker projects on the same host, where containers can have dynamic IP addresses and reside on varying network subnets. Manually managing DNS entries or static `/etc/hosts` entries in such environments can be error-prone and time-consuming. This tool automates the process, ensuring:

- **Seamless Service Discovery:**  
  Containers can reliably communicate using consistent hostnames, regardless of changes in IP addresses.
- **Reduced Configuration Overhead:**  
  No need to manually update or maintain `/etc/hosts` for each Docker container.
- **Dynamic Network Adaptability:**  
  Automatically adapts to changes in container networks and subnets, streamlining development and testing across multiple projects.

## Usage

### Running the Script Manually

To run the script manually, execute it with appropriate privileges (since it modifies `/etc/hosts`):

```bash
sudo ./docker-update-hosts
```

### Integration with systemd

For a seamless, always-on solution, you can set up the script as a systemd service.

#### Systemd Unit File

Below is the systemd unit file used to run the script: 

#### Installing the Service

Follow these steps to install and enable the systemd service: [Sytemd unit file example - docker-update-hosts.service](docker-update-hosts.service)

1. **Place the Script:**

   Copy the `docker-update-hosts` script to `/opt/docker-update-hosts/` and make it executable:

   ```bash
   sudo mkdir -p /opt/docker-update-hosts
   sudo cp docker-update-hosts /opt/docker-update-hosts/docker-update-hosts
   sudo chmod +x /opt/docker-update-hosts/docker-update-hosts
   ```

2. **Install the Systemd Unit File:**

   Save the unit file as `docker-update-hosts.service` and copy it to the systemd directory:

   ```bash
   sudo cp docker-update-hosts.service /etc/systemd/system/docker-update-hosts.service
   ```

3. **Reload systemd and Enable the Service:**

   Reload the systemd configuration, enable the service to start on boot, and then start it:

   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable docker-update-hosts.service
   sudo systemctl start docker-update-hosts.service
   ```

4. **Verify Service Status:**

   Check the status of the service to ensure it is running properly:

   ```bash
   sudo systemctl status docker-update-hosts.service
   ```

## Development Notes

### Code Structure

- **docker-update-hosts (Python Script):**
  - **Initialization:**  
    Checks `/etc/hosts` for the existence of a designated block and creates it if absent.
  - **Data Gathering:**  
    Uses Docker commands to obtain container IDs and inspects them to extract IP addresses and names.
  - **Hostname Transformation:**  
    Applies rules to transform container names (removing leading slashes, trailing `_1`, replacing underscores with hyphens, and appending `.docker`).
  - **Hosts File Update:**  
    Replaces the designated block in `/etc/hosts` with updated container mappings.
  - **Event Monitoring:**  
    Listens for Docker events to trigger updates automatically when containers start or disconnect from networks.

### Customization

- **Domain Suffix:**  
  The default domain suffix `.docker` can be changed by modifying the `DOMAIN_SUFFIX` variable in the script.
- **Logging & Error Handling:**  
  The script outputs status messages to the console. Developers can enhance logging or modify error handling to suit specific needs.

## Contributing

Contributions, bug reports, and feature suggestions are welcome. Please follow standard GitHub practices for pull requests and issue reporting.

## License

This project is licensed under the [MIT License](LICENSE).

## Disclaimer

**Warning:** This script modifies your system's `/etc/hosts` file. Always back up your original hosts file before running the script to prevent unintended disruptions.
