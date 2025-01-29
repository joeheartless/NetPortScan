# Port Scanner and OS Detection with Scapy

This script performs a port scan and attempts to detect the operating system of a given target IP using Scapy.

## Features
- **Port Scanning**: Scans ports from 1 to 10000 on the target IP.
  - Displays only the open ports.
  - Uses SYN packets to determine open ports.
  
- **Operating System Detection**: Attempts to detect the target's OS based on its network behavior.
  - Analyzes **TTL (Time To Live)** and **Window Size** from the response.
  - Possible OS guesses:
    - **Linux/Unix**: If TTL is low (<= 64).
    - **Windows**: If TTL is higher (<= 128).
    - **Undetermined**: If TTL is higher or different from known values.

## Requirements
- Python 3.x
- Scapy
- tqdm (for progress bar)

## Installation
To install the required libraries, use the following command:
```bash
pip install scapy tqdm
