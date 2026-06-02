# Port Scanner

A simple TCP port scanner built in Python.

## What it does
- Scans a target IP or hostname for open ports
- Accepts multiple targets at once (comma-separated)
- Displays the service name for each open port
- Handles invalid IPs and unresolvable hostnames gracefully

## Requirements
- Python 3.x
- IPy library

## Installation
pip install IPy

## Usage
python port_scanner.py

## Example output
==================================================
         Simple Port Scanner
==================================================
  Target(s) — comma-separate for multiple:
  > google.com
  Start port [default 1]:    
  End port   [default 1024]: 

  Target  : google.com  (209.85.202.101)
  Ports   : 1–1024
  [+] Port 80     open   (http)
  [+] Port 443    open   (https)
  Done. 2 open port(s) found in 87s.

## Disclaimer
Only scan systems you own or have explicit permission to scan.
Unauthorised scanning is illegal.
