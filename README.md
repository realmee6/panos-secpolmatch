# Security Policy Check script for PAN-OS
This is a sample script that I have found to be extremely useful to check if the communication flows have been affected by policy change. This script performs the following:

1. Connects to a PAN-OS firewall management interface on a specified port.
2. Checks the result for the specified traffic flows in the validaion.csv file.
3. Saves the output in a CSV file provded after the script execution.

All parameters in the CSV file are mandatory for the script to execute successfully. The validate.csv file provided in the repository is a dummy one and should be replaced with real values for your scenario.

The CSV file must contain the following:
- sourceip: source IP for the traffic flow
- sourcezone: source zone for the traffic flow (case sensitive)
- destinationip: destination IP for the traffic flow
- destinationzone: destination zone for the traffic flow (case sensitive)
- proto: protocol number, e.g. 17 for UDP and 6 for TCP.
- appid: web-browsing, dns, ssl etc... (case sensitive)
- port: 443, 80, 53 etc...

## Prerequisites
The following libraries are required in order to run this script:
1. Install xmltodict using `pip3 install xmltodict` 

## To-Do:
1. Better error handling.
2. Additional use cases and flexibility for the use case testing.
3. Web Interface.

## Video
[![asciicast](https://asciinema.org/a/530268.svg)](https://asciinema.org/a/530268)
