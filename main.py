#!/usr/bin/env python3

import argparse
import socket
import requests
import logging
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Lookup ASN (Autonomous System Number) information for a given IP address or hostname.")
    parser.add_argument("target", help="IP address or hostname to lookup ASN information for.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging.")
    return parser

def resolve_hostname(hostname):
    """
    Resolves a hostname to an IP address.
    
    Args:
        hostname (str): The hostname to resolve.
    
    Returns:
        str: The IP address if resolution is successful, None otherwise.
    """
    try:
        ip_address = socket.gethostbyname(hostname)
        logging.info(f"Hostname {hostname} resolved to {ip_address}")
        return ip_address
    except socket.gaierror as e:
        logging.error(f"Failed to resolve hostname {hostname}: {e}")
        return None

def lookup_asn_info(ip_address):
    """
    Looks up ASN information for a given IP address using a public API.
    
    Args:
        ip_address (str): The IP address to lookup.
    
    Returns:
        dict: A dictionary containing the ASN information if successful, None otherwise.
    """
    try:
        url = f"https://api.hackertarget.com/aslookup/?q={ip_address}" # Example API - Could be rate-limited
        response = requests.get(url, timeout=5)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        
        if "No ASN records found" in response.text:
            logging.warning(f"No ASN records found for {ip_address}")
            return None

        # Basic parsing of the response.  Ideally, a JSON API should be used for structured data.
        # This approach is brittle and depends on the exact format of the API response.
        asn_info = {}
        lines = response.text.strip().split("\n")
        if len(lines) > 0:
            asn_info['asn'] = lines[0].split('|')[0].strip() if '|' in lines[0] else lines[0].strip()
        if len(lines) > 1:
            asn_info['description'] = lines[1].strip()
        
        logging.info(f"ASN information found for {ip_address}: {asn_info}")
        return asn_info
    except requests.exceptions.RequestException as e:
        logging.error(f"Request failed: {e}")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return None

def validate_ip_address(ip_address):
    """
    Validates if a given string is a valid IPv4 address.
    
    Args:
        ip_address (str): The string to validate.
    
    Returns:
        bool: True if the string is a valid IPv4 address, False otherwise.
    """
    try:
        socket.inet_pton(socket.AF_INET, ip_address)
        return True
    except socket.error:
        return False

def main():
    """
    Main function to execute the ASN lookup tool.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Verbose logging enabled.")

    target = args.target

    # Validate the target.  Try treating it as an IP address first.
    if validate_ip_address(target):
        ip_address = target
    else:
        # If not a valid IP, assume it's a hostname and try to resolve it.
        ip_address = resolve_hostname(target)
        if not ip_address:
            print(f"Error: Unable to resolve or validate target '{target}'.")
            sys.exit(1)

    asn_info = lookup_asn_info(ip_address)

    if asn_info:
        print("ASN Information:")
        print(f"  ASN: {asn_info.get('asn', 'N/A')}")
        print(f"  Description: {asn_info.get('description', 'N/A')}")
    else:
        print(f"No ASN information found for {ip_address}.")

if __name__ == "__main__":
    main()

# Usage Examples:
# 1. Lookup ASN information for an IP address:
#    python net-asn-lookup.py 8.8.8.8
#
# 2. Lookup ASN information for a hostname:
#    python net-asn-lookup.py google.com
#
# 3. Enable verbose logging:
#    python net-asn-lookup.py 8.8.8.8 -v