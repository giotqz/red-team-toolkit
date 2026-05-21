"""
Helper utilities for Red Team Toolkit
"""

import socket
import re
import json
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse


def is_valid_ip(ip: str) -> bool:
    """
    Validate IP address format

    Args:
        ip: IP address string

    Returns:
        True if valid IP, False otherwise
    """
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False


def is_valid_url(url: str) -> bool:
    """
    Validate URL format

    Args:
        url: URL string

    Returns:
        True if valid URL, False otherwise
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False


def is_valid_port(port: int) -> bool:
    """
    Validate port number

    Args:
        port: Port number

    Returns:
        True if valid port, False otherwise
    """
    return 0 < port < 65536


def parse_port_range(port_string: str) -> List[int]:
    """
    Parse port range string (e.g., "80,443,8000-8005")

    Args:
        port_string: Port range string

    Returns:
        List of port numbers
    """
    ports = []
    for part in port_string.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-")
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return sorted(list(set(ports)))


def sanitize_input(input_str: str, max_length: int = 1000) -> str:
    """
    Sanitize user input

    Args:
        input_str: Input string
        max_length: Maximum allowed length

    Returns:
        Sanitized string
    """
    # Remove null bytes
    sanitized = input_str.replace("\x00", "")
    # Truncate if too long
    sanitized = sanitized[:max_length]
    return sanitized.strip()


def extract_emails(text: str) -> List[str]:
    """
    Extract email addresses from text

    Args:
        text: Text to search

    Returns:
        List of email addresses
    """
    pattern = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
    return list(set(re.findall(pattern, text)))


def extract_urls(text: str) -> List[str]:
    """
    Extract URLs from text

    Args:
        text: Text to search

    Returns:
        List of URLs
    """
    pattern = r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+"
    return list(set(re.findall(pattern, text)))


def extract_ip_addresses(text: str) -> List[str]:
    """
    Extract IP addresses from text

    Args:
        text: Text to search

    Returns:
        List of IP addresses
    """
    pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    potential_ips = re.findall(pattern, text)
    return [ip for ip in potential_ips if is_valid_ip(ip)]


def dict_to_json(data: Dict[str, Any], indent: int = 2) -> str:
    """
    Convert dictionary to JSON string

    Args:
        data: Dictionary to convert
        indent: Indentation level

    Returns:
        JSON string
    """
    return json.dumps(data, indent=indent, default=str)


def json_to_dict(json_str: str) -> Dict[str, Any]:
    """
    Convert JSON string to dictionary

    Args:
        json_str: JSON string

    Returns:
        Dictionary
    """
    return json.loads(json_str)


def merge_dicts(dict1: Dict, dict2: Dict) -> Dict:
    """
    Deep merge two dictionaries

    Args:
        dict1: First dictionary
        dict2: Second dictionary

    Returns:
        Merged dictionary
    """
    result = dict1.copy()
    for key, value in dict2.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = merge_dicts(result[key], value)
        else:
            result[key] = value
    return result
