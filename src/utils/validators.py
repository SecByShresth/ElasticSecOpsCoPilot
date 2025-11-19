"""
Validation utilities for Elastic SecOps Copilot.
Compatible with Python 3.13+
"""

import re
import ipaddress
from typing import Any, Optional, Tuple
from urllib.parse import urlparse


class ValidationError(Exception):
    """Validation error."""
    pass


class IPValidator:
    """IP address validation."""

    @staticmethod
    def is_valid_ipv4(ip: str) -> bool:
        """Check if string is valid IPv4 address."""
        try:
            ipaddress.IPv4Address(ip)
            return True
        except (ipaddress.AddressValueError, ValueError):
            return False

    @staticmethod
    def is_valid_ipv6(ip: str) -> bool:
        """Check if string is valid IPv6 address."""
        try:
            ipaddress.IPv6Address(ip)
            return True
        except (ipaddress.AddressValueError, ValueError):
            return False

    @staticmethod
    def is_valid_ip(ip: str) -> bool:
        """Check if string is valid IPv4 or IPv6 address."""
        return IPValidator.is_valid_ipv4(ip) or IPValidator.is_valid_ipv6(ip)

    @staticmethod
    def is_private_ip(ip: str) -> bool:
        """Check if IP is in private range."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except (ipaddress.AddressValueError, ValueError):
            return False

    @staticmethod
    def is_loopback(ip: str) -> bool:
        """Check if IP is loopback."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_loopback
        except (ipaddress.AddressValueError, ValueError):
            return False


class DomainValidator:
    """Domain name validation."""

    # RFC 1123 domain pattern
    DOMAIN_PATTERN = re.compile(
        r'^(?!-)'
        r'(?:[a-zA-Z0-9-]{0,62}[a-zA-Z0-9]\.)*'
        r'(?!-)[a-zA-Z0-9-]{0,62}[a-zA-Z0-9]'
        r'(?:\.(?!-))?$',
        re.UNICODE
    )

    @staticmethod
    def is_valid_domain(domain: str) -> bool:
        """Check if string is valid domain name."""
        if not domain or len(domain) > 253:
            return False

        domain = domain.lower().rstrip('.')

        if domain.startswith('.'):
            return False

        return DomainValidator.DOMAIN_PATTERN.match(domain) is not None

    @staticmethod
    def is_valid_fqdn(fqdn: str) -> bool:
        """Check if string is valid FQDN (must have at least 2 labels)."""
        if not DomainValidator.is_valid_domain(fqdn):
            return False

        labels = fqdn.rstrip('.').split('.')
        return len(labels) >= 2


class URLValidator:
    """URL validation."""

    @staticmethod
    def is_valid_url(url: str) -> bool:
        """Check if string is valid URL."""
        try:
            result = urlparse(url)
            # Check for required components
            return all([result.scheme, result.netloc])
        except Exception:
            return False

    @staticmethod
    def normalize_url(url: str) -> str:
        """Normalize URL for comparison."""
        try:
            result = urlparse(url)
            # Reconstruct without fragment
            return f"{result.scheme}://{result.netloc}{result.path}?{result.query}"
        except Exception:
            return url


class HashValidator:
    """File hash validation."""

    @staticmethod
    def is_valid_md5(hash_str: str) -> bool:
        """Check if string is valid MD5 hash."""
        return bool(re.match(r'^[a-fA-F0-9]{32}$', hash_str))

    @staticmethod
    def is_valid_sha256(hash_str: str) -> bool:
        """Check if string is valid SHA256 hash."""
        return bool(re.match(r'^[a-fA-F0-9]{64}$', hash_str))

    @staticmethod
    def is_valid_sha512(hash_str: str) -> bool:
        """Check if string is valid SHA512 hash."""
        return bool(re.match(r'^[a-fA-F0-9]{128}$', hash_str))

    @staticmethod
    def detect_hash_type(hash_str: str) -> Optional[str]:
        """Detect hash type from string."""
        hash_str = hash_str.lower()

        if HashValidator.is_valid_md5(hash_str):
            return "md5"
        elif HashValidator.is_valid_sha256(hash_str):
            return "sha256"
        elif HashValidator.is_valid_sha512(hash_str):
            return "sha512"

        return None


class EmailValidator:
    """Email validation."""

    EMAIL_PATTERN = re.compile(
        r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    )

    @staticmethod
    def is_valid_email(email: str) -> bool:
        """Check if string is valid email."""
        return EmailValidator.EMAIL_PATTERN.match(email) is not None


class IOCValidator:
    """Indicator of Compromise validation."""

    @staticmethod
    def validate_ioc(
            ioc_type: str,
            ioc_value: str,
    ) -> Tuple[bool, Optional[str]]:
        """
        Validate IOC value for given type.

        Args:
            ioc_type: Type of IOC (ip, domain, url, file_hash, email, etc.)
            ioc_value: Value to validate

        Returns:
            Tuple of (is_valid, error_message)
        """
        if not ioc_value or not isinstance(ioc_value, str):
            return False, "IOC value must be a non-empty string"

        ioc_value = ioc_value.strip()

        if ioc_type == "ip":
            if not IPValidator.is_valid_ip(ioc_value):
                return False, "Invalid IP address"
            return True, None

        elif ioc_type == "domain":
            if not DomainValidator.is_valid_domain(ioc_value):
                return False, "Invalid domain name"
            return True, None

        elif ioc_type == "url":
            if not URLValidator.is_valid_url(ioc_value):
                return False, "Invalid URL"
            return True, None

        elif ioc_type == "file_hash":
            hash_type = HashValidator.detect_hash_type(ioc_value)
            if not hash_type:
                return False, "Invalid file hash format"
            return True, None

        elif ioc_type == "md5":
            if not HashValidator.is_valid_md5(ioc_value):
                return False, "Invalid MD5 hash"
            return True, None

        elif ioc_type == "sha256":
            if not HashValidator.is_valid_sha256(ioc_value):
                return False, "Invalid SHA256 hash"
            return True, None

        elif ioc_type == "sha512":
            if not HashValidator.is_valid_sha512(ioc_value):
                return False, "Invalid SHA512 hash"
            return True, None

        elif ioc_type == "email":
            if not EmailValidator.is_valid_email(ioc_value):
                return False, "Invalid email address"
            return True, None

        else:
            # Unknown type, accept as-is
            return True, None

    @staticmethod
    def extract_ips(text: str) -> list[str]:
        """Extract IP addresses from text."""
        # Simple IPv4 pattern
        ipv4_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips = re.findall(ipv4_pattern, text)

        # Validate extracted IPs
        return [ip for ip in ips if IPValidator.is_valid_ipv4(ip)]

    @staticmethod
    def extract_domains(text: str) -> list[str]:
        """Extract domain names from text."""
        # Simple domain pattern
        domain_pattern = r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b'
        domains = re.findall(domain_pattern, text, re.IGNORECASE)

        return [d for d in domains if DomainValidator.is_valid_domain(d)]

    @staticmethod
    def extract_urls(text: str) -> list[str]:
        """Extract URLs from text."""
        url_pattern = r'https?://[^\s]+'
        urls = re.findall(url_pattern, text)

        return [u for u in urls if URLValidator.is_valid_url(u)]


class SeverityValidator:
    """Severity score validation."""

    @staticmethod
    def validate_score(score: Any) -> Tuple[bool, Optional[str]]:
        """
        Validate severity score (0-100).

        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            score_float = float(score)
            if 0 <= score_float <= 100:
                return True, None
            else:
                return False, "Score must be between 0 and 100"
        except (ValueError, TypeError):
            return False, "Score must be a number"

    @staticmethod
    def validate_confidence(confidence: Any) -> Tuple[bool, Optional[str]]:
        """
        Validate confidence score (0-1).

        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            conf_float = float(confidence)
            if 0 <= conf_float <= 1:
                return True, None
            else:
                return False, "Confidence must be between 0 and 1"
        except (ValueError, TypeError):
            return False, "Confidence must be a number"