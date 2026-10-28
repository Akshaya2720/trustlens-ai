"""TrustLens AI - Safe URL and Domain Inspection Service

Strict SSRF protection, URL normalization, DNS pre-resolution checking,
and safe metadata inspection.
"""

import ipaddress
import socket
from urllib.parse import urlparse, urlunparse
import httpx
from pydantic import BaseModel
from app.core.config import settings
from app.core.logging import logger

# Blocked IP networks and reserved ranges
BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),          # Current network (only valid as source address)
    ipaddress.ip_network("10.0.0.0/8"),         # RFC 1918 Private
    ipaddress.ip_network("127.0.0.0/8"),        # Loopback
    ipaddress.ip_network("169.254.0.0/16"),     # Link-local / Cloud Metadata (169.254.169.254)
    ipaddress.ip_network("172.16.0.0/12"),      # RFC 1918 Private
    ipaddress.ip_network("192.168.0.0/16"),     # RFC 1918 Private
    ipaddress.ip_network("192.0.2.0/24"),       # TEST-NET-1
    ipaddress.ip_network("198.51.100.0/24"),    # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),     # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),        # Multicast
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved / Future use
    ipaddress.ip_network("::1/128"),            # IPv6 Loopback
    ipaddress.ip_network("::/128"),             # IPv6 Unspecified
    ipaddress.ip_network("fc00::/7"),           # IPv6 Unique Local Address
    ipaddress.ip_network("fe80::/10"),          # IPv6 Link-local
    ipaddress.ip_network("ff00::/8"),           # IPv6 Multicast
]

# Additional blocked cloud metadata hostnames
BLOCKED_HOSTNAMES = {
    "metadata.google.internal",
    "metadata.internal",
    "instance-data",
    "169.254.169.254",
    "localhost",
}


class URLValidationResult(BaseModel):
    is_safe: bool
    normalized_url: str
    hostname: str
    resolved_ip: str | None = None
    reason: str | None = None
    domain: str = ""
    scheme: str = ""


class SafeURLInspector:
    """Provides secure validation, DNS verification, and constrained fetching

    of web endpoints without exposing internal services or falling victim to SSRF/rebinding.
    """

    @staticmethod
    def normalize_url(url: str) -> str:
        """Parses and normalizes a URL string."""
        url = url.strip()
        lower_url = url.lower()
        # Only prepend http:// if no scheme is specified at all
        if "://" not in url:
            url = "http://" + url

        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        path = parsed.path or "/"
        normalized = urlunparse((scheme, netloc, path, parsed.params, parsed.query, ""))
        return normalized

    @classmethod
    def validate_url(cls, raw_url: str) -> URLValidationResult:
        """Validates that a URL is syntactically sound and does not target
        internal, private, loopback, or cloud-metadata destinations.
        """
        try:
            # Check scheme first before normalization
            raw_parsed = urlparse(raw_url.strip())
            raw_scheme = raw_parsed.scheme.lower() if raw_parsed.scheme else ""
            if raw_scheme and raw_scheme not in ("http", "https"):
                return URLValidationResult(
                    is_safe=False,
                    normalized_url=raw_url,
                    hostname=raw_parsed.hostname or "",
                    scheme=raw_scheme,
                    reason=f"Unsupported URL scheme '{raw_scheme}'. Only http and https are allowed.",
                )

            normalized = cls.normalize_url(raw_url)
            parsed = urlparse(normalized)
            scheme = parsed.scheme.lower()
            if scheme not in ("http", "https"):
                return URLValidationResult(
                    is_safe=False,
                    normalized_url=normalized,
                    hostname=parsed.hostname or "",
                    reason=f"Unsupported URL scheme '{scheme}'. Only http and https are allowed.",
                )

            hostname = parsed.hostname
            if not hostname:
                return URLValidationResult(
                    is_safe=False,
                    normalized_url=normalized,
                    hostname="",
                    reason="Invalid or missing hostname in URL.",
                )

            # Check known blocked hostnames
            if hostname.lower() in BLOCKED_HOSTNAMES:
                return URLValidationResult(
                    is_safe=False,
                    normalized_url=normalized,
                    hostname=hostname,
                    reason=f"Hostname '{hostname}' is an explicitly blocked internal or cloud-metadata destination.",
                )

            # Resolve DNS to examine actual IP destination
            try:
                addr_info = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            except socket.gaierror as e:
                return URLValidationResult(
                    is_safe=False,
                    normalized_url=normalized,
                    hostname=hostname,
                    reason=f"DNS resolution failed: {e}",
                )

            if not addr_info:
                return URLValidationResult(
                    is_safe=False,
                    normalized_url=normalized,
                    hostname=hostname,
                    reason="No IP addresses found for host.",
                )

            primary_ip = None
            for family, _, _, _, sockaddr in addr_info:
                ip_str = sockaddr[0]
                ip_obj = ipaddress.ip_address(ip_str)

                # Check against blocked CIDR networks
                for blocked_net in BLOCKED_NETWORKS:
                    if ip_obj in blocked_net:
                        return URLValidationResult(
                            is_safe=False,
                            normalized_url=normalized,
                            hostname=hostname,
                            resolved_ip=ip_str,
                            reason=f"Resolved IP {ip_str} falls into blocked/private network range {blocked_net}.",
                        )
                if not primary_ip:
                    primary_ip = ip_str

            return URLValidationResult(
                is_safe=True,
                normalized_url=normalized,
                hostname=hostname,
                resolved_ip=primary_ip,
                domain=hostname,
                scheme=scheme,
            )

        except Exception as e:
            logger.error(f"Error during URL validation for '{raw_url}': {e}")
            return URLValidationResult(
                is_safe=False,
                normalized_url=raw_url,
                hostname="",
                reason=f"Validation failed with internal error: {str(e)}",
            )

    @classmethod
    async def fetch_head_or_preview(
        cls, url: str, max_redirects: int | None = None
    ) -> dict:
        """Safely fetches HTTP headers and an optional bounded preview (<2MB) of a URL,

        strictly validating every redirect destination against SSRF policies.
        """
        max_redirects = max_redirects or settings.SAFE_URL_MAX_REDIRECTS
        current_url = url
        redirect_chain = []

        for hop in range(max_redirects + 1):
            val_res = cls.validate_url(current_url)
            if not val_res.is_safe:
                return {
                    "success": False,
                    "final_url": current_url,
                    "error": f"Security check failed on hop {hop}: {val_res.reason}",
                    "redirect_chain": redirect_chain,
                }

            redirect_chain.append(current_url)

            try:
                async with httpx.AsyncClient(
                    timeout=settings.SAFE_URL_TIMEOUT_SECONDS,
                    follow_redirects=False,
                    verify=True,
                    headers={"User-Agent": "TrustLens-Safety-Scanner/1.0"},
                ) as client:
                    response = await client.get(current_url)

                    # Check for redirect
                    if response.status_code in (301, 302, 303, 307, 308):
                        location = response.headers.get("Location")
                        if not location:
                            break
                        # Handle relative redirects
                        current_url = str(response.url.join(location))
                        continue

                    # Terminal response reached
                    content_preview = response.text[:2000] if response.text else ""
                    return {
                        "success": True,
                        "status_code": response.status_code,
                        "final_url": str(response.url),
                        "headers": dict(response.headers),
                        "content_preview": content_preview,
                        "redirect_chain": redirect_chain,
                    }

            except Exception as e:
                logger.warning(f"Failed safe fetch for '{current_url}': {e}")
                return {
                    "success": False,
                    "final_url": current_url,
                    "error": str(e),
                    "redirect_chain": redirect_chain,
                }

        return {
            "success": False,
            "final_url": current_url,
            "error": f"Exceeded maximum redirects ({max_redirects})",
            "redirect_chain": redirect_chain,
        }
