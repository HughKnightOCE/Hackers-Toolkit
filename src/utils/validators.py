"""Input validation utilities"""
import re
import ipaddress

class Validators:
    """Validation utilities for security analysis"""
    
    @staticmethod
    def is_valid_ip(ip):
        """Validate IPv4 or IPv6 address"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def is_valid_domain(domain):
        """Validate domain name"""
        domain_regex = r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$'
        return re.match(domain_regex, domain, re.IGNORECASE) is not None
    
    @staticmethod
    def is_valid_url(url):
        """Validate URL"""
        url_regex = r'^https?://[^\s/$.?#].[^\s]*$'
        return re.match(url_regex, url, re.IGNORECASE) is not None
    
    @staticmethod
    def is_valid_port(port):
        """Validate port number"""
        try:
            port_num = int(port)
            return 1 <= port_num <= 65535
        except ValueError:
            return False
    
    @staticmethod
    def is_valid_email(email):
        """Validate email address"""
        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(email_regex, email) is not None
    
    @staticmethod
    def is_valid_hash(hash_string, hash_type='md5'):
        """Validate hash format"""
        patterns = {
            'md5': r'^[a-f0-9]{32}$',
            'sha1': r'^[a-f0-9]{40}$',
            'sha256': r'^[a-f0-9]{64}$',
            'sha512': r'^[a-f0-9]{128}$',
        }
        pattern = patterns.get(hash_type.lower())
        if not pattern:
            return False
        return re.match(pattern, hash_string, re.IGNORECASE) is not None
    
    @staticmethod
    def is_valid_service_name(service_name):
        """Validate service name"""
        service_regex = r'^[a-zA-Z0-9\s\-_.]+$'
        return re.match(service_regex, service_name) is not None and 1 <= len(service_name) <= 100
    
    @staticmethod
    def sanitize_input(user_input):
        """Sanitize user input to prevent injection attacks"""
        if not isinstance(user_input, str):
            return user_input
        # Remove special characters that could be used for injection
        return re.sub(r'[;<>|&`$()\\"\']', '', user_input)
