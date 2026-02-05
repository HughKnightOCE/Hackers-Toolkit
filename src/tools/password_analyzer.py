"""Password strength and analysis tool"""
import re
import math
from utils.logger import Logger
from utils.validators import Validators

class PasswordAnalyzer:
    """Analyze password strength and security"""
    
    def __init__(self):
        self.common_passwords = self._load_common_passwords()
    
    def _load_common_passwords(self):
        """Load common passwords list"""
        return [
            "password", "123456", "12345678", "qwerty", "abc123",
            "monkey", "1234567", "letmein", "trustno1", "dragon"
        ]
    
    def analyze_password(self, password):
        """Analyze password strength"""
        if not password:
            return {"error": "Password required"}
        
        results = {
            "password_length": len(password),
            "has_uppercase": bool(re.search(r'[A-Z]', password)),
            "has_lowercase": bool(re.search(r'[a-z]', password)),
            "has_digits": bool(re.search(r'\d', password)),
            "has_special": bool(re.search(r'[!@#$%^&*()_+\-=\[\]{};":\\|,.<>\/?]', password)),
            "is_common": password.lower() in self.common_passwords,
            "entropy": self._calculate_entropy(password),
            "strength": self._get_strength_rating(password)
        }
        
        Logger.info(f"Password analyzed - Strength: {results['strength']}")
        return results
    
    def _calculate_entropy(self, password):
        """Calculate password entropy"""
        charset_size = 0
        if re.search(r'[a-z]', password):
            charset_size += 26
        if re.search(r'[A-Z]', password):
            charset_size += 26
        if re.search(r'\d', password):
            charset_size += 10
        if re.search(r'[^a-zA-Z0-9]', password):
            charset_size += 32
        
        if charset_size == 0:
            return 0
        
        entropy = len(password) * math.log2(charset_size)
        return round(entropy, 2)
    
    def _get_strength_rating(self, password):
        """Get password strength rating"""
        score = 0
        
        if len(password) >= 8:
            score += 1
        if len(password) >= 12:
            score += 1
        if re.search(r'[a-z]', password) and re.search(r'[A-Z]', password):
            score += 1
        if re.search(r'\d', password):
            score += 1
        if re.search(r'[!@#$%^&*()_+\-=\[\]{};:",<>?/\\|`~]', password):
            score += 1
        if password.lower() not in self.common_passwords:
            score += 1
        
        if score <= 2:
            return "Weak"
        elif score <= 4:
            return "Fair"
        elif score <= 5:
            return "Strong"
        else:
            return "Very Strong"
    
    def generate_password(self, length=16, use_uppercase=True, use_digits=True, use_special=True):
        """Generate secure password"""
        import random
        import string
        
        chars = string.ascii_lowercase
        if use_uppercase:
            chars += string.ascii_uppercase
        if use_digits:
            chars += string.digits
        if use_special:
            chars += r"!@#$%^&*()_+-=[]{};\:,.<>?"
        
        password = ''.join(random.choice(chars) for _ in range(length))
        return {
            "generated_password": password,
            "strength": self._get_strength_rating(password),
            "entropy": self._calculate_entropy(password)
        }
    
    def check_password_breach(self, password):
        """Check if password appears in known breaches (simplified)"""
        # This would integrate with HaveIBeenPwned API in production
        return {
            "password": "*" * len(password),
            "breach_status": "Unknown",
            "note": "Configure API key for full breach checking"
        }
