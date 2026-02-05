"""Hash analysis and cracking tool"""
import hashlib
from utils.logger import Logger
from utils.validators import Validators

class HashAnalyzer:
    """Analyze and identify hashes"""
    
    def __init__(self):
        self.hash_patterns = self._load_hash_patterns()
        self.rainbow_table = self._load_rainbow_table()
    
    def _load_hash_patterns(self):
        """Load hash type patterns"""
        return {
            'md5': (32, r'^[a-f0-9]{32}$'),
            'sha1': (40, r'^[a-f0-9]{40}$'),
            'sha256': (64, r'^[a-f0-9]{64}$'),
            'sha512': (128, r'^[a-f0-9]{128}$'),
            'bcrypt': (None, r'^\$2[aby]\$\d{2}\$.{53}$'),
            'scrypt': (None, r'^\$7\$'),
            'argon2': (None, r'^\$argon2')
        }
    
    def _load_rainbow_table(self):
        """Load common password hashes"""
        return {
            '5f4dcc3b5aa765d61d8327deb882cf99': 'password',
            'e99a18c428cb38d5f260853678922e03': '12345678',
            '8f14e45fceea167a5a36dedd4bea2543': 'password123',
        }
    
    def identify_hash(self, hash_string):
        """Identify hash type"""
        hash_lower = hash_string.lower()
        
        for hash_type, (length, pattern) in self.hash_patterns.items():
            if length:
                if len(hash_lower) == length:
                    return hash_type
            else:
                import re
                if re.match(pattern, hash_lower):
                    return hash_type
        
        return "Unknown"
    
    def analyze_hash(self, hash_string):
        """Analyze hash properties"""
        hash_type = self.identify_hash(hash_string)
        
        result = {
            "hash": hash_string,
            "hash_type": hash_type,
            "length": len(hash_string),
            "is_valid_format": hash_type != "Unknown",
            "analysis_time": None
        }
        
        # Try to crack against rainbow table
        hash_lower = hash_string.lower()
        if hash_lower in self.rainbow_table:
            result["cracked"] = True
            result["plaintext"] = self.rainbow_table[hash_lower]
            Logger.info(f"Hash cracked from rainbow table: {hash_type}")
        else:
            result["cracked"] = False
            result["plaintext"] = None
        
        return result
    
    def generate_hash(self, text, hash_type='sha256'):
        """Generate hash of text"""
        if hash_type == 'md5':
            hash_obj = hashlib.md5()
        elif hash_type == 'sha1':
            hash_obj = hashlib.sha1()
        elif hash_type == 'sha256':
            hash_obj = hashlib.sha256()
        elif hash_type == 'sha512':
            hash_obj = hashlib.sha512()
        else:
            return {"error": "Unsupported hash type"}
        
        hash_obj.update(text.encode())
        return {
            "text": text,
            "hash_type": hash_type,
            "hash": hash_obj.hexdigest()
        }
    
    def batch_hash_analyze(self, hashes):
        """Analyze multiple hashes"""
        results = []
        for hash_value in hashes:
            analysis = self.analyze_hash(hash_value)
            results.append(analysis)
        
        return {
            "total": len(results),
            "results": results
        }
