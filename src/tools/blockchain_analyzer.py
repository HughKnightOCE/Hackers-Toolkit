"""
Blockchain Address Analyzer - Cryptocurrency Address Analysis Tool
Analyzes Bitcoin, Ethereum, and other blockchain addresses
"""

import requests
import json
from datetime import datetime
from utils.logger import Logger
from utils.validators import Validators

class BlockchainAnalyzer:
    """Analyze blockchain addresses and transactions"""
    
    def __init__(self):
        self.logger = Logger()
        self.validators = Validators()
        
    def analyze_bitcoin_address(self, address):
        """
        Analyze Bitcoin address using blockchain.com API
        
        Args:
            address: Bitcoin address to analyze
            
        Returns:
            dict: Address information
        """
        try:
            if not self._is_valid_bitcoin_address(address):
                return {"error": "Invalid Bitcoin address format"}
            
            # Using blockchain.com API (free tier)
            url = f"https://blockchain.info/q/addressbalance/{address}"
            try:
                response = requests.get(url, timeout=5)
                balance = response.text.strip()
                
                # Get more details
                details_url = f"https://blockchain.info/address/{address}?format=json"
                details = requests.get(details_url, timeout=5).json()
                
                return {
                    "address": address,
                    "balance_satoshi": balance,
                    "balance_btc": float(balance) / 100000000 if balance.isdigit() else 0,
                    "total_received": details.get('total_received', 0) / 100000000,
                    "total_sent": details.get('total_sent', 0) / 100000000,
                    "transaction_count": details.get('n_tx', 0),
                    "final_balance": details.get('final_balance', 0) / 100000000,
                    "timestamp": datetime.now().isoformat(),
                    "type": "Bitcoin"
                }
            except requests.exceptions.RequestException:
                return {
                    "address": address,
                    "type": "Bitcoin",
                    "note": "API unavailable - address format valid",
                    "format_valid": True
                }
                
        except Exception as e:
            self.logger.error(f"Bitcoin analysis error: {str(e)}")
            return {"error": str(e)}
    
    def analyze_ethereum_address(self, address):
        """
        Analyze Ethereum address
        
        Args:
            address: Ethereum address to analyze
            
        Returns:
            dict: Address information
        """
        try:
            if not self._is_valid_ethereum_address(address):
                return {"error": "Invalid Ethereum address format"}
            
            # Note: Full Etherscan API requires key, this is basic validation
            return {
                "address": address,
                "type": "Ethereum",
                "format_valid": True,
                "network": "Ethereum",
                "timestamp": datetime.now().isoformat(),
                "note": "For full Ethereum analysis, use Etherscan API with key"
            }
            
        except Exception as e:
            self.logger.error(f"Ethereum analysis error: {str(e)}")
            return {"error": str(e)}
    
    def detect_address_type(self, address):
        """
        Detect cryptocurrency address type
        
        Args:
            address: Address string
            
        Returns:
            dict: Address type and details
        """
        # Bitcoin address patterns
        if (address.startswith('1') or address.startswith('3') or address.startswith('bc1')) and len(address) in [26, 34, 42]:
            if self._is_valid_bitcoin_address(address):
                return {"type": "Bitcoin", "valid": True, "network": "Bitcoin"}
        
        # Ethereum address pattern (0x followed by 40 hex chars)
        if address.startswith('0x') and len(address) == 42:
            if self._is_valid_ethereum_address(address):
                return {"type": "Ethereum", "valid": True, "network": "Ethereum"}
        
        return {"type": "Unknown", "valid": False}
    
    def get_address_risk_score(self, address, address_type="bitcoin"):
        """
        Calculate risk score for address based on patterns
        
        Args:
            address: Address to analyze
            address_type: Type of address (bitcoin/ethereum)
            
        Returns:
            dict: Risk assessment
        """
        risk_score = 0
        risk_factors = []
        
        # Scoring logic (simplified)
        if address_type == "bitcoin":
            # Very new addresses (potential risk)
            risk_score += 10
            risk_factors.append("Address type identified")
        
        return {
            "address": address,
            "risk_score": risk_score,
            "risk_level": "Low" if risk_score < 30 else "Medium" if risk_score < 70 else "High",
            "risk_factors": risk_factors,
            "timestamp": datetime.now().isoformat()
        }
    
    def _is_valid_bitcoin_address(self, address):
        """Validate Bitcoin address format"""
        if len(address) not in [26, 34, 42]:
            return False
        
        # P2PKH (starts with 1), P2SH (starts with 3), P2WPKH (starts with bc1)
        valid_starts = ['1', '3', 'bc1']
        return any(address.startswith(start) for start in valid_starts)
    
    def _is_valid_ethereum_address(self, address):
        """Validate Ethereum address format"""
        if not address.startswith('0x') or len(address) != 42:
            return False
        try:
            int(address[2:], 16)
            return True
        except ValueError:
            return False
