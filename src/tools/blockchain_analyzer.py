"""
Blockchain Address Analyzer
Cryptocurrency address lookup and analysis tool
"""

import requests
from datetime import datetime
from utils.logger import Logger
from utils.validators import Validators

logger = Logger.get_logger("BlockchainAnalyzer")


class BlockchainAnalyzer:
    """Handle blockchain address lookups"""
    
    def __init__(self):
        self.validators = Validators()
    
    def analyze_bitcoin_address(self, address):
        """Query Bitcoin address info from blockchain.com"""
        
        if not self._is_valid_bitcoin_address(address):
            return {"success": False, "error": "Invalid address"}
        
        try:
            # Get balance
            balance_url = f"https://blockchain.info/q/addressbalance/{address}"
            balance_resp = requests.get(balance_url, timeout=5)
            
            if balance_resp.status_code != 200:
                return {"success": False, "error": "API error"}
            
            balance_satoshi = balance_resp.text.strip()
            
            # Get full details
            details_url = f"https://blockchain.info/address/{address}?format=json"
            details_resp = requests.get(details_url, timeout=5)
            
            if details_resp.status_code == 200:
                data = details_resp.json()
                btc_balance = float(balance_satoshi) / 100000000 if balance_satoshi.isdigit() else 0
                
                return {
                    "success": True,
                    "address": address,
                    "btc_balance": round(btc_balance, 8),
                    "satoshi": balance_satoshi,
                    "received": round(data.get('total_received', 0) / 100000000, 8),
                    "sent": round(data.get('total_sent', 0) / 100000000, 8),
                    "transactions": data.get('n_tx', 0),
                    "final_balance": round(data.get('final_balance', 0) / 100000000, 8),
                    "timestamp": datetime.now().isoformat(),
                    "type": "Bitcoin"
                }
        except requests.exceptions.RequestException:
            return {
                "success": False,
                "address": address,
                "type": "Bitcoin",
                "error": "API request failed"
            }
                
        except Exception as e:
            logger.error(f"Bitcoin analysis error: {str(e)}")
            return {"success": False, "error": str(e)}
    
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
            logger.error(f"Ethereum analysis error: {str(e)}")
            return {"success": False, "error": str(e)}
    
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
