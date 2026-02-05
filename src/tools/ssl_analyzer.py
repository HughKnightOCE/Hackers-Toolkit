"""SSL/TLS Certificate analyzer"""
import socket
import ssl
from datetime import datetime
from utils.logger import Logger
from utils.validators import Validators

class SSLAnalyzer:
    """Analyze SSL/TLS certificates"""
    
    def __init__(self):
        self.results = {}
    
    def get_certificate(self, hostname, port=443, timeout=10):
        """Get SSL certificate information"""
        if not (Validators.is_valid_domain(hostname) or Validators.is_valid_ip(hostname)):
            return {"error": "Invalid hostname or IP"}
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    return {
                        "hostname": hostname,
                        "port": port,
                        "subject": dict(x[0] for x in cert.get('subject', [])),
                        "issuer": dict(x[0] for x in cert.get('issuer', [])),
                        "version": cert.get('version'),
                        "serial_number": cert.get('serialNumber'),
                        "not_before": cert.get('notBefore'),
                        "not_after": cert.get('notAfter'),
                        "subject_alt_name": cert.get('subjectAltName', []),
                        "status": "Valid"
                    }
        except ssl.SSLError as e:
            Logger.warning(f"SSL error for {hostname}: {str(e)}")
            return {"error": f"SSL error: {str(e)}"}
        except socket.timeout:
            return {"error": "Connection timeout"}
        except Exception as e:
            Logger.error(f"Certificate fetch error: {str(e)}")
            return {"error": str(e)}
    
    def check_certificate_validity(self, hostname, port=443):
        """Check if certificate is valid and not expired"""
        try:
            cert = self.get_certificate(hostname, port)
            
            if "error" in cert:
                return cert
            
            # Check expiration
            from datetime import datetime
            not_after = cert.get('not_after')
            
            return {
                "hostname": hostname,
                "is_valid": True,
                "certificate_info": cert
            }
        except Exception as e:
            return {"error": str(e)}
    
    def test_ssl_protocols(self, hostname, port=443):
        """Test supported SSL/TLS protocols"""
        protocols = {
            'TLSv1': ssl.PROTOCOL_TLSv1,
            'TLSv1.1': ssl.PROTOCOL_TLSv1_1,
            'TLSv1.2': ssl.PROTOCOL_TLSv1_2,
        }
        
        supported = []
        
        for name, protocol in protocols.items():
            try:
                context = ssl.SSLContext(protocol)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((hostname, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname):
                        supported.append(name)
            except:
                pass
        
        return {
            "hostname": hostname,
            "port": port,
            "supported_protocols": supported
        }
