"""CVE Database and Vulnerability Scanner Tool"""
import json
import os
from datetime import datetime
from utils.logger import Logger
from utils.validators import Validators

class CVEDatabase:
    """Local CVE database and vulnerability matching"""
    
    def __init__(self):
        self.db_file = "data/cve_database.json"
        self._load_or_create_database()
    
    def _load_or_create_database(self):
        """Load or create CVE database"""
        if os.path.exists(self.db_file):
            try:
                with open(self.db_file, 'r') as f:
                    self.db = json.load(f)
                Logger.info("CVE database loaded")
            except Exception as e:
                Logger.warning(f"Error loading CVE database: {str(e)}")
                self._create_default_database()
        else:
            self._create_default_database()
    
    def _create_default_database(self):
        """Create default CVE database with common vulnerabilities"""
        self.db = {
            "vulnerabilities": [
                {
                    "cve_id": "CVE-2021-44228",
                    "software": "Apache Log4j",
                    "affected_versions": ["<2.17.0"],
                    "description": "Remote Code Execution in Log4j",
                    "severity": "CRITICAL",
                    "cvss_score": 10.0,
                    "fix": "Upgrade to version 2.17.0 or later"
                },
                {
                    "cve_id": "CVE-2021-3129",
                    "software": "Laravel Framework",
                    "affected_versions": ["<8.4.2", "<7.30.4"],
                    "description": "Remote Code Execution via debug mode",
                    "severity": "CRITICAL",
                    "cvss_score": 9.8,
                    "fix": "Upgrade Laravel or disable debug mode in production"
                },
                {
                    "cve_id": "CVE-2019-2725",
                    "software": "Oracle WebLogic",
                    "affected_versions": ["10.3.6", "11.2.1", "12.1.3", "12.2.1"],
                    "description": "Remote Code Execution via T3 protocol",
                    "severity": "CRITICAL",
                    "cvss_score": 9.8,
                    "fix": "Apply security patches from Oracle"
                },
                {
                    "cve_id": "CVE-2018-1000656",
                    "software": "Flask",
                    "affected_versions": ["<1.0"],
                    "description": "Insufficient entropy in random token generation",
                    "severity": "HIGH",
                    "cvss_score": 7.5,
                    "fix": "Upgrade to Flask 1.0 or later"
                },
                {
                    "cve_id": "CVE-2014-3566",
                    "software": "OpenSSL",
                    "affected_versions": ["<1.0.1i"],
                    "description": "SSLv3 POODLE vulnerability",
                    "severity": "HIGH",
                    "cvss_score": 7.1,
                    "fix": "Upgrade OpenSSL and disable SSLv3"
                },
                {
                    "cve_id": "CVE-2017-5645",
                    "software": "Apache ActiveMQ",
                    "affected_versions": ["5.11.0-5.15.4"],
                    "description": "OpenWire protocol vulnerability",
                    "severity": "HIGH",
                    "cvss_score": 8.8,
                    "fix": "Upgrade to 5.15.5 or later"
                },
                {
                    "cve_id": "CVE-2021-26919",
                    "software": "Windows",
                    "affected_versions": ["10", "Server 2019", "Server 2016"],
                    "description": "Win32k elevation of privilege",
                    "severity": "HIGH",
                    "cvss_score": 7.8,
                    "fix": "Install Windows security updates"
                },
                {
                    "cve_id": "CVE-2021-31956",
                    "software": "Windows",
                    "affected_versions": ["10", "Server 2019"],
                    "description": "Windows NTFS elevation of privilege",
                    "severity": "HIGH",
                    "cvss_score": 7.0,
                    "fix": "Install latest Windows security patches"
                }
            ]
        }
        self._save_database()
        Logger.info("Default CVE database created")
    
    def _save_database(self):
        """Save database to file"""
        try:
            os.makedirs(os.path.dirname(self.db_file), exist_ok=True)
            with open(self.db_file, 'w') as f:
                json.dump(self.db, f, indent=2)
        except Exception as e:
            Logger.error(f"Error saving CVE database: {str(e)}")
    
    def search_cve(self, cve_id):
        """Search for specific CVE"""
        if not cve_id.startswith("CVE-"):
            return {"error": "Invalid CVE format (should be CVE-YYYY-XXXX)"}
        
        for vuln in self.db.get("vulnerabilities", []):
            if vuln["cve_id"].upper() == cve_id.upper():
                return vuln
        
        return {"error": f"CVE {cve_id} not found in database"}
    
    def search_by_software(self, software_name, version=None):
        """Search vulnerabilities by software name"""
        results = {
            "software": software_name,
            "vulnerabilities": [],
            "scan_date": datetime.now().isoformat()
        }
        
        for vuln in self.db.get("vulnerabilities", []):
            if software_name.lower() in vuln["software"].lower():
                # If version provided, check if affected
                if version:
                    if self._is_version_affected(version, vuln["affected_versions"]):
                        results["vulnerabilities"].append(vuln)
                else:
                    results["vulnerabilities"].append(vuln)
        
        results["found_count"] = len(results["vulnerabilities"])
        return results
    
    def check_service_vulnerabilities(self, service_name, version):
        """Check vulnerabilities for a specific service version"""
        if not Validators.is_valid_service_name(service_name):
            return {"error": "Invalid service name"}
        
        results = {
            "service": service_name,
            "version": version,
            "vulnerabilities": [],
            "risk_level": "LOW",
            "scan_date": datetime.now().isoformat()
        }
        
        for vuln in self.db.get("vulnerabilities", []):
            if service_name.lower() in vuln["software"].lower():
                if self._is_version_affected(version, vuln["affected_versions"]):
                    results["vulnerabilities"].append(vuln)
                    
                    # Update risk level
                    severity = vuln.get("severity", "MEDIUM")
                    if severity == "CRITICAL":
                        results["risk_level"] = "CRITICAL"
                    elif severity == "HIGH" and results["risk_level"] != "CRITICAL":
                        results["risk_level"] = "HIGH"
        
        results["vulnerable_count"] = len(results["vulnerabilities"])
        return results
    
    def get_statistics(self):
        """Get CVE database statistics"""
        vulns = self.db.get("vulnerabilities", [])
        
        severity_count = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0
        }
        
        for vuln in vulns:
            severity = vuln.get("severity", "MEDIUM")
            if severity in severity_count:
                severity_count[severity] += 1
        
        return {
            "total_vulnerabilities": len(vulns),
            "severity_breakdown": severity_count,
            "software_count": len(set(v["software"] for v in vulns)),
            "last_updated": datetime.now().isoformat()
        }
    
    def add_custom_vulnerability(self, cve_data):
        """Add custom vulnerability to database"""
        required_fields = ["cve_id", "software", "affected_versions", "severity", "cvss_score"]
        
        if not all(field in cve_data for field in required_fields):
            return {"error": f"Missing required fields: {required_fields}"}
        
        try:
            self.db["vulnerabilities"].append(cve_data)
            self._save_database()
            Logger.info(f"Added custom CVE: {cve_data['cve_id']}")
            return {"success": True, "cve_id": cve_data["cve_id"]}
        except Exception as e:
            Logger.error(f"Error adding custom vulnerability: {str(e)}")
            return {"error": str(e)}
    
    def _is_version_affected(self, version, affected_versions):
        """Check if version is affected by vulnerability"""
        from packaging import version as pkg_version
        
        try:
            check_version = pkg_version.parse(version)
            
            for affected in affected_versions:
                # Handle version ranges like "<2.0", ">=1.0,<2.0", etc.
                if affected.startswith("<"):
                    affected_ver = pkg_version.parse(affected[1:])
                    if check_version < affected_ver:
                        return True
                elif affected.startswith(">"):
                    affected_ver = pkg_version.parse(affected[1:])
                    if check_version > affected_ver:
                        return True
                elif affected.startswith("="):
                    affected_ver = pkg_version.parse(affected[1:])
                    if check_version == affected_ver:
                        return True
                elif affected == version:
                    return True
            
            return False
        except Exception:
            # Fallback: simple string comparison
            return version in affected_versions
    
    def get_critical_vulnerabilities(self):
        """Get all critical severity vulnerabilities"""
        critical = [v for v in self.db.get("vulnerabilities", []) 
                   if v.get("severity") == "CRITICAL"]
        
        return {
            "critical_count": len(critical),
            "vulnerabilities": critical,
            "scan_date": datetime.now().isoformat()
        }
    
    def compare_versions(self, software, version1, version2):
        """Compare vulnerability risk between two versions"""
        result = {
            "software": software,
            "version1": {
                "version": version1,
                "vulnerable": False,
                "vulnerabilities": []
            },
            "version2": {
                "version": version2,
                "vulnerable": False,
                "vulnerabilities": []
            }
        }
        
        for vuln in self.db.get("vulnerabilities", []):
            if software.lower() in vuln["software"].lower():
                if self._is_version_affected(version1, vuln["affected_versions"]):
                    result["version1"]["vulnerable"] = True
                    result["version1"]["vulnerabilities"].append(vuln["cve_id"])
                
                if self._is_version_affected(version2, vuln["affected_versions"]):
                    result["version2"]["vulnerable"] = True
                    result["version2"]["vulnerabilities"].append(vuln["cve_id"])
        
        result["recommendation"] = self._get_version_recommendation(result)
        return result
    
    def _get_version_recommendation(self, comparison):
        """Provide version upgrade recommendation"""
        v1_count = len(comparison["version1"]["vulnerabilities"])
        v2_count = len(comparison["version2"]["vulnerabilities"])
        
        if v1_count == 0:
            return f"Version {comparison['version1']['version']} is secure"
        elif v2_count == 0:
            return f"Upgrade to version {comparison['version2']['version']} (secure)"
        elif v2_count < v1_count:
            return f"Version {comparison['version2']['version']} has fewer vulnerabilities"
        else:
            return f"Version {comparison['version1']['version']} is better (fewer vulnerabilities)"
