"""
Load Tester - HTTP/Network Load Testing Tool
Tests server performance under load conditions
"""

import requests
import threading
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils.logger import Logger
from utils.validators import Validators

class LoadTester:
    """HTTP load testing tool for performance analysis"""
    
    def __init__(self):
        self.logger = Logger()
        self.validators = Validators()
        self.results = []
        
    def test_endpoint(self, url, num_requests=100, concurrent=10, timeout=10):
        """
        Test endpoint with configurable load
        
        Args:
            url: Target URL to test
            num_requests: Number of total requests
            concurrent: Number of concurrent threads
            timeout: Request timeout in seconds
            
        Returns:
            dict: Performance metrics
        """
        try:
            if not self.validators.is_valid_url(url):
                self.logger.error(f"Invalid URL: {url}")
                return {"error": "Invalid URL format"}
            
            self.results = []
            successful_requests = 0
            failed_requests = 0
            total_time = 0
            min_time = float('inf')
            max_time = 0
            status_codes = {}
            
            start_time = time.time()
            
            with ThreadPoolExecutor(max_workers=min(concurrent, num_requests)) as executor:
                futures = [executor.submit(self._make_request, url, timeout) 
                          for _ in range(num_requests)]
                
                for future in as_completed(futures):
                    try:
                        response_time, status_code, success = future.result()
                        
                        if success:
                            successful_requests += 1
                            total_time += response_time
                            min_time = min(min_time, response_time)
                            max_time = max(max_time, response_time)
                        else:
                            failed_requests += 1
                        
                        status_codes[status_code] = status_codes.get(status_code, 0) + 1
                        
                    except Exception as e:
                        failed_requests += 1
                        self.logger.error(f"Request error: {str(e)}")
            
            total_duration = time.time() - start_time
            
            result = {
                "url": url,
                "total_requests": num_requests,
                "successful_requests": successful_requests,
                "failed_requests": failed_requests,
                "success_rate": round((successful_requests / num_requests) * 100, 2),
                "min_response_time": round(min_time, 3) if min_time != float('inf') else 0,
                "max_response_time": round(max_time, 3),
                "avg_response_time": round(total_time / successful_requests if successful_requests > 0 else 0, 3),
                "total_duration": round(total_duration, 2),
                "throughput": round(num_requests / total_duration, 2),
                "status_codes": status_codes,
                "timestamp": datetime.now().isoformat()
            }
            
            self.logger.info(f"Load test completed: {successful_requests}/{num_requests} successful")
            return result
            
        except Exception as e:
            self.logger.error(f"Load test error: {str(e)}")
            return {"error": str(e)}
    
    def _make_request(self, url, timeout):
        """Make single HTTP request and record metrics"""
        try:
            start = time.time()
            response = requests.get(url, timeout=timeout, allow_redirects=True)
            elapsed = time.time() - start
            return elapsed, response.status_code, response.status_code < 400
        except requests.Timeout:
            return timeout, 408, False
        except requests.ConnectionError:
            return 0, 0, False
        except Exception as e:
            return 0, 0, False
    
    def test_multiple_endpoints(self, urls, requests_per_endpoint=50):
        """
        Test multiple endpoints sequentially
        
        Args:
            urls: List of URLs to test
            requests_per_endpoint: Requests per URL
            
        Returns:
            dict: Results for all endpoints
        """
        results = {}
        for url in urls:
            results[url] = self.test_endpoint(url, num_requests=requests_per_endpoint)
        return results
    
    def stress_test(self, url, duration_seconds=30, concurrent=20):
        """
        Stress test for extended duration
        
        Args:
            url: Target URL
            duration_seconds: How long to run test
            concurrent: Number of concurrent requests
            
        Returns:
            dict: Stress test results
        """
        successful = 0
        failed = 0
        total_time = 0
        response_times = []
        
        start_time = time.time()
        request_count = 0
        
        with ThreadPoolExecutor(max_workers=concurrent) as executor:
            futures = []
            
            while time.time() - start_time < duration_seconds:
                for _ in range(concurrent):
                    future = executor.submit(self._make_request, url, 10)
                    futures.append(future)
                
                for future in as_completed(futures):
                    try:
                        response_time, status_code, success = future.result()
                        
                        if success:
                            successful += 1
                            total_time += response_time
                            response_times.append(response_time)
                        else:
                            failed += 1
                        
                        request_count += 1
                        
                    except Exception as e:
                        failed += 1
                        request_count += 1
                
                futures = []
        
        actual_duration = time.time() - start_time
        
        return {
            "url": url,
            "test_type": "stress_test",
            "duration_seconds": duration_seconds,
            "actual_duration": round(actual_duration, 2),
            "total_requests": request_count,
            "successful_requests": successful,
            "failed_requests": failed,
            "success_rate": round((successful / request_count) * 100, 2) if request_count > 0 else 0,
            "avg_response_time": round(total_time / successful if successful > 0 else 0, 3),
            "requests_per_second": round(request_count / actual_duration, 2),
            "timestamp": datetime.now().isoformat()
        }
    
    def get_test_history(self):
        """Return test history"""
        return self.results
