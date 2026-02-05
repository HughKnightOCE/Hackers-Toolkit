"""
Security Audit Log Analyzer
Parses and analyzes system audit logs for security events
"""

import re
from datetime import datetime
from collections import defaultdict
from src.utils.logger import Logger

logger = Logger.get_logger("AuditLogAnalyzer")


class AuditLogAnalyzer:
    """Analyzes system audit and security logs"""
    
    def __init__(self):
        self.log_patterns = {
            'failed_login': re.compile(r'(failed|failure|unauthorized|denied|error).*login', re.IGNORECASE),
            'privilege_escalation': re.compile(r'(sudo|su|elevation|privilege)', re.IGNORECASE),
            'file_access': re.compile(r'(open|access|read|write|permission|chmod)', re.IGNORECASE),
            'process': re.compile(r'(process|execution|exec|command)', re.IGNORECASE),
            'network': re.compile(r'(connection|tcp|udp|port|listen)', re.IGNORECASE),
        }
    
    def analyze_log_file(self, file_path, max_lines=10000):
        """Analyze audit log file"""
        try:
            with open(file_path, 'r') as f:
                lines = [f.readline() for _ in range(max_lines)]
            
            events = self._parse_events(lines)
            
            return {
                'file': file_path,
                'lines_analyzed': len([l for l in lines if l.strip()]),
                'timestamp': datetime.now().isoformat(),
                'total_events': len(events),
                'event_summary': self._summarize_events(events),
                'suspicious_activity': self._find_suspicious(events)
            }
        
        except Exception as e:
            logger.error(f"Log parsing error: {str(e)}")
            return {'error': str(e)}
    
    def _parse_events(self, lines):
        """Parse log lines into events"""
        events = []
        
        for i, line in enumerate(lines, 1):
            if not line.strip():
                continue
            
            event = {
                'line_number': i,
                'raw_log': line.strip(),
                'timestamp': None,
                'event_type': None,
                'severity': 'INFO'
            }
            
            # Categorize event
            for event_type, pattern in self.log_patterns.items():
                if pattern.search(line):
                    event['event_type'] = event_type
                    
                    # Determine severity
                    if 'failed' in line.lower() or 'denied' in line.lower():
                        event['severity'] = 'WARNING'
                    if 'error' in line.lower():
                        event['severity'] = 'ERROR'
                    break
            
            events.append(event)
        
        return events
    
    def _summarize_events(self, events):
        """Summarize events by type"""
        summary = defaultdict(int)
        
        for event in events:
            if event['event_type']:
                summary[event['event_type']] += 1
        
        return dict(summary)
    
    def _find_suspicious(self, events):
        """Identify suspicious activity patterns"""
        suspicious = {
            'failed_logins': [],
            'privilege_escalations': [],
            'file_modifications': [],
            'unusual_processes': []
        }
        
        failed_attempts = defaultdict(int)
        
        for event in events:
            if event['event_type'] == 'failed_login':
                suspicious['failed_logins'].append(event)
                # Extract username if possible
                user_match = re.search(r'user=(\S+)', event['raw_log'], re.IGNORECASE)
                if user_match:
                    failed_attempts[user_match.group(1)] += 1
            
            elif event['event_type'] == 'privilege_escalation':
                suspicious['privilege_escalations'].append(event)
            
            elif event['event_type'] == 'file_access':
                suspicious['file_modifications'].append(event)
        
        # Flag accounts with multiple failed attempts
        for user, count in failed_attempts.items():
            if count > 3:
                suspicious['brute_force_attempts'] = suspicious.get('brute_force_attempts', [])
                suspicious['brute_force_attempts'].append({
                    'user': user,
                    'attempts': count
                })
        
        return suspicious
    
    def generate_report(self, events):
        """Generate security audit report"""
        report = {
            'total_events': len(events),
            'event_types': defaultdict(int),
            'severity_breakdown': defaultdict(int),
            'timeline': defaultdict(int),
            'risk_score': 0
        }
        
        for event in events:
            if event['event_type']:
                report['event_types'][event['event_type']] += 1
            
            report['severity_breakdown'][event['severity']] += 1
            
            # Calculate risk score
            if event['severity'] == 'ERROR':
                report['risk_score'] += 3
            elif event['severity'] == 'WARNING':
                report['risk_score'] += 1
        
        return report
