"""
Firewall Rules Analyzer
Analyzes firewall configurations and rule effectiveness
"""

import re
from datetime import datetime
from src.utils.logger import Logger

logger = Logger.get_logger("FirewallAnalyzer")


class FirewallRulesAnalyzer:
    """Analyzes firewall configuration files"""
    
    def __init__(self):
        self.rule_patterns = {
            'allow': re.compile(r'(allow|accept|permit)', re.IGNORECASE),
            'deny': re.compile(r'(deny|reject|drop)', re.IGNORECASE),
            'log': re.compile(r'(log|logging|syslog)', re.IGNORECASE),
            'port': re.compile(r'port\s+(\d+)', re.IGNORECASE),
            'protocol': re.compile(r'(tcp|udp|icmp)', re.IGNORECASE),
        }
    
    def parse_rules_file(self, file_path):
        """Parse firewall rules from file"""
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            
            rules = self._parse_rules(content)
            
            return {
                'file': file_path,
                'timestamp': datetime.now().isoformat(),
                'total_rules': len(rules),
                'rules': rules,
                'analysis': self._analyze_rules(rules)
            }
        
        except Exception as e:
            logger.error(f"File parsing error: {str(e)}")
            return {'error': str(e)}
    
    def _parse_rules(self, content):
        """Extract rules from configuration"""
        rules = []
        lines = content.split('\n')
        
        for i, line in enumerate(lines, 1):
            # Skip comments and empty lines
            if line.strip().startswith('#') or not line.strip():
                continue
            
            rule = {
                'line_number': i,
                'raw': line.strip(),
                'action': None,
                'protocol': None,
                'ports': [],
                'logging': False
            }
            
            # Extract action
            if self.rule_patterns['allow'].search(line):
                rule['action'] = 'ALLOW'
            elif self.rule_patterns['deny'].search(line):
                rule['action'] = 'DENY'
            
            # Extract protocol
            protocol_match = self.rule_patterns['protocol'].search(line)
            if protocol_match:
                rule['protocol'] = protocol_match.group(1).upper()
            
            # Extract ports
            port_matches = self.rule_patterns['port'].findall(line)
            rule['ports'] = [int(p) for p in port_matches]
            
            # Check for logging
            if self.rule_patterns['log'].search(line):
                rule['logging'] = True
            
            rules.append(rule)
        
        return rules
    
    def _analyze_rules(self, rules):
        """Analyze rule effectiveness"""
        analysis = {
            'total_rules': len(rules),
            'allow_rules': 0,
            'deny_rules': 0,
            'unlogged_rules': 0,
            'risky_patterns': [],
            'open_ports': []
        }
        
        for rule in rules:
            if rule['action'] == 'ALLOW':
                analysis['allow_rules'] += 1
            elif rule['action'] == 'DENY':
                analysis['deny_rules'] += 1
            
            if not rule['logging']:
                analysis['unlogged_rules'] += 1
            
            # Check for risky patterns
            if rule['action'] == 'ALLOW' and not rule['logging']:
                analysis['risky_patterns'].append({
                    'rule': rule['raw'],
                    'issue': 'Allow rule without logging'
                })
            
            # Track commonly allowed ports
            if rule['action'] == 'ALLOW':
                for port in rule['ports']:
                    analysis['open_ports'].append(port)
        
        return analysis
    
    def check_rule_conflicts(self, rules):
        """Identify conflicting rules"""
        conflicts = []
        
        for i, rule1 in enumerate(rules):
            for rule2 in rules[i+1:]:
                if (rule1['protocol'] == rule2['protocol'] and 
                    rule1['ports'] == rule2['ports'] and 
                    rule1['action'] != rule2['action']):
                    
                    conflicts.append({
                        'rule1': rule1['raw'],
                        'rule2': rule2['raw'],
                        'issue': 'Conflicting actions for same protocol/ports'
                    })
        
        return {
            'conflicts_found': len(conflicts),
            'conflicts': conflicts
        }
    
    def identify_weak_rules(self, rules):
        """Identify potentially weak firewall rules"""
        weak = {
            'overly_permissive': [],
            'unsafe_protocols': [],
            'missing_logging': []
        }
        
        unsafe_protocols = ['telnet', 'ftp', 'http']
        
        for rule in rules:
            if rule['action'] == 'ALLOW' and len(rule['ports']) == 0:
                weak['overly_permissive'].append(rule['raw'])
            
            if rule['protocol'] in unsafe_protocols:
                weak['unsafe_protocols'].append(rule['raw'])
            
            if not rule['logging'] and rule['action'] == 'ALLOW':
                weak['missing_logging'].append(rule['raw'])
        
        return weak
