import os
import re
from typing import List, Dict, Tuple, Set
import argparse
import json
import urllib.parse
import socket

class BackdoorDetector:
    def __init__(self):
        # 初始化各种语言的后门模式正则表达式
        self.patterns = {
            'generic': {
                'hardcoded_credentials': r'(password|passwd|pwd|secret|key)\s*=\s*[\'"][^\'"]+[\'"]',
                'ip_address': r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
                'suspicious_url': r'(http|https|ftp)://[^\s/$.?#].[^\s]*',
                'eval_danger': r'eval\s*\(|exec\s*\(',
                'base64_encoded': r'[A-Za-z0-9+/=]{20,}',
                'obfuscated_code': r'(\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4})+',
                'external_command': r'(system|popen|exec[lv]?|run_command|call)\s*\(',
                'network_connection': r'(socket|connect|bind|listen|HTTP|curl|wget|fetch)\s*\(',
                'dynamic_loading': r'(dlopen|LoadLibrary|Assembly\.Load|Class\.forName)\s*\(',
                'external_process': r'(Process|ProcessBuilder|spawn|fork)\s*\(',
            },
            'python': {
                'pickle_unsafe': r'pickle\.loads?\(',
                'os_command': r'os\.system\s*\(|subprocess\.(run|call|Popen)\s*\(',
                'dangerous_imports': r'import\s+(os|subprocess|pickle|marshal|ctypes|socket|urllib\.request)',
                'dynamic_import': r'__import__\s*\(',
                'code_execution': r'exec\s*\(|eval\s*\(',
                'python_network': r'urllib\.(request|urlopen)|requests\.(get|post)|socket\.(create_connection|connect)',
                'python_external': r'subprocess\.(run|call|Popen)\s*\(',
            },
            'java': {
                'runtime_exec': r'Runtime\.getRuntime\(\)\.exec\s*\(',
                'process_builder': r'new\s+ProcessBuilder\s*\(',
                'reflection': r'Class\.forName\s*\(|Method\.invoke\s*\(',
                'jni_usage': r'System\.loadLibrary\s*\(',
                'serialization': r'ObjectInputStream|ObjectOutputStream',
                'java_network': r'(HttpURLConnection|URL|Socket)\.',
                'java_external': r'ProcessBuilder\s*\(',
            },
            'go': {
                'command_exec': r'exec\.Command\s*\(',
                'unsafe_pkg': r'import\s+"unsafe"',
                'cgo_usage': r'import\s+"C"',
                'network_calls': r'net\.(Dial|Listen)\s*\(',
                'syscall': r'syscall\.(Exec|ForkExec)\s*\(',
                'go_network': r'http\.(Get|Post|Do)|net\.(Dial|DialTCP|DialUDP)',
                'go_external': r'os/exec\.Command\s*\(',
            },
            'javascript': {
                'eval_usage': r'eval\s*\(',
                'function_constructor': r'new\s+Function\s*\(',
                'dangerous_globals': r'window\.|document\.|process\.',
                'websocket_suspicious': r'new\s+WebSocket\s*\(',
                'postmessage_risk': r'postMessage\s*\(',
                'js_network': r'fetch\s*\(|XMLHttpRequest|axios\.(get|post)|require\s*\(\s*["\']http',
                'js_external': r'child_process\.(exec|spawn)',
            }
        }
        
        # 严重性等级
        self.severity_levels = {
            'critical': ['external_command', 'network_connection', 'dynamic_loading', 'external_process'],
            'high': ['eval_danger', 'os_command', 'runtime_exec', 'command_exec', 'eval_usage'],
            'medium': ['hardcoded_credentials', 'dynamic_import', 'reflection', 'function_constructor'],
            'low': ['ip_address', 'suspicious_url', 'dangerous_imports']
        }
        
        # 已知的合法域名和IP地址白名单
        self.whitelist = {
            'domains': ['localhost', '127.0.0.1', 'example.com', 'google.com', 'microsoft.com'],
            'ips': ['127.0.0.1', '0.0.0.0', '::1']
        }
    
    def scan_directory(self, directory_path: str) -> Dict[str, List[Dict]]:
        """扫描目录中的所有文件"""
        results = {}
        
        directory_path = os.path.normpath(directory_path)
        
        if not os.path.isdir(directory_path):
            print(f"Error: {directory_path} is not a valid directory")
            return results
            
        try:
            for root, _, files in os.walk(directory_path):
                for file in files:
                    file_path = os.path.normpath(os.path.join(root, file))
                    try:
                        detections = self.detect_in_file(file_path)
                        if detections:
                            results[file_path] = detections
                    except Exception as e:
                        print(f"Error processing file {file_path}: {str(e)}")
                        continue
        except Exception as e:
            print(f"Error walking directory {directory_path}: {str(e)}")
        
        return results
    
    def detect_in_file(self, file_path: str) -> List[Dict]:
        """检测单个文件中的后门模式"""
        results = []
        
        file_path = os.path.normpath(file_path)
        
        if not os.path.isfile(file_path):
            print(f"Error: {file_path} is not a valid file")
            return results
        
        # 根据文件扩展名确定语言
        lang = self._detect_language(file_path)
        if not lang:
            return results
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
                # 检查通用模式
                for pattern_name, pattern in self.patterns['generic'].items():
                    matches = self._check_pattern(content, pattern, pattern_name)
                    if matches:
                        results.extend(matches)
                
                # 检查特定语言模式
                if lang in self.patterns:
                    for pattern_name, pattern in self.patterns[lang].items():
                        matches = self._check_pattern(content, pattern, pattern_name)
                        if matches:
                            results.extend(matches)
                
                # 特别检查URL和网络连接
                url_matches = self._detect_external_connections(content, lang)
                if url_matches:
                    results.extend(url_matches)
                            
        except Exception as e:
            print(f"Error processing file {file_path}: {str(e)}")
        
        return results
    
    def _detect_language(self, file_path: str) -> str:
        """根据文件扩展名检测编程语言"""
        ext = os.path.splitext(file_path)[1].lower()
        
        if ext in ('.py', '.pyw'):
            return 'python'
        elif ext in ('.java', '.jsp'):
            return 'java'
        elif ext == '.go':
            return 'go'
        elif ext in ('.js', '.jsx', '.ts', '.tsx', '.vue'):
            return 'javascript'
        elif ext in ('.php', '.rb', '.pl', '.sh', '.bash', '.zsh', '.c', '.cpp', '.h', '.hpp'):
            return 'generic'
        
        return ''
    
    def _check_pattern(self, content: str, pattern: str, pattern_name: str) -> List[Dict]:
        """检查内容中是否存在指定的模式"""
        matches = []
        
        for match in re.finditer(pattern, content, re.IGNORECASE):
            line_number = content.count('\n', 0, match.start()) + 1
            severity = self._get_severity_level(pattern_name)
            
            matches.append({
                'pattern': pattern_name,
                'severity': severity,
                'line': line_number,
                'match': match.group(),
                'description': self._get_description(pattern_name)
            })
        
        return matches
    
    def _get_severity_level(self, pattern_name: str) -> str:
        """获取模式的严重性等级"""
        for level, patterns in self.severity_levels.items():
            if pattern_name in patterns:
                return level
        return 'low'
    
    def _get_description(self, pattern_name: str) -> str:
        """获取模式的描述"""
        descriptions = {
            'hardcoded_credentials': 'Hardcoded credentials detected',
            'ip_address': 'Suspicious IP address found',
            'suspicious_url': 'Suspicious URL found',
            'eval_danger': 'Potential dangerous eval/exec usage',
            'base64_encoded': 'Base64 encoded string found',
            'obfuscated_code': 'Possible obfuscated code detected',
            'external_command': 'External command execution detected',
            'network_connection': 'Network connection detected',
            'dynamic_loading': 'Dynamic code loading detected',
            'external_process': 'External process creation detected',
            'pickle_unsafe': 'Potential unsafe pickle usage',
            'os_command': 'OS command execution detected',
            'dangerous_imports': 'Potentially dangerous import',
            'dynamic_import': 'Dynamic import detected',
            'code_execution': 'Dynamic code execution detected',
            'runtime_exec': 'Runtime command execution detected',
            'process_builder': 'Process builder detected',
            'reflection': 'Reflection usage detected',
            'jni_usage': 'JNI usage detected',
            'serialization': 'Serialization usage detected',
            'command_exec': 'Command execution detected',
            'unsafe_pkg': 'Unsafe package usage detected',
            'cgo_usage': 'CGO usage detected',
            'eval_usage': 'eval usage detected',
            'function_constructor': 'Function constructor usage detected',
            'dangerous_globals': 'Potentially dangerous global object access',
            'external_connection': 'External connection detected'
        }
        return descriptions.get(pattern_name, 'Suspicious pattern detected')
    
    def _detect_external_connections(self, content: str, lang: str) -> List[Dict]:
        """特别检测外部连接"""
        results = []
        
        # 检测URL连接
        url_pattern = r'(https?|ftp)://([^\s/$.?#]+)([^\s]*)'
        for match in re.finditer(url_pattern, content):
            url = match.group()
            domain = match.group(2)
            
            # 检查是否在白名单中
            if not self._is_whitelisted(domain):
                line_number = content.count('\n', 0, match.start()) + 1
                results.append({
                    'pattern': 'external_connection',
                    'severity': 'critical',
                    'line': line_number,
                    'match': url,
                    'description': f'External connection to {domain}'
                })
        
        # 检测IP地址连接
        ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
        for match in re.finditer(ip_pattern, content):
            ip = match.group()
            
            # 检查是否是私有IP或保留IP
            if not (self._is_private_ip(ip) or self._is_whitelisted(ip)):
                line_number = content.count('\n', 0, match.start()) + 1
                results.append({
                    'pattern': 'external_connection',
                    'severity': 'critical',
                    'line': line_number,
                    'match': ip,
                    'description': f'External connection to IP {ip}'
                })
        
        return results
    
    def _is_whitelisted(self, domain_or_ip: str) -> bool:
        """检查域名或IP是否在白名单中"""
        # 检查域名白名单
        for domain in self.whitelist['domains']:
            if domain_or_ip.endswith(domain):
                return True
        
        # 检查IP白名单
        if domain_or_ip in self.whitelist['ips']:
            return True
        
        return False
    
    def _is_private_ip(self, ip: str) -> bool:
        """检查是否是私有IP地址"""
        try:
            ip_num = socket.inet_aton(ip)
            
            # 私有IP范围:
            # 10.0.0.0 - 10.255.255.255
            # 172.16.0.0 - 172.31.255.255
            # 192.168.0.0 - 192.168.255.255
            if ip.startswith('10.') or \
               (ip.startswith('172.') and 16 <= int(ip.split('.')[1]) <= 31) or \
               ip.startswith('192.168.'):
                return True
                
        except socket.error:
            return False
        
        return False

def main():
    parser = argparse.ArgumentParser(description='Enhanced Backdoor Detector Tool with External Connection Detection')
    parser.add_argument('path', help='File or directory path to scan')
    parser.add_argument('--output', '-o', help='Output file for results (JSON format)')
    parser.add_argument('--whitelist', '-w', help='Path to JSON file containing whitelist domains and IPs')
    args = parser.parse_args()
    
    detector = BackdoorDetector()
    
    # 加载自定义白名单
    if args.whitelist:
        try:
            with open(args.whitelist, 'r') as f:
                custom_whitelist = json.load(f)
                detector.whitelist['domains'].extend(custom_whitelist.get('domains', []))
                detector.whitelist['ips'].extend(custom_whitelist.get('ips', []))
        except Exception as e:
            print(f"Warning: Could not load whitelist file: {str(e)}")
    
    path = os.path.normpath(args.path)
    
    if os.path.isfile(path):
        results = {path: detector.detect_in_file(path)}
    elif os.path.isdir(path):
        results = detector.scan_directory(path)
    else:
        print(f"Error: Path {path} does not exist")
        return
    
    # 打印结果
    for file_path, detections in results.items():
        if detections:
            print(f"\nFound {len(detections)} potential issues in {file_path}:")
            for issue in detections:
                print(f"  [Line {issue['line']}] [{issue['severity'].upper()}] {issue['pattern']}: {issue['match']}")
                print(f"    Description: {issue['description']}")
    
    # 保存结果到文件
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\nResults saved to {args.output}")

if __name__ == '__main__':
    main()