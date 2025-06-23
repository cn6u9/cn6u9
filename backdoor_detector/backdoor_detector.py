import os
import re
from typing import List, Dict
import argparse
import json
import socket

class BackdoorDetector:
    def __init__(self):
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

        self.severity_levels = {
            'critical': ['external_command', 'network_connection', 'dynamic_loading', 'external_process'],
            'high': ['eval_danger', 'os_command', 'runtime_exec', 'command_exec', 'eval_usage'],
            'medium': ['hardcoded_credentials', 'dynamic_import', 'reflection', 'function_constructor'],
            'low': ['ip_address', 'suspicious_url', 'dangerous_imports']
        }

        self.whitelist = {
            'domains': ['localhost', '127.0.0.1', 'example.com', 'google.com', 'microsoft.com'],
            'ips': ['127.0.0.1', '0.0.0.0', '::1']
        }

    def scan_directory(self, directory_path: str) -> Dict[str, Dict]:
        results = {}
        for root, _, files in os.walk(directory_path):
            for file in files:
                file_path = os.path.normpath(os.path.join(root, file))
                detections = self.detect_in_file(file_path)
                if detections:
                    results[file_path] = {
                        'language': self._detect_language(file_path),
                        'detections': detections
                    }
        return results

    def detect_in_file(self, file_path: str) -> List[Dict]:
        results = []
        if not os.path.isfile(file_path):
            return results

        lang = self._detect_language(file_path)
        if not lang:
            return results

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

                for pattern_name, pattern in self.patterns['generic'].items():
                    results.extend(self._check_pattern(content, pattern, pattern_name))

                if lang in self.patterns:
                    for pattern_name, pattern in self.patterns[lang].items():
                        results.extend(self._check_pattern(content, pattern, pattern_name))

                results.extend(self._detect_external_connections(content))
        except Exception as e:
            print(f"Error reading {file_path}: {str(e)}")

        return results

    def _detect_language(self, file_path: str) -> str:
        ext = os.path.splitext(file_path)[1].lower()
        if ext in ('.py', '.pyw'):
            return 'python'
        elif ext in ('.java', '.jsp'):
            return 'java'
        elif ext == '.go':
            return 'go'
        elif ext in ('.jss', '.jsx', '.ts', '.tsx', '.vue'):
            return 'javascript'
        elif ext in ('.php', '.rb', '.pl', '.sh', '.bash', '.zsh', '.c', '.cpp', '.h', '.hpp'):
            return 'generic'
        return ''

    def _check_pattern(self, content: str, pattern: str, pattern_name: str) -> List[Dict]:
        matches = []
        for match in re.finditer(pattern, content, re.IGNORECASE):
            line_number = content.count('\n', 0, match.start()) + 1
            matches.append({
                'pattern': pattern_name,
                'severity': self._get_severity_level(pattern_name),
                'line': line_number,
                'match': match.group(),
                'description': self._get_description(pattern_name),
                'context': self._get_line_context(content, line_number)
            })
        return matches



    def _get_line_context(self, content: str, line_num: int) -> List[str]:
        lines = content.splitlines()
        start = max(0, line_num - 2)
        end = min(len(lines), line_num + 1)
        return [f"line {i+1}: {lines[i]}" for i in range(start, end)]


    def _get_severity_level(self, pattern_name: str) -> str:
        for level, patterns in self.severity_levels.items():
            if pattern_name in patterns:
                return level
        return 'low'

    def _get_description(self, pattern_name: str) -> str:
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

    def _detect_external_connections(self, content: str) -> List[Dict]:
        results = []

        url_pattern = r'(https?|ftp)://([^\s/$.?#]+)([^\s]*)'
        for match in re.finditer(url_pattern, content):
            domain = match.group(2)
            if not self._is_whitelisted(domain):
                line_number = content.count('\n', 0, match.start()) + 1
                results.append({
                    'pattern': 'external_connection',
                    'severity': 'critical',
                    'line': line_number,
                    'match': match.group(),
                    'description': f'External connection to {domain}',
                    'context': self._get_line_context(content, line_number)
                })

        ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
        for match in re.finditer(ip_pattern, content):
            ip = match.group()
            if not (self._is_private_ip(ip) or self._is_whitelisted(ip)):
                line_number = content.count('\n', 0, match.start()) + 1
                results.append({
                    'pattern': 'external_connection',
                    'severity': 'critical',
                    'line': line_number,
                    'match': ip,
                    'description': f'External connection to IP {ip}',
                    'context': self._get_line_context(content, line_number)
                })

        return results

    def _is_whitelisted(self, domain_or_ip: str) -> bool:
        return any(domain_or_ip.endswith(d) for d in self.whitelist['domains']) or domain_or_ip in self.whitelist['ips']

    def _is_private_ip(self, ip: str) -> bool:
        try:
            return ip.startswith('10.') or \
                   (ip.startswith('172.') and 16 <= int(ip.split('.')[1]) <= 31) or \
                   ip.startswith('192.168.')
        except:
            return False

def main():
    parser = argparse.ArgumentParser(description='Backdoor Detector with context-enhanced JSON output')
    parser.add_argument('path', help='Path to file or directory to scan')
    parser.add_argument('--output', '-o', help='Output JSON file path')
    parser.add_argument('--whitelist', '-w', help='Custom whitelist JSON')
    args = parser.parse_args()

    detector = BackdoorDetector()

    if args.whitelist:
        try:
            with open(args.whitelist, 'r') as f:
                custom = json.load(f)
                detector.whitelist['domains'].extend(custom.get('domains', []))
                detector.whitelist['ips'].extend(custom.get('ips', []))
        except Exception as e:
            print(f"Warning: failed to load whitelist: {e}")

    path = os.path.normpath(args.path)
    results = {}

    if os.path.isfile(path):
        detections = detector.detect_in_file(path)
        if detections:
            results[path] = {
                'language': detector._detect_language(path),
                'detections': detections
            }
    elif os.path.isdir(path):
        results = detector.scan_directory(path)
    else:
        print(f"Error: {path} is not valid.")
        return

    for file_path, info in results.items():
        print(f"\n{file_path} ({info['language']})")
        for d in info['detections']:
            print(f"  [Line {d['line']}] [{d['severity'].upper()}] {d['pattern']}: {d['match']}")
            print(f"    Description: {d['description']}")

    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\nResults saved to {args.output}")

if __name__ == '__main__':
    main()
