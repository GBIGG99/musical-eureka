import requests
import argparse
import time
import random
import json
import re
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import List, Dict, Set

# ===== CONFIGURATION =====
PROXY_CONFIG = {
    'http': 'socks5h://127.0.0.1:9050',
    'https': 'socks5h://127.0.0.1:9050'
}

GITHUB_TOKENS = []  # Load from env or file for rotation

CRITICAL_PATTERNS = {
    'api_keys': [r'[a-zA-Z0-9_]{24,40}', r'[a-zA-Z0-9_]{64,128}'],
    'emails': [r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'],
    'jwt_tokens': [r'eyJhbGciOiJ[^\s"]+'],
    'aws_keys': [r'AKIA[0-9A-Z]{16}', r'aws_access_key_id'],
    'database_urls': [r'mysql://[^\s]+', r'postgresql://[^\s]+', r'mongodb://[^\s]+'],
    'private_keys': [r'-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----']
}

class AdvancedGitHubRecon:
    def __init__(self, tor_proxy=False, max_threads=5):
        self.session = requests.Session()
        self.tor_proxy = tor_proxy
        if tor_proxy:
            self.session.proxies = PROXY_CONFIG
        self.max_threads = max_threads
        self.found_leaks = []
        self.scanned_repos = set()
        self.rate_limit_delay = 2
        
        # Load rotating user agents
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64; rv:90.0) Gecko/20100101 Firefox/90.0'
        ]
        
    def rotate_headers(self):
        return {
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'application/vnd.github.v3+json',
            'Accept-Language': 'en-US,en;q=0.5',
        }
    
    def search_github(self, dork: str, max_results: int = 50) -> List[Dict]:
        """Advanced GitHub search with evasion techniques"""
        results = []
        page = 1
        
        while len(results) < max_results:
            try:
                headers = self.rotate_headers()
                url = f"https://api.github.com/search/code?q={dork}&page={page}&per_page=100"
                
                response = self.session.get(url, headers=headers, timeout=30)
                
                if response.status_code == 403:
                    print("[!] Rate limit detected. Increasing delay...")
                    self.rate_limit_delay += 5
                    time.sleep(self.rate_limit_delay)
                    continue
                
                if response.status_code != 200:
                    break
                
                data = response.json()
                if not data.get('items'):
                    break
                
                results.extend(data['items'])
                
                # Evasion delay
                time.sleep(random.uniform(self.rate_limit_delay, self.rate_limit_delay + 3))
                page += 1
                
            except Exception as e:
                print(f"[!] Search error: {e}")
                break
        
        return results[:max_results]
    
    def extract_repo_contents(self, repo_url: str) -> List[Dict]:
        """Clone repository structure for deep analysis"""
        repo_contents = []
        try:
            headers = self.rotate_headers()
            url = repo_url.replace('github.com', 'api.github.com/repos') + '/contents/'
            
            response = self.session.get(url, headers=headers, timeout=30)
            if response.status_code == 200:
                repo_contents = response.json()
        except Exception as e:
            print(f"[!] Repo contents error: {e}")
        
        return repo_contents
    
    def analyze_content(self, content_url: str, repo_info: Dict) -> List[Dict]:
        """Deep content analysis with pattern matching"""
        findings = []
        try:
            raw_url = content_url.replace('github.com', 'raw.githubusercontent.com').replace('/blob/', '/')
            
            headers = self.rotate_headers()
            response = self.session.get(raw_url, headers=headers, timeout=30)
            
            if response.status_code == 200:
                content = response.text
                
                # Pattern matching
                for pattern_type, patterns in CRITICAL_PATTERNS.items():
                    for pattern in patterns:
                        matches = re.findall(pattern, content)
                        for match in matches:
                            if self.validate_finding(pattern_type, match):
                                findings.append({
                                    'type': pattern_type,
                                    'match': match,
                                    'repo': repo_info['repository']['full_name'],
                                    'file_path': repo_info['path'],
                                    'url': raw_url,
                                    'timestamp': datetime.now().isoformat()
                                })
        except Exception as e:
            print(f"[!] Content analysis error: {e}")
        
        return findings
    
    def validate_finding(self, pattern_type: str, match: str) -> bool:
        """Validate found patterns to reduce false positives"""
        if pattern_type == 'emails':
            if match.endswith('.github.com') or 'noreply' in match:
                return False
        elif pattern_type == 'api_keys':
            if len(match) < 20:  # Basic length check
                return False
        return True
    
    def generate_advanced_dorks(self, target: str, domains: List[str]) -> List[str]:
        """Generate comprehensive dork list"""
        base_dorks = [
            f'"{target}" filename:.env',
            f'"{target}" filename:config.yml',
            f'"{target}" filename:docker-compose.yml',
            f'"{target}" filename:credentials',
            f'"{target}" filename:config.json',
            f'"{target}" extension:sql',
            f'"{target}" extension:pem',
            f'"{target}" extension:ppk',
            f'"{target}" extension:key',
            f'"{target}" "API_KEY"',
            f'"{target}" "SECRET_KEY"',
            f'"{target}" "ACCESS_KEY"',
            f'"{target}" "PASSWORD"',
            f'"{target}" "TOKEN"',
            f'"{target}" "AUTH"',
        ]
        
        domain_dorks = []
        for domain in domains:
            domain_dorks.extend([
                f'"{domain}" password',
                f'"{domain}" secret',
                f'"{domain}" token',
                f'"{domain}" api_key',
                f'@{domain}',
                f'email@{domain}',
            ])
        
        return base_dorks + domain_dorks
    
    def run_comprehensive_scan(self, target: str, domains: List[str], output_file: str):
        """Execute full reconnaissance operation"""
        print(f"[*] Starting comprehensive scan for {target}")
        
        dorks = self.generate_advanced_dorks(target, domains)
        all_findings = []
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_dork = {
                executor.submit(self.process_dork, dork, target): dork 
                for dork in dorks
            }
            
            for future in as_completed(future_to_dork):
                dork = future_to_dork[future]
                try:
                    findings = future.result()
                    if findings:
                        print(f"[!] Found {len(findings)} leaks with dork: {dork}")
                        all_findings.extend(findings)
                except Exception as e:
                    print(f"[!] Error processing dork {dork}: {e}")
        
        # Save results
        if all_findings:
            self.save_results(all_findings, output_file)
            print(f"[+] Scan complete. Found {len(all_findings)} critical leaks.")
        else:
            print("[-] No critical leaks found.")
    
    def process_dork(self, dork: str, target: str) -> List[Dict]:
        """Process individual dork with comprehensive analysis"""
        findings = []
        results = self.search_github(dork)
        
        for result in results:
            repo_name = result['repository']['full_name']
            if repo_name in self.scanned_repos:
                continue
                
            self.scanned_repos.add(repo_name)
            
            # Analyze the specific file found
            file_findings = self.analyze_content(result['html_url'], result)
            findings.extend(file_findings)
            
            # Optional: Deep scan entire repository (use with caution)
            # repo_findings = self.deep_scan_repository(result['repository']['url'])
            # findings.extend(repo_findings)
        
        return findings
    
    def save_results(self, findings: List[Dict], output_file: str):
        """Save results in multiple formats"""
        # JSON format
        with open(f"{output_file}.json", 'w') as f:
            json.dump(findings, f, indent=2)
        
        # Text summary
        with open(f"{output_file}.txt", 'w') as f:
            for finding in findings:
                f.write(f"[{finding['type']}] {finding['match']}\n")
                f.write(f"Repo: {finding['repo']}\n")
                f.write(f"File: {finding['file_path']}\n")
                f.write(f"URL: {finding['url']}\n")
                f.write("-" * 50 + "\n")
        
        # CSV format
        with open(f"{output_file}.csv", 'w') as f:
            f.write("type,match,repo,file_path,url,timestamp\n")
            for finding in findings:
                f.write(f"{finding['type']},{finding['match']},{finding['repo']},{finding['file_path']},{finding['url']},{finding['timestamp']}\n")

def main():
    parser = argparse.ArgumentParser(description="SPECTRE-GIT - Advanced GitHub Reconnaissance")
    parser.add_argument("-t", "--target", required=True, help="Target company name")
    parser.add_argument("-d", "--domains", nargs='+', required=True, help="Target domains")
    parser.add_argument("-o", "--output", default="results", help="Output file base name")
    parser.add_argument("--tor", action="store_true", help="Use Tor proxy")
    parser.add_argument("--threads", type=int, default=3, help="Number of threads")
    
    args = parser.parse_args()
    
    # Initialize scanner
    scanner = AdvancedGitHubRecon(tor_proxy=args.tor, max_threads=args.threads)
    
    # Execute operation
    scanner.run_comprehensive_scan(args.target, args.domains, args.output)

if __name__ == "__main__":
    if os.geteuid() == 0:
        print("[!] Warning: Running as root is not recommended")
    
    # Check Tor connection if specified
    if '--tor' in sys.argv:
        try:
            test_response = requests.get("https://check.torproject.org/api/ip", 
                                       proxies=PROXY_CONFIG, timeout=10)
            if "Congratulations" not in test_response.text:
                print("[!] Tor connection not active")
                sys.exit(1)
        except:
            print("[!] Tor connection failed")
            sys.exit(1)
    
    main()
