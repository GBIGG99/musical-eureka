def deep_repository_analysis(self, repo_url: str):
    """Analyze entire repository structure and commit history"""
    analysis_results = []
    
    try:
        # Get repository details
        repo_api_url = repo_url.replace('github.com', 'api.github.com/repos')
        headers = self.rotate_headers()
        
        # Analyze commits
        commits_url = f"{repo_api_url}/commits"
        response = self.session.get(commits_url, headers=headers)
        if response.status_code == 200:
            commits = response.json()
            for commit in commits[:10]:  # Last 10 commits
                commit_analysis = self.analyze_commit(commit['url'])
                analysis_results.extend(commit_analysis)
        
        # Analyze issues and wikis
        issues_url = f"{repo_api_url}/issues"
        response = self.session.get(issues_url, headers=headers)
        if response.status_code == 200:
            issues = response.json()
            for issue in issues[:5]:
                if self.scan_text(issue.get('body', '')):
                    analysis_results.append({
                        'type': 'issue_leak',
                        'source': 'issue',
                        'repo': repo_url,
                        'content': issue.get('body', '')[:200] + '...'
                    })
    
    except Exception as e:
        print(f"[!] Deep analysis error: {e}")
    
    return analysis_results

def analyze_commit(self, commit_url: str):
    """Analyze individual commit for secrets"""
    findings = []
    try:
        headers = self.rotate_headers()
        response = self.session.get(commit_url, headers=headers)
        if response.status_code == 200:
            commit_data = response.json()
            # Check patch content for secrets
            if 'files' in commit_data:
                for file in commit_data['files']:
                    if file.get('patch'):
                        if self.scan_text(file['patch']):
                            findings.append({
                                'type': 'commit_leak',
                                'file': file['filename'],
                                'repo': commit_url,
                                'patch_snippet': file['patch'][:500] + '...'
                            })
    except:
        pass
    return findings
