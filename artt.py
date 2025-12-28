#!/usr/bin/env python3
"""
Advanced Red Team Toolkit (ARTT)
A comprehensive suite of tools for penetration testing and red team operations.

Features:
- Credential harvesting
- Lateral movement detection
- Command execution monitoring
- File integrity verification
- Network reconnaissance
- Privilege escalation detection
"""

import os
import sys
import time
import json
import base64
import hashlib
import subprocess
import threading
import socket
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import logging
import psutil
import pyshark
import requests
import paramiko
from cryptography.fernet import Fernet

class ARTT:
    def __init__(self, config_file: str = "config.json"):
        self.config = self._load_config(config_file)
        self.logger = self._setup_logging()
        self.results_dir = f"artt_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(self.results_dir, exist_ok=True)
        
    def _load_config(self, config_file: str) -> Dict:
        """Load configuration from JSON file."""
        try:
            with open(config_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            default_config = {
                "targets": ["192.168.1.0/24"],
                "credentials": [],
                "exploits": [],
                "scan_timeout": 300,
                "output_format": "json"
            }
            with open(config_file, 'w') as f:
                json.dump(default_config, f, indent=4)
            return default_config
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logger with rotating file handler."""
        logger = logging.getLogger('ARTT')
        logger.setLevel(logging.DEBUG)
        
        # File handler
        file_handler = logging.FileHandler(
            os.path.join(self.results_dir, 'artt.log'))
        file_handler.setLevel(logging.DEBUG)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        return logger

    def credential_harvesting(self) -> Dict:
        """Harvest credentials from common locations."""
        self.logger.info("Starting credential harvesting...")
        results = {
            "hashes": [],
            "passwords": [],
            "ssh_keys": []
        }
        
        # Check for password files
        pwd_files = ["/etc/passwd", "/etc/shadow", "/etc/group"]
        for file_path in pwd_files:
            if os.path.exists(file_path):
                try:
                    with open(file_path, 'r') as f:
                        content = f.read()
                        # Extract hashes
                        for line in content.splitlines():
                            if ':' in line:
                                username, password_hash = line.split(':', 1)
                                if '*' not in password_hash and '!' not in password_hash:
                                    results["hashes"].append({
                                        "file": file_path,
                                        "username": username,
                                        "hash": password_hash
                                    })
                except Exception as e:
                    self.logger.error(f"Error reading {file_path}: {str(e)}")
        
        # Check for SSH keys
        ssh_dirs = ["/root/.ssh", "/home/*/.ssh"]
        for ssh_dir in ssh_dirs:
            try:
                for root, dirs, files in os.walk(ssh_dir):
                    for file in files:
                        if file.startswith("id_") and not file.endswith(".pub"):
                            key_path = os.path.join(root, file)
                            try:
                                with open(key_path, 'r') as f:
                                    key_content = f.read()
                                    results["ssh_keys"].append({
                                        "path": key_path,
                                        "size": len(key_content)
                                    })
                            except Exception as e:
                                self.logger.error(f"Error reading {key_path}: {str(e)}")
            except Exception as e:
                self.logger.error(f"Error walking SSH directory: {str(e)}")
        
        self.logger.info(f"Harvested {len(results['hashes'])} hashes and {len(results['ssh_keys'])} SSH keys")
        return results

    def lateral_movement_detection(self) -> Dict:
        """Detect lateral movement via network traffic analysis."""
        self.logger.info("Analyzing network traffic for lateral movement...")
        results = {
            "potential_jmps": [],
            "suspicious_connections": [],
            "known_targets": []
        }
        
        # Check for common C2 ports
        c2_ports = [443, 80, 53, 1433, 3389]
        local_ip = socket.gethostbyname(socket.gethostname())
        
        try:
            # Capture live traffic
            cap = pyshark.LiveCapture(interface=self.config.get("capture_interface", "eth0"))
            for packet in cap.sniff_continuously(timeout=30):
                try:
                    if hasattr(packet, 'tcp'):
                        src_ip = packet.ip.src
                        dst_ip = packet.ip.dst
                        dst_port = int(packet.tcp.dstport)
                        
                        # Check for potential pivots
                        if src_ip != local_ip and dst_ip == local_ip:
                            results["potential_jmps"].append({
                                "source": src_ip,
                                "destination": dst_ip,
                                "port": dst_port,
                                "timestamp": packet.sniff_time
                            })
                        
                        # Check for known malicious destinations
                        if dst_port in c2_ports:
                            results["suspicious_connections"].append({
                                "source": src_ip,
                                "destination": dst_ip,
                                "port": dst_port,
                                "timestamp": packet.sniff_time
                            })
                            
                        # Check for targets in our scan list
                        if dst_ip in self.config.get("targets", []):
                            results["known_targets"].append({
                                "source": src_ip,
                                "destination": dst_ip,
                                "port": dst_port,
                                "timestamp": packet.sniff_time
                            })
                except Exception as e:
                    self.logger.debug(f"Error processing packet: {str(e)}")
        except Exception as e:
            self.logger.error(f"Traffic analysis failed: {str(e)}")
            
        return results

    def command_execution_monitor(self) -> Dict:
        """Monitor for suspicious command execution."""
        self.logger.info("Monitoring command execution...")
        results = {
            "suspicious_commands": [],
            "unusual_processes": [],
            "shell_activity": []
        }
        
        # Common suspicious commands
        suspicious_commands = [
            "sudo", "su", "passwd", "chpasswd", "crontab",
            "netstat", "ps", "lsof", "ssh", "scp", "wget",
            "curl", "nc", "ncat", "nmap", "ping", "whoami",
            "id", "groups", "cat /etc/passwd", "cat /etc/shadow"
        ]
        
        # Check running processes
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                cmd = " ".join(proc.info['cmdline'] or [])
                
                # Check for suspicious commands
                for suspicious in suspicious_commands:
                    if suspicious in cmd.lower():
                        results["suspicious_commands"].append({
                            "process": proc.info['name'],
                            "command": cmd,
                            "pid": proc.info['pid']
                        })
                        break
                
                # Check for unusual process names
                if proc.info['name'].lower() in ['bash', 'sh', 'python', 'perl']:
                    if not any(suspicious in cmd.lower() for suspicious in suspicious_commands):
                        results["unusual_processes"].append({
                            "process": proc.info['name'],
                            "command": cmd,
                            "pid": proc.info['pid']
                        })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        return results

    def execute_scan(self) -> Dict:
        """Execute all scans and return combined results."""
        start_time = time.time()
        self.logger.info("Starting full red team assessment...")
        
        results = {
            "timestamp": datetime.now().isoformat(),
            "target": socket.gethostname(),
            "credential_harvesting": self.credential_harvesting(),
            "lateral_movement": self.lateral_movement_detection(),
            "command_execution": self.command_execution_monitor(),
            "scan_duration": 0
        }
        
        results["scan_duration"] = time.time() - start_time
        self.logger.info(f"Scan completed in {results['scan_duration']} seconds")
        
        # Save results
        output_file = os.path.join(self.results_dir, 'scan_results.json')
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=4)
            
        self.logger.info(f"Results saved to {output_file}")
        return results

def main():
    """Main entry point."""
    print("""
    ╔════════════════════════════════════════════════════════╗
    ║              Advanced Red Team Toolkit (ARTT)          ║
    ║                 Penetration Testing Framework          ║
    ╚════════════════════════════════════════════════════════╝
    """)
    
    tool = ARTT()
    results = tool.execute_scan()
    
    # Display summary
    print("\n[+] Scan Summary:")
    print(f"    Duration: {results['scan_duration']:.2f}s")
    print(f"    Credentials Found: {len(results['credential_harvesting']['hashes'])}")
    print(f"    Potential Lateral Movement: {len(results['lateral_movement']['potential_jmps'])}")
    print(f"    Suspicious Commands: {len(results['command_execution']['suspicious_commands'])}")
    print(f"\n[+] Results saved to {tool.results_dir}")

if __name__ == "__main__":
    main()