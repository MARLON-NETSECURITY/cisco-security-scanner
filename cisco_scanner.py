#!/usr/bin/env python3
"""
Cisco Configuration Security Scanner
A tool to identify security vulnerabilities in Cisco router/switch configurations
Marlon netsec
"""

import re
import json
import click
from datetime import datetime
from dataclasses import dataclass
from typing import List, Dict, Tuple
from pathlib import Path

@dataclass
class SecurityFinding:
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    category: str
    title: str
    description: str
    line_number: int
    config_line: str
    recommendation: str
    cve_reference: str = ""

class CiscoConfigScanner:
    def __init__(self):
        self.findings: List[SecurityFinding] = []
        self.config_lines: List[str] = []
        self.stats = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'total_lines': 0
        }
        
    def load_config(self, config_path: str) -> bool:
        """Load Cisco configuration file"""
        try:
            with open(config_path, 'r', encoding='utf-8', errors='ignore') as f:
                self.config_lines = f.readlines()
            self.stats['total_lines'] = len(self.config_lines)
            click.echo(f"✓ Loaded config: {len(self.config_lines)} lines")
            return True
        except Exception as e:
            click.echo(f"✗ Error loading config: {e}", err=True)
            return False
    
    def load_config_text(self, config_text: str):
        """Load configuration from text string"""
        self.config_lines = config_text.split('\n')
        self.stats['total_lines'] = len(self.config_lines)
    
    def scan_all(self) -> List[SecurityFinding]:
        """Run all security checks"""
        click.echo("🔍 Starting security scan...")
        
        # Reset findings
        self.findings = []
        
        # Run all checks
        self._check_passwords()
        self._check_snmp()
        self._check_services()
        self._check_acls()
        self._check_interfaces()
        self._check_authentication()
        self._check_logging()
        self._check_banners()
        
        # Update statistics
        self._update_stats()
        
        click.echo(f"✓ Scan complete: {len(self.findings)} findings")
        return self.findings
    
    def _add_finding(self, severity: str, category: str, title: str, 
                    description: str, line_num: int, config_line: str, 
                    recommendation: str, cve: str = ""):
        """Add a security finding"""
        finding = SecurityFinding(
            severity=severity,
            category=category,
            title=title,
            description=description,
            line_number=line_num,
            config_line=config_line.strip(),
            recommendation=recommendation,
            cve_reference=cve
        )
        self.findings.append(finding)
    
    def _check_passwords(self):
        """Check for password security issues"""
        password_encryption_enabled = False
        default_passwords = ['cisco', 'admin', 'password', '123456', 'secret']
        
        for i, line in enumerate(self.config_lines, 1):
            line_lower = line.lower().strip()
            
            # Check if password encryption is enabled
            if 'service password-encryption' in line_lower:
                password_encryption_enabled = True
            
            # Check for default passwords
            if 'password' in line_lower or 'secret' in line_lower:
                for default_pwd in default_passwords:
                    if default_pwd in line_lower:
                        self._add_finding(
                            'CRITICAL',
                            'Authentication',
                            'Default Password Detected',
                            f'Default or weak password found: {default_pwd}',
                            i, line,
                            f'Change password to a strong, unique value'
                        )
            
            # Check for unencrypted passwords (type 0)
            if re.search(r'password 0 ', line_lower):
                self._add_finding(
                    'HIGH',
                    'Authentication',
                    'Unencrypted Password',
                    'Password stored in plaintext',
                    i, line,
                    'Enable "service password-encryption" or use encrypted passwords'
                )
            
            # Check for weak enable passwords
            if re.search(r'enable password', line_lower) and 'secret' not in line_lower:
                self._add_finding(
                    'HIGH',
                    'Authentication',
                    'Weak Enable Password',
                    'Using "enable password" instead of "enable secret"',
                    i, line,
                    'Use "enable secret" instead of "enable password"'
                )
        
        # Check if password encryption is disabled
        if not password_encryption_enabled:
            self._add_finding(
                'MEDIUM',
                'Authentication',
                'Password Encryption Disabled',
                'Service password-encryption is not configured',
                0, '',
                'Configure "service password-encryption"'
            )
    
    def _check_snmp(self):
        """Check SNMP security configuration"""
        snmp_found = False
        
        for i, line in enumerate(self.config_lines, 1):
            line_lower = line.lower().strip()
            
            if 'snmp-server community' in line_lower:
                snmp_found = True
                
                # Check for default community strings
                default_communities = ['public', 'private', 'cisco']
                for community in default_communities:
                    if community in line_lower:
                        self._add_finding(
                            'CRITICAL',
                            'SNMP',
                            'Default SNMP Community',
                            f'Default SNMP community string detected: {community}',
                            i, line,
                            'Change to a unique, complex community string'
                        )
                
                # Check for RW access
                if ' rw' in line_lower or 'write' in line_lower:
                    self._add_finding(
                        'HIGH',
                        'SNMP',
                        'SNMP Write Access Enabled',
                        'SNMP write access is configured',
                        i, line,
                        'Use read-only access unless write access is required'
                    )
                
                # Check if no ACL is applied
                if not re.search(r'\d+$', line.strip()):
                    self._add_finding(
                        'MEDIUM',
                        'SNMP',
                        'SNMP No Access Control',
                        'SNMP community has no access list restriction',
                        i, line,
                        'Apply an access list to restrict SNMP access'
                    )
            
            # Check for SNMPv1/v2 usage
            if 'snmp-server' in line_lower and 'version' in line_lower:
                if 'version 1' in line_lower or 'version 2c' in line_lower:
                    self._add_finding(
                        'HIGH',
                        'SNMP',
                        'Insecure SNMP Version',
                        'SNMPv1 or v2c is less secure than SNMPv3',
                        i, line,
                        'Upgrade to SNMPv3 with authentication and encryption'
                    )
    
    def _check_services(self):
        """Check for unnecessary or insecure services"""
        dangerous_services = {
            'ip http server': 'HTTP server enabled (unencrypted)',
            'service finger': 'Finger service enabled',
            'service tcp-small-servers': 'TCP small servers enabled',
            'service udp-small-servers': 'UDP small servers enabled',
            'service config': 'Config service enabled',
            'ip bootp server': 'BOOTP server enabled'
        }
        
        for i, line in enumerate(self.config_lines, 1):
            line_lower = line.lower().strip()
            
            for service, description in dangerous_services.items():
                if service in line_lower and not line_lower.startswith('no '):
                    severity = 'HIGH' if 'http server' in service else 'MEDIUM'
                    self._add_finding(
                        severity,
                        'Services',
                        'Unnecessary Service Enabled',
                        description,
                        i, line,
                        f'Disable with "no {service}" if not required'
                    )
            
            # Check for Telnet vs SSH
            if 'line vty' in line_lower:
                # Look ahead for transport input
                for j in range(i, min(i+10, len(self.config_lines))):
                    next_line = self.config_lines[j].lower().strip()
                    if 'transport input telnet' in next_line:
                        self._add_finding(
                            'HIGH',
                            'Services',
                            'Telnet Access Enabled',
                            'Telnet is unencrypted and insecure',
                            j+1, self.config_lines[j],
                            'Use "transport input ssh" instead of telnet'
                        )
                        break
    
    def _check_acls(self):
        """Check Access Control List security"""
        for i, line in enumerate(self.config_lines, 1):
            line_lower = line.lower().strip()
            
            # Check for overly permissive ACLs
            if 'access-list' in line_lower and 'permit' in line_lower:
                if 'any any' in line_lower:
                    self._add_finding(
                        'HIGH',
                        'Access Control',
                        'Overly Permissive ACL',
                        'ACL rule permits traffic from any source to any destination',
                        i, line,
                        'Restrict source and destination to specific networks'
                    )
            
            # Check for extended ACL best practices
            if re.search(r'access-list \d+ ', line_lower):
                acl_num = re.search(r'access-list (\d+)', line_lower).group(1)
                if int(acl_num) < 100:
                    self._add_finding(
                        'LOW',
                        'Access Control',
                        'Standard ACL Usage',
                        'Standard ACL in use - consider extended ACL for granular control',
                        i, line,
                        'Use extended ACLs (100-199) for better security control'
                    )
    
    def _check_interfaces(self):
        """Check interface security configuration"""
        current_interface = None
        interface_configs = {}
        
        for i, line in enumerate(self.config_lines, 1):
            line_stripped = line.strip()
            line_lower = line_stripped.lower()
            
            # Track current interface
            if line_lower.startswith('interface '):
                current_interface = line_stripped
                interface_configs[current_interface] = []
            elif current_interface and line_stripped.startswith(' '):
                interface_configs[current_interface].append((i, line_stripped))
        
        # Analyze each interface
        for interface, configs in interface_configs.items():
            is_shutdown = False
            has_description = False
            
            for line_num, config in configs:
                config_lower = config.lower()
                
                if 'shutdown' in config_lower:
                    is_shutdown = True
                if 'description' in config_lower:
                    has_description = True
                
                # Check for DTP auto mode
                if 'switchport mode dynamic auto' in config_lower:
                    self._add_finding(
                        'MEDIUM',
                        'Interface Security',
                        'DTP Auto Mode',
                        'Dynamic Trunking Protocol auto mode can be exploited',
                        line_num, config,
                        'Use "switchport mode access" or "switchport mode trunk"'
                    )
                
                # Check for CDP on external interfaces
                if 'cdp enable' in config_lower and 'external' in interface.lower():
                    self._add_finding(
                        'MEDIUM',
                        'Interface Security',
                        'CDP Enabled on External Interface',
                        'CDP can leak network topology information',
                        line_num, config,
                        'Disable CDP on external interfaces'
                    )
            
            # Check for unused interfaces without shutdown
            if not is_shutdown and not has_description and 'loopback' not in interface.lower():
                self._add_finding(
                    'LOW',
                    'Interface Security',
                    'Unused Interface Not Shutdown',
                    f'Interface {interface} appears unused but not shutdown',
                    0, interface,
                    'Shutdown unused interfaces or add description'
                )
    
    def _check_authentication(self):
        """Check authentication and authorization settings"""
        aaa_enabled = False
        
        for i, line in enumerate(self.config_lines, 1):
            line_lower = line.lower().strip()
            
            if 'aaa new-model' in line_lower:
                aaa_enabled = True
            
            # Check for local user accounts with privilege 15
            if line_lower.startswith('username ') and 'privilege 15' in line_lower:
                self._add_finding(
                    'MEDIUM',
                    'Authentication',
                    'High Privilege Local User',
                    'Local user account with full administrative privileges',
                    i, line,
                    'Use role-based access control and limit privileges'
                )
        
        if not aaa_enabled:
            self._add_finding(
                'MEDIUM',
                'Authentication',
                'AAA Not Configured',
                'Authentication, Authorization, and Accounting (AAA) is not enabled',
                0, '',
                'Configure "aaa new-model" for centralized authentication'
            )
    
    def _check_logging(self):
        """Check logging configuration"""
        logging_configured = False
        
        for i, line in enumerate(self.config_lines, 1):
            line_lower = line.lower().strip()
            
            if 'logging' in line_lower and not line_lower.startswith('no logging'):
                logging_configured = True
                break
        
        if not logging_configured:
            self._add_finding(
                'MEDIUM',
                'Logging',
                'Logging Not Configured',
                'System logging is not properly configured',
                0, '',
                'Configure logging to a secure syslog server'
            )
    
    def _check_banners(self):
        """Check for security banners"""
        has_login_banner = False
        has_motd_banner = False
        
        for i, line in enumerate(self.config_lines, 1):
            line_lower = line.lower().strip()
            
            if 'banner login' in line_lower:
                has_login_banner = True
            elif 'banner motd' in line_lower:
                has_motd_banner = True
        
        if not has_login_banner:
            self._add_finding(
                'LOW',
                'Configuration',
                'No Login Banner',
                'No login banner configured for legal protection',
                0, '',
                'Configure "banner login" with appropriate legal notice'
            )
        
        if not has_motd_banner:
            self._add_finding(
                'LOW',
                'Configuration',
                'No MOTD Banner',
                'No message of the day banner configured',
                0, '',
                'Configure "banner motd" with system information'
            )
    
    def _update_stats(self):
        """Update finding statistics"""
        self.stats = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'total_lines': len(self.config_lines)}
        
        for finding in self.findings:
            severity_key = finding.severity.lower()
            if severity_key in self.stats:
                self.stats[severity_key] += 1
    
    def generate_report(self, output_format='text') -> str:
        """Generate security report"""
        if output_format == 'text':
            return self._generate_text_report()
        elif output_format == 'json':
            return self._generate_json_report()
        else:
            return self._generate_text_report()
    
    def _generate_text_report(self) -> str:
        """Generate text-based security report"""
        report = []
        report.append("=" * 60)
        report.append("CISCO CONFIGURATION SECURITY SCAN REPORT")
        report.append("=" * 60)
        report.append(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Configuration Lines: {self.stats['total_lines']}")
        report.append(f"Total Findings: {len(self.findings)}")
        report.append("")
        
        # Executive Summary
        report.append("EXECUTIVE SUMMARY")
        report.append("-" * 20)
        report.append(f"Critical Issues: {self.stats['critical']}")
        report.append(f"High Risk Issues: {self.stats['high']}")
        report.append(f"Medium Risk Issues: {self.stats['medium']}")
        report.append(f"Low Risk Issues: {self.stats['low']}")
        report.append("")
        
        # Findings by severity
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            severity_findings = [f for f in self.findings if f.severity == severity]
            if severity_findings:
                report.append(f"{severity} FINDINGS")
                report.append("-" * 20)
                
                for i, finding in enumerate(severity_findings, 1):
                    report.append(f"{i}. {finding.title}")
                    report.append(f"   Category: {finding.category}")
                    report.append(f"   Description: {finding.description}")
                    if finding.line_number > 0:
                        report.append(f"   Line {finding.line_number}: {finding.config_line}")
                    report.append(f"   Recommendation: {finding.recommendation}")
                    if finding.cve_reference:
                        report.append(f"   CVE: {finding.cve_reference}")
                    report.append("")
        
        report.append("=" * 60)
        report.append("END OF REPORT")
        report.append("=" * 60)
        
        return "\n".join(report)
    
    def _generate_json_report(self) -> str:
        """Generate JSON-based security report"""
        report_data = {
            'scan_date': datetime.now().isoformat(),
            'statistics': self.stats,
            'findings': []
        }
        
        for finding in self.findings:
            report_data['findings'].append({
                'severity': finding.severity,
                'category': finding.category,
                'title': finding.title,
                'description': finding.description,
                'line_number': finding.line_number,
                'config_line': finding.config_line,
                'recommendation': finding.recommendation,
                'cve_reference': finding.cve_reference
            })
        
        return json.dumps(report_data, indent=2)

@click.command()
@click.argument('config_file', type=click.Path(exists=True))
@click.option('--format', 'output_format', 
              type=click.Choice(['text', 'json']), 
              default='text',
              help='Output format for the report')
@click.option('--output', '-o', 
              type=click.Path(), 
              help='Save report to file')
@click.option('--severity', 
              type=click.Choice(['all', 'critical', 'high', 'medium', 'low']), 
              default='all',
              help='Filter findings by severity level')
@click.option('--quiet', '-q', 
              is_flag=True, 
              help='Suppress console output except errors')
@click.version_option(version='1.1.0', prog_name='Cisco Security Scanner')
def main(config_file, output_format, output, severity, quiet):
    """
    Cisco Configuration Security Scanner
    
    Analyzes Cisco router and switch configurations for security vulnerabilities.
    
    Example usage:
        python cisco_scanner.py config.txt
        python cisco_scanner.py config.txt --format json --output report.json
        python cisco_scanner.py config.txt --severity critical
    """
    
    if not quiet:
        click.echo("🔍 Cisco Configuration Security Scanner v1.1.0")
        click.echo("=" * 50)
    
    # Initialize scanner
    scanner = CiscoConfigScanner()
    
    # Load and scan configuration
    if scanner.load_config(config_file):
        findings = scanner.scan_all()
        
        # Filter findings by severity
        if severity != 'all':
            findings = [f for f in findings if f.severity.lower() == severity.lower()]
        
        # Generate report
        report = scanner.generate_report(output_format)
        
        # Output report
        if output:
            with open(output, 'w') as f:
                f.write(report)
            if not quiet:
                click.echo(f"\n📄 Report saved to: {output}")
        else:
            if not quiet:
                click.echo("\n" + report)
        
        # Summary
        if not quiet:
            critical_count = scanner.stats['critical']
            high_count = scanner.stats['high']
            
            if critical_count > 0:
                click.echo(f"\n🚨 URGENT: {critical_count} critical security issues found!", err=True)
            elif high_count > 0:
                click.echo(f"\n⚠️  WARNING: {high_count} high-risk issues found!")
            else:
                click.echo(f"\n✅ Good: No critical security issues detected")
    
    else:
        click.echo("Failed to load configuration file", err=True)
        raise click.Abort()

if __name__ == "__main__":
    main()