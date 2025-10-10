"""
Generates readable security reports from threat analysis results
Outputs to text files (could add HTML/PDF later if needed)
Dependencies: Only standard library (datetime, typing)
"""

from datetime import datetime
from typing import List, Dict


class ReportGenerator:
    """
    Creates formatted security reports
    """
    
    def __init__(self, output_file: str):
        """
        Initialize report generator
        
        Args:
            output_file: Path where report will be saved
        """
        self.output_file = output_file
        self.report_lines = []
    
    def generate_report(self, threats: Dict, log_entries: List[Dict]):
        """
        Main report generation function
        
        Args:
            threats: Dictionary of detected threats
            log_entries: Original log entries for context
        """
        self.report_lines = []
        
        # Header
        self._add_header()
        
        # Executive summary
        self._add_summary(threats, log_entries)
        
        # Detailed findings
        self._add_section("DETAILED FINDINGS")
        
        if threats['critical']:
            self._add_critical_threats(threats['critical'])
        
        if threats['brute_force']:
            self._add_brute_force_section(threats['brute_force'])
        
        if threats['suspicious_ips']:
            self._add_suspicious_ips_section(threats['suspicious_ips'])
        
        if threats['port_scans']:
            self._add_port_scans_section(threats['port_scans'])
        
        if threats['injections']:
            self._add_injections_section(threats['injections'])
        
        # Recommendations
        self._add_recommendations(threats)
        
        # Footer
        self._add_footer()
        
        # Write to file
        self._write_report()
    
    def _add_header(self):
        """Add report header"""
        self.report_lines.append("="*80)
        self.report_lines.append(" " * 20 + "SECURITY LOG ANALYSIS REPORT")
        self.report_lines.append(" " * 25 + f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        self.report_lines.append("="*80)
        self.report_lines.append("")
    
    def _add_section(self, title: str):
        """Add a major section header"""
        self.report_lines.append("")
        self.report_lines.append("-" * 80)
        self.report_lines.append(title)
        self.report_lines.append("-" * 80)
        self.report_lines.append("")
    
    def _add_subsection(self, title: str):
        """Add a subsection header"""
        self.report_lines.append("")
        self.report_lines.append(title)
        self.report_lines.append("-" * len(title))
        self.report_lines.append("")
    
    def _add_summary(self, threats: Dict, log_entries: List[Dict]):
        """Add executive summary section"""
        self._add_section("EXECUTIVE SUMMARY")
        
        total_threats = (len(threats['brute_force']) + 
                        len(threats['suspicious_ips']) + 
                        len(threats['port_scans']) + 
                        len(threats['injections']))
        
        self.report_lines.append(f"Total log entries analyzed: {len(log_entries)}")
        self.report_lines.append(f"Total threats detected: {total_threats}")
        self.report_lines.append(f"Critical threats: {len(threats['critical'])}")
        self.report_lines.append("")
        
        # Breakdown
        self.report_lines.append("Threat Breakdown:")
        self.report_lines.append(f"  - Brute force attempts: {len(threats['brute_force'])}")
        self.report_lines.append(f"  - Suspicious IP behavior: {len(threats['suspicious_ips'])}")
        self.report_lines.append(f"  - Port scan attempts: {len(threats['port_scans'])}")
        self.report_lines.append(f"  - Injection attempts: {len(threats['injections'])}")
        self.report_lines.append("")
        
        # Risk level
        if threats['critical']:
            risk_level = "HIGH - Critical threats detected!"
        elif total_threats > 10:
            risk_level = "MEDIUM - Multiple threats detected"
        elif total_threats > 0:
            risk_level = "LOW - Some suspicious activity"
        else:
            risk_level = "MINIMAL - No significant threats"
        
        self.report_lines.append(f"Overall Risk Level: {risk_level}")
        self.report_lines.append("")
    
    def _add_critical_threats(self, critical_threats: List[Dict]):
        """Add critical threats section - these need immediate attention"""
        self._add_subsection("CRITICAL THREATS (Immediate Action Required)")
        
        if not critical_threats:
            self.report_lines.append("None detected.")
            self.report_lines.append("")
            return
        
        for i, threat in enumerate(critical_threats, 1):
            self.report_lines.append(f"{i}. IP Address: {threat['ip']}")
            self.report_lines.append(f"   Threat Types: {', '.join(threat['threat_types'])}")
            self.report_lines.append(f"   Number of threat categories: {threat['threat_count']}")
            self.report_lines.append(f"   Severity: {threat['severity'].upper()}")
            self.report_lines.append(f"   Recommendation: Block this IP immediately and investigate further")
            self.report_lines.append("")
    
    def _add_brute_force_section(self, brute_force_attacks: List[Dict]):
        """Add brute force attacks section"""
        self._add_subsection("BRUTE FORCE ATTACKS")
        
        if not brute_force_attacks:
            self.report_lines.append("None detected.")
            self.report_lines.append("")
            return
        
        for i, attack in enumerate(brute_force_attacks, 1):
            self.report_lines.append(f"{i}. IP Address: {attack.get('ip', 'Unknown')}")
            self.report_lines.append(f"   Failed login attempts: {attack.get('failed_attempts', attack.get('count', 'N/A'))}")
            self.report_lines.append(f"   Time window: {attack.get('time_window', 'N/A')}")
            usernames = attack.get('usernames', attack.get('username', ['Unknown']))
            if isinstance(usernames, str):
                usernames = [usernames]
            self.report_lines.append(f"   Targeted accounts: {', '.join(usernames)}")
            self.report_lines.append("")
    
    def _add_suspicious_ips_section(self, suspicious_ips: List[Dict]):
        """Add suspicious IP behavior section"""
        self._add_subsection("SUSPICIOUS IP BEHAVIOR")
        
        if not suspicious_ips:
            self.report_lines.append("None detected.")
            self.report_lines.append("")
            return
        
        for i, ip_data in enumerate(suspicious_ips, 1):
            self.report_lines.append(f"{i}. IP Address: {ip_data.get('ip', 'Unknown')}")
            self.report_lines.append(f"   Total requests: {ip_data.get('request_count', ip_data.get('count', 'N/A'))}")
            patterns = ip_data.get('patterns', ['Multiple requests'])
            if isinstance(patterns, str):
                patterns = [patterns]
            self.report_lines.append(f"   Suspicious patterns: {', '.join(patterns)}")
            self.report_lines.append(f"   Risk level: {ip_data.get('risk_level', 'Medium')}")
            self.report_lines.append("")
    
    def _add_port_scans_section(self, port_scans: List[Dict]):
        """Add port scanning attempts section"""
        self._add_subsection("PORT SCANNING ATTEMPTS")
        
        if not port_scans:
            self.report_lines.append("None detected.")
            self.report_lines.append("")
            return
        
        for i, scan in enumerate(port_scans, 1):
            self.report_lines.append(f"{i}. IP Address: {scan.get('ip', 'Unknown')}")
            self.report_lines.append(f"   Ports targeted: {scan.get('port_count', scan.get('count', 'N/A'))} different ports")
            self.report_lines.append(f"   Scan type: {scan.get('scan_type', 'Sequential scan')}")
            self.report_lines.append(f"   Time span: {scan.get('time_span', 'N/A')}")
            self.report_lines.append("")
    
    def _add_injections_section(self, injections: List[Dict]):
        """Add injection attempt section"""
        self._add_subsection("INJECTION ATTEMPTS")
        
        if not injections:
            self.report_lines.append("None detected.")
            self.report_lines.append("")
            return
        
        for i, injection in enumerate(injections, 1):
            self.report_lines.append(f"{i}. IP Address: {injection.get('ip', 'Unknown')}")
            self.report_lines.append(f"   Injection type: {injection.get('type', 'Unknown')}")
            self.report_lines.append(f"   Attack vector: {injection.get('vector', 'Unknown')}")
            payload = injection.get('payload', 'N/A')
            if payload != 'N/A' and len(payload) > 100:
                payload = payload[:100] + "..."
            self.report_lines.append(f"   Payload sample: {payload}")
            self.report_lines.append("")
    
    def _add_recommendations(self, threats: Dict):
        """Add security recommendations based on findings"""
        self._add_section("RECOMMENDATIONS")
        
        recommendations = []
        
        if threats['critical']:
            recommendations.append("1. IMMEDIATE: Block all critical threat IPs at firewall level")
            recommendations.append("2. IMMEDIATE: Review and patch any vulnerabilities being exploited")
        
        if threats['brute_force']:
            recommendations.append(f"{len(recommendations)+1}. Implement rate limiting on authentication endpoints")
            recommendations.append(f"{len(recommendations)+1}. Enable account lockout after failed attempts")
            recommendations.append(f"{len(recommendations)+1}. Consider implementing CAPTCHA or MFA")
        
        if threats['port_scans']:
            recommendations.append(f"{len(recommendations)+1}. Review firewall rules to minimize exposed ports")
            recommendations.append(f"{len(recommendations)+1}. Implement port scan detection at network level")
        
        if threats['injections']:
            recommendations.append(f"{len(recommendations)+1}. Review and strengthen input validation")
            recommendations.append(f"{len(recommendations)+1}. Implement parameterized queries/prepared statements")
            recommendations.append(f"{len(recommendations)+1}. Deploy Web Application Firewall (WAF)")
        
        if threats['suspicious_ips']:
            recommendations.append(f"{len(recommendations)+1}. Monitor suspicious IPs closely")
            recommendations.append(f"{len(recommendations)+1}. Consider implementing IP reputation checking")
        
        if not recommendations:
            recommendations.append("No specific threats detected. Continue monitoring.")
            recommendations.append("Maintain regular security audits and log reviews.")
        
        for rec in recommendations:
            self.report_lines.append(rec)
        
        self.report_lines.append("")
    
    def _add_footer(self):
        """Add report footer"""
        self.report_lines.append("")
        self.report_lines.append("="*80)
        self.report_lines.append(" " * 30 + "END OF REPORT")
        self.report_lines.append("="*80)
    
    def _write_report(self):
        """Write the report to file"""
        try:
            with open(self.output_file, 'w') as f:
                f.write('\n'.join(self.report_lines))
            print(f"Report successfully generated: {self.output_file}")
        except Exception as e:
            print(f"Error writing report: {e}")
            raise