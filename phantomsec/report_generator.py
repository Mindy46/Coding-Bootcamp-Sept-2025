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
            self