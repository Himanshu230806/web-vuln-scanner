"""
PDF Report Generator
Generates professional PDF vulnerability reports
"""
import html
import logging
import os
from datetime import datetime
from typing import Dict, List

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, Image, ListFlowable, ListItem
)
from reportlab.lib.utils import ImageReader

from config import OUTPUT_DIR, REPORT_CONFIG

logger = logging.getLogger(__name__)


class PDFReportGenerator:
    """
    Professional PDF Report Generator
    """
    
    def __init__(self):
        self.company_name = REPORT_CONFIG['company_name']
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
        
    def _setup_custom_styles(self):
        """Setup custom paragraph styles"""
        # Custom Title
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1a1a2e'),
            spaceAfter=30,
            alignment=TA_CENTER,
        ))
        
        # Section Header
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#16213e'),
            spaceAfter=12,
            spaceBefore=12,
        ))
        
        # Vulnerability Title
        self.styles.add(ParagraphStyle(
            name='VulnTitle',
            parent=self.styles['Heading3'],
            fontSize=12,
            textColor=colors.HexColor('#e94560'),
        ))
        
        # Custom Body Text - use Normal as parent
        self.styles.add(ParagraphStyle(
            name='CustomBodyText',
            parent=self.styles['Normal'],
            fontSize=10,
            leading=14,
        ))
        
        # Custom Code style - use Normal as parent
        self.styles.add(ParagraphStyle(
            name='CustomCode',
            parent=self.styles['Normal'],
            fontSize=8,
            leading=10,
            backColor=colors.HexColor('#f5f5f5'),
            leftIndent=20,
            fontName='Courier',
        ))
    
    def generate_report(self, target: str, vulnerabilities: List[Dict], 
                       scan_stats: Dict, output_file: str = None) -> str:
        """
        Generate PDF vulnerability report
        """
        if output_file is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = OUTPUT_DIR / f"vulnerability_report_{timestamp}.pdf"
        
        doc = SimpleDocTemplate(
            str(output_file),
            pagesize=A4,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=18,
        )
        
        story = []
        
        # Cover Page
        self._add_cover_page(story, target, scan_stats)
        
        # Executive Summary
        self._add_executive_summary(story, vulnerabilities, scan_stats)
        
        # Findings Summary
        self._add_findings_summary(story, vulnerabilities)
        
        # Detailed Findings
        self._add_detailed_findings(story, vulnerabilities)
        
        # Recommendations
        self._add_recommendations(story, vulnerabilities)
        
        # Technical Details
        self._add_technical_details(story, vulnerabilities, scan_stats)
        
        # Build PDF
        doc.build(story)
        
        logger.info(f"PDF report generated: {output_file}")
        return str(output_file)
    
    def _add_cover_page(self, story, target: str, scan_stats: Dict):
        """Add cover page"""
        story.append(Spacer(1, 2*inch))
        
        # Title
        story.append(Paragraph(
            "VULNERABILITY ASSESSMENT REPORT",
            self.styles['CustomTitle']
        ))
        
        story.append(Spacer(1, 0.5*inch))
        
        # Subtitle
        story.append(Paragraph(
            f"<b>Target:</b> {target}",
            ParagraphStyle(
                name='Subtitle',
                parent=self.styles['Normal'],
                fontSize=14,
                alignment=TA_CENTER,
                spaceAfter=20,
            )
        ))
        
        # Company info
        story.append(Paragraph(
            f"Prepared by: {self.company_name}",
            ParagraphStyle(
                name='Company',
                parent=self.styles['Normal'],
                fontSize=12,
                alignment=TA_CENTER,
            )
        ))
        
        # Date
        story.append(Spacer(1, 0.3*inch))
        story.append(Paragraph(
            f"Date: {datetime.now().strftime('%B %d, %Y')}",
            ParagraphStyle(
                name='Date',
                parent=self.styles['Normal'],
                fontSize=12,
                alignment=TA_CENTER,
            )
        ))
        
        # Confidentiality notice
        story.append(Spacer(1, inch))
        story.append(Table(
            [[Paragraph(
                "<b>CONFIDENTIAL</b><br/>This document contains confidential "
                "and proprietary information. Unauthorized disclosure is prohibited.",
                ParagraphStyle(
                    name='Confidential',
                    parent=self.styles['Normal'],
                    fontSize=9,
                    alignment=TA_CENTER,
                    textColor=colors.red,
                )
            )]],
            colWidths=[6*inch],
            style=TableStyle([
                ('BOX', (0, 0), (-1, -1), 1, colors.red),
                ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#fff5f5')),
                ('PADDING', (0, 0), (-1, -1), 12),
            ])
        ))
        
        story.append(PageBreak())
    
    def _add_executive_summary(self, story, vulnerabilities: List[Dict], scan_stats: Dict):
        """Add executive summary section"""
        story.append(Paragraph("Executive Summary", self.styles['SectionHeader']))
        
        # Calculate severity counts
        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
        for vuln in vulnerabilities:
            sev = vuln.get('severity', 'Info')
            if sev in severity_counts:
                severity_counts[sev] += 1
        
        total = len(vulnerabilities)
        
        summary_text = f"""
        This report presents the findings of a web application security assessment 
        conducted on <b>{scan_stats.get('target', 'the target application')}</b>. 
        The assessment was performed using automated vulnerability scanning tools 
        and manual verification techniques.<br/><br/>
        
        <b>Scan Duration:</b> {scan_stats.get('duration', 'N/A')}<br/>
        <b>URLs Tested:</b> {scan_stats.get('urls_crawled', 0)}<br/>
        <b>Forms Tested:</b> {scan_stats.get('forms_tested', 0)}<br/>
        <b>Total Vulnerabilities:</b> {total}<br/><br/>
        
        The scan identified <b>{severity_counts['Critical']}</b> Critical, 
        <b>{severity_counts['High']}</b> High, <b>{severity_counts['Medium']}</b> Medium, 
        and <b>{severity_counts['Low']}</b> Low severity vulnerabilities.
        """
        
        story.append(Paragraph(summary_text, self.styles['CustomBodyText']))
        story.append(Spacer(1, 0.2*inch))
        
        # Risk rating
        if severity_counts['Critical'] > 0:
            risk_level = "CRITICAL"
            risk_color = colors.red
        elif severity_counts['High'] > 0:
            risk_level = "HIGH"
            risk_color = colors.orange
        elif severity_counts['Medium'] > 0:
            risk_level = "MEDIUM"
            risk_color = colors.yellow
        else:
            risk_level = "LOW"
            risk_color = colors.green
        
        story.append(Table(
            [[Paragraph(
                f"<b>OVERALL RISK RATING: {risk_level}</b>",
                ParagraphStyle(
                    name='RiskRating',
                    parent=self.styles['Normal'],
                    fontSize=14,
                    alignment=TA_CENTER,
                    textColor=risk_color,
                )
            )]],
            colWidths=[6*inch],
            style=TableStyle([
                ('BOX', (0, 0), (-1, -1), 2, risk_color),
                ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#fff9f9')),
                ('PADDING', (0, 0), (-1, -1), 15),
            ])
        ))
        
        story.append(PageBreak())
    
    def _add_findings_summary(self, story, vulnerabilities: List[Dict]):
        """Add findings summary table"""
        story.append(Paragraph("Findings Summary", self.styles['SectionHeader']))
        
        # Group by type
        vuln_by_type = {}
        for vuln in vulnerabilities:
            vtype = vuln.get('type', 'Unknown')
            if vtype not in vuln_by_type:
                vuln_by_type[vtype] = []
            vuln_by_type[vtype].append(vuln)
        
        # Create table data
        table_data = [['Vulnerability Type', 'Severity', 'Count', 'Status']]
        
        for vtype, vulns in sorted(vuln_by_type.items()):
            severity = vulns[0].get('severity', 'Info')
            count = len(vulns)
            
            # Color code severity
            severity_colors = {
                'Critical': colors.red,
                'High': colors.orange,
                'Medium': colors.yellow,
                'Low': colors.green,
                'Info': colors.blue,
            }
            sev_color = severity_colors.get(severity, colors.black)
            
            table_data.append([
                vtype,
                Paragraph(f"<font color='{sev_color.hexval()}'>{severity}</font>"),
                str(count),
                'Open'
            ])
        
        if len(table_data) == 1:
            table_data.append(['No vulnerabilities found', '-', '0', '-'])
        
        # Create table
        table = Table(table_data, colWidths=[2.5*inch, 1*inch, 1*inch, 1.5*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#16213e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        
        story.append(table)
        story.append(PageBreak())
        
    
    def _add_detailed_findings(self, story, vulnerabilities: List[Dict]):
        """Add detailed vulnerability findings"""
        story.append(Paragraph("Detailed Findings", self.styles['SectionHeader']))
        
        # Sort by severity
        severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Info': 4}
        sorted_vulns = sorted(
            vulnerabilities,
            key=lambda x: severity_order.get(x.get('severity', 'Info'), 5)
        )
        
        for i, vuln in enumerate(sorted_vulns, 1):
            # Vulnerability header
            severity = vuln.get('severity', 'Info')
            vuln_type = vuln.get('type', 'Unknown')
            
            severity_colors = {
                'Critical': colors.red,
                'High': colors.orange,
                'Medium': colors.yellow,
                'Low': colors.green,
                'Info': colors.blue,
            }
            
            story.append(Paragraph(
                f"{i}. {vuln_type}",
                self.styles['VulnTitle']
            ))
            
            # Severity badge
            story.append(Paragraph(
                f"<b>Severity:</b> <font color='{severity_colors.get(severity, colors.black).hexval()}'>{severity}</font>",
                self.styles['CustomBodyText']
            ))
            
            # Details
            story.append(Paragraph(
                f"<b>URL:</b> {vuln.get('url', 'N/A')}",
                self.styles['CustomBodyText']
            ))
            
            if vuln.get('parameter'):
                story.append(Paragraph(
                    f"<b>Parameter:</b> {vuln['parameter']}",
                    self.styles['CustomBodyText']
                ))
            
            description = html.escape(vuln.get('description', 'No description available.'))
            story.append(Paragraph(
                f"<b>Description:</b> {description}",
                self.styles['CustomBodyText']
            ))
            
            if vuln.get('details'):
                # Escape HTML to prevent parsing errors
                details_str = html.escape(str(vuln['details']))
                story.append(Paragraph(
                    f"<b>Details:</b> {details_str}",
                    self.styles['CustomBodyText']
                ))
            
            if vuln.get('evidence'):
                story.append(Paragraph("<b>Evidence:</b>", self.styles['CustomBodyText']))
                # Escape HTML in evidence
                evidence_str = html.escape(vuln['evidence'])
                story.append(Paragraph(
                    evidence_str,
                    self.styles['CustomCode']
                ))
            
            if vuln.get('solution'):
                story.append(Paragraph(
                    f"<b>Remediation:</b> {vuln['solution']}",
                    self.styles['CustomBodyText']
                ))
            
            if vuln.get('reference'):
                story.append(Paragraph(
                    f"<b>References:</b> {vuln['reference']}",
                    self.styles['CustomBodyText']
                ))
            
            story.append(Spacer(1, 0.2*inch))
        
        if not vulnerabilities:
            story.append(Paragraph(
                "No vulnerabilities were detected during this scan.",
                self.styles['CustomBodyText']
            ))
        
        story.append(PageBreak())
    
    def _add_recommendations(self, story, vulnerabilities: List[Dict]):
        """Add recommendations section"""
        story.append(Paragraph("Recommendations", self.styles['SectionHeader']))
        
        # Group recommendations by category
        recommendations = {
            'Input Validation': [],
            'Authentication': [],
            'Session Management': [],
            'Access Control': [],
            'Cryptography': [],
            'Configuration': [],
        }
        
        for vuln in vulnerabilities:
            vtype = vuln.get('type', '')
            
            if 'SQL' in vtype or 'XSS' in vtype or 'Injection' in vtype:
                recommendations['Input Validation'].append(vuln)
            elif 'CSRF' in vtype:
                recommendations['Session Management'].append(vuln)
            elif 'Redirect' in vtype:
                recommendations['Access Control'].append(vuln)
        
        # Add prioritized recommendations
        story.append(Paragraph("Priority Actions:", self.styles['Heading4']))
        
        priority_actions = []
        if any(v.get('severity') == 'Critical' for v in vulnerabilities):
            priority_actions.append(
                "1. Immediately address Critical severity vulnerabilities "
                "as they pose significant security risks."
            )
        if any(v.get('type') == 'SQL Injection' for v in vulnerabilities):
            priority_actions.append(
                "2. Implement parameterized queries and prepared statements "
                "to prevent SQL injection attacks."
            )
        if any(v.get('type') == 'Cross-Site Scripting (XSS)' for v in vulnerabilities):
            priority_actions.append(
                "3. Implement proper output encoding and Content Security Policy "
                "to mitigate XSS vulnerabilities."
            )
        
        for action in priority_actions:
            story.append(Paragraph(action, self.styles['CustomBodyText']))
            story.append(Spacer(1, 0.1*inch))
        
        story.append(PageBreak())
    
    def _add_technical_details(self, story, vulnerabilities: List[Dict], scan_stats: Dict):
        """Add technical details and methodology"""
        story.append(Paragraph("Technical Details", self.styles['SectionHeader']))
        
        story.append(Paragraph("Scan Methodology", self.styles['Heading4']))
        
        methodology = """
        This assessment employed a combination of automated scanning tools and 
        manual verification techniques. The following methodology was used:<br/><br/>
        
        <b>1. Reconnaissance:</b> Initial discovery of application structure 
        and entry points.<br/><br/>
        
        <b>2. Automated Scanning:</b> Using custom-built scanners and OWASP ZAP 
        to identify potential vulnerabilities.<br/><br/>
        
        <b>3. Manual Verification:</b> Confirmed findings through manual testing 
        to eliminate false positives.<br/><br/>
        
        <b>4. Reporting:</b> Documentation of findings with remediation guidance.
        """
        
        story.append(Paragraph(methodology, self.styles['CustomBodyText']))
        story.append(Spacer(1, 0.2*inch))
        
        story.append(Paragraph("Tools Used", self.styles['Heading4']))
        tools = [
            "• Custom Python-based Vulnerability Scanner",
            "• OWASP ZAP (Zed Attack Proxy)",
            "• Selenium WebDriver for dynamic content",
            "• BeautifulSoup for HTML parsing",
        ]
        for tool in tools:
            story.append(Paragraph(tool, self.styles['CustomBodyText']))
        
        story.append(Spacer(1, 0.2*inch))
        
        story.append(Paragraph("Scan Statistics", self.styles['Heading4']))
        stats = f"""
        <b>Scan Start:</b> {scan_stats.get('start_time', 'N/A')}<br/>
        <b>Scan End:</b> {scan_stats.get('end_time', 'N/A')}<br/>
        <b>URLs Crawled:</b> {scan_stats.get('urls_crawled', 0)}<br/>
        <b>Forms Tested:</b> {scan_stats.get('forms_tested', 0)}<br/>
        <b>Parameters Tested:</b> {scan_stats.get('parameters_tested', 0)}<br/>
        """
        story.append(Paragraph(stats, self.styles['CustomBodyText']))
