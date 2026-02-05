"""Report Generator Tool"""
import json
import os
from datetime import datetime
from utils.logger import Logger

try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
except ImportError:
    SimpleDocTemplate = None

class ReportGenerator:
    """Generate professional security scan reports"""
    
    def __init__(self):
        self.report_dir = "reports"
        if not os.path.exists(self.report_dir):
            os.makedirs(self.report_dir)
            Logger.info(f"Created reports directory: {self.report_dir}")
    
    def generate_pdf_report(self, scan_results, report_title="Security Scan Report"):
        """Generate PDF report from scan results"""
        if SimpleDocTemplate is None:
            return {"error": "reportlab not installed. Install with: pip install reportlab"}
        
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"report_{timestamp}.pdf"
            filepath = os.path.join(self.report_dir, filename)
            
            # Create PDF document
            doc = SimpleDocTemplate(filepath, pagesize=letter,
                                   rightMargin=72, leftMargin=72,
                                   topMargin=72, bottomMargin=18)
            
            # Container for PDF elements
            elements = []
            styles = getSampleStyleSheet()
            
            # Title
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=24,
                textColor=colors.HexColor('#1f4788'),
                spaceAfter=30,
                alignment=1
            )
            elements.append(Paragraph(report_title, title_style))
            elements.append(Spacer(1, 0.3*inch))
            
            # Metadata
            meta_data = [
                ["Report Generated:", datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
                ["Scan Type:", scan_results.get("scan_type", "Unknown")],
                ["Target:", scan_results.get("target", "Unknown")]
            ]
            
            meta_table = Table(meta_data, colWidths=[2*inch, 4*inch])
            meta_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#e6f2ff')),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                ('GRID', (0, 0), (-1, -1), 1, colors.grey)
            ]))
            
            elements.append(meta_table)
            elements.append(Spacer(1, 0.3*inch))
            
            # Results section
            if scan_results.get("results"):
                elements.append(Paragraph("Scan Results", styles['Heading2']))
                elements.append(Spacer(1, 0.2*inch))
                
                results_data = self._format_results_for_table(scan_results["results"])
                results_table = Table(results_data, colWidths=[2*inch, 4*inch])
                results_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1f4788')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                    ('GRID', (0, 0), (-1, -1), 1, colors.grey),
                    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f0f0f0')])
                ]))
                
                elements.append(results_table)
            
            # Build PDF
            doc.build(elements)
            Logger.info(f"PDF report generated: {filepath}")
            
            return {
                "success": True,
                "filepath": filepath,
                "filename": filename,
                "size": os.path.getsize(filepath)
            }
            
        except Exception as e:
            Logger.error(f"PDF generation error: {str(e)}")
            return {"error": str(e)}
    
    def generate_html_report(self, scan_results, report_title="Security Scan Report"):
        """Generate HTML report from scan results"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"report_{timestamp}.html"
            filepath = os.path.join(self.report_dir, filename)
            
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title>{report_title}</title>
                <style>
                    body {{
                        font-family: Arial, sans-serif;
                        margin: 40px;
                        background-color: #f5f5f5;
                    }}
                    .header {{
                        background-color: #1f4788;
                        color: white;
                        padding: 20px;
                        border-radius: 5px;
                        margin-bottom: 30px;
                    }}
                    .header h1 {{
                        margin: 0;
                        font-size: 28px;
                    }}
                    .metadata {{
                        background-color: white;
                        padding: 15px;
                        border-left: 4px solid #1f4788;
                        margin-bottom: 20px;
                        border-radius: 3px;
                    }}
                    .metadata p {{
                        margin: 8px 0;
                    }}
                    .metadata strong {{
                        color: #1f4788;
                    }}
                    table {{
                        width: 100%;
                        border-collapse: collapse;
                        background-color: white;
                        margin-top: 20px;
                        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                    }}
                    table th {{
                        background-color: #1f4788;
                        color: white;
                        padding: 12px;
                        text-align: left;
                        font-weight: bold;
                    }}
                    table td {{
                        padding: 12px;
                        border-bottom: 1px solid #ddd;
                    }}
                    table tr:nth-child(even) {{
                        background-color: #f9f9f9;
                    }}
                    .footer {{
                        margin-top: 40px;
                        text-align: center;
                        color: #666;
                        font-size: 12px;
                    }}
                    .section {{
                        margin-top: 30px;
                    }}
                    .section h2 {{
                        color: #1f4788;
                        border-bottom: 2px solid #1f4788;
                        padding-bottom: 10px;
                    }}
                </style>
            </head>
            <body>
                <div class="header">
                    <h1>{report_title}</h1>
                </div>
                
                <div class="metadata">
                    <p><strong>Report Generated:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
                    <p><strong>Scan Type:</strong> {scan_results.get("scan_type", "Unknown")}</p>
                    <p><strong>Target:</strong> {scan_results.get("target", "Unknown")}</p>
                </div>
            """
            
            if scan_results.get("results"):
                html_content += self._format_results_for_html(scan_results["results"])
            
            html_content += """
                <div class="footer">
                    <p>This report was automatically generated by Hackers Toolkit</p>
                </div>
            </body>
            </html>
            """
            
            with open(filepath, 'w') as f:
                f.write(html_content)
            
            Logger.info(f"HTML report generated: {filepath}")
            
            return {
                "success": True,
                "filepath": filepath,
                "filename": filename,
                "size": os.path.getsize(filepath)
            }
            
        except Exception as e:
            Logger.error(f"HTML generation error: {str(e)}")
            return {"error": str(e)}
    
    def generate_json_report(self, scan_results):
        """Generate JSON report from scan results"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"report_{timestamp}.json"
            filepath = os.path.join(self.report_dir, filename)
            
            report_data = {
                "generated": datetime.now().isoformat(),
                "scan_results": scan_results
            }
            
            with open(filepath, 'w') as f:
                json.dump(report_data, f, indent=2, default=str)
            
            Logger.info(f"JSON report generated: {filepath}")
            
            return {
                "success": True,
                "filepath": filepath,
                "filename": filename,
                "size": os.path.getsize(filepath)
            }
            
        except Exception as e:
            Logger.error(f"JSON generation error: {str(e)}")
            return {"error": str(e)}
    
    def _format_results_for_table(self, results):
        """Format results for PDF table"""
        data = [["Field", "Value"]]
        
        if isinstance(results, dict):
            for key, value in results.items():
                if not isinstance(value, (dict, list)):
                    data.append([str(key), str(value)[:50]])
        
        return data
    
    def _format_results_for_html(self, results):
        """Format results for HTML table"""
        html = '<div class="section"><h2>Scan Results</h2><table>'
        html += '<tr><th>Field</th><th>Value</th></tr>'
        
        if isinstance(results, dict):
            for key, value in results.items():
                if not isinstance(value, (dict, list)):
                    html += f'<tr><td>{key}</td><td>{str(value)[:100]}</td></tr>'
        
        html += '</table></div>'
        return html
    
    def list_reports(self):
        """List all generated reports"""
        try:
            reports = []
            if os.path.exists(self.report_dir):
                for filename in os.listdir(self.report_dir):
                    filepath = os.path.join(self.report_dir, filename)
                    reports.append({
                        "filename": filename,
                        "size": os.path.getsize(filepath),
                        "created": datetime.fromtimestamp(os.path.getctime(filepath)).isoformat()
                    })
            
            return {"reports": reports, "count": len(reports)}
        except Exception as e:
            Logger.error(f"List reports error: {str(e)}")
            return {"error": str(e)}
