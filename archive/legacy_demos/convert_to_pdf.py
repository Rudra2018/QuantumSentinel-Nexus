#!/usr/bin/env python3
"""
Convert HTML Report to Professional PDF
Using WeasyPrint for high-quality PDF generation
"""

import sys
import weasyprint
from pathlib import Path

def convert_html_to_pdf(html_file_path):
    """Convert HTML report to PDF"""
    html_path = Path(html_file_path)

    if not html_path.exists():
        print(f"❌ HTML file not found: {html_file_path}")
        return None

    # Generate PDF path
    pdf_path = html_path.with_suffix('.pdf')

    try:
        print(f"🔄 Converting HTML to PDF...")
        print(f"📄 Input:  {html_path}")
        print(f"📄 Output: {pdf_path}")

        # Convert HTML to PDF
        weasyprint.HTML(filename=str(html_path)).write_pdf(str(pdf_path))

        print(f"✅ PDF report generated successfully!")
        return str(pdf_path)

    except Exception as e:
        print(f"❌ PDF conversion failed: {e}")
        return None

if __name__ == "__main__":
    # Find the most recent HTML report
    assessments_dir = Path("assessments")

    if not assessments_dir.exists():
        print("❌ No assessments directory found")
        sys.exit(1)

    # Find latest Red Bull assessment
    redbull_dirs = sorted([d for d in assessments_dir.glob("redbull_*") if d.is_dir()], reverse=True)

    if not redbull_dirs:
        print("❌ No Red Bull assessment directories found")
        sys.exit(1)

    latest_dir = redbull_dirs[0]
    html_files = list(latest_dir.glob("reports/*.html"))

    if not html_files:
        print(f"❌ No HTML reports found in {latest_dir}")
        sys.exit(1)

    html_file = html_files[0]
    pdf_path = convert_html_to_pdf(html_file)

    if pdf_path:
        print(f"\n🏆 RED BULL SECURITY ASSESSMENT - PDF REPORT READY")
        print(f"📄 PDF Report: {pdf_path}")
        print(f"📊 Report Size: {Path(pdf_path).stat().st_size // 1024}KB")
        print(f"🎯 Status: Ready for Intigriti submission")
    else:
        sys.exit(1)