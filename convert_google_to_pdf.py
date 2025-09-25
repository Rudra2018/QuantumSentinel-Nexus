#!/usr/bin/env python3
"""
Convert Google OSS HTML Report to Professional PDF
"""

import sys
import weasyprint
from pathlib import Path

def convert_google_html_to_pdf():
    """Convert Google OSS HTML report to PDF"""

    # Find the most recent Google OSS assessment
    assessments_dir = Path("assessments")

    if not assessments_dir.exists():
        print("❌ No assessments directory found")
        return None

    # Find latest Google OSS assessment
    google_dirs = sorted([d for d in assessments_dir.glob("google_oss_*") if d.is_dir()], reverse=True)

    if not google_dirs:
        print("❌ No Google OSS assessment directories found")
        return None

    latest_dir = google_dirs[0]
    html_files = list(latest_dir.glob("reports/*.html"))

    if not html_files:
        print(f"❌ No HTML reports found in {latest_dir}")
        return None

    html_file = html_files[0]
    pdf_path = html_file.with_suffix('.pdf')

    try:
        print(f"🔄 Converting Google OSS HTML to PDF...")
        print(f"📄 Input:  {html_file}")
        print(f"📄 Output: {pdf_path}")

        # Convert HTML to PDF
        weasyprint.HTML(filename=str(html_file)).write_pdf(str(pdf_path))

        print(f"✅ PDF report generated successfully!")
        return str(pdf_path)

    except Exception as e:
        print(f"❌ PDF conversion failed: {e}")
        return None

if __name__ == "__main__":
    pdf_path = convert_google_html_to_pdf()

    if pdf_path:
        print(f"\n🏆 GOOGLE BUG HUNTERS OPEN SOURCE SECURITY - PDF REPORT READY")
        print(f"📄 PDF Report: {pdf_path}")
        print(f"📊 Report Size: {Path(pdf_path).stat().st_size // 1024}KB")
        print(f"🎯 Program: Google Bug Hunters Open Source Security")
        print(f"💰 Reward Range: $100 - $31,337")
        print(f"🚀 Status: Ready for Google Bug Hunters submission")
    else:
        sys.exit(1)