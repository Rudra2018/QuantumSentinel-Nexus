# Report Templates

This directory contains HTML templates for generating professional security assessment reports.

## Files

- `comprehensive_report.html` - Main report template (auto-generated)
- Custom templates can be added here for specialized reporting needs

## Usage

Templates use Jinja2 templating engine with the following data structure:

```python
report_data = {
    'target': 'example.com',
    'assessment_id': 'assessment_123',
    'findings': [...],
    'charts': {...},
    'executive_summary': {...}
}
```