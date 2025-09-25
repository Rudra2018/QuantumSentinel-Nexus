# Wordlists Directory

This directory contains wordlists for security testing tools.

## External Wordlists

For comprehensive testing, download external wordlists:

### SecLists (Recommended)
```bash
git clone https://github.com/danielmiessler/SecLists.git
```

### Common Wordlists
- `common.txt` - Common directories and files
- `parameters.txt` - Common HTTP parameters
- `subdomains.txt` - Common subdomain names

## Docker Integration

The Docker image automatically downloads SecLists during build.

## Usage

Tools will automatically use appropriate wordlists:
- Dirsearch: Uses SecLists web content wordlists
- FFUF: Uses parameter discovery wordlists
- Subfinder: Uses built-in subdomain wordlists