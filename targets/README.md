# Target Configuration

This directory contains target configuration files for authorized security testing.

## Important Security Notice

⚠️ **ONLY TEST AUTHORIZED TARGETS** ⚠️

- Only include domains/targets you have explicit permission to test
- Follow bug bounty program rules and scope definitions
- Respect ethical hacking guidelines and legal boundaries

## File Formats

### authorized_domains.txt
```
example.com
*.example.com
api.example.com
```

### scope_config.yaml
```yaml
target: "example.com"
in_scope:
  - "*.example.com"
  - "api.example.com"
out_of_scope:
  - "admin.example.com"
program: "HackerOne"
```

## Usage

```bash
python3 quantumsentinel_orchestrator.py \
    --target example.com \
    --scope-file targets/authorized_domains.txt
```