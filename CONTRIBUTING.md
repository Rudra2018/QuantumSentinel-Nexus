# Contributing to QuantumSentinel-Nexus

Thank you for your interest in contributing to QuantumSentinel-Nexus! This document provides guidelines and information for contributors.

## 🤝 Code of Conduct

By participating in this project, you agree to abide by our code of conduct:

- **Respect**: Treat all community members with respect and courtesy
- **Collaboration**: Work together constructively and professionally
- **Security Focus**: Prioritize security and ethical practices
- **Quality**: Maintain high standards for code quality and documentation

## 🛡️ Security Guidelines

### Ethical Standards
- Only contribute features that support authorized security testing
- Do not include exploits or tools designed for malicious use
- Follow responsible disclosure practices
- Respect bug bounty program rules and scope

### Security Review
- All contributions undergo security review
- Sensitive code patterns are flagged during review
- Contributors must explain the purpose of security-related code

## 🚀 Getting Started

### Development Setup

1. **Fork and Clone**
   ```bash
   git clone https://github.com/yourusername/QuantumSentinel-Nexus.git
   cd QuantumSentinel-Nexus
   ```

2. **Docker Development Environment**
   ```bash
   # Build development image
   docker build -t quantumsentinel/nexus:dev .

   # Run development container
   docker run -it --rm \
     -v $(pwd):/app \
     --cap-add=NET_ADMIN \
     quantumsentinel/nexus:dev
   ```

## 📞 Getting Help

### Communication Channels

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: General questions and community discussions
- **Email**: security@quantumsentinel.com for security-related concerns

---

**Thank you for contributing to QuantumSentinel-Nexus!**

Your efforts help make mobile security testing more effective and accessible to the security community.