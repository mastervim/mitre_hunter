# Security Policy

## Overview

MitreHunter is designed with security in mind. This document outlines our security practices and how to report vulnerabilities.

## Security Features

### 1. Dependency Management
- **Pinned Versions**: All dependencies are pinned to exact versions in `requirements.txt` to prevent supply chain attacks
- **Regular Updates**: Dependencies should be reviewed and updated monthly
- **Vulnerability Scanning**: Run `pip install safety && safety check` to scan for known vulnerabilities

### 2. DoS Protection
- **Result Limiting**: Query results are automatically limited to 1,000 techniques to prevent memory exhaustion
- **Configurable Limits**: Users can adjust `MAX_RESULTS` in `src/query.py` if needed

### 3. Data Integrity
- **SHA256 Verification**: Downloaded MITRE data is verified using SHA256 hashing
- **Size Validation**: Files are checked for suspicious sizes that may indicate corruption
- **HTTPS Only**: All data is fetched over HTTPS from official MITRE repositories

### 4. Input Sanitization
- **No Code Execution**: User input is never passed to `eval()`, `exec()`, or similar functions
- **String Matching Only**: Searches use simple string matching (`.lower()` and `in` operators)
- **No Regex Injection**: Regular expressions are not used on user input

## Deployment Security

### For Local Use
1. Install in a virtual environment: `python -m venv venv`
2. Verify dependencies: `safety check`
3. Keep Python updated to the latest patch version

### For Web Deployment
1. **Use HTTPS**: Always deploy behind HTTPS (use Streamlit Cloud or reverse proxy)
2. **Enable CORS Protection**: Configure Streamlit's CORS settings
3. **Rate Limiting**: Consider adding rate limiting for public deployments
4. **Monitoring**: Monitor logs for suspicious query patterns

### For Enterprise Use
1. **Internal Mirror**: Consider mirroring MITRE data internally
2. **Network Isolation**: Deploy in a secure network segment
3. **Access Control**: Implement authentication if needed (not included by default)
4. **Audit Logging**: Add logging for compliance requirements

## Known Limitations

1. **No Authentication**: MitreHunter does not include built-in authentication
2. **Public Data Only**: Tool is designed for public MITRE ATT&CK data
3. **Read-Only**: No database writes or persistent storage of user data

## Reporting Vulnerabilities

If you discover a security vulnerability:

1. **Do NOT** open a public GitHub issue
2. Email the maintainer directly at: [your-email@example.com]
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We will respond within 48 hours and work with you to address the issue.

## Security Updates

Security updates will be released as patch versions (e.g., 1.1.1, 1.1.2) and tagged with `[SECURITY]` in the release notes.

## Compliance

MitreHunter is designed to work with publicly available data and does not:
- Collect personal information
- Store user credentials
- Transmit data to third parties
- Require special permissions

## Best Practices

1. **Keep Updated**: Regularly update to the latest version
2. **Review Dependencies**: Run `safety check` before deployment
3. **Secure Deployment**: Follow deployment security guidelines above
4. **Monitor Usage**: Watch for unusual query patterns
5. **Backup Data**: Keep backups of cached MITRE data

## Security Checklist

Before deploying to production:

- [ ] Dependencies pinned and scanned
- [ ] HTTPS enabled
- [ ] Rate limiting configured (if public)
- [ ] Logs monitored
- [ ] Access controls in place (if needed)
- [ ] Incident response plan documented

---

Last Updated: 2025-11-20
Version: 1.1.0
