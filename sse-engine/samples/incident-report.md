# Incident report: credential exposure

On Tuesday a staging API token was committed to a public repository.
The token was rotated within 40 minutes and no customer data was accessed.
Root cause: a missing secret-scanning hook in the CI pipeline.
Remediation: enforce pre-commit scanning, shorten token lifetime, audit access logs.
