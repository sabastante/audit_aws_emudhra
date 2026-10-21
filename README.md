# AWS eMudhra certificate exposure audit

`audit_aws_emudhra.py` is a read-only inventory and triage tool for the October
2026 compromise of private keys associated with eight eMudhra subordinate CA
certificates. It searches AWS Certificate Manager (ACM) certificate material
for the built-in SHA-256 certificate fingerprints and for `eMudhra`/`emSign`
names that warrant manual review.

This is an exposure check, not a compromise assessment. A match means that
certificate material in the account is related to the incident; it does not by
itself show that an attacker issued or used a fraudulent certificate.

Incident reference: [Mozilla dev-security-policy announcement](https://groups.google.com/a/mozilla.org/g/dev-security-policy/c/0R3XLJL6FuE)

## Fast path

Use a dedicated read-only incident-response role and write the output to a
protected case directory.

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install boto3 cryptography

aws sso login --profile incident-readonly    # if the profile uses IAM Identity Center
python audit_aws_emudhra.py \
  --profile incident-readonly \
  --output findings-$(date -u +%Y%m%dT%H%M%SZ).json
```

`cryptography` is operationally required for fingerprint matching. If it is
missing, the script can still collect metadata, but each attempted chain
inspection is recorded as an error and exact fingerprint checks are not done.

Immediately review both matches and errors:

```bash
jq '.potential_matches' findings-*.json
jq '.errors' findings-*.json
```

Do not use the command's exit status as a clean/affected signal. Except for
startup or argument failures, the current script exits successfully even when
it finds matches or records per-service errors. Gate automation on the JSON
fields instead:

```bash
jq -e '(.potential_matches | length) == 0 and (.errors | length) == 0' findings.json
```

## What it checks

The script obtains the caller's account ID, discovers enabled AWS Regions, and
then performs the following checks.

| Scope | Inspection |
| --- | --- |
| ACM, every enabled Region | Lists certificates, records certificate metadata, retrieves available leaf/chain PEM, and calculates SHA-256 certificate fingerprints. |
| Elastic Load Balancing v2 | Inventories HTTPS/TLS listeners and their ACM certificates on Application and Network Load Balancers. Gateway Load Balancers do not use these listener protocols. |
| API Gateway REST APIs (v1) | Inventories regional and edge-optimized custom domain certificate references. Edge certificate material is looked up in `us-east-1`. |
| API Gateway v2 | Inventories custom domain certificate references. |
| CloudFront | Inventories viewer certificates and aliases. ACM viewer certificates are looked up in `us-east-1`. |

All ACM certificates are inspected independently of their use by the listed
services. Consequently, a fingerprint match can still be found even when the
script does not identify the consuming AWS service.

The script only calls read/list/describe APIs. It does not export private keys,
replace certificates, modify listeners, or revoke anything.

## Prerequisites

- Python 3.9 or newer is recommended.
- `boto3` and `cryptography` must be installed in the active Python environment.
- Valid AWS credentials from a profile or the normal boto3 credential chain.
- Network access to the relevant AWS service endpoints.
- `jq` is optional, but useful for tactical triage.
- The current implementation assumes the standard commercial AWS partition;
  it uses `us-east-1` for global and edge-service lookups.

Confirm the identity before scanning:

```bash
aws sts get-caller-identity --profile incident-readonly
```

### Read-only IAM policy

The scanning principal needs these permissions. Resource-level restrictions
may be added where AWS supports them, but confirm that they do not hide
certificates from the incident scan.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EmudhraAuditInventory",
      "Effect": "Allow",
      "Action": [
        "sts:GetCallerIdentity",
        "ec2:DescribeRegions",
        "acm:ListCertificates",
        "acm:DescribeCertificate",
        "acm:GetCertificate",
        "elasticloadbalancing:DescribeLoadBalancers",
        "elasticloadbalancing:DescribeListeners",
        "elasticloadbalancing:DescribeListenerCertificates",
        "apigateway:GET",
        "cloudfront:ListDistributions"
      ],
      "Resource": "*"
    }
  ]
}
```

An AWS Organizations service control policy, permission boundary, session
policy, resource policy, or explicit deny can still make the scan incomplete.
The resulting access failures appear in the JSON `errors` array.

## Command reference

```text
python audit_aws_emudhra.py [--profile PROFILE] [--output FILE]
                            [--fingerprints FILE] [--quiet]
```

- `--profile`: AWS shared-config profile. If omitted, boto3 uses its normal
  credential resolution chain.
- `--output`: JSON output path. Defaults to `aws_emudhra_audit.json` and
  overwrites that file if it already exists.
- `--fingerprints`: adds SHA-256 **certificate** fingerprints to the built-in
  incident set. This does not replace the built-in set.
- `--quiet`: suppresses per-check progress on stderr; the final stdout summary
  is still printed.

The additional fingerprint file accepts one 64-hex-character SHA-256
certificate fingerprint per line. Colons, whitespace, blank lines, and lines
beginning with `#` are accepted. Do not supply SPKI hashes: they are a different
identifier and will not produce a valid comparison against the script's
certificate fingerprints.

Example:

```text
# Additional certificate fingerprint from an approved incident source
AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99
```

## Reading the result

The top-level JSON object contains:

- `account`: the scanned AWS account ID.
- `timestamp_utc`: completion timestamp.
- `regions_scanned`: enabled Regions returned to the caller.
- `records`: full inventory collected by the script.
- `potential_matches`: records selected for incident review.
- `errors`: failed or incomplete checks. Any entry weakens a negative result.
- `limitations`: coverage warnings embedded by the script.

There are three useful match signals:

| Signal | Meaning | Tactical priority |
| --- | --- | --- |
| `confirmed_fingerprint_match: true` | A certificate in retrievable ACM leaf/chain material exactly matches the built-in or operator-supplied SHA-256 certificate set. | High-confidence exposure; escalate immediately. |
| `name_match: true` | A parsed chain certificate subject or issuer contains `eMudhra` or `emSign`. | Investigative lead; verify its fingerprint against the latest authoritative incident list. |
| `issuer_name_match: true` | ACM metadata's issuer string contains `eMudhra` or `emSign`. | Investigative lead; metadata alone is not proof that the affected intermediate is present. |

Extract a compact match list:

```bash
jq -r '.potential_matches[] |
  [.kind, .region, .resource, (.sha256 // "-"),
   (.confirmed_fingerprint_match // false), (.name_match // false),
   (.issuer_name_match // false)] | @tsv' findings.json
```

List incomplete checks by service and Region:

```bash
jq -r '.errors[] | [.service, .region, .error] | @tsv' findings.json
```

Find AWS resources that reference a matched ACM certificate ARN:

```bash
MATCHED_ARN='arn:aws:acm:REGION:ACCOUNT:certificate/ID'
jq --arg arn "$MATCHED_ARN" \
  '.records[] | select(.resource == $arn or .certificate_arn == $arn)' \
  findings.json
```

An `acm_certificate` record is inventory, not automatically a finding. It only
appears in `potential_matches` when one of the match fields above is true.

## Tactical decision flow

1. Confirm `account`, `regions_scanned`, and the assumed AWS identity. Preserve
   the JSON as incident evidence; it contains the scan time and coverage.
2. Review `errors` before interpreting a zero-match result. Correct missing
   permissions, expired credentials, unavailable endpoints, or missing
   `cryptography`, then rerun.
3. For each exact fingerprint match, locate every reference to its ACM ARN in
   `records`. Also search infrastructure-as-code, Kubernetes secrets, instance
   filesystems, and other certificate stores that this tool cannot see.
4. For name-only leads, obtain the certificate and compare its full SHA-256
   certificate fingerprint with the latest fingerprint list from an
   authoritative incident source. Do not treat organization-name text as
   confirmation.
5. If confirmed, follow the organization's certificate incident procedure:
   preserve evidence, notify the certificate/PKI and service owners, replace
   the leaf certificate and affected chain with material from a trusted CA,
   deploy it to every termination point, and validate externally what clients
   are actually served. Avoid deleting the old ACM certificate before all
   dependencies and rollback requirements are understood.
6. Review relevant certificate issuance, import, and configuration activity in
   CloudTrail and other PKI logs for the incident window. This script does not
   perform that historical analysis.
7. Rerun the inventory after remediation and retain both before/after outputs.

## Coverage limitations

A clean JSON file is not proof of no exposure. In particular, this tool does
not inspect:

- trust stores or certificate files inside EC2, ECS/EKS workloads, Lambda
  layers, containers, appliances, or on-premises systems;
- outbound TLS connections made by workloads;
- IAM server certificates or non-ACM certificate stores;
- CloudFront custom-origin TLS certificates;
- certificates terminated by Cloudflare or any other external CDN, load
  balancer, proxy, ingress controller, or SaaS provider;
- certificates in other AWS accounts or disabled/opted-out Regions;
- historical certificates already deleted or replaced;
- evidence that a fraudulent leaf certificate was issued or used;
- service associations beyond the resources listed under **What it checks**.

ACM certificate material may also be unavailable in some states. Such failures
must be assessed through the `errors` array rather than silently treated as a
negative result.

## Multi-account operations

Run the script once per account/role and give every output a unique name. For
example:

```bash
for profile in prod-readonly shared-readonly security-readonly; do
  python audit_aws_emudhra.py \
    --profile "$profile" \
    --output "findings-${profile}-$(date -u +%Y%m%dT%H%M%SZ).json"
done
```

Keep stdout and stderr in the case log if chain of custody or later coverage
review matters. The JSON contains AWS account IDs, ARNs, certificate subjects,
domain names, and CloudFront aliases; handle it as sensitive infrastructure
inventory.

## Validation and troubleshooting

Check the script locally without making AWS calls:

```bash
python -m py_compile audit_aws_emudhra.py
python audit_aws_emudhra.py --help
```

Common conditions:

- **`Install boto3`**: install dependencies in the active interpreter with
  `python -m pip install boto3 cryptography`.
- **Profile or token errors**: authenticate/refresh the selected profile and
  confirm it with `aws sts get-caller-identity --profile PROFILE`.
- **Many `cryptography` errors**: install `cryptography` and rerun; the prior
  result did not perform exact chain fingerprint checks.
- **`AccessDenied` entries**: add the missing read action to the audit role or
  investigate an overriding policy. Rerun after correction.
- **No matches plus errors**: report the result as *inconclusive for the failed
  scope*, not clean.
- **Long runtime or throttling**: the scan is serial across all enabled Regions
  and enumerates listeners and certificates. Retry with the same identity and
  preserve both outputs if throttling caused errors.

## Current implementation notes

- Built-in indicators are 16 SHA-256 certificate fingerprints: eight affected
  certificates and eight Sectigo cross-certificates, as documented in the
  script source.
- Fingerprints are calculated over DER certificate objects parsed from ACM's
  returned PEM, not over public keys/SPKI.
- Listener certificate discovery inspects non-default ELB certificates for
  matches, but only default listener certificates get a dedicated
  `load_balancer_listener` association record. Search the AWS listener directly
  when a matched ACM ARN has no association in the JSON.
- The scanner catches most per-service AWS API failures and continues, favoring
  broad collection over fail-fast behavior. Always assess `errors`.
