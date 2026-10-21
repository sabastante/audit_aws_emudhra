#!/usr/bin/env python3
"""Read-only AWS certificate exposure inventory for the eMudhra incident.

Usage:
  python audit_aws_emudhra.py --profile myprofile --output findings.json
  python audit_aws_emudhra.py --fingerprints additional_sha256.txt

The built-in fingerprints are SHA-256 certificate fingerprints published in
Mozilla's incident notice. The optional file adds certificate fingerprints;
do not put SPKI hashes in it.
"""
import argparse
import json
import re
import sys
from datetime import datetime, timezone

try:
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError
except ImportError:
    sys.exit('Install boto3: python -m pip install boto3')


PATTERN = re.compile(r'emudhra|emsign', re.I)

# Eight affected certificates plus their eight Sectigo cross-certificates.
# Source: Mozilla's 2026-10-20 oss-security incident notice.
AFFECTED_CERT_SHA256 = {
    'e7568fe6e12331f4fd7de61da4c7559d0f8eb192a218d4741a3ba75184333838',
    '98b896625c0c230adeec3eb2cf6aad5001ecf9156a68644e82374ce5833bc25b',
    '42c4accd12c4f59597925e1a08a7a90102608543809308d50ec427e118ba1493',
    '432ec25f0d28de9006d97bf752f17bbb2cd41f669933fcb072d9a1148d0261f3',
    'cb6e15165ac802e9b3f993f16c25d41f4e81c21ebde71ae1b012ac00bf9c7c3f',
    '0164d7ceae5bb909c272af151ff44b1177ae9b47d9424b94f1d9558c30934d19',
    '9e39de2881273acc225a149c72ba3e0f51424963669ab633ee1dc7df5db067b4',
    '4b2460a466f95fd40113bcdcca2ceb29b3b093921de45474da7df48874c630b1',
    '579480aea166290bd3c643589e795fc0d0e54e86505d180f1dff99efd3199512',
    '5f1ded4dd590af74631290cf073b122a2aac6a1fa479778a0bd43579bd832699',
    '45a883f349aedfd5f3a649b5498ffb121712ba8b448f3f2a91dbc5a766fcddbe',
    'fd9d5c2dbbd4995ab69b8d50c439d9527b00529199c2fd01b2174eb58f07021f',
    '7485b51c0ed192878fa1d2f948fb529ae1842cc5086c4b67f7be5b2039de9489',
    '62b7f9868263f72f6911fc78ceaf72c1979158b7368bf648683bb2aa39b02e72',
    'a496e23ac0cab8155fc9b117b97eae368efcbb9041aec8804d5a308d2d01c2d8',
    '84112972b8e59d14560ae7e7119654474aad119990cf3722bfc1e3b91615e1fd',
}


def normalize_fp(value):
    fingerprint = re.sub(r'[:\s]', '', value).lower()
    if not re.fullmatch(r'[a-f0-9]{64}', fingerprint):
        raise ValueError('Invalid SHA256 certificate fingerprint: ' + value)
    return fingerprint


def load_fps(path):
    fingerprints = set(AFFECTED_CERT_SHA256)
    if not path:
        return fingerprints
    with open(path, encoding='utf-8') as handle:
        fingerprints.update(
            normalize_fp(line.strip())
            for line in handle
            if line.strip() and not line.lstrip().startswith('#')
        )
    return fingerprints


def paginate(client, operation, result_key, **kwargs):
    paginator = client.get_paginator(operation)
    for page in paginator.paginate(**kwargs):
        yield from page.get(result_key, [])


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--profile', help='AWS CLI profile')
    parser.add_argument('--output', default='aws_emudhra_audit.json')
    parser.add_argument('--fingerprints', help='File containing additional SHA-256 certificate fingerprints')
    parser.add_argument('--quiet', action='store_true', help='Suppress progress messages (final summary is still printed)')
    args = parser.parse_args()
    try:
        fps = load_fps(args.fingerprints)
    except (OSError, ValueError) as error:
        parser.error(str(error))

    session = boto3.Session(profile_name=args.profile)
    try:
        account = session.client('sts').get_caller_identity()['Account']
        regions = sorted(
            region['RegionName']
            for region in session.client('ec2', region_name='us-east-1').describe_regions(AllRegions=False)['Regions']
        )
    except (BotoCoreError, ClientError) as error:
        parser.exit(2, f'Unable to initialize AWS inventory: {error}\n')

    records, errors = [], []
    certs = {}

    def progress(state, message):
        if not args.quiet:
            print(f'[{state:^5}] {message}', file=sys.stderr, flush=True)

    def start_check(message):
        progress('CHECK', message)
        return len(records), len(errors)

    def finish_check(message, started):
        record_count = len(records) - started[0]
        error_count = len(errors) - started[1]
        if error_count:
            progress('WARN', f'{message}: {record_count} record(s), {error_count} error(s)')
        else:
            progress('OK', f'{message}: {record_count} record(s)')

    def record(kind, region, resource, **fields):
        item = {'kind': kind, 'region': region, 'resource': resource, **fields}
        records.append(item)
        return item

    def failure(service, region, error):
        errors.append({'service': service, 'region': region, 'error': str(error)})

    def certificate(arn, region):
        cache_key = (region, arn)
        if not arn:
            return None
        if cache_key in certs:
            return certs[cache_key]
        try:
            acm = session.client('acm', region_name=region)
            c = acm.describe_certificate(CertificateArn=arn)['Certificate']
            issuer = c.get('Issuer', '')
            status = c.get('Status', '')
            managed = c.get('Type', '')
            certificate_record = record(
                'acm_certificate', region, arn,
                domain=c.get('DomainName'),
                issuer=issuer,
                certificate_authority_arn=c.get('CertificateAuthorityArn'),
                status=status,
                certificate_type=managed,
                issuer_name_match=bool(PATTERN.search(issuer)),
            )
            certs[cache_key] = certificate_record
            # GetCertificate is available for both Amazon-issued and imported
            # certificates when the certificate has been issued. Inspect every
            # retrievable chain, not just imported certificates.
            try:
                bundle = acm.get_certificate(CertificateArn=arn)
                pem = (bundle.get('Certificate') or '') + '\n' + (bundle.get('CertificateChain') or '')
                try:
                    from cryptography import x509
                    from cryptography.hazmat.primitives import hashes
                except ImportError:
                    failure('cryptography', region, 'Install cryptography to inspect ACM certificate chains')
                else:
                    blocks = re.findall(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', pem, re.S)
                    for idx, block in enumerate(blocks):
                        try:
                            cert = x509.load_pem_x509_certificate(block.encode())
                        except ValueError as error:
                            failure('x509.parse', region, f'{arn} chain position {idx}: {error}')
                            continue
                        fingerprint = cert.fingerprint(hashes.SHA256()).hex()
                        subject = cert.subject.rfc4514_string()
                        cert_issuer = cert.issuer.rfc4514_string()
                        name_match = bool(PATTERN.search(cert_issuer + subject))
                        if fingerprint in fps or name_match:
                            record('certificate_chain_match', region, arn, position=idx,
                                   subject=subject, issuer=cert_issuer, sha256=fingerprint,
                                   confirmed_fingerprint_match=fingerprint in fps,
                                   name_match=name_match)
            except (ClientError, BotoCoreError) as error:
                # PENDING_VALIDATION and some ineligible certificate states do
                # not have retrievable certificate material.
                code = error.response.get('Error', {}).get('Code', '') if isinstance(error, ClientError) else ''
                if status == 'ISSUED' or code not in {'ResourceNotFoundException'}:
                    failure('acm.get_certificate', region, error)
            return certificate_record
        except (ClientError, BotoCoreError) as e:
            failure('acm.describe_certificate', region, e)
            certs[cache_key] = None
            return None

    def certificate_reference_fields(arn, region):
        details = certificate(arn, region) if arn and ':acm:' in arn else None
        if not details:
            return {'certificate_issuer': None, 'certificate_authority_arn': None}
        return {
            'certificate_issuer': details.get('issuer'),
            'certificate_authority_arn': details.get('certificate_authority_arn'),
        }

    progress('INFO', f'Account {account}; scanning {len(regions)} enabled region(s)')
    for region in regions:
        label = f'{region} / ACM certificates'
        started = start_check(label)
        try:
            acm = session.client('acm', region_name=region)
            for summary in paginate(acm, 'list_certificates', 'CertificateSummaryList',
                                    Includes={'keyTypes': ['RSA_1024','RSA_2048','RSA_3072','RSA_4096','EC_prime256v1','EC_secp384r1','EC_secp521r1']}):
                certificate(summary['CertificateArn'], region)
        except (ClientError, BotoCoreError) as e:
            failure('acm.list_certificates', region, e)
        finish_check(label, started)

        label = f'{region} / load balancers'
        started = start_check(label)
        try:
            elb = session.client('elbv2', region_name=region)
            for lb in paginate(elb, 'describe_load_balancers', 'LoadBalancers'):
                for listener in paginate(elb, 'describe_listeners', 'Listeners', LoadBalancerArn=lb['LoadBalancerArn']):
                    if listener.get('Protocol') in ('HTTPS', 'TLS'):
                        for item in listener.get('Certificates', []):
                            arn = item.get('CertificateArn')
                            record('load_balancer_listener', region, listener['ListenerArn'],
                                   load_balancer=lb['LoadBalancerArn'], certificate_arn=arn,
                                   **certificate_reference_fields(arn, region))
                        try:
                            for item in paginate(elb, 'describe_listener_certificates', 'Certificates', ListenerArn=listener['ListenerArn']):
                                arn = item.get('CertificateArn')
                                if arn and ':acm:' in arn:
                                    certificate(arn, region)
                        except (ClientError, BotoCoreError) as e:
                            failure('elbv2.describe_listener_certificates', region, e)
        except (ClientError, BotoCoreError) as e:
            failure('elbv2', region, e)
        finish_check(label, started)

        label = f'{region} / API Gateway v1 domains'
        started = start_check(label)
        try:
            apigw = session.client('apigateway', region_name=region)
            for item in paginate(apigw, 'get_domain_names', 'items'):
                arn = item.get('regionalCertificateArn') or item.get('certificateArn')
                certificate_region = 'us-east-1' if item.get('certificateArn') else region
                record('apigateway_v1_domain', region, item['domainName'], certificate_arn=arn,
                       **certificate_reference_fields(arn, certificate_region))
        except (ClientError, BotoCoreError) as e:
            failure('apigateway', region, e)
        finish_check(label, started)

        label = f'{region} / API Gateway v2 domains'
        started = start_check(label)
        try:
            apigw2 = session.client('apigatewayv2', region_name=region)
            for item in paginate(apigw2, 'get_domain_names', 'Items'):
                for cfg in item.get('DomainNameConfigurations', []):
                    arn = cfg.get('CertificateArn')
                    record('apigateway_v2_domain', region, item['DomainName'], certificate_arn=arn,
                           **certificate_reference_fields(arn, region))
        except (ClientError, BotoCoreError) as e:
            failure('apigatewayv2', region, e)
        finish_check(label, started)

    label = 'global / CloudFront distributions'
    started = start_check(label)
    try:
        cf = session.client('cloudfront', region_name='us-east-1')
        for dist in paginate(cf, 'list_distributions', 'Items'):
            viewer = dist.get('ViewerCertificate', {})
            arn = viewer.get('ACMCertificateArn')
            record('cloudfront_distribution', 'global', dist['ARN'], certificate_arn=arn,
                   aliases=dist.get('Aliases', {}).get('Items', []),
                   iam_certificate_id=viewer.get('IAMCertificateId'),
                   **certificate_reference_fields(arn, 'us-east-1'))
            # Custom origins have separate TLS validation behavior and are not covered.
    except (ClientError, BotoCoreError) as e:
        failure('cloudfront', 'global', e)
    finish_check(label, started)

    matches = [r for r in records if r.get('issuer_name_match') or r.get('name_match') or r.get('confirmed_fingerprint_match')]
    result = {'account': account, 'timestamp_utc': datetime.now(timezone.utc).isoformat(),
              'regions_scanned': regions, 'records': records, 'potential_matches': matches,
              'errors': errors, 'limitations': [
                  'Issuer-name matches are investigative leads, not proof of an affected intermediate.',
                  'Built-in incident fingerprints and valid additions supplied with --fingerprints count as confirmed matches.',
                  'Does not audit workload trust stores, outbound TLS, IAM server certificates, CloudFront origin TLS, or Cloudflare.',
                  'A clean result does not prove absence of exposure. Check errors and scan coverage.',
                  'ACM public certificates and some chains may not be retrievable via get_certificate.']}
    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2, default=str)
    if matches:
        progress('ALERT', f'{len(matches)} potential match(es) require review')
    elif errors:
        progress('WARN', 'No matches found, but scan errors prevent a clean result')
    else:
        progress('OK', 'Scan completed with no potential matches')
    print(f'Account: {account}; regions: {len(regions)}; records: {len(records)}; potential matches: {len(matches)}; errors: {len(errors)}')
    print('Results:', args.output)
    if matches:
        for item in matches:
            print('MATCH', item['kind'], item['region'], item['resource'])
    if errors:
        print('WARNING: Some checks failed. Review errors in the JSON output.', file=sys.stderr)

if __name__ == '__main__':
    main()
