#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Read-only AWS certificate exposure inventory for the eMudhra incident.

Usage:
  python audit_aws_emudhra.py --profile myprofile --output findings.json
  python audit_aws_emudhra.py --fingerprints additional_sha256.txt
  python audit_aws_emudhra.py --profile myprofile --strong

The built-in fingerprints are SHA-256 certificate fingerprints published in
Mozilla's incident notice. The optional file adds certificate fingerprints;
do not put SPKI hashes in it.
"""
import argparse
import concurrent.futures
import json
import re
import shutil
import socket
import ssl
import subprocess
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


def parse_runtime_endpoint(value):
    """Return (host, port) for HOST, HOST:PORT, or [IPv6]:PORT."""
    value = value.strip()
    if not value:
        raise ValueError('Runtime endpoint cannot be empty')
    if value.startswith('['):
        match = re.fullmatch(r'\[([^]]+)](?::(\d+))?', value)
        if not match:
            raise ValueError('Invalid runtime endpoint: ' + value)
        host, port = match.group(1), int(match.group(2) or 443)
    elif value.count(':') == 1:
        host, port_text = value.rsplit(':', 1)
        if not port_text.isdigit():
            raise ValueError('Invalid runtime endpoint port: ' + value)
        port = int(port_text)
    elif ':' in value:
        host, port = value, 443  # unbracketed IPv6 address
    else:
        host, port = value, 443
    host = host.rstrip('.').strip()
    if (not host or host.startswith('*.') or re.search(r'[\s/?#]', host)
            or not 1 <= port <= 65535):
        raise ValueError('Invalid runtime endpoint: ' + value)
    return host, port


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--profile', help='AWS CLI profile')
    parser.add_argument('--output', default='aws_emudhra_audit.json')
    parser.add_argument('--fingerprints', help='File containing additional SHA-256 certificate fingerprints')
    parser.add_argument('--quiet', action='store_true', help='Suppress progress messages (final summary is still printed)')
    parser.add_argument('--strong', action='store_true',
                        help='Enable both --deep and --runtime analysis')
    parser.add_argument('--deep', action='store_true',
                        help='Also inspect IAM server certificates and AWS Private CA chains')
    parser.add_argument('--runtime', action='store_true',
                        help='Probe TLS chains currently served by discovered endpoints')
    parser.add_argument('--runtime-endpoint', action='append', default=[], metavar='HOST[:PORT]',
                        help='Additional endpoint to probe with --runtime (repeatable)')
    parser.add_argument('--runtime-timeout', type=float, default=5.0, metavar='SECONDS',
                        help='Per-connection timeout for --runtime (default: 5)')
    parser.add_argument('--runtime-workers', type=int, default=8, metavar='N',
                        help='Concurrent endpoint probes for --runtime (default: 8)')
    args = parser.parse_args()
    if args.strong:
        args.deep = True
        args.runtime = True
    if args.runtime_endpoint and not args.runtime:
        parser.error('--runtime-endpoint requires --runtime')
    if args.runtime_timeout <= 0:
        parser.error('--runtime-timeout must be greater than zero')
    if not 1 <= args.runtime_workers <= 64:
        parser.error('--runtime-workers must be between 1 and 64')
    if args.deep or args.runtime:
        try:
            import cryptography  # noqa: F401
        except ImportError:
            parser.error('--deep and --runtime require cryptography; install it with python -m pip install cryptography')
    try:
        fps = load_fps(args.fingerprints)
        extra_runtime_endpoints = [parse_runtime_endpoint(value) for value in args.runtime_endpoint]
    except (OSError, ValueError) as error:
        parser.error(str(error))

    try:
        session = boto3.Session(profile_name=args.profile)
        account = session.client('sts').get_caller_identity()['Account']
        regions = sorted(
            region['RegionName']
            for region in session.client('ec2', region_name='us-east-1').describe_regions(AllRegions=False)['Regions']
        )
    except (BotoCoreError, ClientError) as error:
        parser.exit(2, f'Unable to initialize AWS inventory: {error}\n')

    records, errors = [], []
    certs = {}
    runtime_targets = {}

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

    def add_runtime_target(host, port, source, resource):
        if not host:
            return
        host = host.rstrip('.').lower()
        if host.startswith('*.'):
            return  # Wildcards are certificate names, not connectable endpoints.
        target = runtime_targets.setdefault((host, int(port)), {'sources': [], 'resources': []})
        if source not in target['sources']:
            target['sources'].append(source)
        if resource not in target['resources']:
            target['resources'].append(resource)

    def add_certificate_runtime_targets(details, port, source, resource):
        if not details:
            return
        names = [details.get('domain')] + details.get('subject_alternative_names', [])
        for name in names:
            add_runtime_target(name, port, source, resource)

    def inspect_pem_bundle(kind, region, resource, pem, **fields):
        """Parse a PEM bundle and add one record for each incident-related certificate."""
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes
        except ImportError:
            failure('cryptography', region, 'Install cryptography to inspect certificate chains')
            return
        blocks = re.findall(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', pem, re.S)
        for idx, block in enumerate(blocks):
            try:
                cert = x509.load_pem_x509_certificate(block.encode())
            except ValueError as error:
                failure('x509.parse', region, f'{resource} chain position {idx}: {error}')
                continue
            fingerprint = cert.fingerprint(hashes.SHA256()).hex()
            subject = cert.subject.rfc4514_string()
            cert_issuer = cert.issuer.rfc4514_string()
            name_match = bool(PATTERN.search(cert_issuer + subject))
            if fingerprint in fps or name_match:
                record(kind, region, resource, position=idx, subject=subject,
                       issuer=cert_issuer, sha256=fingerprint,
                       confirmed_fingerprint_match=fingerprint in fps,
                       name_match=name_match, **fields)

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
                subject_alternative_names=c.get('SubjectAlternativeNames', []),
                issuer=issuer,
                certificate_authority_arn=c.get('CertificateAuthorityArn'),
                status=status,
                certificate_type=managed,
                serial=c.get('Serial'),
                not_before=c.get('NotBefore'),
                not_after=c.get('NotAfter'),
                in_use_by=c.get('InUseBy', []),
                key_algorithm=c.get('KeyAlgorithm'),
                issuer_name_match=bool(PATTERN.search(issuer)),
            )
            certs[cache_key] = certificate_record
            # GetCertificate is available for both Amazon-issued and imported
            # certificates when the certificate has been issued. Inspect every
            # retrievable chain, not just imported certificates.
            try:
                bundle = acm.get_certificate(CertificateArn=arn)
                pem = (bundle.get('Certificate') or '') + '\n' + (bundle.get('CertificateChain') or '')
                inspect_pem_bundle('certificate_chain_match', region, arn, pem, source='acm')
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

    progress('INFO', f'Account {account}; scanning {len(regions)} enabled region(s); '
                     f'deep={args.deep}; runtime={args.runtime}')
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
                        add_runtime_target(lb.get('DNSName'), listener.get('Port', 443),
                                           'load_balancer_listener', listener['ListenerArn'])
                        default_arns = set()
                        for item in listener.get('Certificates', []):
                            arn = item.get('CertificateArn')
                            if arn:
                                default_arns.add(arn)
                            details = certificate(arn, region) if arn and ':acm:' in arn else None
                            add_certificate_runtime_targets(
                                details, listener.get('Port', 443),
                                'load_balancer_certificate_name', listener['ListenerArn'])
                            record('load_balancer_listener', region, listener['ListenerArn'],
                                   load_balancer=lb['LoadBalancerArn'], dns_name=lb.get('DNSName'),
                                   port=listener.get('Port'), certificate_arn=arn,
                                   **certificate_reference_fields(arn, region))
                        try:
                            for item in paginate(elb, 'describe_listener_certificates', 'Certificates', ListenerArn=listener['ListenerArn']):
                                arn = item.get('CertificateArn')
                                if arn and ':acm:' in arn:
                                    details = certificate(arn, region)
                                    add_certificate_runtime_targets(
                                        details, listener.get('Port', 443),
                                        'load_balancer_certificate_name', listener['ListenerArn'])
                                if arn and arn not in default_arns:
                                    record('load_balancer_listener_certificate', region, listener['ListenerArn'],
                                           load_balancer=lb['LoadBalancerArn'], dns_name=lb.get('DNSName'),
                                           port=listener.get('Port'), certificate_arn=arn,
                                           is_default=item.get('IsDefault', False),
                                           **certificate_reference_fields(arn, region))
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
                add_runtime_target(item.get('domainName'), 443, 'apigateway_v1_domain', item['domainName'])
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
                add_runtime_target(item.get('DomainName'), 443, 'apigateway_v2_domain', item['DomainName'])
                for cfg in item.get('DomainNameConfigurations', []):
                    arn = cfg.get('CertificateArn')
                    record('apigateway_v2_domain', region, item['DomainName'], certificate_arn=arn,
                           **certificate_reference_fields(arn, region))
        except (ClientError, BotoCoreError) as e:
            failure('apigatewayv2', region, e)
        finish_check(label, started)

        if args.deep:
            label = f'{region} / AWS Private CA chains'
            started = start_check(label)
            try:
                pca = session.client('acm-pca', region_name=region)
                for item in paginate(pca, 'list_certificate_authorities', 'CertificateAuthorities'):
                    ca_arn = item['Arn']
                    record('private_certificate_authority', region, ca_arn,
                           status=item.get('Status'), ca_type=item.get('Type'),
                           key_algorithm=item.get('KeyAlgorithm'),
                           signing_algorithm=item.get('SigningAlgorithm'))
                    if item.get('Status') in {'DELETED', 'PENDING_CERTIFICATE', 'CREATING'}:
                        continue
                    try:
                        bundle = pca.get_certificate_authority_certificate(CertificateAuthorityArn=ca_arn)
                        pem = (bundle.get('Certificate') or '') + '\n' + (bundle.get('CertificateChain') or '')
                        inspect_pem_bundle('private_ca_chain_match', region, ca_arn, pem,
                                           source='acm-pca')
                    except (ClientError, BotoCoreError) as error:
                        failure('acm-pca.get_certificate_authority_certificate', region, error)
            except (ClientError, BotoCoreError) as error:
                failure('acm-pca.list_certificate_authorities', region, error)
            finish_check(label, started)

    label = 'global / CloudFront distributions'
    started = start_check(label)
    try:
        cf = session.client('cloudfront', region_name='us-east-1')
        for dist in paginate(cf, 'list_distributions', 'Items'):
            viewer = dist.get('ViewerCertificate', {})
            arn = viewer.get('ACMCertificateArn')
            add_runtime_target(dist.get('DomainName'), 443, 'cloudfront_distribution', dist['ARN'])
            for alias in dist.get('Aliases', {}).get('Items', []):
                add_runtime_target(alias, 443, 'cloudfront_alias', dist['ARN'])
            origins = []
            for origin in dist.get('Origins', {}).get('Items', []):
                origin_record = {'id': origin.get('Id'), 'domain_name': origin.get('DomainName')}
                custom = origin.get('CustomOriginConfig')
                if custom:
                    origin_record.update({
                        'https_port': custom.get('HTTPSPort', 443),
                        'origin_protocol_policy': custom.get('OriginProtocolPolicy'),
                    })
                    if custom.get('OriginProtocolPolicy') in {'https-only', 'match-viewer'}:
                        add_runtime_target(origin.get('DomainName'), custom.get('HTTPSPort', 443),
                                           'cloudfront_custom_origin', dist['ARN'])
                origins.append(origin_record)
            record('cloudfront_distribution', 'global', dist['ARN'], certificate_arn=arn,
                   domain_name=dist.get('DomainName'),
                   aliases=dist.get('Aliases', {}).get('Items', []),
                   origins=origins,
                   iam_certificate_id=viewer.get('IAMCertificateId'),
                   **certificate_reference_fields(arn, 'us-east-1'))
    except (ClientError, BotoCoreError) as e:
        failure('cloudfront', 'global', e)
    finish_check(label, started)

    if args.deep:
        label = 'global / IAM server certificates'
        started = start_check(label)
        try:
            iam = session.client('iam')
            for summary in paginate(iam, 'list_server_certificates', 'ServerCertificateMetadataList'):
                name = summary['ServerCertificateName']
                try:
                    item = iam.get_server_certificate(ServerCertificateName=name)['ServerCertificate']
                    metadata = item['ServerCertificateMetadata']
                    arn = metadata['Arn']
                    record('iam_server_certificate', 'global', arn,
                           name=name, path=metadata.get('Path'),
                           expiration=metadata.get('Expiration'))
                    pem = (item.get('CertificateBody') or '') + '\n' + (item.get('CertificateChain') or '')
                    inspect_pem_bundle('iam_server_certificate_match', 'global', arn, pem, source='iam')
                except (ClientError, BotoCoreError) as error:
                    failure('iam.get_server_certificate', 'global', error)
        except (ClientError, BotoCoreError) as error:
            failure('iam.list_server_certificates', 'global', error)
        finish_check(label, started)

    for host, port in extra_runtime_endpoints:
        add_runtime_target(host, port, 'operator_supplied', f'{host}:{port}')

    def runtime_probe(target_item):
        (host, port), context = target_item
        endpoint = f'[{host}]:{port}' if ':' in host else f'{host}:{port}'
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes, serialization
        except ImportError:
            return endpoint, None, 'Install cryptography to run TLS endpoint inspection'

        der_chain = []
        tls_version = None
        cipher = None
        try:
            unverified = ssl._create_unverified_context()
            with socket.create_connection((host, port), timeout=args.runtime_timeout) as raw:
                with unverified.wrap_socket(raw, server_hostname=host) as tls:
                    tls_version = tls.version()
                    cipher_info = tls.cipher()
                    cipher = cipher_info[0] if cipher_info else None
                    get_chain = getattr(tls, 'get_unverified_chain', None)
                    if get_chain:
                        for certificate_item in get_chain():
                            if isinstance(certificate_item, bytes):
                                der_chain.append(certificate_item)
                            else:
                                encoded = certificate_item.public_bytes()
                                if isinstance(encoded, str):
                                    der_chain.append(x509.load_pem_x509_certificate(encoded.encode()).public_bytes(
                                        serialization.Encoding.DER))
                                else:
                                    der_chain.append(encoded)
                    else:
                        leaf = tls.getpeercert(binary_form=True)
                        if leaf:
                            der_chain.append(leaf)
        except (OSError, ssl.SSLError, ValueError) as error:
            return endpoint, None, f'TLS collection failed: {error}'

        if not der_chain:
            return endpoint, None, 'TLS endpoint did not return a certificate chain'

        # Python versions before get_unverified_chain expose only the leaf.
        # Use the OpenSSL CLI as a chain-capable fallback when it is available.
        if not hasattr(ssl.SSLSocket, 'get_unverified_chain'):
            openssl = shutil.which('openssl')
            if not openssl:
                return endpoint, None, (
                    'Full chain inspection requires Python with SSLSocket.get_unverified_chain '
                    'or the openssl command')
            try:
                completed = subprocess.run(
                    [openssl, 's_client', '-connect', endpoint, '-servername', host,
                     '-showcerts'],
                    input=b'', capture_output=True, timeout=args.runtime_timeout, check=False)
                output = (completed.stdout + completed.stderr).decode('utf-8', errors='replace')
                blocks = re.findall(
                    r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', output, re.S)
                if not blocks:
                    return endpoint, None, 'OpenSSL did not return a certificate chain'
                der_chain = [x509.load_pem_x509_certificate(block.encode()).public_bytes(
                    serialization.Encoding.DER) for block in blocks]
            except (OSError, subprocess.TimeoutExpired, ValueError) as error:
                return endpoint, None, f'OpenSSL chain collection failed: {error}'

        certificates = []
        try:
            for position, der in enumerate(der_chain):
                cert = x509.load_der_x509_certificate(der)
                fingerprint = cert.fingerprint(hashes.SHA256()).hex()
                subject = cert.subject.rfc4514_string()
                issuer = cert.issuer.rfc4514_string()
                certificates.append({
                    'position': position,
                    'subject': subject,
                    'issuer': issuer,
                    'sha256': fingerprint,
                    'confirmed_fingerprint_match': fingerprint in fps,
                    'name_match': bool(PATTERN.search(subject + issuer)),
                })
        except ValueError as error:
            return endpoint, None, f'Runtime certificate parsing failed: {error}'

        chain_trusted = True
        trust_error = None
        try:
            verified = ssl.create_default_context()
            verified.check_hostname = False
            with socket.create_connection((host, port), timeout=args.runtime_timeout) as raw:
                with verified.wrap_socket(raw, server_hostname=host):
                    pass
        except (OSError, ssl.SSLError) as error:
            chain_trusted = False
            trust_error = str(error)

        return endpoint, {
            'host': host,
            'port': port,
            'sources': context['sources'],
            'referenced_resources': context['resources'],
            'tls_version': tls_version,
            'cipher': cipher,
            'chain_trusted_by_local_store': chain_trusted,
            'trust_error': trust_error,
            'certificates': certificates,
            'confirmed_fingerprint_match': any(
                item['confirmed_fingerprint_match'] for item in certificates),
            'name_match': any(item['name_match'] for item in certificates),
        }, None

    def safe_runtime_probe(target_item):
        try:
            return runtime_probe(target_item)
        except Exception as error:  # Keep one malformed endpoint from aborting the inventory.
            host, port = target_item[0]
            endpoint = f'[{host}]:{port}' if ':' in host else f'{host}:{port}'
            return endpoint, None, f'Unexpected runtime probe failure: {error}'

    if args.runtime:
        label = f'runtime / {len(runtime_targets)} TLS endpoint(s)'
        started = start_check(label)
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.runtime_workers) as executor:
            results = list(executor.map(safe_runtime_probe, sorted(runtime_targets.items())))
        for endpoint, details, error in results:
            if error:
                failure('runtime.tls', 'runtime', f'{endpoint}: {error}')
            else:
                record('runtime_tls_endpoint', 'runtime', endpoint, **details)
        finish_check(label, started)

    matches = [r for r in records if r.get('issuer_name_match') or r.get('name_match') or r.get('confirmed_fingerprint_match')]
    result = {'account': account, 'timestamp_utc': datetime.now(timezone.utc).isoformat(),
              'regions_scanned': regions, 'deep_analysis': args.deep,
              'runtime_analysis': args.runtime,
              'runtime_targets': len(runtime_targets) if args.runtime else 0,
              'records': records, 'potential_matches': matches,
              'errors': errors, 'limitations': [
                  'Issuer-name matches are investigative leads, not proof of an affected intermediate.',
                  'Built-in incident fingerprints and valid additions supplied with --fingerprints count as confirmed matches.',
                  'Base mode does not audit IAM server certificates or AWS Private CA chains; use --deep.',
                  'Runtime mode checks served TLS chains, not certificate files or trust stores inside compute instances or containers.',
                  'Does not audit workload trust stores, outbound TLS, historical certificates, or third-party services not supplied as runtime endpoints.',
                  'A clean result does not prove absence of exposure. Check errors and scan coverage.',
                  'ACM public certificates and some chains may not be retrievable via get_certificate.']}
    try:
        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2, default=str)
    except OSError as error:
        parser.exit(2, f'Unable to write output {args.output}: {error}\n')
    if matches:
        progress('ALERT', f'{len(matches)} potential match(es) require review')
    elif errors:
        progress('WARN', 'No matches found, but scan errors prevent a clean result')
    else:
        progress('OK', 'Scan completed with no potential matches')
    print(f'Account: {account}; regions: {len(regions)}; deep: {args.deep}; '
          f'runtime targets: {len(runtime_targets) if args.runtime else 0}; '
          f'records: {len(records)}; potential matches: {len(matches)}; errors: {len(errors)}')
    print('Results:', args.output)
    if matches:
        for item in matches:
            print('MATCH', item['kind'], item['region'], item['resource'])
    if errors:
        print('WARNING: Some checks failed. Review errors in the JSON output.', file=sys.stderr)

if __name__ == '__main__':
    main()
