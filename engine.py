"""Bounded assessment helpers; standard library only."""
import http.client
import ipaddress
import re
import shutil
import socket
import ssl
import subprocess
import xml.etree.ElementTree as ET
from urllib.parse import urlsplit


def target(value):
    u = urlsplit(value)
    if u.scheme not in ('http', 'https') or not u.hostname or u.username or u.password or u.query or u.fragment:
        raise ValueError('Use an exact HTTP(S) URL without credentials, query or fragment')
    port = u.port or (443 if u.scheme == 'https' else 80)
    if port not in (80, 443, 8000, 8080, 8443):
        raise ValueError('Port is not in the supported bounded set')
    host = u.hostname.encode('idna').decode('ascii').lower()
    return u.scheme, host, port, u.path or '/'


def public_ip(host, port):
    addresses = {x[4][0] for x in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)}
    if not addresses or any(not ipaddress.ip_address(x).is_global for x in addresses):
        raise ValueError('Private, local, reserved or mixed DNS targets are blocked')
    return sorted(addresses)[0]


def header_check(url):
    scheme, host, port, path = target(url)
    address = public_ip(host, port)
    # Connect to the validated numeric address, retaining hostname verification/SNI.
    connection = http.client.HTTPConnection(host, port, timeout=10)
    sock = socket.create_connection((address, port), timeout=10)
    try:
        if scheme == 'https':
            sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
        connection.sock = sock
        connection.request('HEAD', path, headers={'User-Agent': 'BountyWorkbench/0.1', 'Connection': 'close'})
        response = connection.getresponse()
        code = response.status
        if code == 429 or code >= 500:
            return [{'status': 'Not tested', 'severity': 'Informational', 'title': 'Stopped on server response', 'evidence': f'HEAD returned {code}; no retry.'}]
        headers = {k.lower(): v for k, v in response.getheaders()}
        results = [{'status': 'Informational', 'severity': 'Informational', 'title': 'HTTP observation', 'evidence': f'HEAD {url} returned {code}. One request; redirects were not followed.'}]
        for key in ('content-security-policy', 'x-content-type-options', 'referrer-policy'):
            if key not in headers:
                results.append({'status': 'Informational', 'severity': 'Informational', 'title': f'Header absent: {key}', 'evidence': 'Absent in this HEAD response only. No exploit or user impact established.'})
        if 300 <= code < 400:
            results.append({'status': 'Not tested', 'severity': 'Informational', 'title': 'Redirect not followed', 'evidence': 'Destination requires a separate scope decision.'})
        return results
    finally:
        connection.close()
        sock.close()


def nmap_check(url):
    _, host, port, _ = target(url)
    # Nmap scans hosts/ports rather than URL paths; scoped path must be root.
    if target(url)[3] != '/':
        raise ValueError('Nmap requires explicit host-level authorization at root URL')
    executable = shutil.which('nmap')
    if not executable:
        raise ValueError('Nmap is not installed. No installation was attempted.')
    address = public_ip(host, port)
    args = [executable, '-n', '-Pn', '-sT', '-p', str(port), '--max-retries', '0', '--max-parallelism', '1', '--scan-delay', '1s', '--host-timeout', '20s', '-oX', '-']
    if ipaddress.ip_address(address).version == 6:
        args.append('-6')
    args.append(address)
    result = subprocess.run(args, capture_output=True, text=True, timeout=25, check=False)
    if result.returncode:
        raise ValueError('Nmap did not complete successfully; no retry was attempted')
    doc = ET.fromstring(result.stdout)
    findings = []
    for item in doc.findall('.//port'):
        state = item.find('state')
        findings.append({'status': 'Informational', 'severity': 'Informational', 'title': f"TCP port {item.get('portid')}", 'evidence': f"State: {state.get('state') if state is not None else 'unknown'}. Open ports alone do not prove a vulnerability."})
    return findings or [{'status': 'Not tested', 'severity': 'Informational', 'title': 'No port result', 'evidence': 'Nmap returned no port observation.'}]


def sql_review(source):
    findings = []
    for number, line in enumerate(source.splitlines(), 1):
        if re.search(r'\b(execute|executemany|rawQuery|execSQL)\s*\(', line, re.I) and re.search(r'\+|\bf[\x22\x27]|\.format\s*\(|%\s*\(', line):
            findings.append({'status': 'Suspected', 'severity': 'Unrated', 'title': 'Review SQL construction', 'evidence': f'Line {number}: dynamic SQL pattern. Input controllability and parameter binding need manual data-flow review. Source text intentionally omitted.'})
    return findings or [{'status': 'Informational', 'severity': 'Informational', 'title': 'No heuristic match', 'evidence': 'This narrow heuristic is not proof that the code is safe.'}]


def report(job, findings):
    lines = ['# Bounty Workbench — Draft', '', f"Assessment: {job['created']}", f"Exact asset: {job['target']}", f"Mode: {job['mode']}", f"Policy: {job['policy']}", '', '## Authorization and scope', job['rules'], '', '## Summary', f"{len(findings)} observation(s). Scanner output is not automatically a confirmed vulnerability."]
    for item in findings:
        lines += ['', '## ' + item['title'], 'Status: ' + item['status'], 'Severity: ' + item['severity'], '', '### Evidence and safe reproduction', item['evidence'], '', '### Impact', 'No impact beyond the recorded observation has been established.', '', '### Remediation', 'Review this observation in application context before choosing a fix.']
    lines += ['', '## Limitations', 'Only the recorded mode and exact asset were assessed. No comprehensive coverage claim. No automatic exploitation, sensitive data extraction, or submission.', '', '## Submission', 'Draft for manual review; not submitted.']
    return '\n'.join(lines)
