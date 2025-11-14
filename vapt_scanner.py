#!/usr/bin/env python3
import subprocess, sys, datetime, xml.etree.ElementTree as ET
import pandas as pd
from bs4 import BeautifulSoup

def run_nmap(target, out='nmap_output.xml'):
    args = ['nmap', '-sV', '-O', '-p-', '--top-ports', '1000', '-oX', out, target]
    subprocess.run(args, check=True)
    return out

def parse_xml(f):
    tree = ET.parse(f)
    root = tree.getroot()
    rows = []
    for host in root.findall('host'):
        addr = host.find("./address")
        ip = addr.get('addr') if addr is not None else 'unknown'
        hostname_elem = host.find('./hostnames/hostname')
        hostname = hostname_elem.get('name') if hostname_elem is not None else ''
        os_elem = host.find('./os/osmatch')
        osname = os_elem.get('name') if os_elem is not None else ''
        for port in host.findall('./ports/port'):
            portid = port.get('portid')
            proto = port.get('protocol')
            state = port.find('state').get('state')
            svc = port.find('service')
            service = svc.get('name') if svc is not None else ''
            ver = svc.get('version') if svc is not None and 'version' in svc.attrib else ''
            banner = (service + ' ' + ver).strip()
            rows.append({
                'ip': ip, 'hostname': hostname, 'os': osname,
                'port': portid, 'protocol': proto, 'state': state,
                'service': service, 'version': ver, 'banner': banner
            })
    return rows

def suggest(r):
    port = int(r['port'])
    s = r['service'].lower()
    notes = []
    if r['state'] != 'open':
        return ''
    if port in (22,):
        notes.append('Use key-based SSH and disable password auth.')
    if s == 'telnet':
        notes.append('Replace Telnet with SSH.')
    if port in (80, 8080):
        notes.append('Review web server versions and apply patches.')
    if port in (3306, 5432):
        notes.append('Restrict DB to localhost and enforce strong auth.')
    if not notes:
        notes.append('Review service configuration and apply updates.')
    return ' | '.join(notes)

def write_reports(rows, target):
    df = pd.DataFrame(rows)
    if not df.empty:
        df['suggestions'] = df.apply(suggest, axis=1)
    ts = datetime.datetime.utcnow().strftime('%Y%m%dT%H%MZ')
    csv = f'vapt_report_{target}_{ts}.csv'
    html = f'vapt_report_{target}_{ts}.html'
    df.to_csv(csv, index=False)
    body = df.to_html(index=False)
    soup = BeautifulSoup(f"""<html><head><meta charset='utf-8'><title>Report</title></head><body>
    <h1>VAPT Report - {target}</h1><p>Generated: {ts} UTC</p>{body}
    <p>Run further checks manually; do not exploit without permission.</p></body></html>""", 'html.parser')
    with open(html, 'w') as f:
        f.write(str(soup))
    print(csv, html)

def main():
    if len(sys.argv) < 2:
        print('Usage: python vapt_scanner.py <target>')
        sys.exit(1)
    target = sys.argv[1].replace('/', '_')
    xml = run_nmap(target)
    rows = parse_xml(xml)
    write_reports(rows, target)

if __name__ == '__main__':
    main()
