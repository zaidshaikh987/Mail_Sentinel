"""Controlled Postfix/Dovecot captures. No real accounts, delivery or external network.
A seed corpus, not a representative benchmark. Ground truth is the configuration.
"""
import imaplib
import json
import poplib
import signal
import smtplib
import ssl
import subprocess
import time
from pathlib import Path


def command(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL)


def main():
    output = Path('/output')
    output.mkdir(exist_ok=True)
    command('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', '/tmp/mail.key',
            '-out', '/tmp/mail.crt', '-days', '30', '-subj', '/CN=mail.lab', '-addext', 'subjectAltName=DNS:mail.lab')
    with open('/etc/hosts', 'a') as hosts:
        hosts.write('\n127.0.0.1 mail.lab\n')
    Path('/etc/dovecot/dovecot.conf').write_text('''protocols = imap pop3
listen = 127.0.0.1
ssl = yes
ssl_cert = </tmp/mail.crt
ssl_key = </tmp/mail.key
ssl_min_protocol = TLSv1.2
mail_location = maildir:/tmp/mailbox
passdb {
 driver = static
 args = password=lab-only
}
userdb {
 driver = static
 args = uid=nobody gid=nogroup home=/tmp
}
''')
    command('postconf', '-e', 'inet_interfaces=loopback-only', 'myhostname=mail.lab',
            'smtpd_tls_security_level=may', 'smtpd_tls_cert_file=/tmp/mail.crt',
            'smtpd_tls_key_file=/tmp/mail.key', 'smtpd_tls_protocols=>=TLSv1.2', 'maillog_file=/dev/stdout')
    dovecot = subprocess.Popen(['dovecot', '-F'])
    command('postfix', 'start')
    entries = []
    try:
        time.sleep(2)
        for protocol, port in [('smtp', 25), ('imap', 143), ('pop3', 110)]:
            for mode in ['cleartext', 'tls12', 'tls13']:
                for batch in range(3):
                    name = f'{protocol}-{mode}-{batch}.pcap'
                    log = output / f'{name}.capture.log'
                    with log.open('w') as diagnostics:
                        recorder = subprocess.Popen(['tcpdump', '-i', 'lo', '-U', '-s', '0', '-w', str(output / name), 'tcp', 'port', str(port)], stderr=diagnostics)
                        time.sleep(.4)
                        try:
                            if recorder.poll() is not None:
                                raise RuntimeError(f'tcpdump failed; see {log}')
                            for _ in range(8):
                                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                                # Only this isolated fixture client accepts the deliberately self-signed certificate.
                                context.check_hostname = False
                                context.verify_mode = ssl.CERT_NONE
                                version = ssl.TLSVersion.TLSv1_2 if mode == 'tls12' else ssl.TLSVersion.TLSv1_3
                                context.minimum_version = context.maximum_version = version
                                if protocol == 'smtp':
                                    client = smtplib.SMTP('mail.lab', port, timeout=10)
                                    client.ehlo()
                                    if mode != 'cleartext': client.starttls(context=context); client.ehlo()
                                    client.noop(); client.quit()
                                elif protocol == 'imap':
                                    client = imaplib.IMAP4('mail.lab', port, timeout=10)
                                    if mode != 'cleartext': client.starttls(ssl_context=context)
                                    client.noop(); client.logout()
                                else:
                                    client = poplib.POP3('mail.lab', port, timeout=10)
                                    client.capa()
                                    if mode != 'cleartext': client.stls(context=context)
                                    client.noop(); client.quit()
                            time.sleep(.3)
                        finally:
                            recorder.send_signal(signal.SIGINT)
                            recorder.wait(timeout=10)
                    entries.append({'path': name, 'configuration_id': f'{protocol}-{mode}',
                                    'label': 'critical' if mode == 'cleartext' else 'weak',
                                    'ground_truth': {'server': 'Postfix' if protocol == 'smtp' else 'Dovecot',
                                                     'protocol': protocol, 'tls': mode, 'certificate': 'self_signed',
                                                     'authentication': 'none; no messages or real credentials',
                                                     'scope': 'controlled lab posture; cleartext labelled critical by classifier definition'}})
        (output / 'manifest.json').write_text(json.dumps({'captures': entries}, indent=2))
    finally:
        command('postfix', 'stop')
        dovecot.terminate(); dovecot.wait(timeout=10)

if __name__ == '__main__':
    main()
