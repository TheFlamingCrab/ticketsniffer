import pyshark

cap = pyshark.FileCapture('/home/htb-ac-369790/Downloads/capture.pcapng')
for packet in cap:
    if 'KERBEROS' in packet:
        print('KERBEROS TICKET FOUND')
        if packet.kerberos.msg_type == '13':
            print('ENCRYPTION TYPE IS', packet.kerberos.etype)
            print('FOUND TSG-REP')
            #print(packet.kerberos._all_fields)
            #cipher = packet.kerberos.cipher.replace(':', '')
            #user = packet.kerberos.cnamestring
            #print(user)
            #realm = packet.kerberos.realm
            #print(realm)
            #print(packet.kerberos.sname._all_fields)
            #sname = packet.kerberos.SNameString
            #print(sname)
            #etype = packet.kerberos.etype
            #print(etype)
            kerberos_layer = packet.kerberos
            for field in kerberos_layer.field_names:
                if 'sname_string' in field:
                    field_value = getattr(kerberos_layer, field)
                    print(field_value)
            print(packet.kerberos.field_names)
            print(packet.kerberos.snamestring)
            print(packet.kerberos.sname_string)
            print('.'.join(packet.kerberos.sname_string))
            #print(f'$krb5tgs${etype}$*blah${realm}$blahspn${cipher}'):
