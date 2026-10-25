"""Fabrication de GPO de test : Registry.pol, GptTmpl.inf, fichiers VGP et préférences."""
import os
import struct

REG_SZ, REG_DWORD, REG_MULTI_SZ = 1, 4, 7


def pol(entrees) -> bytes:
    """[(clé, nom, type, donnée)] → contenu d’un Registry.pol."""
    b = b'PReg' + struct.pack('<I', 1)
    for cle, nom, typ, v in entrees:
        if typ == REG_DWORD:
            d = struct.pack('<I', v)
        elif typ == REG_MULTI_SZ:
            d = ''.join(x + '\0' for x in v).encode('utf-16-le') + b'\0\0'
        else:
            d = (str(v) + '\0').encode('utf-16-le')
        u = lambda s: s.encode('utf-16-le')
        b += u('[') + u(cle + '\0') + u(';') + u(nom + '\0') + u(';') + struct.pack('<I', typ) + u(';') + struct.pack('<I', len(d)) + u(';') + d + u(']')
    return b


def ecrire(racine, relatif, contenu):
    p = os.path.join(racine, relatif)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, 'wb') as fh:
        fh.write(contenu if isinstance(contenu, bytes) else contenu.encode('utf-8'))
    return p


def inf(sections: dict) -> bytes:
    t = '[Unicode]\r\nUnicode=yes\r\n' + ''.join(f'[{s}]\r\n' + ''.join(f'{k} = {v}\r\n' for k, v in d.items()) for s, d in sections.items())
    return b'\xff\xfe' + t.encode('utf-16-le')


def vgp(contenu_data: str) -> str:
    return ('<?xml version="1.0" encoding="UTF-8"?>\n<vgppolicy><policysetting><version>1</version><name>x</name>'
            f'<description>x</description><apply_mode>merge</apply_mode><data>{contenu_data}</data></policysetting></vgppolicy>')
