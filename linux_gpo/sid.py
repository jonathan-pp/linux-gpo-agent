"""SID et descripteurs de sécurité (filtrage de sécurité des GPO : droit « Appliquer la stratégie de groupe »)."""
from __future__ import annotations

import struct
import uuid

APPLIQUER_GPO = uuid.UUID('edacfd8f-ffb3-11d1-b41d-00a0c968f939')
LIRE_PROP = 0x10
DROIT_ETENDU = 0x100
GENERIQUE_LECTURE = 0x80000000
GENERIQUE_TOUT = 0x10000000
INHERIT_ONLY = 0x08
TOUT_LE_MONDE = 'S-1-1-0'
UTILISATEURS_AUTHENTIFIES = 'S-1-5-11'


def sid_texte(b: bytes) -> str:
    if len(b) < 8:
        raise ValueError('SID trop court')
    rev, n = b[0], b[1]
    autorite = int.from_bytes(b[2:8], 'big')
    sous = struct.unpack('<' + 'I' * n, b[8:8 + 4 * n])
    return f'S-{rev}-{autorite}' + ''.join(f'-{x}' for x in sous)


def sid_binaire(s: str) -> bytes:
    p = s.split('-')
    sous = [int(x) for x in p[3:]]
    return bytes([int(p[1]), len(sous)]) + int(p[2]).to_bytes(6, 'big') + struct.pack('<' + 'I' * len(sous), *sous)


def filtre_sid(s: str) -> str:
    """objectSid=… pour un filtre LDAP (octets échappés)."""
    return ''.join('\\%02x' % c for c in sid_binaire(s))


def _aces(sd: bytes):
    """ACE du DACL d’un descripteur auto-relatif : (type, drapeaux, masque, type d’objet ou None, SID)."""
    if len(sd) < 20:
        return
    off_dacl = struct.unpack('<I', sd[16:20])[0]
    if not off_dacl:
        return
    _, _, _, n, _ = struct.unpack('<BBHHH', sd[off_dacl:off_dacl + 8])
    i = off_dacl + 8
    for _ in range(n):
        typ, fl, taille = struct.unpack('<BBH', sd[i:i + 4])
        corps = sd[i + 4:i + taille]
        masque = struct.unpack('<I', corps[:4])[0]
        objet = None
        if typ in (5, 6):  # ACE objet (autorisation / refus)
            drapeaux = struct.unpack('<I', corps[4:8])[0]
            j = 8
            if drapeaux & 1:
                objet = uuid.UUID(bytes_le=corps[j:j + 16])
                j += 16
            if drapeaux & 2:
                j += 16
            sid = sid_texte(corps[j:])
        elif typ in (0, 1):
            sid = sid_texte(corps[4:])
        else:
            i += taille
            continue
        yield typ, fl, masque, objet, sid
        i += taille


def peut_appliquer(sd: bytes, sids: set[str]) -> bool:
    """Le jeton (ensemble de SID) a-t-il la lecture et le droit « Appliquer la stratégie de groupe » ?
    Évaluation dans l’ordre du DACL, comme Windows : le premier ACE qui décide d’un droit l’emporte."""
    accorde = refuse = 0
    for typ, fl, masque, objet, sid in _aces(sd):
        if fl & INHERIT_ONLY or sid not in sids:
            continue
        m = masque
        if m & (GENERIQUE_LECTURE | GENERIQUE_TOUT):
            m |= LIRE_PROP
        if m & GENERIQUE_TOUT:
            m |= DROIT_ETENDU
        if objet is not None:
            # ACE limité à un droit étendu ou un attribut : ne compte que pour « Appliquer la stratégie »
            m &= DROIT_ETENDU if objet == APPLIQUER_GPO else 0
        m &= LIRE_PROP | DROIT_ETENDU
        if typ in (0, 5):
            accorde |= m & ~refuse
        else:
            refuse |= m & ~accorde
    return (accorde & (LIRE_PROP | DROIT_ETENDU)) == (LIRE_PROP | DROIT_ETENDU)
