"""Lecture des fichiers de stratégie : Registry.pol (format PReg) et GptTmpl.inf."""
from __future__ import annotations

import struct

REG_SZ, REG_EXPAND_SZ, REG_BINARY, REG_DWORD, REG_DWORD_BE, REG_MULTI_SZ, REG_QWORD = 1, 2, 3, 4, 5, 7, 11


def _valeur(typ: int, b: bytes):
    if typ in (REG_SZ, REG_EXPAND_SZ):
        return b.decode('utf-16-le', 'replace').split('\x00')[0]
    if typ == REG_DWORD and len(b) >= 4:
        return struct.unpack('<I', b[:4])[0]
    if typ == REG_DWORD_BE and len(b) >= 4:
        return struct.unpack('>I', b[:4])[0]
    if typ == REG_QWORD and len(b) >= 8:
        return struct.unpack('<Q', b[:8])[0]
    if typ == REG_MULTI_SZ:
        return [x for x in b.decode('utf-16-le', 'replace').split('\x00') if x]
    return b


def lire_pol(donnees: bytes) -> list[tuple[str, str, int, object]]:
    """Entrées (clé, nom de valeur, type, donnée) dans l’ordre du fichier."""
    if donnees[:4] != b'PReg':
        raise ValueError('fichier Registry.pol invalide')
    res, i, n = [], 8, len(donnees)

    def chaine(i):
        j = i
        while j + 1 < n and donnees[j:j + 2] != b'\0\0':
            j += 2
        return donnees[i:j].decode('utf-16-le', 'replace'), j + 2

    while i + 2 <= n:
        if donnees[i:i + 2] != b'[\0':
            i += 1
            continue
        cle, i = chaine(i + 2)
        i += 2  # ;
        nom, i = chaine(i)
        i += 2
        typ, = struct.unpack('<I', donnees[i:i + 4])
        i += 6
        taille, = struct.unpack('<I', donnees[i:i + 4])
        i += 6
        b = donnees[i:i + taille]
        i += taille + 2  # ]
        res.append((cle, nom, typ, _valeur(typ, b)))
    return res


def lire_inf(donnees: bytes) -> dict[str, dict[str, str]]:
    """GptTmpl.inf (UTF-16 ou UTF-8) → {section en minuscules: {clé en minuscules: valeur brute}}."""
    if donnees[:2] in (b'\xff\xfe', b'\xfe\xff'):
        texte = donnees.decode('utf-16')
    else:
        texte = donnees.decode('utf-8-sig', 'replace')
    res, section = {}, None
    for ligne in texte.splitlines():
        ligne = ligne.strip()
        if not ligne or ligne.startswith(';'):
            continue
        if ligne.startswith('[') and ligne.endswith(']'):
            section = res.setdefault(ligne[1:-1].strip().lower(), {})
        elif section is not None and '=' in ligne:
            k, v = ligne.split('=', 1)
            section[k.strip().lower()] = v.strip()
    return res
