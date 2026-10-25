"""Requête DNS SRV minimale (sans dépendance) pour trouver les contrôleurs de domaine."""
from __future__ import annotations

import random
import socket
import struct

from .systeme import chemin


def serveurs_dns() -> list[str]:
    s = []
    try:
        with open(chemin('/etc/resolv.conf'), encoding='utf-8') as fh:
            for ligne in fh:
                p = ligne.split()
                if len(p) >= 2 and p[0] == 'nameserver':
                    s.append(p[1])
    except OSError:
        pass
    return s or ['127.0.0.1']


def _nom(donnees: bytes, i: int) -> tuple[str, int]:
    morceaux, fin, sauts = [], None, 0
    while True:
        n = donnees[i]
        if n == 0:
            i += 1
            break
        if n & 0xC0 == 0xC0:  # pointeur de compression
            if fin is None:
                fin = i + 2
            i = struct.unpack('>H', donnees[i:i + 2])[0] & 0x3FFF
            sauts += 1
            if sauts > 50:
                raise ValueError('réponse DNS invalide')
            continue
        morceaux.append(donnees[i + 1:i + 1 + n].decode('ascii', 'replace'))
        i += 1 + n
    return '.'.join(morceaux), (fin if fin is not None else i)


def srv(nom: str, delai: float = 3.0) -> list[tuple[int, int, int, str]]:
    """Enregistrements SRV (priorité, poids, port, cible), triés par priorité puis poids aléatoire."""
    ident = random.randint(0, 0xFFFF)
    q = struct.pack('>HHHHHH', ident, 0x0100, 1, 0, 0, 0)
    q += b''.join(bytes([len(p)]) + p.encode('ascii') for p in nom.rstrip('.').split('.')) + b'\0'
    q += struct.pack('>HH', 33, 1)
    for serveur in serveurs_dns():
        famille = socket.AF_INET6 if ':' in serveur else socket.AF_INET
        try:
            with socket.socket(famille, socket.SOCK_DGRAM) as s:
                s.settimeout(delai)
                s.sendto(q, (serveur, 53))
                r = s.recv(4096)
        except OSError:
            continue
        if len(r) < 12 or struct.unpack('>H', r[:2])[0] != ident:
            continue
        nq, nr = struct.unpack('>HH', r[4:8])
        i = 12
        for _ in range(nq):
            _, i = _nom(r, i)
            i += 4
        res = []
        for _ in range(nr):
            _, i = _nom(r, i)
            typ, _, _, lg = struct.unpack('>HHIH', r[i:i + 10])
            i += 10
            if typ == 33:
                prio, poids, port = struct.unpack('>HHH', r[i:i + 6])
                cible, _ = _nom(r, i + 6)
                res.append((prio, poids, port, cible))
            i += lg
        if res:
            return sorted(res, key=lambda x: (x[0], -x[1] * random.random()))
    return []


def controleurs(domaine: str) -> list[str]:
    return [c for _, _, _, c in srv(f'_ldap._tcp.dc._msdcs.{domaine}')] or \
           [c for _, _, _, c in srv(f'_ldap._tcp.{domaine}')]
