"""Configuration de l’agent : /etc/linux-gpo/agent.conf, sinon détection automatique du domaine.

    [agent]
    domaine = exemple.local          # nom DNS du domaine (détecté depuis sssd, Samba, krb5 ou le nom du poste)
    serveur = dc01.exemple.local     # contrôleur à utiliser (sinon : enregistrements DNS SRV du domaine)
    keytab = /etc/krb5.keytab        # clés du compte machine, créées par la jonction au domaine
    compte = PC01$                   # compte machine (par défaut : nom court du poste en majuscules + $)
"""
from __future__ import annotations

import configparser
import os
import re
import socket
from dataclasses import dataclass, field

from .systeme import chemin, lancer

FICHIER = '/etc/linux-gpo/agent.conf'
CACHE = '/var/cache/linux-gpo'
ETAT = '/var/lib/linux-gpo'


@dataclass
class Conf:
    domaine: str
    serveur: str = ''
    keytab: str = '/etc/krb5.keytab'
    compte: str = ''
    cache: str = CACHE
    etat: str = ETAT
    options: dict = field(default_factory=dict)

    @property
    def royaume(self) -> str:
        return self.domaine.upper()

    @property
    def base(self) -> str:
        return ','.join('DC=' + x for x in self.domaine.split('.'))


def _ini(f: str) -> configparser.ConfigParser:
    cp = configparser.ConfigParser(interpolation=None, strict=False)
    try:
        cp.read(chemin(f), encoding='utf-8')
    except (configparser.Error, UnicodeDecodeError):
        pass
    return cp


def _domaine_detecte() -> str:
    cp = _ini('/etc/sssd/sssd.conf')
    for s in cp.sections():
        if s.startswith('domain/'):
            d = cp.get(s, 'ad_domain', fallback='') or (s[7:] if '.' in s else '')
            if d:
                return d
    cp = _ini('/etc/samba/smb.conf')
    if cp.get('global', 'realm', fallback=''):
        return cp.get('global', 'realm')
    try:
        with open(chemin('/etc/krb5.conf'), encoding='utf-8') as fh:
            m = re.search(r'^\s*default_realm\s*=\s*(\S+)', fh.read(), re.M)
            if m:
                return m.group(1)
    except OSError:
        pass
    fq = socket.getfqdn()
    return fq.split('.', 1)[1] if '.' in fq else ''


def compte_machine() -> str:
    nom = socket.gethostname().split('.')[0]
    return nom.upper()[:15] + '$'


def charger(f: str = FICHIER) -> Conf:
    cp = _ini(f)
    a = cp['agent'] if cp.has_section('agent') else {}
    domaine = (a.get('domaine') or _domaine_detecte()).lower()
    c = Conf(domaine=domaine, serveur=a.get('serveur', ''), keytab=a.get('keytab', '/etc/krb5.keytab'),
             compte=a.get('compte', '') or compte_machine(), cache=a.get('cache', CACHE), etat=a.get('etat', ETAT),
             options={k: v for k, v in a.items()})
    return c


def sssd_controle_gpo() -> bool:
    """Vrai si sssd applique déjà lui-même les droits d’ouverture de session des GPO Windows."""
    cp = _ini('/etc/sssd/sssd.conf')
    for s in cp.sections():
        if s.startswith('domain/') and cp.get(s, 'id_provider', fallback='') == 'ad':
            return cp.get(s, 'ad_gpo_access_control', fallback='enforcing').strip() == 'enforcing'
    return False


def jonction() -> str:
    """sssd, winbind ou '' selon le mode de jonction détecté."""
    if os.path.exists(chemin('/etc/sssd/sssd.conf')):
        return 'sssd'
    if lancer(['wbinfo', '--ping-dc']).returncode == 0 or os.path.exists(chemin('/etc/samba/smb.conf')):
        return 'winbind'
    return ''
