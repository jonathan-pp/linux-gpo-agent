"""Accès au domaine avec Kerberos : LDAP (ldapsearch) et SYSVOL (smbclient).

Le compte machine s’authentifie avec son keytab dans un cache de tickets privé, comme le fait Windows
avec le compte d’ordinateur ; en mode utilisateur, le ticket de la session de l’utilisateur est utilisé.
"""
from __future__ import annotations

import base64
import logging
import os
import re
import shutil
import tempfile

from . import dns
from .systeme import ErreurAgent, lancer

journal = logging.getLogger('linux-gpo')
# contrôle LDAP « SD flags » : DACL seulement (BER de SEQUENCE { INTEGER 4 })
SD_DACL = '!1.2.840.113556.1.4.801=::MAMCAQQ='


class Annuaire:
    def __init__(self, conf, ccache: str | None = None):
        self.conf = conf
        self.env = {}
        self._prive = None
        if ccache:
            self.env['KRB5CCNAME'] = ccache
        self.serveur = conf.serveur
        self._smb_kerberos = None

    # ------------------------------------------------------------ Kerberos
    def connexion_machine(self) -> None:
        """Ticket du compte machine depuis le keytab, dans un cache privé (supprimé à la fin)."""
        if not os.path.exists(self.conf.keytab):
            raise ErreurAgent(f'{self.conf.keytab} introuvable : le poste est-il joint au domaine (realm join, net ads join) ?')
        self._prive = tempfile.mkdtemp(prefix='linux-gpo-')
        cc = 'FILE:' + os.path.join(self._prive, 'krb5cc')
        self.env['KRB5CCNAME'] = cc
        principal = f'{self.conf.compte}@{self.conf.royaume}'
        r = lancer(['kinit', '-k', '-t', self.conf.keytab, principal], env=self.env, delai=30)
        if r.returncode:
            raise ErreurAgent(f'kinit {principal} : {(r.stderr or r.stdout).strip()}')

    def fermer(self) -> None:
        if self._prive:
            lancer(['kdestroy'], env=self.env)
            shutil.rmtree(self._prive, ignore_errors=True)
            self._prive = None

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.fermer()

    # ------------------------------------------------------------ contrôleur
    def controleur(self) -> str:
        if not self.serveur:
            dcs = dns.controleurs(self.conf.domaine)
            for dc in dcs:
                if self._joignable(dc):
                    self.serveur = dc
                    break
            else:
                self.serveur = dcs[0] if dcs else self.conf.domaine
        return self.serveur

    @staticmethod
    def _joignable(hote: str) -> bool:
        import socket
        try:
            with socket.create_connection((hote, 389), timeout=3):
                return True
        except OSError:
            return False

    # ------------------------------------------------------------ LDAP
    def chercher(self, base: str, filtre: str = '(objectClass=*)', attrs: list[str] | None = None,
                 portee: str = 'base', controles: list[str] | None = None) -> list[dict]:
        cmd = ['ldapsearch', '-LLL', '-Q', '-N', '-Y', 'GSSAPI', '-o', 'ldif-wrap=no', '-o', 'nettimeout=15',
               '-H', f'ldap://{self.controleur()}', '-b', base, '-s', portee]
        for c in controles or []:
            cmd += ['-E', c]
        cmd += [filtre] + (attrs or [])
        r = lancer(cmd, env=self.env, delai=60)
        if r.returncode == 32:  # objet absent
            return []
        if r.returncode:
            raise ErreurAgent(f'LDAP ({self.serveur}) : {(r.stderr or r.stdout).strip()[-300:]}')
        return ldif(r.stdout)

    # ------------------------------------------------------------ SYSVOL
    def _smb(self, partage: str, commandes: str, dossier: str = '') -> str:
        hote = self.controleur()
        base = ['smbclient', f'//{hote}/{partage}']
        if self._smb_kerberos is None:
            aide = lancer(['smbclient', '--help'])
            self._smb_kerberos = ['--use-kerberos=required'] if '--use-kerberos' in aide.stdout + aide.stderr else ['-k']
        cmd = base + self._smb_kerberos + (['-D', dossier] if dossier else []) + ['-c', commandes]
        r = lancer(cmd, env=self.env, delai=300)
        if r.returncode:
            raise ErreurAgent(f'SMB //{hote}/{partage} : {(r.stderr or r.stdout).strip()[-300:]}')
        return r.stdout

    def copier_dossier(self, chemin_unc: str, destination: str) -> None:
        """Copie récursive d’un dossier \\\\serveur\\partage\\chemin (le serveur est remplacé par le contrôleur)."""
        partage, dossier = _unc(chemin_unc)
        os.makedirs(destination, exist_ok=True)
        self._smb(partage, f'prompt OFF; recurse ON; lcd "{destination}"; mget *', dossier)

    def copier_fichier(self, chemin_unc: str, destination: str) -> None:
        hote, partage, chemin = _unc_complet(chemin_unc)
        dossier, nom = os.path.split(chemin.replace('\\', '/'))
        if hote and hote.lower() not in (self.conf.domaine, self.conf.domaine.split('.')[0]) and hote.lower() != self.controleur().lower():
            # serveur de fichiers autre que le contrôleur
            serveur, self.serveur = self.serveur, hote
            try:
                self._smb(partage, f'get "{nom}" "{destination}"', dossier)
            finally:
                self.serveur = serveur
        else:
            self._smb(partage, f'get "{nom}" "{destination}"', dossier)
        if not os.path.exists(destination):
            raise ErreurAgent(f'{chemin_unc} : fichier introuvable')


def _unc_complet(p: str) -> tuple[str, str, str]:
    m = re.match(r'^[\\/]{2}([^\\/]+)[\\/]+([^\\/]+)[\\/]*(.*)$', p.strip())
    if not m:
        raise ErreurAgent(f'chemin réseau invalide : {p}')
    return m.group(1), m.group(2), m.group(3).replace('\\', '/')


def _unc(p: str) -> tuple[str, str]:
    _, partage, chemin = _unc_complet(p)
    return partage, chemin


def ldif(texte: str) -> list[dict]:
    """Entrées LDIF → [{'dn': str, 'attribut en minuscules': [bytes, …]}]."""
    entrees, cur = [], None
    for ligne in texte.split('\n'):
        if not ligne.strip():
            if cur:
                entrees.append(cur)
            cur = None
            continue
        if ligne.startswith('#'):
            continue
        if ligne.startswith(' ') and cur is not None:  # suite de ligne (ne devrait pas arriver avec ldif-wrap=no)
            continue
        if ':' not in ligne:
            continue
        k, v = ligne.split(':', 1)
        if v.startswith(':'):
            val = base64.b64decode(v[1:].strip())
        elif v.startswith('<'):
            continue
        else:
            val = v[1:].encode('utf-8') if v.startswith(' ') else v.encode('utf-8')
        k = k.lower()
        if k == 'ref':
            cur = None
            continue
        if k == 'dn':
            cur = {'dn': val.decode('utf-8')}
        elif cur is not None:
            cur.setdefault(k, []).append(val)
    if cur:
        entrees.append(cur)
    return entrees


def un(e: dict, attr: str, defaut: str = '') -> str:
    v = e.get(attr.lower())
    return v[0].decode('utf-8', 'replace') if v else defaut


def separer_dn(dn: str) -> list[str]:
    """Composants d’un DN, en respectant les virgules échappées."""
    return [x for x in re.split(r'(?<!\\),', dn) if x]


def parents(dn: str) -> list[str]:
    """DN des conteneurs parents, du plus proche au domaine."""
    p = separer_dn(dn)
    return [','.join(p[i:]) for i in range(1, len(p)) if p[i].upper().startswith(('OU=', 'DC=', 'CN='))]


def echapper_filtre(v: str) -> str:
    return ''.join('\\%02x' % ord(c) if c in '*()\\\x00' else c for c in v)
