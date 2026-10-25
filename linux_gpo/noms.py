"""Correspondance entre les comptes du domaine (DOMAINE\\nom, SID) et leurs noms sur le poste.

Le nom d’un compte du domaine dépend de la jonction : « DOMAINE\\nom » (winbind), « nom@domaine.local »
(sssd par défaut) ou « nom » (use_fully_qualified_names = False, winbind use default domain = yes).
On essaie les formes possibles et on garde celle que le système connaît.
"""
from __future__ import annotations

import grp
import logging
import pwd

from .annuaire import un
from .sid import filtre_sid

journal = logging.getLogger('linux-gpo')
# groupes intégrés de Windows → groupes d’administration habituels sous Linux
ADMINS_LOCAUX = ['sudo', 'wheel', 'admin']
SID_INTEGRES = {
    'S-1-5-32-544': '@admins',        # Administrateurs
    'S-1-5-32-545': '@tous',          # Utilisateurs
    'S-1-1-0': '@tous',               # Tout le monde
    'S-1-5-11': '@tous',              # Utilisateurs authentifiés
    'S-1-5-32-555': None,             # Utilisateurs du Bureau à distance
    'S-1-5-32-551': None,             # Opérateurs de sauvegarde
}


class Noms:
    def __init__(self, conf, annuaire=None):
        self.domaine = conf.domaine
        self.nb = conf.options.get('netbios', '') or conf.domaine.split('.')[0].upper()
        self.annuaire = annuaire
        self._cache = {}

    def _formes(self, nom: str) -> list[str]:
        nb, _, sam = nom.rpartition('\\')
        nb = nb or self.nb
        return [f'{nb}\\{sam}', f'{sam}@{self.domaine}', f'{sam}@{self.domaine.upper()}', sam, sam.lower(),
                f'{nb.lower()}\\{sam.lower()}', f'{sam.lower()}@{self.domaine}']

    def local(self, nom: str, groupe: bool) -> str | None:
        """Nom connu du système pour DOMAINE\\nom (ou None si le compte est inconnu sur ce poste)."""
        cle = (nom.lower(), groupe)
        if cle in self._cache:
            return self._cache[cle]
        res = None
        for f in self._formes(nom):
            try:
                res = grp.getgrnam(f).gr_name if groupe else pwd.getpwnam(f).pw_name
                break
            except KeyError:
                continue
        self._cache[cle] = res
        return res

    def nom_de_sid(self, sid: str) -> tuple[str, bool] | None:
        """(DOMAINE\\nom, est un groupe) d’après l’annuaire."""
        if not self.annuaire:
            return None
        r = self.annuaire.chercher(self.annuaire.conf.base, f'(objectSid={filtre_sid(sid)})', ['sAMAccountName', 'objectClass'],
                                   portee='sub')
        if not r:
            return None
        classes = [c.decode().lower() for c in r[0].get('objectclass', [])]
        return f'{self.nb}\\{un(r[0], "samaccountname")}', 'group' in classes

    def local_de_sid(self, sid: str) -> tuple[str, bool] | None:
        """Nom local (nom, est un groupe) d’un SID ; les SID intégrés donnent '@admins' ou '@tous'."""
        sid = sid.lstrip('*').strip()
        if sid in SID_INTEGRES:
            return (SID_INTEGRES[sid], True) if SID_INTEGRES[sid] else None
        n = self.nom_de_sid(sid)
        if not n:
            return None
        loc = self.local(n[0], n[1])
        return (loc, n[1]) if loc else None


def admins_locaux() -> list[str]:
    res = []
    for g in ADMINS_LOCAUX:
        try:
            grp.getgrnam(g)
            res.append(g)
        except KeyError:
            continue
    return res


def echapper_sudo(nom: str) -> str:
    return ''.join('\\' + c if c in '\\ ,:=()!#"' else c for c in nom)
