"""Extensions : chacune traduit une famille de paramètres de GPO en configuration Linux.

Une extension déclare ses fichiers dans `appliquer` (via ctx.f) ; après le passage, `apres` reçoit la liste
des fichiers modifiés ou retirés pour recharger les services concernés.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field

journal = logging.getLogger('linux-gpo')

# clés de registre lues
K_SAMBA = r'Software\Policies\Samba\Unix Settings'
K_LGPO = r'Software\Policies\LinuxGPO'
K_WIN_SYS = r'Software\Microsoft\Windows\CurrentVersion\Policies\System'
K_WIN_EXPL = r'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
INF_SYS = 'MACHINE\\' + K_WIN_SYS


@dataclass
class Contexte:
    conf: object
    pol: object                  # Politique
    f: object                    # Fichiers
    noms: object                 # Noms
    annuaire: object = None      # Annuaire (None hors ligne)
    simuler: bool = False
    utilisateur: str = ''        # mode utilisateur : nom du compte
    sid_domaine: str = ''        # S-1-5-21-… du domaine
    jeton: set = field(default_factory=set)   # SID du compte et de ses groupes
    ouverture: bool = False      # mode utilisateur : passage d’ouverture de session
    rapport: dict = field(default_factory=dict)

    def admins_domaine(self) -> list[str]:
        """Nom local du groupe « Admins du domaine » (SID …-512), s’il est connu du poste."""
        if self.sid_domaine and self.annuaire:
            n = self.noms.local_de_sid(self.sid_domaine + '-512')
            return [n[0]] if n else []
        return [n for n in [self.noms.local(f'{self.noms.nb}\\Domain Admins', True)] if n]

    def noter(self, ext: str, texte: str) -> None:
        """Ligne du rapport (affiché par « linux-gpo resultat »)."""
        self.rapport.setdefault(ext, []).append(texte)


class Extension:
    nom = ''
    machine = True

    def appliquer(self, ctx: Contexte) -> None:
        raise NotImplementedError

    def apres(self, ctx: Contexte, changes: list[str]) -> None:
        pass


def extensions(machine: bool = True) -> list[Extension]:
    from . import (acces, bureau, deploiement, heure, logiciels, messages, mises_a_jour, navigateurs, parefeu,
                   permissions, raccourcis, scripts, ssh, sudo, utilisateur)
    if not machine:
        return [utilisateur.BureauUtilisateur(), utilisateur.Lecteurs(), raccourcis.Raccourcis(), utilisateur.ScriptsSession()]
    return [messages.Messages(), sudo.Sudo(), acces.Acces(), ssh.Ssh(), parefeu.Parefeu(), scripts.Scripts(),
            deploiement.Deploiement(), navigateurs.Navigateurs(), bureau.Bureau(), permissions.Permissions(),
            mises_a_jour.MisesAJour(), logiciels.Logiciels(), heure.Heure()]


def vrai(v) -> bool:
    if isinstance(v, int):
        return v != 0
    return str(v or '').strip().lower() in ('1', 'true', 'oui', 'yes')


def texte(v) -> str:
    """Texte d’une valeur de registre (REG_MULTI_SZ : une ligne par élément)."""
    if isinstance(v, (list, tuple)):
        return '\n'.join(str(x) for x in v)
    return '' if v is None else str(v)


def entier(v, defaut: int = 0) -> int:
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return defaut
