"""Fichiers gérés par l’agent.

À chaque passage, les extensions déclarent les fichiers (ou blocs dans un fichier existant) qu’elles veulent ;
à la fin, tout ce que l’agent avait écrit et qui n’est plus demandé est retiré : le fichier d’origine est
remis s’il existait, sinon le fichier est supprimé. Une stratégie retirée de la GPO disparaît donc du poste,
comme sous Windows.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import pwd
import grp
import shutil
import tempfile

from .systeme import chemin as reel

journal = logging.getLogger('linux-gpo')
DEBUT, FIN = '>>> linux-gpo : ne pas modifier ce bloc, il est géré par les stratégies de groupe', '<<< linux-gpo'


def _empreinte(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _lire(p: str) -> bytes | None:
    try:
        with open(reel(p), 'rb') as fh:
            return fh.read()
    except OSError:
        return None


class Fichiers:
    def __init__(self, dossier_etat: str, simuler: bool = False):
        self.dossier = dossier_etat
        self.simuler = simuler
        self.fichier_etat = os.path.join(dossier_etat, 'etat.json')
        try:
            with open(self.fichier_etat, encoding='utf-8') as fh:
                self.etat = json.load(fh)
        except (OSError, ValueError):
            self.etat = {}
        self.etat.setdefault('fichiers', {})
        self.etat.setdefault('ext', {})
        self.demandes: dict[str, str] = {}   # chemin → extension
        self.changes: dict[str, str] = {}    # chemin → extension
        self.gardees: set[str] = set()

    # ------------------------------------------------------------ état propre aux extensions
    def memoire(self, ext: str) -> dict:
        return self.etat['ext'].setdefault(ext, {})

    # ------------------------------------------------------------ écriture
    def _sauvegarder(self, p: str, ext: str, genre: str) -> None:
        if p in self.etat['fichiers']:
            return
        sauvegarde = None
        if os.path.lexists(reel(p)) and genre != 'bloc':
            sauvegarde = os.path.join(self.dossier, 'sauvegardes', p.strip('/').replace('/', '%'))
            if not self.simuler:
                os.makedirs(os.path.dirname(sauvegarde), mode=0o700, exist_ok=True)
                if os.path.islink(reel(p)):
                    if os.path.lexists(sauvegarde):
                        os.unlink(sauvegarde)
                    os.symlink(os.readlink(reel(p)), sauvegarde)
                else:
                    shutil.copy2(reel(p), sauvegarde)
        self.etat['fichiers'][p] = {'ext': ext, 'genre': genre, 'sauvegarde': sauvegarde}

    def _poser(self, p: str, donnees: bytes, mode: int, proprio: str | None) -> None:
        r = reel(p)
        os.makedirs(os.path.dirname(r), mode=0o755, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(r), prefix='.linux-gpo-')
        try:
            with os.fdopen(fd, 'wb') as fh:
                fh.write(donnees)
            os.chmod(tmp, mode)
            if proprio:
                u, _, g = proprio.partition(':')
                os.chown(tmp, pwd.getpwnam(u).pw_uid if u else -1, grp.getgrnam(g).gr_gid if g else -1)
            if os.path.islink(r):
                os.unlink(r)
            os.replace(tmp, r)
        except BaseException:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise

    def ecrire(self, p: str, contenu: str | bytes, ext: str, mode: int = 0o644, proprio: str | None = None) -> bool:
        donnees = contenu.encode('utf-8') if isinstance(contenu, str) else contenu
        self.demandes[p] = ext
        actuel = _lire(p)
        meta_ok = True
        if actuel is not None:
            try:
                st = os.stat(reel(p))
                meta_ok = (st.st_mode & 0o7777) == mode and not os.path.islink(reel(p))
                if proprio:
                    u, _, g = proprio.partition(':')
                    meta_ok = meta_ok and (not u or st.st_uid == pwd.getpwnam(u).pw_uid) and (not g or st.st_gid == grp.getgrnam(g).gr_gid)
            except (OSError, KeyError):
                meta_ok = False
        if actuel == donnees and meta_ok and p in self.etat['fichiers']:
            return False
        self._sauvegarder(p, ext, 'fichier')
        self.etat['fichiers'][p]['ext'] = ext
        if actuel == donnees and meta_ok:
            return False
        journal.info('%s : %s', ext, p)
        if not self.simuler:
            self._poser(p, donnees, mode, proprio)
        self.changes[p] = ext
        return True

    def lien(self, p: str, cible: str, ext: str) -> bool:
        self.demandes[p] = ext
        r = reel(p)
        if os.path.islink(r) and os.readlink(r) == cible and p in self.etat['fichiers']:
            return False
        if os.path.lexists(r) and p not in self.etat['fichiers'] and not os.path.islink(r):
            journal.warning('%s : %s existe déjà et n’est pas un lien, laissé tel quel', ext, p)
            self.demandes.pop(p)
            return False
        self._sauvegarder(p, ext, 'lien')
        if not self.simuler:
            os.makedirs(os.path.dirname(r), exist_ok=True)
            if os.path.lexists(r):
                os.unlink(r)
            os.symlink(cible, r)
        self.changes[p] = ext
        return True

    def bloc(self, p: str, texte: str, ext: str, commentaire: str = '#', au_debut: bool = False, mode: int = 0o644) -> bool:
        """Bloc délimité dans un fichier partagé avec le système (sshd_config, access.conf, profil dconf…)."""
        cle = p + '#bloc'
        self.demandes[cle] = ext
        actuel = (_lire(p) or b'').decode('utf-8', 'replace')
        sans = _retirer_bloc(actuel, commentaire)
        bloc = f'{commentaire} {DEBUT}\n{texte.rstrip()}\n{commentaire} {FIN}\n'
        nouveau = bloc + sans if au_debut else (sans + ('' if not sans or sans.endswith('\n') else '\n') + bloc)
        if cle not in self.etat['fichiers']:
            self.etat['fichiers'][cle] = {'ext': ext, 'genre': 'bloc', 'sauvegarde': None, 'commentaire': commentaire,
                                          'cree': _lire(p) is None}
        if nouveau == actuel:
            return False
        journal.info('%s : %s (bloc)', ext, p)
        if not self.simuler:
            st_mode = os.stat(reel(p)).st_mode & 0o7777 if os.path.exists(reel(p)) else mode
            self._poser(p, nouveau.encode('utf-8'), st_mode, None)
        self.changes[cle] = ext
        return True

    def garder(self, ext: str) -> None:
        """L’extension a échoué : ses fichiers actuels sont conservés tels quels."""
        self.gardees.add(ext)

    # ------------------------------------------------------------ fin de passage
    def terminer(self) -> dict[str, str]:
        for p, info in list(self.etat['fichiers'].items()):
            if p in self.demandes or info.get('ext') in self.gardees:
                continue
            ext = info.get('ext', '')
            journal.info('%s : retrait de %s', ext, p.replace('#bloc', ' (bloc)'))
            if not self.simuler:
                self._retirer(p, info)
            self.changes[p] = ext
            del self.etat['fichiers'][p]
        self.sauver()
        return self.changes

    def sauver(self) -> None:
        if self.simuler:
            return
        os.makedirs(self.dossier, mode=0o700, exist_ok=True)
        tmp = self.fichier_etat + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as fh:
            json.dump(self.etat, fh, indent=1, ensure_ascii=False)
        os.replace(tmp, self.fichier_etat)

    def _retirer(self, p: str, info: dict) -> None:
        if info.get('genre') == 'bloc':
            f = p[:-5]
            actuel = _lire(f)
            if actuel is None:
                return
            sans = _retirer_bloc(actuel.decode('utf-8', 'replace'), info.get('commentaire', '#'))
            if not sans.strip() and info.get('cree'):
                os.unlink(reel(f))
            else:
                self._poser(f, sans.encode('utf-8'), os.stat(reel(f)).st_mode & 0o7777, None)
            return
        r = reel(p)
        s = info.get('sauvegarde')
        if os.path.lexists(r):
            os.unlink(r)
        if s and os.path.lexists(s):
            if os.path.islink(s):
                os.symlink(os.readlink(s), r)
                os.unlink(s)
            else:
                shutil.move(s, r)

    def changes_de(self, ext: str) -> list[str]:
        return [p for p, e in self.changes.items() if e == ext]

    def tout_retirer(self) -> dict[str, str]:
        """Désinstallation : remet le poste dans son état d’origine."""
        self.demandes.clear()
        self.gardees.clear()
        return self.terminer()


def _retirer_bloc(texte: str, commentaire: str) -> str:
    lignes, dedans, res = texte.split('\n'), False, []
    for l in lignes:
        if l.strip() == f'{commentaire} {DEBUT}':
            dedans = True
            continue
        if dedans and l.strip() == f'{commentaire} {FIN}':
            dedans = False
            continue
        if not dedans:
            res.append(l)
    return '\n'.join(res)
