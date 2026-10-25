"""Stratégie résultante : les GPO applicables copiées depuis SYSVOL, et leurs valeurs fusionnées
(Registry.pol, GptTmpl.inf) dans l’ordre d’application — la dernière GPO l’emporte, comme sous Windows."""
from __future__ import annotations

import json
import logging
import os
import shutil

from . import preg
from .gpo import Gpo
from .systeme import ErreurAgent

journal = logging.getLogger('linux-gpo')


def trouver(racine: str, relatif: str) -> str | None:
    """Chemin réel de `relatif` sous `racine` sans tenir compte de la casse (SYSVOL est insensible à la casse ;
    une copie peut contenir à la fois « Machine » et « MACHINE », on cherche dans les deux)."""
    parts = [p for p in relatif.replace('\\', '/').split('/') if p]

    def chercher(cur, i):
        if i == len(parts):
            return cur
        try:
            noms = sorted(os.listdir(cur))
        except OSError:
            return None
        for n in noms:
            if n.lower() == parts[i].lower():
                r = chercher(os.path.join(cur, n), i + 1)
                if r:
                    return r
        return None
    return chercher(racine, 0)


class Politique:
    def __init__(self, gpos: list[Gpo], machine: bool):
        self.gpos = gpos
        self.machine = machine
        self.partie = 'MACHINE' if machine else 'USER'
        self.registre: dict[str, dict[str, tuple]] = {}
        self.casse: dict[str, str] = {}      # clé en minuscules → clé telle qu’écrite dans la GPO
        self.inf: dict[str, dict[str, tuple[str, str]]] = {}
        for g in gpos:
            self._fusionner(g)

    # ------------------------------------------------------------ construction
    def _fusionner(self, g: Gpo) -> None:
        f = self.fichier(g, f'{self.partie}/Registry.pol')
        if f:
            try:
                with open(f, 'rb') as fh:
                    entrees = preg.lire_pol(fh.read())
            except (OSError, ValueError) as e:
                journal.warning('%s : Registry.pol illisible (%s)', g.nom, e)
                entrees = []
            for cle, nom, typ, val in entrees:
                k = cle.lower()
                self.casse.setdefault(k, cle)
                n = nom.lower()
                vals = self.registre.setdefault(k, {})
                if n.startswith('**delvals'):
                    vals.clear()
                elif n.startswith('**del.'):
                    vals.pop(n[6:], None)
                elif n.startswith('**deletevalues'):
                    for x in str(val).split(';'):
                        vals.pop(x.strip().lower(), None)
                elif n.startswith('**deletekeys'):
                    for x in str(val).split(';'):
                        for kk in [kk for kk in self.registre if kk == (k + '\\' + x.strip().lower()) or kk.startswith(k + '\\' + x.strip().lower() + '\\')]:
                            self.registre[kk].clear()
                elif n.startswith('**soft.'):
                    vals.setdefault(n[7:], (nom[7:], typ, val, g.nom))
                elif n.startswith('**'):
                    continue
                else:
                    vals[n] = (nom, typ, val, g.nom)
        if self.machine:
            f = self.fichier(g, 'MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf')
            if f:
                try:
                    with open(f, 'rb') as fh:
                        inf = preg.lire_inf(fh.read())
                except OSError:
                    inf = {}
                for section, cles in inf.items():
                    d = self.inf.setdefault(section, {})
                    for k, v in cles.items():
                        d[k] = (v, g.nom)

    # ------------------------------------------------------------ lecture
    def valeur(self, cle: str, nom: str, defaut=None):
        v = self.registre.get(cle.lower(), {}).get(nom.lower())
        return v[2] if v else defaut

    def valeurs(self, cle: str) -> dict[str, object]:
        """{nom de valeur (casse d’origine): donnée} d’une clé."""
        return {v[0]: v[2] for v in self.registre.get(cle.lower(), {}).values()}

    def liste(self, cle: str) -> list:
        """Valeurs d’une liste ADMX (noms 1, 2, 3… ou noms libres), dans l’ordre."""
        vals = list(self.registre.get(cle.lower(), {}).values())
        vals.sort(key=lambda v: (0, int(v[0])) if str(v[0]).isdigit() else (1, 0))
        return [v[2] for v in vals]

    def sous_cles(self, prefixe: str) -> list[str]:
        p = prefixe.lower().rstrip('\\') + '\\'
        return sorted({k for k in self.registre if k.startswith(p) and self.registre[k]})

    def entrees(self, prefixe: str) -> list[tuple[str, str, int, object]]:
        """Toutes les valeurs sous une clé et ses sous-clés : (clé, nom, type, donnée)."""
        p = prefixe.lower().rstrip('\\')
        res = []
        for k, vals in self.registre.items():
            if k == p or k.startswith(p + '\\'):
                res += [(self.casse.get(k, k), v[0], v[1], v[2]) for v in vals.values()]
        return res

    def inf_valeur(self, section: str, cle: str, defaut=None):
        v = self.inf.get(section.lower(), {}).get(cle.lower())
        return v[0] if v else defaut

    def reg_inf(self, chemin: str, defaut=None):
        """Valeur de la section [Registry Values] de GptTmpl.inf (« 4,600 » → 600)."""
        v = self.inf_valeur('Registry Values', chemin)
        if v is None:
            return defaut
        typ, _, val = v.partition(',')
        val = val.strip().strip('"')
        if typ.strip() == '7':  # REG_MULTI_SZ : une ligne par élément
            return '\n'.join(x.strip().strip('"') for x in val.split(','))
        return int(val) if typ.strip() == '4' and val.lstrip('-').isdigit() else val

    def fichier(self, g: Gpo, relatif: str) -> str | None:
        return trouver(g.local, relatif) if g.local else None

    def fichiers(self, relatif: str) -> list[tuple[Gpo, str]]:
        return [(g, f) for g in self.gpos for f in [self.fichier(g, relatif)] if f]

    def provenance(self) -> dict:
        """Pour l’affichage du résultat : valeurs et GPO d’origine."""
        return {k: {v[0]: [v[2] if not isinstance(v[2], bytes) else v[2].hex(), v[3]] for v in vals.values()}
                for k, vals in sorted(self.registre.items()) if vals}


def copier_sysvol(a, gpos: list[Gpo], machine: bool, cache: str) -> None:
    """Copie locale de la partie utile de chaque GPO (MACHINE ou USER), seulement si sa version a changé."""
    partie = 'MACHINE' if machine else 'USER'
    os.makedirs(cache, mode=0o700, exist_ok=True)
    for g in gpos:
        dossier = os.path.join(cache, g.guid)
        repere = os.path.join(dossier, '.version')
        version = g.version_partie(machine)
        try:
            with open(repere, encoding='utf-8') as fh:
                if json.load(fh) == [g.version, g.chemin] and os.path.isdir(dossier):
                    g.local = dossier
                    continue
        except (OSError, ValueError):
            pass
        tmp = dossier + '.tmp'
        shutil.rmtree(tmp, ignore_errors=True)
        os.makedirs(tmp, mode=0o700)
        if version:
            try:
                a.copier_dossier(g.chemin.rstrip('\\') + '\\' + partie, os.path.join(tmp, partie))
            except ErreurAgent as e:
                if 'NOT_FOUND' not in str(e) and 'NO_SUCH' not in str(e):
                    shutil.rmtree(tmp, ignore_errors=True)
                    raise
        with open(os.path.join(tmp, '.version'), 'w', encoding='utf-8') as fh:
            json.dump([g.version, g.chemin], fh)
        shutil.rmtree(dossier, ignore_errors=True)
        os.rename(tmp, dossier)
        g.local = dossier
    # GPO qui ne s’appliquent plus : copie locale retirée
    gardes = {g.guid for g in gpos}
    for n in os.listdir(cache):
        if n.startswith('{') and n.split('.')[0] not in gardes:
            shutil.rmtree(os.path.join(cache, n), ignore_errors=True)
