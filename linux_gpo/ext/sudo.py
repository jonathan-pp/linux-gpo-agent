"""Droits sudo : /etc/sudoers.d/50-linux-gpo, chaque règle vérifiée par visudo avant d’être posée.

Sources : LinuxGPO\\Sudo\\Rules, Samba « Unix Settings\\Sudo Rights » (règles sudoers) et le fichier VGP
SudoersConfiguration (samba-tool). Les comptes y sont nommés DOMAINE\\nom ; ils sont réécrits avec le nom
que le poste connaît (DOMAINE\\nom avec winbind, nom@domaine avec sssd…).
"""
import os
import re
import tempfile
import xml.etree.ElementTree as ET

from . import K_LGPO, K_SAMBA, Extension
from ..noms import echapper_sudo
from ..systeme import chemin, lancer

FICHIER = '/etc/sudoers.d/50-linux-gpo'
VGP = 'MACHINE/VGP/VTLA/Sudo/SudoersConfiguration/manifest.xml'


def _sans_echap(t: str) -> str:
    return re.sub(r'\\(.)', r'\1', t)


class Sudo(Extension):
    nom = 'sudo'

    def _traduire(self, ctx, regle: str) -> str | None:
        """Remplace DOMAINE\\compte (en tête de règle, échappé pour sudoers) par le nom local."""
        regle = regle.strip()
        if not regle or regle.startswith('#'):
            return None
        m = re.match(r'((?:\\.|\S)+)(\s+)(.*)$', regle)
        if not m:
            return None
        tete, sep, reste = m.groups()
        noms = []
        for morceau in re.split(r'(?<!\\),', tete):
            groupe = morceau.startswith('%')
            brut = _sans_echap(morceau.lstrip('%'))
            if '\\' in brut or '@' in brut:
                loc = ctx.noms.local(brut.split('@')[0] if '@' in brut else brut, groupe)
                if not loc:
                    ctx.noter(self.nom, f'compte inconnu sur ce poste, règle ignorée : {brut}')
                    return None
                noms.append(('%' if groupe else '') + echapper_sudo(loc))
            else:
                noms.append(morceau)
        return ','.join(noms) + sep + reste

    def regles(self, ctx) -> list[str]:
        pol = ctx.pol
        brutes = pol.liste(K_LGPO + r'\Sudo\Rules') + pol.liste(K_SAMBA + r'\Sudo Rights')
        for _, f in pol.fichiers(VGP):
            try:
                data = ET.parse(f).getroot().find('policysetting/data')
            except (OSError, ET.ParseError):
                continue
            for e in (data.findall('sudoers_entry') if data is not None else []):
                principaux = [p for le in e.findall('listelement') for p in le.findall('principal')]
                qui = ','.join(('%' if p.get('type') == 'group' else '') + echapper_sudo(p.text or '') for p in principaux) or 'ALL'
                np = ' NOPASSWD:' if e.find('password') is None else ''
                brutes.append(f"{qui} ALL=({e.findtext('user') or 'ALL'}){np} {e.findtext('command') or 'ALL'}")
        return [str(r) for r in brutes if str(r).strip()]

    def appliquer(self, ctx):
        bonnes = []
        for brute in self.regles(ctx):
            r = self._traduire(ctx, brute)
            if r is None:
                continue
            if not _valide(r):
                ctx.noter(self.nom, f'règle refusée par visudo : {r}')
                continue
            bonnes.append(r)
            ctx.noter(self.nom, r)
        if bonnes:
            if not os.path.isdir(chemin('/etc/sudoers.d')) and not ctx.simuler:
                os.makedirs(chemin('/etc/sudoers.d'), mode=0o750, exist_ok=True)
            ctx.f.ecrire(FICHIER, '# Règles sudo des stratégies de groupe (linux-gpo)\n' + '\n'.join(bonnes) + '\n',
                         self.nom, mode=0o440)
            if not _inclus():
                ctx.noter(self.nom, '/etc/sudoers n’inclut pas /etc/sudoers.d : ajoutez « @includedir /etc/sudoers.d »')


def _valide(regle: str) -> bool:
    if not lancer(['visudo', '--version']).returncode == 0:
        return True  # visudo absent (sudo non installé) : le fichier sera ignoré de toute façon
    with tempfile.NamedTemporaryFile('w', suffix='.sudoers', delete=False, encoding='utf-8') as fh:
        fh.write(regle + '\n')
    try:
        return lancer(['visudo', '-c', '-q', '-f', fh.name]).returncode == 0
    finally:
        os.unlink(fh.name)


def _inclus() -> bool:
    try:
        with open(chemin('/etc/sudoers'), encoding='utf-8') as fh:
            return bool(re.search(r'^[#@]includedir\s+/etc/sudoers\.d', fh.read(), re.M))
    except OSError:
        return True
