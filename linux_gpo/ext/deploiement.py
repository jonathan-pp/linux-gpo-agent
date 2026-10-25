"""Fichiers et liens déployés sur le poste.

Sources :
  - fichiers VGP « Files » et « Symbolic Links » de Samba (fichier source rangé dans la GPO) ;
  - LinuxGPO\\Files : nom de valeur = chemin sur le poste, donnée = « \\\\serveur\\partage\\fichier;0644;root:root »
    (droits et propriétaire facultatifs) — le fichier est lu avec le compte de l’ordinateur, comme sous Windows ;
  - préférences Windows « Fichiers » (Files.xml) dont la cible est un chemin Linux (commence par « / »).
"""
import os
import tempfile
import xml.etree.ElementTree as ET

from . import K_LGPO, Extension
from ..systeme import ErreurAgent

VGP_FICHIERS = 'MACHINE/VGP/VTLA/Unix/Files/manifest.xml'
VGP_LIENS = 'MACHINE/VGP/VTLA/Unix/Symlink/manifest.xml'
GPP = 'MACHINE/Preferences/Files/Files.xml'
INTERDITS = ('/proc', '/sys', '/dev', '/run/linux-gpo', '/var/lib/linux-gpo')


def _mode_vgp(e) -> int:
    mode = 0
    for p in e.findall('permissions'):
        dec = {'user': 6, 'group': 3, 'other': 0}.get(p.get('type'), None)
        if dec is None:
            continue
        for droit, bit in (('read', 4), ('write', 2), ('execute', 1)):
            if p.find(droit) is not None:
                mode |= bit << dec
    return mode or 0o644


def _cible_ok(p: str) -> bool:
    p = os.path.normpath(p)
    return p.startswith('/') and not any(p == x or p.startswith(x + '/') for x in INTERDITS)


class Deploiement(Extension):
    nom = 'fichiers'

    def appliquer(self, ctx):
        pol = ctx.pol
        for g, f in pol.fichiers(VGP_FICHIERS):
            try:
                data = ET.parse(f).getroot().find('policysetting/data')
            except (OSError, ET.ParseError):
                continue
            for e in (data.findall('file_properties') if data is not None else []):
                cible, source = e.findtext('target') or '', e.findtext('source') or ''
                src = pol.fichier(g, os.path.join(os.path.dirname(os.path.relpath(f, g.local)), source))
                if not _cible_ok(cible) or not src:
                    ctx.noter(self.nom, f'ignoré : {source} → {cible}')
                    continue
                with open(src, 'rb') as fh:
                    contenu = fh.read()
                self._poser(ctx, cible, contenu, _mode_vgp(e), f"{e.findtext('user') or 'root'}:{e.findtext('group') or 'root'}")
        for _, f in pol.fichiers(VGP_LIENS):
            try:
                data = ET.parse(f).getroot().find('policysetting/data')
            except (OSError, ET.ParseError):
                continue
            for e in (data.findall('file_properties') if data is not None else []):
                cible, source = e.findtext('target') or '', e.findtext('source') or ''
                if _cible_ok(cible) and source:
                    ctx.f.lien(cible, source, self.nom)
                    ctx.noter(self.nom, f'lien {cible} → {source}')
        reseau = [(str(k), str(v)) for k, v in pol.valeurs(K_LGPO + r'\Files').items()]
        for g, f in pol.fichiers(GPP):
            try:
                racine = ET.parse(f).getroot()
            except (OSError, ET.ParseError):
                continue
            for el in racine.iter('File'):
                pr = el.find('Properties')
                if pr is None or not (pr.get('targetPath') or '').startswith('/') or pr.get('action', 'U') == 'D':
                    continue
                reseau.append((pr.get('targetPath'), pr.get('fromPath') or ''))
        for cible, spec in reseau:
            unc, mode, proprio = (spec.split(';') + ['', ''])[:3]
            if not _cible_ok(cible) or not unc.startswith(('\\\\', '//')):
                ctx.noter(self.nom, f'ignoré : {spec} → {cible}')
                continue
            if not ctx.annuaire:
                continue
            with tempfile.TemporaryDirectory() as d:
                try:
                    ctx.annuaire.copier_fichier(unc, os.path.join(d, 'f'))
                    with open(os.path.join(d, 'f'), 'rb') as fh:
                        contenu = fh.read()
                except (ErreurAgent, OSError) as e:
                    ctx.noter(self.nom, f'{unc} : {e}')
                    ctx.f.garder(self.nom)
                    continue
            self._poser(ctx, cible, contenu, int(mode, 8) if mode.strip() else 0o644, proprio.strip() or 'root:root')

    def _poser(self, ctx, cible, contenu, mode, proprio):
        try:
            ctx.f.ecrire(cible, contenu, self.nom, mode=mode, proprio=proprio)
            ctx.noter(self.nom, f'{cible} ({oct(mode)[2:]}, {proprio})')
        except KeyError:
            ctx.noter(self.nom, f'{cible} : propriétaire inconnu sur ce poste ({proprio})')
