"""Serveur SSH : /etc/ssh/sshd_config.d/10-linux-gpo.conf, vérifié par « sshd -t » avant rechargement.

Sources : LinuxGPO\\SSH (nom de valeur = directive sshd) et le fichier VGP SshD (samba-tool, console).
sshd garde la première valeur lue : le fichier est inclus en tête de sshd_config.
"""
import os
import xml.etree.ElementTree as ET

from . import K_LGPO, Extension
from ..fichiers import _retirer_bloc
from ..systeme import chemin, gere_par_nix, lancer, outil, service, service_actif

FICHIER = '/etc/ssh/sshd_config.d/10-linux-gpo.conf'
PRINCIPAL = '/etc/ssh/sshd_config'
VGP = 'MACHINE/VGP/VTLA/SshCfg/SshD/manifest.xml'
INCLUDE = 'Include /etc/ssh/sshd_config.d/*.conf'


def _deja_inclus(texte: str) -> bool:
    for l in texte.splitlines():
        l = l.strip()
        if l.lower().startswith('match '):
            return False  # un Include placé après un Match ne s’applique pas à tout
        if l.lower().startswith('include ') and 'sshd_config.d' in l:
            return True
    return False


class Ssh(Extension):
    nom = 'ssh'

    def appliquer(self, ctx):
        directives = {}
        for _, f in ctx.pol.fichiers(VGP):
            try:
                cf = ET.parse(f).getroot().find('policysetting/data/configfile')
            except (OSError, ET.ParseError):
                continue
            for sec in (cf.findall('configsection') if cf is not None else []):
                if sec.findtext('sectionname'):
                    continue
                for kv in sec.findall('keyvaluepair'):
                    if kv.findtext('key'):
                        directives[kv.findtext('key').strip()] = (kv.findtext('value') or '').strip()
        for k, v in ctx.pol.valeurs(K_LGPO + r'\SSH').items():
            directives[str(k).strip()] = str(v).strip()
        directives = {k: v for k, v in directives.items() if k and v and '\n' not in k + v}
        if not directives:
            return
        if not outil('sshd') and not os.path.exists(chemin(PRINCIPAL)):
            ctx.noter(self.nom, 'serveur SSH non installé : réglages ignorés')
            return
        texte = '# Réglages du serveur SSH des stratégies de groupe (linux-gpo)\n' + ''.join(f'{k} {v}\n' for k, v in directives.items())
        if ctx.f.memoire(self.nom).get('refuse') == texte:
            ctx.noter(self.nom, 'configuration refusée par sshd -t lors d’un passage précédent : non appliquée')
            return
        ctx.f.ecrire(FICHIER, texte, self.nom)
        self.texte = texte
        for k, v in directives.items():
            ctx.noter(self.nom, f'{k} {v}')
        try:
            with open(chemin(PRINCIPAL), encoding='utf-8') as fh:
                principal = _retirer_bloc(fh.read(), '#')  # sans l’Include que l’agent a lui-même ajouté
        except OSError:
            principal = ''
        if gere_par_nix(PRINCIPAL):
            if not _deja_inclus(principal):
                ctx.noter(self.nom, 'NixOS : activez services.linux-gpo (il ajoute l’Include dans sshd_config)')
        elif not _deja_inclus(principal):
            ctx.f.bloc(PRINCIPAL, INCLUDE, self.nom, au_debut=True)

    def apres(self, ctx, changes):
        if not changes or ctx.simuler:
            return
        if outil('sshd'):
            r = lancer(['sshd', '-t'])
            if r.returncode:
                # configuration refusée : on retire nos réglages au prochain passage plutôt que de casser sshd
                ctx.noter(self.nom, f'sshd -t refuse la configuration : {r.stderr.strip()[-200:]}')
                ctx.f.memoire(self.nom)['refuse'] = getattr(self, 'texte', '')
                try:
                    os.unlink(chemin(FICHIER))
                except OSError:
                    pass
                return
        ctx.f.memoire(self.nom).pop('refuse', None)
        for s in ('ssh', 'sshd'):
            if service_actif(s):
                service('reload', s)
                break
