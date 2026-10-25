"""Scripts : planifiés (toutes les heures, jours, semaines, mois) et de démarrage.

Sources :
  - Samba « Unix Settings\\{Hourly,Daily,Weekly,Monthly} Scripts » et LinuxGPO\\Scripts\\{Hourly,…} :
    nom de valeur = nom du script, donnée = contenu (ou une ligne de commande) ;
  - LinuxGPO\\Scripts\\Startup (nom = libellé, donnée = commande) et le fichier VGP « Startup Scripts » de
    Samba (script copié dans la GPO, éventuellement « une seule fois »).

Les scripts planifiés deviennent des minuteurs systemd (dans /run, recréés à chaque démarrage par l’agent) ;
sans systemd, les dossiers /etc/cron.* sont utilisés.
"""
import hashlib
import os
import re
import xml.etree.ElementTree as ET

from . import K_LGPO, K_SAMBA, Extension
from ..systeme import chemin, lancer, systemd_actif

FREQUENCES = {'Hourly': 'hourly', 'Daily': 'daily', 'Weekly': 'weekly', 'Monthly': 'monthly'}
DOSSIER = '/var/lib/linux-gpo/scripts'
UNITES = '/run/systemd/system'
VGP = 'MACHINE/VGP/VTLA/Unix/Scripts/Startup/manifest.xml'


def _contenu(texte: str) -> str:
    texte = str(texte).replace('\r\n', '\n')
    return texte if texte.startswith('#!') else '#!/bin/sh\n' + texte.rstrip('\n') + '\n'


def _court(nom: str, contenu: str) -> str:
    propre = re.sub(r'[^A-Za-z0-9_-]+', '-', nom).strip('-')[:40] or 'script'
    return f'{propre}-{hashlib.sha256(contenu.encode()).hexdigest()[:8]}'


def _id_demarrage() -> str:
    try:
        with open('/proc/sys/kernel/random/boot_id', encoding='ascii') as fh:
            return fh.read().strip()
    except OSError:
        return ''


class Scripts(Extension):
    nom = 'scripts'

    def appliquer(self, ctx):
        pol = ctx.pol
        self.unites = []
        for cle, freq in FREQUENCES.items():
            vals = {**pol.valeurs(f'{K_SAMBA}\\{cle} Scripts'), **pol.valeurs(f'{K_LGPO}\\Scripts\\{cle}')}
            for nom, texte in vals.items():
                if not str(texte).strip():
                    continue
                contenu = _contenu(texte)
                court = _court(str(nom), contenu)
                script = f'{DOSSIER}/{court}.sh'
                ctx.f.ecrire(script, contenu, self.nom, mode=0o700)
                ctx.noter(self.nom, f'{freq} : {nom}')
                if systemd_actif() or ctx.simuler:
                    service = f'linux-gpo-{court}'
                    ctx.f.ecrire(f'{UNITES}/{service}.service', f'[Unit]\nDescription=Script de GPO « {nom} »\n\n[Service]\n'
                                 f'Type=oneshot\nExecStart={script}\n', self.nom)
                    ctx.f.ecrire(f'{UNITES}/{service}.timer', f'[Unit]\nDescription=Script de GPO « {nom} » ({freq})\n\n[Timer]\n'
                                 f'OnCalendar={freq}\nPersistent=true\nRandomizedDelaySec=5min\n\n[Install]\nWantedBy=timers.target\n',
                                 self.nom)
                    self.unites.append(service + '.timer')
                elif os.path.isdir(chemin(f'/etc/cron.{freq}')):
                    ctx.f.lien(f'/etc/cron.{freq}/linux-gpo-{court}', script, self.nom)
        self._demarrage(ctx)

    def _demarrage(self, ctx):
        pol = ctx.pol
        a_lancer = []  # (identifiant, commande, une seule fois)
        for nom, cmd in pol.valeurs(K_LGPO + r'\Scripts\Startup').items():
            if str(cmd).strip():
                contenu = _contenu(cmd)
                court = _court(str(nom), contenu)
                p = f'{DOSSIER}/demarrage-{court}.sh'
                ctx.f.ecrire(p, contenu, self.nom, mode=0o700)
                a_lancer.append((court, [p], False))
                ctx.noter(self.nom, f'démarrage : {nom}')
        for g, f in pol.fichiers(VGP):
            try:
                data = ET.parse(f).getroot().find('policysetting/data')
            except (OSError, ET.ParseError):
                continue
            for le in (data.findall('listelement') if data is not None else []):
                script = le.findtext('script') or ''
                src = pol.fichier(g, os.path.join(os.path.dirname(os.path.relpath(f, g.local)), script))
                if not src:
                    ctx.noter(self.nom, f'script de démarrage absent de la GPO : {script}')
                    continue
                with open(src, 'rb') as fh:
                    contenu = fh.read().decode('utf-8', 'replace')
                court = _court(os.path.basename(script), contenu + (le.findtext('parameters') or ''))
                p = f'{DOSSIER}/demarrage-{court}.sh'
                ctx.f.ecrire(p, contenu, self.nom, mode=0o700)
                params = (le.findtext('parameters') or '').split()
                once = le.find('run_once') is not None
                a_lancer.append((court, [p] + params, once))
                ctx.noter(self.nom, f"démarrage{' (une fois)' if once else ''} : {script}")
        if ctx.simuler or not a_lancer:
            return
        mem = ctx.f.memoire(self.nom)
        boot = _id_demarrage()
        deja = mem.setdefault('lances', {})
        for court, cmd, once in a_lancer:
            if deja.get(court) == (boot if not once else 'une fois'):
                continue
            if systemd_actif():
                lancer(['systemd-run', '--no-block', '--collect', f'--unit=linux-gpo-demarrage-{court}'] + cmd)
            else:
                lancer(cmd, delai=600)
            deja[court] = boot if not once else 'une fois'
        mem['lances'] = {k: v for k, v in deja.items() if any(k == c for c, _, _ in a_lancer)}

    def apres(self, ctx, changes):
        if ctx.simuler or not systemd_actif() or not any(p.startswith(UNITES) for p in changes):
            return
        for p in changes:
            if p.startswith(UNITES) and p.endswith('.timer') and not os.path.exists(chemin(p)):
                lancer(['systemctl', 'stop', os.path.basename(p)])
        lancer(['systemctl', 'daemon-reload'])
        for u in getattr(self, 'unites', []):
            lancer(['systemctl', 'start', u])
