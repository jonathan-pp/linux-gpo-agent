"""Synchronisation de l’heure sur les contrôleurs du domaine (Kerberos refuse un écart de plus de 5 minutes).

Réglages (ordinateur, LinuxGPO\\Time) :
  UseDomainTime   1 : synchroniser l’heure sur le domaine
  NtpServers      serveurs NTP séparés par des espaces (par défaut : le nom du domaine, qui désigne ses contrôleurs)
Repris de Windows : « Configurer le client NTP Windows » (W32Time\\Parameters, NtpServer).
"""
import os

from . import K_LGPO, Extension, vrai
from ..systeme import chemin, gere_par_nix, outil, service, service_actif

K = K_LGPO + r'\Time'
K_W32 = r'Software\Policies\Microsoft\W32Time\Parameters'


class Heure(Extension):
    nom = 'heure'

    def appliquer(self, ctx):
        pol = ctx.pol
        serveurs = str(pol.valeur(K, 'NtpServers') or '').split()
        if not serveurs and str(pol.valeur(K_W32, 'Type') or '').upper() == 'NTP':
            serveurs = [s.split(',')[0] for s in str(pol.valeur(K_W32, 'NtpServer') or '').split() if s]
        if not serveurs and not vrai(pol.valeur(K, 'UseDomainTime')):
            return
        serveurs = serveurs or [ctx.conf.domaine]
        ctx.noter(self.nom, 'serveurs de temps : ' + ' '.join(serveurs))
        self.services = []
        if outil('chronyd') or os.path.isdir(chemin('/etc/chrony')):
            dossier = '/etc/chrony/sources.d' if os.path.isdir(chemin('/etc/chrony/sources.d')) else None
            if dossier:
                ctx.f.ecrire(f'{dossier}/linux-gpo.sources', ''.join(f'server {s} iburst\n' for s in serveurs), self.nom)
            else:
                conf = '/etc/chrony.conf' if os.path.exists(chemin('/etc/chrony.conf')) else '/etc/chrony/chrony.conf'
                if not gere_par_nix(conf):
                    ctx.f.bloc(conf, ''.join(f'server {s} iburst\n' for s in serveurs), self.nom)
            self.services += ['chronyd', 'chrony']
        elif os.path.isdir(chemin('/etc/systemd')) and not gere_par_nix('/etc/systemd/timesyncd.conf'):
            ctx.f.ecrire('/etc/systemd/timesyncd.conf.d/linux-gpo.conf', f"[Time]\nNTP={' '.join(serveurs)}\n", self.nom)
            self.services.append('systemd-timesyncd')

    def apres(self, ctx, changes):
        if ctx.simuler or not changes:
            return
        for s in getattr(self, 'services', []) or ['chronyd', 'chrony', 'systemd-timesyncd']:
            if service_actif(s):
                service('restart', s)
