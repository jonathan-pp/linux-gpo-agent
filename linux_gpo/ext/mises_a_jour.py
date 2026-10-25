"""Mises à jour automatiques du système.

Réglages (ordinateur, LinuxGPO\\Updates) :
  Mode        0 : désactivées ; 1 : correctifs de sécurité ; 2 : toutes les mises à jour
  Time        heure d’installation (« 03:00 »)
  Reboot      1 : redémarrer automatiquement si une mise à jour l’exige (même heure + 30 min)
Repris de Windows Update (« Configuration du service Mises à jour automatiques ») : mise à jour automatique
(option 4) → toutes les mises à jour à l’heure planifiée ; mises à jour automatiques désactivées → 0.

Debian/Ubuntu : unattended-upgrades (installé si besoin). Fedora : dnf. Arch : pacman -Syu (mode 2 seulement :
Arch n’a pas de correctifs de sécurité séparés). openSUSE : zypper patch. NixOS : system.autoUpgrade.
"""
import re

from . import K_LGPO, Extension, entier, vrai
from ..systeme import chemin, est_nixos, famille, lancer, outil, systemd_actif

K = K_LGPO + r'\Updates'
K_AU = r'Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
APT = '/etc/apt/apt.conf.d/52linux-gpo'
UNITES = '/run/systemd/system'


def reglage(pol) -> tuple[int | None, str, bool]:
    mode = pol.valeur(K, 'Mode')
    heure = str(pol.valeur(K, 'Time') or '')
    if mode is None:
        if vrai(pol.valeur(K_AU, 'NoAutoUpdate')):
            mode = 0
        elif entier(pol.valeur(K_AU, 'AUOptions')) == 4:
            mode = 2
            h = entier(pol.valeur(K_AU, 'ScheduledInstallTime'), 3)
            heure = heure or f'{h % 24:02d}:00'
    if not re.fullmatch(r'\d{1,2}:\d{2}', heure):
        heure = '03:00'
    return (None if mode is None else entier(mode)), heure, vrai(pol.valeur(K, 'Reboot'))


def _plus_30(h: str) -> str:
    hh, mm = (int(x) for x in h.split(':'))
    t = (hh * 60 + mm + 30) % 1440
    return f'{t // 60:02d}:{t % 60:02d}'


class MisesAJour(Extension):
    nom = 'mises-a-jour'

    def appliquer(self, ctx):
        mode, heure, redemarrer = reglage(ctx.pol)
        if mode is None:
            return
        ctx.noter(self.nom, ['désactivées', 'correctifs de sécurité', 'toutes'][max(0, min(mode, 2))]
                  + (f' à {heure}' if mode else '') + (', redémarrage automatique' if mode and redemarrer else ''))
        fam = famille()
        if est_nixos():
            ctx.noter(self.nom, 'NixOS : utilisez system.autoUpgrade dans la configuration')
            return
        if fam == 'debian':
            if mode and not outil('unattended-upgrade') and not ctx.simuler:
                lancer(['apt-get', 'install', '-y', '-q', 'unattended-upgrades'], env={'DEBIAN_FRONTEND': 'noninteractive'}, delai=900)
            texte = ('// Stratégies de groupe (linux-gpo)\n'
                     f'APT::Periodic::Update-Package-Lists "{1 if mode else 0}";\n'
                     f'APT::Periodic::Unattended-Upgrade "{1 if mode else 0}";\n')
            if mode >= 2:
                texte += 'Unattended-Upgrade::Origins-Pattern { "origin=*"; };\n'
            if mode:
                texte += (f'Unattended-Upgrade::Automatic-Reboot "{"true" if redemarrer else "false"}";\n'
                          f'Unattended-Upgrade::Automatic-Reboot-Time "{_plus_30(heure)}";\n')
            ctx.f.ecrire(APT, texte, self.nom)
            if mode and systemd_actif():
                # heure de passage d’apt-daily-upgrade
                ctx.f.ecrire('/run/systemd/system/apt-daily-upgrade.timer.d/linux-gpo.conf',
                             f'[Timer]\nOnCalendar=\nOnCalendar=*-*-* {heure}\nRandomizedDelaySec=15min\n', self.nom)
            return
        cmd = {('fedora', 1): 'dnf -y upgrade --security', ('fedora', 2): 'dnf -y upgrade',
               ('arch', 2): 'pacman -Syu --noconfirm', ('suse', 1): 'zypper -n patch --category security',
               ('suse', 2): 'zypper -n update'}.get((fam, mode))
        if mode and not cmd:
            ctx.noter(self.nom, f'non pris en charge sur cette distribution ({fam}, mode {mode})')
            return
        if not mode:
            return  # rien d’automatique sur ces distributions par défaut
        if not systemd_actif() and not ctx.simuler:
            ctx.noter(self.nom, 'systemd absent : mises à jour automatiques non planifiées')
            return
        apres = '\nExecStartPost=/usr/bin/env linux-gpo redemarrer-si-besoin' if redemarrer else ''
        ctx.f.ecrire(f'{UNITES}/linux-gpo-mises-a-jour.service', '[Unit]\nDescription=Mises à jour automatiques (stratégie de groupe)\n'
                     f'After=network-online.target\n\n[Service]\nType=oneshot\nExecStart=/bin/sh -c "{cmd}"{apres}\n', self.nom)
        ctx.f.ecrire(f'{UNITES}/linux-gpo-mises-a-jour.timer', '[Unit]\nDescription=Mises à jour automatiques (stratégie de groupe)\n\n'
                     f'[Timer]\nOnCalendar=*-*-* {heure}\nPersistent=true\nRandomizedDelaySec=15min\n', self.nom)

    def apres(self, ctx, changes):
        if ctx.simuler or not changes or not systemd_actif():
            return
        lancer(['systemctl', 'daemon-reload'])
        if any(p.endswith('linux-gpo-mises-a-jour.timer') for p in changes):
            import os
            present = os.path.exists(chemin(f'{UNITES}/linux-gpo-mises-a-jour.timer'))
            lancer(['systemctl', 'start' if present else 'stop', 'linux-gpo-mises-a-jour.timer'])


def redemarrage_necessaire() -> bool:
    import os
    if os.path.exists('/var/run/reboot-required'):
        return True
    if outil('needs-restarting'):
        return lancer(['needs-restarting', '-r']).returncode == 1
    noyau = os.uname().release
    return not os.path.isdir(f'/usr/lib/modules/{noyau}') and not os.path.isdir(f'/lib/modules/{noyau}')
