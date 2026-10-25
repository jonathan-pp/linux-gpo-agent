"""Droits des utilisateurs, pour tous les bureaux (règles polkit) : supports amovibles, extinction,
installation de logiciels, réglages réseau. Les administrateurs du poste ne sont pas concernés.

Réglages (ordinateur) :
  LinuxGPO\\Devices\\DenyRemovableStorage   1 : montage interdit ; 2 : pilote USB de stockage bloqué en plus
      ← Windows « Toutes les classes de stockage amovible : refuser tout accès » (= 2)
  LinuxGPO\\Permissions\\DenyPowerOff        extinction, redémarrage, mise en veille interdits
  LinuxGPO\\Permissions\\DenySoftwareInstall installation de logiciels interdite (PackageKit, Flatpak, Snap)
  LinuxGPO\\Permissions\\DenyNetworkConfig   modification des connexions réseau interdite (NetworkManager)
  LinuxGPO\\Permissions\\AdminGroups         groupes administrateurs du poste, séparés par « ; »
                                              (par défaut : sudo, wheel, admin et les Admins du domaine)
"""
import json
import os

from . import K_LGPO, Extension, entier, vrai
from ..noms import admins_locaux
from ..systeme import chemin, lancer, outil

K_WIN_USB = r'Software\Policies\Microsoft\Windows\RemovableStorageDevices'
REGLES_JS = '/etc/polkit-1/rules.d/40-linux-gpo.rules'
REGLES_PKLA = '/etc/polkit-1/localauthority/50-local.d/50-linux-gpo.pkla'
MODPROBE = '/etc/modprobe.d/linux-gpo-stockage.conf'
ACTIONS = {
    'stockage': ['org.freedesktop.udisks2.'],
    'extinction': ['org.freedesktop.login1.power-off', 'org.freedesktop.login1.reboot', 'org.freedesktop.login1.halt',
                   'org.freedesktop.login1.suspend', 'org.freedesktop.login1.hibernate'],
    'logiciels': ['org.freedesktop.packagekit.', 'org.freedesktop.Flatpak.', 'io.snapcraft.snapd.', 'org.debian.apt.'],
    'reseau': ['org.freedesktop.NetworkManager.settings.modify.', 'org.freedesktop.NetworkManager.enable-disable-'],
}
LIBELLES = {'stockage': 'supports amovibles', 'extinction': 'extinction et redémarrage', 'logiciels': 'installation de logiciels',
            'reseau': 'réglages réseau'}


def _polkit_js() -> bool:
    """polkit 0.106 et plus lit des règles JavaScript ; avant (Ubuntu 22.04…), des fichiers .pkla."""
    v = lancer(['pkaction', '--version']).stdout.split()
    try:
        n = v[-1].split('.')
        return int(n[1]) >= 106 if n[0] == '0' else int(n[0]) >= 106
    except (ValueError, IndexError):
        return os.path.isdir(chemin('/usr/share/polkit-1/rules.d')) or os.path.isdir(chemin('/etc/polkit-1/rules.d'))


def _racine_sur_usb() -> bool:
    try:
        st = os.stat(chemin('/'))
        p = os.path.realpath(f'/sys/dev/block/{os.major(st.st_dev)}:{os.minor(st.st_dev)}')
        return '/usb' in p
    except OSError:
        return False


class Permissions(Extension):
    nom = 'droits'

    def appliquer(self, ctx):
        pol = ctx.pol
        stockage = entier(pol.valeur(K_LGPO + r'\Devices', 'DenyRemovableStorage'))
        if vrai(pol.valeur(K_WIN_USB, 'Deny_All')):
            stockage = max(stockage, 2)
        interdits = [c for c, v in (('stockage', stockage), ('extinction', pol.valeur(K_LGPO + r'\Permissions', 'DenyPowerOff')),
                                    ('logiciels', pol.valeur(K_LGPO + r'\Permissions', 'DenySoftwareInstall')),
                                    ('reseau', pol.valeur(K_LGPO + r'\Permissions', 'DenyNetworkConfig'))) if vrai(v)]
        if not interdits:
            return
        admins = []
        for nom in str(pol.valeur(K_LGPO + r'\Permissions', 'AdminGroups') or '').split(';'):
            nom = nom.strip()
            if nom:
                loc = ctx.noms.local(nom, True) if ('\\' in nom or '@' in nom) else nom
                if loc:
                    admins.append(loc)
        admins = admins or (admins_locaux() + ctx.admins_domaine())
        prefixes = [p for c in interdits for p in ACTIONS[c]]
        for c in interdits:
            ctx.noter(self.nom, f'interdit aux non-administrateurs : {LIBELLES[c]}')
        ctx.noter(self.nom, 'administrateurs du poste : ' + ', '.join(admins))
        if _polkit_js():
            ctx.f.ecrire(REGLES_JS, '// Stratégies de groupe (linux-gpo) : actions interdites aux utilisateurs non administrateurs\n'
                         'polkit.addRule(function(action, subject) {\n'
                         f'    var admins = {json.dumps(admins, ensure_ascii=False)};\n'
                         f'    var interdits = {json.dumps(prefixes)};\n'
                         '    if (subject.user == "root") return polkit.Result.NOT_HANDLED;\n'
                         '    for (var i = 0; i < admins.length; i++)\n'
                         '        if (subject.isInGroup(admins[i])) return polkit.Result.NOT_HANDLED;\n'
                         '    for (var j = 0; j < interdits.length; j++)\n'
                         '        if (action.id.indexOf(interdits[j]) == 0) return polkit.Result.NO;\n'
                         '    return polkit.Result.NOT_HANDLED;\n'
                         '});\n', self.nom)
        else:
            motifs = ';'.join(p + '*' for p in prefixes)
            ident = ';'.join('unix-group:' + a for a in admins)
            ctx.f.ecrire(REGLES_PKLA, f'[linux-gpo : interdit]\nIdentity=unix-user:*\nAction={motifs}\nResultAny=no\nResultInactive=no\nResultActive=no\n\n'
                         f'[linux-gpo : administrateurs]\nIdentity={ident}\nAction={motifs}\nResultAny=auth_admin\n'
                         'ResultInactive=auth_admin\nResultActive=auth_admin_keep\n', self.nom)
        if stockage >= 2:
            if _racine_sur_usb():
                ctx.noter(self.nom, 'le système démarre depuis un disque USB : pilote de stockage USB laissé actif')
            else:
                ctx.f.ecrire(MODPROBE, '# Stratégies de groupe (linux-gpo) : stockage USB bloqué\ninstall usb_storage /bin/false\n'
                             'install uas /bin/false\n', self.nom)
                ctx.noter(self.nom, 'pilote de stockage USB bloqué (effet complet au prochain branchement ou redémarrage)')

    def apres(self, ctx, changes):
        if ctx.simuler:
            return
        if REGLES_PKLA in changes or REGLES_JS in changes:
            # polkit relit seul ses règles ; un rechargement accélère la prise en compte des anciennes versions
            if outil('systemctl'):
                lancer(['systemctl', 'try-reload-or-restart', 'polkit'])
