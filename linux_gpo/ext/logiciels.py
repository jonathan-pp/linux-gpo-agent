"""Logiciels : paquets à installer ou à retirer, applications Flatpak.

Réglages (ordinateur) :
  LinuxGPO\\Software\\Install   un paquet par valeur : « nom », ou un nom par gestionnaire
                                « apt:libreoffice pacman:libreoffice-fresh dnf:libreoffice »
  LinuxGPO\\Software\\Remove    même format : paquets à désinstaller
  LinuxGPO\\Software\\Flatpak   identifiants d’applications Flathub (« org.libreoffice.LibreOffice »)
Un paquet retiré de la liste reste installé (comme une application déployée sans « désinstaller si hors
de portée ») ; pour le retirer, ajoutez-le à Remove.
"""
from . import K_LGPO, Extension
from ..systeme import est_nixos, lancer, outil

K = K_LGPO + r'\Software'
GESTIONNAIRES = ['apt', 'pacman', 'dnf', 'zypper']
FLATHUB = 'https://dl.flathub.org/repo/flathub.flatpakrepo'


def gestionnaire() -> str | None:
    for g, exe in (('apt', 'apt-get'), ('pacman', 'pacman'), ('dnf', 'dnf'), ('zypper', 'zypper')):
        if outil(exe):
            return g
    return None


def nom_pour(spec: str, g: str) -> str | None:
    """« apt:a pacman:b » → nom du paquet pour ce gestionnaire ; « nom » → nom ; absent → None."""
    morceaux = spec.split()
    if not any(':' in m for m in morceaux):
        return spec.strip() or None
    for m in morceaux:
        k, _, v = m.partition(':')
        if k == g or (g == 'zypper' and k == 'rpm') or (g == 'dnf' and k == 'rpm'):
            return v
    return None


def installe(g: str, p: str) -> bool:
    if g == 'apt':
        return 'install ok installed' in lancer(['dpkg-query', '-W', '-f=${Status}', p]).stdout
    if g == 'pacman':
        return lancer(['pacman', '-Q', p]).returncode == 0
    return lancer(['rpm', '-q', '--whatprovides', p]).returncode == 0


ENV = {'DEBIAN_FRONTEND': 'noninteractive'}


def installer(g: str, paquets: list[str]) -> tuple[int, str]:
    if g == 'apt':
        lancer(['apt-get', 'update', '-q'], env=ENV, delai=600)
        r = lancer(['apt-get', 'install', '-y', '-q'] + paquets, env=ENV, delai=3600)
    elif g == 'pacman':
        r = lancer(['pacman', '-S', '--noconfirm', '--needed'] + paquets, delai=3600)
    elif g == 'dnf':
        r = lancer(['dnf', 'install', '-y'] + paquets, delai=3600)
    else:
        r = lancer(['zypper', '-n', 'install'] + paquets, delai=3600)
    return r.returncode, (r.stderr or r.stdout).strip()[-300:]


def retirer(g: str, paquets: list[str]) -> tuple[int, str]:
    cmd = {'apt': ['apt-get', 'remove', '-y', '-q'], 'pacman': ['pacman', '-R', '--noconfirm'], 'dnf': ['dnf', 'remove', '-y'],
           'zypper': ['zypper', '-n', 'remove']}[g]
    r = lancer(cmd + paquets, env=ENV, delai=1800)
    return r.returncode, (r.stderr or r.stdout).strip()[-300:]


class Logiciels(Extension):
    nom = 'logiciels'

    def appliquer(self, ctx):
        pol = ctx.pol
        a_installer = [str(v) for v in pol.liste(K + r'\Install') if str(v).strip()]
        a_retirer = [str(v) for v in pol.liste(K + r'\Remove') if str(v).strip()]
        flatpaks = [str(v).strip() for v in pol.liste(K + r'\Flatpak') if str(v).strip()]
        if not (a_installer or a_retirer or flatpaks):
            return
        g = gestionnaire()
        if est_nixos() and (a_installer or a_retirer):
            ctx.noter(self.nom, 'NixOS : les paquets se déclarent dans la configuration (environment.systemPackages)')
            a_installer = a_retirer = []
        if g is None and (a_installer or a_retirer):
            ctx.noter(self.nom, 'aucun gestionnaire de paquets reconnu')
            a_installer = a_retirer = []
        manquants = [n for n in (nom_pour(s, g) for s in a_installer) if n and not installe(g, n)]
        presents = [n for n in (nom_pour(s, g) for s in a_retirer) if n and installe(g, n)]
        for n in [nom_pour(s, g) for s in a_installer if nom_pour(s, g)]:
            ctx.noter(self.nom, f"{n} : {'à installer' if n in manquants else 'installé'}")
        if ctx.simuler:
            return
        if manquants:
            code, msg = installer(g, manquants)
            ctx.noter(self.nom, f"installation de {', '.join(manquants)} : {'faite' if code == 0 else 'échec — ' + msg}")
        if presents:
            code, msg = retirer(g, presents)
            ctx.noter(self.nom, f"désinstallation de {', '.join(presents)} : {'faite' if code == 0 else 'échec — ' + msg}")
        if flatpaks:
            installer_flatpaks(ctx, self.nom, flatpaks)


def installer_flatpaks(ctx, ext: str, apps: list[str]) -> list[str]:
    """Installe pour tout le poste les applications Flathub manquantes (flatpak installé au besoin) ; renvoie celles en échec."""
    if not outil('flatpak'):
        g = gestionnaire()
        if g and not est_nixos():
            installer(g, ['flatpak'])
        if not outil('flatpak'):
            ctx.noter(ext, 'flatpak non disponible : applications ignorées')
            return list(apps)
    lancer(['flatpak', 'remote-add', '--system', '--if-not-exists', 'flathub', FLATHUB], delai=300)
    echecs = []
    for app in apps:
        if lancer(['flatpak', 'info', '--system', app]).returncode == 0:
            ctx.noter(ext, f'{app} (Flatpak) : installé')
            continue
        r = lancer(['flatpak', 'install', '--system', '-y', '--noninteractive', 'flathub', app], delai=3600)
        if r.returncode:
            echecs.append(app)
        ctx.noter(ext, f"{app} (Flatpak) : {'installé' if r.returncode == 0 else 'échec — ' + (r.stderr or r.stdout).strip()[-200:]}")
    return echecs
