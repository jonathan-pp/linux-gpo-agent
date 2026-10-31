"""Logiciels : paquets à installer ou à retirer, applications Flatpak.

Réglages (ordinateur) :
  LinuxGPO\\Software\\Install   un paquet par valeur : « nom », ou un nom par gestionnaire
                                « apt:libreoffice pacman:libreoffice-fresh dnf:libreoffice »
  LinuxGPO\\Software\\Remove    même format : paquets à désinstaller
  LinuxGPO\\Software\\Flatpak   identifiants d’applications Flathub (« org.libreoffice.LibreOffice »)
Un paquet retiré de la liste reste installé (comme une application déployée sans « désinstaller si hors
de portée ») ; pour le retirer, ajoutez-le à Remove.
"""
import hashlib
import json
import os
import platform
import re
import shutil
import tempfile
import urllib.request

from . import K_LGPO, Extension
from ..systeme import chemin, est_nixos, lancer, os_release, outil

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


# ---------------------------------------------------------------- dernière version d’un dépôt GitHub

DEPOT = re.compile(r'^[A-Za-z0-9][A-Za-z0-9-]{0,38}/\w[\w.-]{0,99}$')
FICHIER_GITHUB = re.compile(r'^[\w.+~-]{1,200}$')
ETAT_GITHUB = '/var/lib/linux-gpo/github.json'     # {dépôt: {paquet, version}} : ce que l’agent a posé, pour ne pas le reposer
TAILLE_MAX = 2 * 1024 ** 3
_ARCH = {'x86_64': re.compile(r'(x86[_-]64|amd64|x64)', re.I), 'aarch64': re.compile(r'(aarch64|arm64)', re.I)}
_AUTRE_ARCH = re.compile(r'(aarch64|arm64|armv7l?|armhf|ppc64|s390x|riscv|i[3-6]86|x86(?![_-]?64)|x86[_-]64|amd64|x64)', re.I)
_VERSIONS = re.compile(r'(?<![a-z])(trixie|bookworm|bullseye|forky|sid|noble|jammy|focal|oracular|plucky|questing|debian[_.-]?\d+|ubuntu[_.-]?\d+(?:\.\d+)?)(?![a-z])', re.I)


def choisir_fichier(noms: list[str], g: str, machine: str, versions: tuple[str, ...] = ()) -> str | None:
    """Fichier de la dernière version à installer : .deb (apt) ou .pkg.tar.zst (pacman) pour l’architecture du poste, de préférence
    construit pour sa version (« …-noble.deb »), puis un fichier générique, puis celui d’une autre version. Sans mention d’architecture,
    le fichier est supposé x86_64. Même choix que PXE Deploy au déploiement."""
    exts = {'apt': ('.deb',), 'pacman': ('.pkg.tar.zst', '.pacman')}.get(g)
    voulue = _ARCH.get(machine)
    if not exts or voulue is None:
        return None
    meilleur = None
    for nom in noms:
        if not nom.lower().endswith(exts) or not FICHIER_GITHUB.match(nom):
            continue
        if voulue.search(nom):
            arch = 0
        elif machine == 'x86_64' and not _AUTRE_ARCH.search(nom):
            arch = 1
        else:
            continue
        mention = _VERSIONS.search(nom)
        nu = re.sub(r'[^a-z0-9]', '', mention.group(1).lower()) if mention else ''
        rang = 5 if not mention else (0 if any(v and (nu == v or (v.isdigit() and nu.endswith(v))) for v in versions) else 9)
        cle = (rang, arch, nom)
        if meilleur is None or cle[:2] < meilleur[:2]:
            meilleur = cle
    return meilleur[2] if meilleur else None


def _version_poste() -> tuple[str, ...]:
    """Nom de code (trixie, noble) et numéro (13, 2404) de la version, pour reconnaître « …-noble.deb » ou « …-debian13.deb »."""
    o = os_release()
    return ((o.get('VERSION_CODENAME') or o.get('UBUNTU_CODENAME') or '').lower(), re.sub(r'\D', '', o.get('VERSION_ID', '')))


def _etat_github() -> dict:
    try:
        with open(chemin(ETAT_GITHUB), encoding='utf-8') as fh:
            d = json.load(fh)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def github_present(g: str | None, depot: str) -> bool:
    """Vrai si l’agent a posé ce dépôt et que le paquet est toujours là."""
    paquet = (_etat_github().get(depot) or {}).get('paquet')
    return bool(g and paquet and installe(g, paquet))


def _ouvrir(url: str, delai: int = 60):
    req = urllib.request.Request(url, headers={'User-Agent': 'linux-gpo', 'Accept': 'application/vnd.github+json'})
    return urllib.request.urlopen(req, timeout=delai)  # noqa: S310 - https://api.github.com ou https://github.com (vérifié)


def installer_github(g: str, depot: str) -> tuple[int, str]:
    """Installe la dernière version d’un dépôt GitHub (« propriétaire/dépôt ») : .deb avec apt, .pkg.tar.zst avec pacman. Le fichier
    est vérifié par son SHA-256 quand GitHub le donne ; (0, version) si tout va bien, sinon (code, message)."""
    if g not in ('apt', 'pacman'):
        return 1, f'GitHub : gestionnaire {g or "inconnu"} non pris en charge'
    if not DEPOT.match(depot):
        return 1, f'GitHub : dépôt invalide ({depot})'
    try:
        with _ouvrir(f'https://api.github.com/repos/{depot}/releases/latest') as r:
            release = json.load(r)
        assets = {a['name']: a for a in release.get('assets') or [] if isinstance(a, dict) and isinstance(a.get('name'), str)}
        nom = choisir_fichier(list(assets), g, platform.machine(), _version_poste())
        if nom is None:
            return 1, f'GitHub : {depot} ne publie pas de fichier {"deb" if g == "apt" else "pkg.tar.zst"} pour {platform.machine()}'
        url = str(assets[nom].get('browser_download_url') or '')
        if not url.startswith(f'https://github.com/{depot.split("/")[0]}/'):
            return 1, 'GitHub : adresse de téléchargement inattendue'
        attendu = str(assets[nom].get('digest') or '')
        attendu = attendu[7:].lower() if re.fullmatch(r'sha256:[0-9a-fA-F]{64}', attendu) else ''
        dossier = tempfile.mkdtemp(prefix='linux-gpo-github-', dir='/var/tmp' if os.path.isdir('/var/tmp') else None)  # pas /tmp : souvent en mémoire
        try:
            os.chmod(dossier, 0o755)
            fichier = os.path.join(dossier, nom)
            h, taille = hashlib.sha256(), 0
            with _ouvrir(url, 300) as src, open(fichier, 'wb') as out:
                for bloc in iter(lambda: src.read(1 << 20), b''):
                    taille += len(bloc)
                    if taille > TAILLE_MAX:
                        return 1, 'GitHub : fichier trop volumineux'
                    h.update(bloc)
                    out.write(bloc)
            if attendu and h.hexdigest() != attendu:
                return 1, 'GitHub : somme SHA-256 différente de celle publiée, fichier refusé'
            os.chmod(fichier, 0o644)
            if g == 'apt':
                paquet = lancer(['dpkg-deb', '-f', fichier, 'Package']).stdout.strip()
                lancer(['apt-get', 'update', '-q'], env=ENV, delai=600)
                r = lancer(['apt-get', 'install', '-y', '-q', fichier], env=ENV, delai=3600)
            else:
                paquet = lancer(['pacman', '-Qp', fichier]).stdout.split(' ')[0].strip()
                r = lancer(['pacman', '-U', '--noconfirm', '--needed', fichier], delai=3600)
        finally:
            shutil.rmtree(dossier, ignore_errors=True)
    except (OSError, ValueError, KeyError) as e:
        return 1, f'GitHub : {e}'
    if r.returncode:
        return r.returncode, (r.stderr or r.stdout).strip()[-300:]
    etat = _etat_github()
    etat[depot] = {'paquet': paquet, 'version': str(release.get('tag_name') or '')}
    cible = chemin(ETAT_GITHUB)
    os.makedirs(os.path.dirname(cible), exist_ok=True)
    with open(cible, 'w', encoding='utf-8') as fh:
        json.dump(etat, fh)
    return 0, etat[depot]['version']


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
