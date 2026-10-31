"""Ce que l’agent sait du poste : distribution, outils présents, exécution de commandes."""
from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess

journal = logging.getLogger('linux-gpo')

# NixOS place les programmes hors des chemins habituels
CHEMINS = ['/usr/local/sbin', '/usr/local/bin', '/usr/sbin', '/usr/bin', '/sbin', '/bin',
           '/run/current-system/sw/bin', '/run/wrappers/bin']
RACINE = os.environ.get('LINUX_GPO_RACINE', '')  # tests : racine du système simulé


def chemin(p: str) -> str:
    """Chemin réel d’un fichier du système (préfixé par la racine de test le cas échéant)."""
    return RACINE + p if RACINE and p.startswith('/') else p


def outil(nom: str) -> str | None:
    return shutil.which(nom, path=os.pathsep.join([os.environ.get('PATH', '')] + CHEMINS))


def lancer(cmd: list[str], entree: str | None = None, env: dict | None = None, delai: int = 120,
           verifier: bool = False) -> subprocess.CompletedProcess:
    """Lance une commande (jamais par le shell). Une commande absente donne le code 127."""
    exe = outil(cmd[0]) if not os.path.isabs(cmd[0]) else cmd[0]
    if not exe:
        r = subprocess.CompletedProcess(cmd, 127, '', f'{cmd[0]} : commande introuvable')
    else:
        try:
            r = subprocess.run([exe] + cmd[1:], input=entree, capture_output=True, text=True, timeout=delai,
                               env={**os.environ, **(env or {})})
        except subprocess.TimeoutExpired:
            r = subprocess.CompletedProcess(cmd, 124, '', f'{cmd[0]} : délai dépassé')
    if r.returncode and verifier:
        raise ErreurAgent(f"{' '.join(cmd[:3])} : {(r.stderr or r.stdout).strip()[-300:]}")
    return r


class ErreurAgent(Exception):
    pass


# Affichage du fond d’écran : numéros du réglage « Style du papier peint » des GPO (WallpaperStyle) →
# valeur GNOME (picture-options) et mode de remplissage de Plasma. 4 = remplir en rognant.
STYLES_GNOME = ['centered', 'wallpaper', 'stretched', 'scaled', 'zoom', 'spanned']
MODES_PLASMA = ['pad', 'tile', 'stretch', 'preserveAspectFit', 'preserveAspectCrop', 'preserveAspectCrop']
STYLE_FOND = 4


def style_fond(valeur) -> int:
    return valeur if isinstance(valeur, int) and not isinstance(valeur, bool) and 0 <= valeur < len(STYLES_GNOME) else STYLE_FOND


def bande_fond(valeur) -> dict:
    """Bandes de l’affichage « ajuster » : {mode: 'couleur'|'flou', couleur: '#rrggbb'} (noir uni sans indication valable)."""
    v = valeur if isinstance(valeur, dict) else {}
    couleur = v.get('couleur')
    return {'mode': 'flou' if v.get('mode') == 'flou' else 'couleur',
            'couleur': couleur.lower() if isinstance(couleur, str) and re.fullmatch(r'#[0-9a-fA-F]{6}', couleur) else '#000000'}


def fond_plasma(image: str, style: int, env: dict | None = None) -> None:
    """Fond d’écran de Plasma avec son mode d’affichage ; une version de Plasma sans --fill-mode garde l’image seule."""
    r = lancer(['plasma-apply-wallpaperimage', '--fill-mode', MODES_PLASMA[style_fond(style)], image], env=env)
    if r.returncode:
        lancer(['plasma-apply-wallpaperimage', image], env=env)


def os_release() -> dict:
    infos = {}
    for f in ('/etc/os-release', '/usr/lib/os-release'):
        try:
            with open(chemin(f), encoding='utf-8') as fh:
                for ligne in fh:
                    if '=' in ligne and not ligne.startswith('#'):
                        k, v = ligne.rstrip('\n').split('=', 1)
                        infos[k] = v.strip().strip('"\'')
            break
        except OSError:
            continue
    return infos


def famille() -> str:
    """debian, arch, fedora, suse, nixos ou autre (d’après ID et ID_LIKE)."""
    o = os_release()
    ids = [o.get('ID', '')] + o.get('ID_LIKE', '').split()
    for f, noms in (('nixos', ('nixos',)), ('debian', ('debian', 'ubuntu')), ('arch', ('arch', 'archlinux')),
                    ('fedora', ('fedora', 'rhel', 'centos')), ('suse', ('suse', 'opensuse'))):
        if any(i in noms for i in ids):
            return f
    return 'autre'


def est_nixos() -> bool:
    return famille() == 'nixos'


def systemd_actif() -> bool:
    return os.path.isdir(chemin('/run/systemd/system')) and not RACINE


def service_actif(nom: str) -> bool:
    return systemd_actif() and lancer(['systemctl', 'is-active', '--quiet', nom]).returncode == 0


def service(action: str, nom: str) -> None:
    """reload / restart / try-reload-or-restart d’un service s’il tourne (rien hors systemd)."""
    if systemd_actif():
        r = lancer(['systemctl', action, nom])
        if r.returncode:
            journal.warning('systemctl %s %s : %s', action, nom, r.stderr.strip())


def gere_par_nix(p: str) -> bool:
    """Vrai si le fichier est produit par la configuration NixOS (lien vers /nix/store) : ne pas y toucher."""
    try:
        return os.path.islink(chemin(p)) and os.path.realpath(chemin(p)).startswith('/nix/store/')
    except OSError:
        return False
