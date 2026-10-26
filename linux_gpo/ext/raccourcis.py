"""Raccourcis (préférences Windows « Raccourcis », Shortcuts.xml), dans la session de l’utilisateur.

  - adresse web → lien (.desktop de type Link) ;
  - partage \\\\serveur\\dossier → lien smb:// (ouvert par Dolphin, Nautilus…) ;
  - application → copie du lanceur de l’application installée : la cible est son nom (« Firefox », « VLC »), l’identifiant
    de son lanceur (« org.onlyoffice.desktopeditors ») ou un chemin Windows (C:\\…\\chrome.exe : « chrome ») ;
  - chemin Linux → dossier ouvert ou programme lancé.
Emplacements : Bureau (dossier du bureau de l’utilisateur, « Bureau » en français), menu Démarrer et Programmes (menu des
applications), Démarrage (lancé à l’ouverture de session). Filtrage par groupe respecté ; un raccourci retiré de la GPO
disparaît du poste.
"""
import os
import re
import xml.etree.ElementTree as ET

from . import Extension
from .utilisateur import Lecteurs
from ..systeme import lancer, outil

SHORTCUTS = 'USER/Preferences/Shortcuts/Shortcuts.xml'
DOSSIERS_APPLIS = ['~/.local/share/flatpak/exports/share/applications', '/var/lib/flatpak/exports/share/applications',
                   '/var/lib/snapd/desktop/applications', '~/.local/share/applications', '/usr/local/share/applications',
                   '/usr/share/applications']


def dossier_bureau() -> str:
    """Dossier du bureau (XDG_DESKTOP_DIR) ; créé par xdg-user-dirs s’il ne l’est pas encore (première session)."""
    dirs = os.path.expanduser('~/.config/user-dirs.dirs')
    if not os.path.exists(dirs) and outil('xdg-user-dirs-update'):
        lancer(['xdg-user-dirs-update'], delai=30)
    try:
        with open(dirs, encoding='utf-8') as fh:
            m = re.search(r'^XDG_DESKTOP_DIR="([^"]+)"', fh.read(), re.M)
        if m:
            return m.group(1).replace('$HOME', os.path.expanduser('~'))
    except OSError:
        pass
    return os.path.expanduser('~/Desktop')


def _lanceurs() -> dict[str, str]:
    """{identifiant du lanceur : chemin}, le premier trouvé l’emporte (Flatpak et Snap avant les paquets)."""
    trouves = {}
    for d in DOSSIERS_APPLIS:
        d = os.path.expanduser(d)
        try:
            noms = sorted(os.listdir(d))
        except OSError:
            continue
        for n in noms:
            if n.endswith('.desktop'):
                trouves.setdefault(n[:-8], os.path.join(d, n))
    return trouves


def _nom_affiche(chemin: str) -> str:
    try:
        with open(chemin, encoding='utf-8', errors='replace') as fh:
            m = re.search(r'^Name=(.+)$', fh.read(), re.M)
        return m.group(1).strip() if m else ''
    except OSError:
        return ''


def trouver_application(cible: str, lanceurs: dict[str, str]) -> str | None:
    c = cible.strip().replace('/', '\\').split('\\')[-1]
    c = re.sub(r'(?i)\.(exe|lnk|desktop)$', '', c).strip().lower()
    if not c:
        return None
    ids = {i.lower(): p for i, p in lanceurs.items()}
    if c in ids:
        return ids[c]
    for i, p in ids.items():  # org.mozilla.firefox, com.google.Chrome…
        if i.rsplit('.', 1)[-1] == c:
            return p
    for p in lanceurs.values():
        if _nom_affiche(p).lower() == c:
            return p
    for i, p in sorted(ids.items()):  # google-chrome pour « chrome »
        if re.search(r'(^|[.\-_])' + re.escape(c) + r'($|[.\-_])', i):
            return p
    return None


def lanceur(cible: str, nom: str, args: str, lanceurs: dict[str, str]) -> str | None:
    """Contenu du fichier .desktop pour cette cible, None si elle n’existe pas sur ce poste."""
    def lien(url):
        return f'[Desktop Entry]\nType=Link\nName={nom}\nURL={url}\nIcon={"folder-remote" if url.startswith("smb:") else "text-html"}\n'
    if re.match(r'(?i)^https?://', cible):
        return lien(cible)
    if cible.startswith('\\\\'):
        return lien('smb:' + cible.replace('\\', '/'))
    if cible.startswith('/'):
        if os.path.isdir(cible):
            return f'[Desktop Entry]\nType=Link\nName={nom}\nURL=file://{cible}\nIcon=folder\n'
        if os.access(cible, os.X_OK):
            return f'[Desktop Entry]\nType=Application\nName={nom}\nExec={cible}{" " + args if args else ""}\nIcon=application-x-executable\n'
        return None
    p = trouver_application(cible, lanceurs)
    if not p:
        return None
    try:
        with open(p, encoding='utf-8', errors='replace') as fh:
            return fh.read()
    except OSError:
        return None


class Raccourcis(Extension):
    nom = 'raccourcis'
    machine = False

    def appliquer(self, ctx):
        voulus = {}
        for _, f in ctx.pol.fichiers(SHORTCUTS):
            try:
                racine = ET.parse(f).getroot()
            except (OSError, ET.ParseError):
                continue
            for el in racine.iter('Shortcut'):
                pr = el.find('Properties')
                if pr is None or el.get('disabled') == '1' or not Lecteurs._filtre_ok(self, ctx, el):
                    continue
                ou, _, nom = (pr.get('shortcutPath') or '').partition('\\')
                nom = (nom or el.get('name') or '').strip()
                if not nom:
                    continue
                cle = (ou.upper(), nom.lower())
                if pr.get('action', 'U') == 'D':
                    voulus.pop(cle, None)
                else:
                    voulus[cle] = (ou.upper(), nom, pr.get('targetPath') or '', pr.get('arguments') or '')
        if not voulus:
            return
        lanceurs = _lanceurs()
        bureau = None
        for ou, nom, cible, args in voulus.values():
            contenu = lanceur(cible, nom, args, lanceurs)
            if contenu is None:
                ctx.noter(self.nom, f'{nom} : {cible} introuvable sur ce poste')
                continue
            if ou == '%DESKTOPDIR%':
                bureau = bureau or dossier_bureau()
                dossier = bureau
            elif ou == '%STARTUPDIR%':
                dossier = os.path.expanduser('~/.config/autostart')
            else:
                dossier = os.path.expanduser('~/.local/share/applications')
            fichier = os.path.join(dossier, 'linux-gpo-' + re.sub(r'[^A-Za-z0-9._-]', '_', nom) + '.desktop')
            ctx.noter(self.nom, f'{nom} → {fichier}')
            if ctx.simuler:
                continue
            # exécutable : Plasma et GNOME ne lancent un lanceur du bureau que s’il l’est (sinon : « fichier non fiable »)
            ctx.f.ecrire(fichier, contenu, self.nom, mode=0o755)
            if dossier == bureau and outil('gio'):
                lancer(['gio', 'set', fichier, 'metadata::trusted', 'true'], delai=10)
