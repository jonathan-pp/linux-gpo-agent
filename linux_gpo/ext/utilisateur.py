"""Stratégies utilisateur, appliquées à l’ouverture de session avec le ticket Kerberos de l’utilisateur.

  - Lecteurs réseau (préférences Windows « Mappages de lecteurs », Drives.xml) → favoris du gestionnaire de
    fichiers (GNOME/GTK et KDE) et montage par gio quand il est disponible ; filtrage par groupe respecté ;
  - écran de veille Windows (actif, délai, protégé par mot de passe) → verrouillage de l’écran ;
  - papier peint Windows (Wallpaper, WallpaperStyle) → fond d’écran (image copiée depuis le partage) ;
  - « Désactiver l’accès à l’invite de commandes » et « Supprimer le menu Exécuter » → terminal interdit ;
  - LinuxGPO\\Desktop (mêmes réglages qu’en ordinateur) et LinuxGPO\\Scripts\\Logon (commandes lancées à
    l’ouverture de session).
Ces réglages sont ceux de l’utilisateur : il pourrait les modifier, mais ils sont remis à chaque session et
toutes les 90 minutes. Pour les imposer, utilisez les mêmes réglages côté ordinateur (verrous).
"""
import html
import os
import re
import xml.etree.ElementTree as ET

from . import K_LGPO, K_WIN_EXPL, K_WIN_SYS, Extension, entier, vrai
from ..systeme import ErreurAgent, lancer, outil

K_DESK = r'Software\Policies\Microsoft\Windows\Control Panel\Desktop'
K_CMD = r'Software\Policies\Microsoft\Windows\System'
DRIVES = 'USER/Preferences/Drives/Drives.xml'
STYLES_GNOME = ['centered', 'wallpaper', 'stretched', 'scaled', 'zoom', 'spanned']


def _maison(p: str) -> str:
    return os.path.join(os.path.expanduser('~'), p)


class BureauUtilisateur(Extension):
    nom = 'bureau-utilisateur'
    machine = False

    def appliquer(self, ctx):
        pol = ctx.pol
        r = {}
        if vrai(pol.valeur(K_LGPO + r'\Desktop', 'DisableCommandLine')) or entier(pol.valeur(K_CMD, 'DisableCMD')) in (1, 2) \
                or vrai(pol.valeur(K_WIN_EXPL, 'NoRun')):
            r['terminal'] = True
        delai = entier(pol.valeur(K_LGPO + r'\Desktop', 'LockDelay'))
        if not delai and vrai(pol.valeur(K_DESK, 'ScreenSaveActive')) and vrai(pol.valeur(K_DESK, 'ScreenSaverIsSecure')):
            delai = entier(pol.valeur(K_DESK, 'ScreenSaveTimeOut'), 900)
        if delai:
            r['verrou'] = delai
        fond = str(pol.valeur(K_LGPO + r'\Desktop', 'Wallpaper') or pol.valeur(K_WIN_SYS, 'Wallpaper') or '').strip()
        if fond:
            r['fond'] = (fond, entier(pol.valeur(K_WIN_SYS, 'WallpaperStyle'), 4))
        mem = ctx.f.memoire(self.nom)
        avant = set(mem.get('dconf', []))
        cles = {}
        if r.get('terminal'):
            cles.update({'/org/gnome/desktop/lockdown/disable-command-line': 'true',
                         '/org/cinnamon/desktop/lockdown/disable-command-line': 'true',
                         '/org/mate/desktop/lockdown/disable-command-line': 'true'})
        if 'verrou' in r:
            s = r['verrou']
            cles.update({'/org/gnome/desktop/session/idle-delay': f'uint32 {s}', '/org/gnome/desktop/screensaver/lock-enabled': 'true',
                         '/org/cinnamon/desktop/session/idle-delay': f'uint32 {s}', '/org/cinnamon/desktop/screensaver/lock-enabled': 'true',
                         '/org/mate/session/idle-delay': str(max(1, (s + 59) // 60)), '/org/mate/screensaver/lock-enabled': 'true'})
        if 'fond' in r:
            image = self._image(ctx, r['fond'][0])
            if image:
                uri = "'file://" + image + "'"
                style = "'" + STYLES_GNOME[r['fond'][1] if 0 <= r['fond'][1] < 6 else 4] + "'"
                cles.update({'/org/gnome/desktop/background/picture-uri': uri, '/org/gnome/desktop/background/picture-uri-dark': uri,
                             '/org/gnome/desktop/background/picture-options': style, '/org/cinnamon/desktop/background/picture-uri': uri,
                             '/org/mate/desktop/background/picture-filename': "'" + image + "'"})
                if outil('plasma-apply-wallpaperimage') and not ctx.simuler and mem.get('fond_kde') != image:
                    lancer(['plasma-apply-wallpaperimage', image])
                    mem['fond_kde'] = image
        for k, v in r.items():
            ctx.noter(self.nom, f'{k} : {v[0] if isinstance(v, tuple) else "oui" if v is True else v}')
        if ctx.simuler:
            return
        if outil('dconf') and (cles or avant):
            poses, echec = [], ''
            for k, v in cles.items():
                if lancer(['dconf', 'read', k]).stdout.strip() != v:
                    r = lancer(['dconf', 'write', k, v])
                    if r.returncode:
                        echec = r.stderr.strip()
                        continue
                poses.append(k)
            for k in avant - set(cles):
                lancer(['dconf', 'reset', k])
            if echec:
                ctx.noter(self.nom, f'dconf : {echec[-160:]}')
            mem['dconf'] = sorted(poses)
        kw = outil('kwriteconfig6') or outil('kwriteconfig5')
        if kw:
            kde = []
            if r.get('terminal'):
                kde += [('kdeglobals', 'KDE Action Restrictions', 'shell_access', 'false'),
                        ('kdeglobals', 'KDE Action Restrictions', 'run_command', 'false')]
            if 'verrou' in r:
                kde += [('kscreenlockerrc', 'Daemon', 'Autolock', 'true'),
                        ('kscreenlockerrc', 'Daemon', 'Timeout', str(max(1, (r['verrou'] + 59) // 60)))]
            for f, g, k, v in kde:
                lancer([kw, '--file', f, '--group', g, '--key', k, v])
            for f, g, k in [tuple(x) for x in mem.get('kde', [])]:
                if not any((f, g, k) == x[:3] for x in kde):
                    lancer([kw, '--file', f, '--group', g, '--key', k, '--delete'])
            mem['kde'] = [list(x[:3]) for x in kde]

    def _image(self, ctx, chemin: str) -> str | None:
        if chemin.startswith('/'):
            return chemin
        if not chemin.startswith(('\\\\', '//')) or not ctx.annuaire:
            return None
        ext = os.path.splitext(chemin)[1].lower() or '.jpg'
        dest = _maison(f'.cache/linux-gpo/fond{ext}')
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        try:
            ctx.annuaire.copier_fichier(chemin, dest + '.tmp')
            os.replace(dest + '.tmp', dest)
        except (ErreurAgent, OSError) as e:
            ctx.noter(self.nom, f'papier peint {chemin} : {e}')
            return dest if os.path.exists(dest) else None
        return dest


class Lecteurs(Extension):
    nom = 'lecteurs'
    machine = False

    def _filtre_ok(self, ctx, el) -> bool:
        f = el.find('Filters')
        if f is None:
            return True
        jeton = ctx.jeton
        for fg in f.findall('FilterGroup') + f.findall('FilterUser'):
            sid = fg.get('sid', '')
            ok = sid in jeton if sid else True
            if fg.get('not') == '1':
                ok = not ok
            if fg.get('bool', 'AND') == 'AND' and not ok:
                return False
        return True

    def appliquer(self, ctx):
        lecteurs = {}
        for _, f in ctx.pol.fichiers(DRIVES):
            try:
                racine = ET.parse(f).getroot()
            except (OSError, ET.ParseError):
                continue
            for el in racine.iter('Drive'):
                pr = el.find('Properties')
                if pr is None or el.get('disabled') == '1' or not self._filtre_ok(ctx, el):
                    continue
                chemin = (pr.get('path') or '').replace('%USERNAME%', ctx.utilisateur).replace('%LOGONUSER%', ctx.utilisateur)
                cle = (pr.get('letter') or chemin).upper()
                if pr.get('action', 'U') == 'D':
                    lecteurs.pop(cle, None)
                    continue
                if chemin.startswith('\\\\'):
                    url = 'smb:' + chemin.replace('\\', '/')
                    libelle = pr.get('label') or f"{chemin.rstrip(chr(92)).split(chr(92))[-1]} ({pr.get('letter', '')}:)"
                    lecteurs[cle] = (url, libelle)
        mem = ctx.f.memoire(self.nom)
        voulus = sorted(lecteurs.values())
        for url, lib in voulus:
            ctx.noter(self.nom, f'{lib} → {url}')
        if ctx.simuler or (voulus == [tuple(x) for x in mem.get('lecteurs', [])] and not voulus):
            return
        self._gtk(voulus, [tuple(x) for x in mem.get('lecteurs', [])])
        self._kde(voulus)
        if outil('gio'):
            for url, _ in voulus:
                lancer(['gio', 'mount', url], delai=30)
        mem['lecteurs'] = [list(x) for x in voulus]

    @staticmethod
    def _gtk(voulus, avant):
        p = _maison('.config/gtk-3.0/bookmarks')
        try:
            with open(p, encoding='utf-8') as fh:
                lignes = fh.read().splitlines()
        except OSError:
            lignes = []
        anciennes = {f'{u} {l}' for u, l in avant}
        lignes = [l for l in lignes if l not in anciennes]
        for u, l in voulus:
            if f'{u} {l}' not in lignes:
                lignes.append(f'{u} {l}')
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, 'w', encoding='utf-8') as fh:
            fh.write('\n'.join(lignes) + ('\n' if lignes else ''))

    @staticmethod
    def _kde(voulus):
        p = _maison('.local/share/user-places.xbel')
        if not os.path.exists(p) and not (outil('dolphin') or outil('plasmashell')):
            return
        try:
            with open(p, encoding='utf-8') as fh:
                texte = fh.read()
        except OSError:
            texte = ('<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE xbel>\n<xbel xmlns:bookmark="http://www.freedesktop.org/standards/desktop-bookmarks"'
                     ' xmlns:kdepriv="http://www.kde.org/kdepriv" xmlns:mime="http://www.freedesktop.org/standards/shared-mime-info">\n</xbel>\n')
        texte = re.sub(r'\s*<bookmark href="[^"]*">(?:(?!</bookmark>).)*?<ID>linux-gpo-[^<]*</ID>(?:(?!</bookmark>).)*?</bookmark>', '', texte, flags=re.S)
        ajout = ''.join(f'\n <bookmark href="{html.escape(u)}">\n  <title>{html.escape(l)}</title>\n  <info>\n'
                        '   <metadata owner="http://freedesktop.org">\n    <bookmark:icon name="folder-remote"/>\n   </metadata>\n'
                        f'   <metadata owner="http://www.kde.org">\n    <ID>linux-gpo-{i}</ID>\n    <isSystemItem>false</isSystemItem>\n'
                        '   </metadata>\n  </info>\n </bookmark>' for i, (u, l) in enumerate(voulus))
        texte = texte.replace('</xbel>', ajout + '\n</xbel>', 1) if ajout else texte
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, 'w', encoding='utf-8') as fh:
            fh.write(texte)


class ScriptsSession(Extension):
    nom = 'scripts-session'
    machine = False

    def appliquer(self, ctx):
        cmds = {k: str(v) for k, v in ctx.pol.valeurs(K_LGPO + r'\Scripts\Logon').items() if str(v).strip()}
        for nom, cmd in cmds.items():
            ctx.noter(self.nom, f'{nom} : {cmd[:60]}')
        if ctx.simuler or not cmds or not ctx.ouverture:
            return
        for cmd in cmds.values():
            lancer(['/bin/sh', '-c', cmd], delai=600)
