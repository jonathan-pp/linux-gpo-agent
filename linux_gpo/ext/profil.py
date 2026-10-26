"""Profils de bureau (Console Annuaire › Profils de bureau) : icônes du bureau, épingles de la barre des tâches,
applications à installer et fond d’écran, dessinés une fois pour un groupe d’utilisateurs.

Un profil est une GPO qui contient USER/LinuxGPO/bureau.json :

    {"version": 1, "nom": "Bureau RH",
     "apps": [{"id": "firefox", "nom": "Firefox", "type": "appli", "flatpak": "org.mozilla.firefox",
               "lanceurs": ["firefox", "firefox_firefox"], "paquet": "apt:firefox pacman:firefox"},
              {"id": "intranet", "nom": "Intranet", "type": "web", "url": "https://intranet.exemple.local"},
              {"id": "rh", "nom": "Partage RH", "type": "partage", "chemin": "\\\\dc01\\RH"},
              {"id": "perso", "nom": "Dossier personnel", "type": "perso"}],
     "bureau": [{"app": "firefox", "col": 0, "lig": 0}, …],
     "barre": ["firefox", …],
     "fond": "fond.png"}                       (image placée à côté de bureau.json, facultative)

Dans la session (extension Profil) : les applications déjà présentes sur le poste (paquet, Snap ou Flatpak, reconnues par
leur lanceur) sont posées sur le bureau et épinglées (Plasma, GNOME) ; celles qui manquent sont demandées au service
système de l’agent, qui les installe depuis Flathub pour tout le poste (extension ApplicationsProfils), puis posées à leur
tour. Les épingles sont posées quand le profil change : l’utilisateur peut ensuite les modifier, comme avec la disposition
de la barre des tâches de Windows. Les icônes du bureau sont reposées à chaque passage et retirées avec le profil.

Poste hors domaine : le profil posé par PXE Deploy (ou à la main) dans /etc/linux-gpo/bureau.json est appliqué de la
même façon à tous les comptes locaux ; `linux-gpo bureau-local` en installe les applications.
"""
from __future__ import annotations

import json
import logging
import os
import re
import shutil
import tempfile
import time

from . import Extension
from .raccourcis import _lanceurs, dossier_bureau, trouver_application
from ..annuaire import un
from ..systeme import chemin, lancer, outil

journal = logging.getLogger('linux-gpo')

FICHIER = 'USER/LinuxGPO/bureau.json'
LOCAL = '/etc/linux-gpo/bureau.json'
DEMANDES = '/var/spool/linux-gpo'          # 1733 : chaque utilisateur y dépose sa demande, sans voir celles des autres
ID = re.compile(r'^[a-z0-9][a-z0-9._-]{0,63}$')
FLATPAK = re.compile(r'^[A-Za-z][\w-]*(\.[\w-]+){2,}$')
GUID = re.compile(r'^\{[0-9A-Fa-f-]{36}\}$')
EXPORTS = ['/var/lib/flatpak/exports/share', '~/.local/share/flatpak/exports/share']
TAILLES = ['scalable', '512x512', '256x256', '128x128', '96x96', '64x64', '48x48']
NOUVEL_ESSAI = 6 * 3600                    # application en échec : redemandée au plus toutes les 6 heures


# ---------------------------------------------------------------- lecture et fusion des profils

def charger(f: str) -> dict | None:
    """Profil lu et nettoyé (champs inconnus ignorés), None s’il est illisible."""
    try:
        with open(f, encoding='utf-8') as fh:
            d = json.load(fh)
    except (OSError, ValueError):
        return None
    if not isinstance(d, dict) or not isinstance(d.get('apps', []), list):
        return None
    apps = {}
    for a in d.get('apps') or []:
        if not isinstance(a, dict) or not ID.match(str(a.get('id', ''))) or not str(a.get('nom', '')).strip():
            continue
        t = a.get('type', 'appli')
        if t not in ('appli', 'web', 'partage', 'perso'):
            continue
        p = {'id': a['id'], 'nom': str(a['nom']).strip()[:120], 'type': t}
        if t == 'appli':
            p['flatpak'] = str(a.get('flatpak') or '') if FLATPAK.match(str(a.get('flatpak') or '')) else ''
            p['lanceurs'] = [str(x) for x in a.get('lanceurs') or [] if re.match(r'^[\w.+-]{1,120}$', str(x))][:10]
            p['paquet'] = str(a.get('paquet') or '')[:200]
        elif t == 'web':
            if not re.match(r'(?i)^https?://[^\s"]+$', str(a.get('url') or '')):
                continue
            p['url'] = a['url']
        elif t == 'partage':
            if not re.match(r'^\\\\[^\\/\s]+\\[^\n"]+$', str(a.get('chemin') or '')):
                continue
            p['chemin'] = a['chemin']
        apps[p['id']] = p
    bureau = []
    for b in d.get('bureau') or []:
        i = b.get('app') if isinstance(b, dict) else b
        if i in apps and i not in [x['app'] for x in bureau]:
            bureau.append({'app': i, 'col': _entier(b.get('col') if isinstance(b, dict) else 0),
                           'lig': _entier(b.get('lig') if isinstance(b, dict) else len(bureau))})
    barre = [i for i in dict.fromkeys(d.get('barre') or []) if i in apps and apps[i]['type'] == 'appli']
    fond = str(d.get('fond') or '')
    if fond and (os.sep in fond or fond.startswith('.') or not re.match(r'^[\w.-]+\.(png|jpe?g|svg|webp)$', fond, re.I)):
        fond = ''
    return {'nom': str(d.get('nom') or '')[:120], 'apps': apps, 'bureau': bureau, 'barre': barre,
            'fond': os.path.join(os.path.dirname(f), fond) if fond else ''}


def _entier(v) -> int:
    try:
        return max(0, int(v))
    except (TypeError, ValueError):
        return 0


def profils(ctx) -> list[tuple[str, dict]]:
    """[(source, profil)] dans l’ordre d’application : profil local du poste, puis GPO (la dernière l’emporte)."""
    res = []
    p = charger(chemin(LOCAL))
    if p:
        res.append(('local', p))
    for g, f in ctx.pol.fichiers(FICHIER):
        p = charger(f)
        if p:
            res.append((g.guid, p))
    return res


def fusionner(liste: list[dict]) -> dict:
    """Icônes : toutes celles des profils (ordre du bureau : colonne par colonne) ; barre et fond : le dernier profil qui
    en définit l’emporte."""
    apps, bureau, barre, fond = {}, [], [], ''
    for p in liste:
        apps.update(p['apps'])
        for b in sorted(p['bureau'], key=lambda b: (b['col'], b['lig'])):
            if b['app'] not in bureau:
                bureau.append(b['app'])
        barre = p['barre'] or barre
        fond = p['fond'] or fond
    return {'apps': apps, 'bureau': bureau, 'barre': barre, 'fond': fond}


# ---------------------------------------------------------------- applications

def lanceur_de(app: dict, lanceurs: dict[str, str]) -> str | None:
    """Lanceur (.desktop) de l’application sur ce poste : identifiant Flatpak, autres identifiants connus (paquet, Snap),
    sinon recherche par nom."""
    bas = {k.lower(): v for k, v in lanceurs.items()}
    for i in list(app.get('lanceurs') or []) + [app.get('flatpak')]:  # lanceurs précis d’abord (LibreOffice Writer…)
        if i and i.lower() in bas:
            return bas[i.lower()]
    return trouver_application(app['nom'], lanceurs)


def icone_flatpak(nom: str) -> str | None:
    """Icône d’une application Flatpak : chemin absolu, car le thème d’icônes ne connaît les applications Flatpak qu’après
    une nouvelle ouverture de session (variable XDG_DATA_DIRS)."""
    for base in EXPORTS:
        base = os.path.expanduser(base)
        for t in TAILLES:
            for ext in ('svg', 'png'):
                p = os.path.join(base, 'icons/hicolor', t, 'apps', f'{nom}.{ext}')
                if os.path.exists(p):
                    return p
    return None


def contenu_appli(f: str) -> str | None:
    try:
        with open(f, encoding='utf-8', errors='replace') as fh:
            t = fh.read()
    except OSError:
        return None
    if '/flatpak/exports/' in f:
        m = re.search(r'^Icon=(\S+)$', t, re.M)
        if m and not m.group(1).startswith('/'):
            p = icone_flatpak(m.group(1))
            if p:
                t = t[:m.start()] + 'Icon=' + p + t[m.end():]
    return t


def unc_vers_smb(unc: str, domaine: str) -> str:
    hote, _, reste = unc[2:].partition('\\')
    if '.' not in hote and domaine:
        hote += '.' + domaine  # nom court NetBIOS : non résolu sous Linux sans le suffixe du domaine
    return 'smb://' + hote + '/' + reste.replace('\\', '/')


def lien(nom: str, url: str, icone: str) -> str:
    return f'[Desktop Entry]\nType=Link\nName={nom}\nURL={url}\nIcon={icone}\n'


def demander_installation(ctx, sources: list[str], apps: list[str]) -> bool:
    """Demande au service système d’installer ces applications (Flatpak) et attend la fin de son passage."""
    try:
        os.makedirs(DEMANDES, exist_ok=True)
    except OSError:
        pass
    f = os.path.join(DEMANDES, f'{os.getuid()}.json')
    try:
        fd = os.open(f, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, 'O_NOFOLLOW', 0), 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as fh:
            json.dump({'sources': sources, 'apps': apps}, fh)
    except OSError as e:
        ctx.noter('profil', f'demande d’installation impossible ({e}) : applications installées au prochain passage ordinateur')
        return False
    # service système : autorisé aux sessions locales par la règle polkit installée avec l’agent
    r = lancer(['systemctl', 'start', 'linux-gpo-applications.service'], delai=3600)
    if r.returncode:
        ctx.noter('profil', 'service linux-gpo-applications non démarré : applications installées au prochain passage ordinateur')
        return False
    return True


# ---------------------------------------------------------------- barre des tâches

def _bus() -> dict:
    if os.environ.get('DBUS_SESSION_BUS_ADDRESS'):
        return {}
    return {'DBUS_SESSION_BUS_ADDRESS': f'unix:path=/run/user/{os.getuid()}/bus'}


def epingler_plasma(urls: list[str], attente: int = 90) -> bool:
    """Lanceurs épinglés du gestionnaire de tâches de Plasma (script du bureau, appliqué au panneau en cours)."""
    gdbus = outil('gdbus')
    if not gdbus:
        return False
    script = ('var l = ' + json.dumps(urls) + ', n = 0;\n'
              'panels().forEach(function (p) { p.widgets().forEach(function (w) {\n'
              '  if (w.type == "org.kde.plasma.icontasks" || w.type == "org.kde.plasma.taskmanager") {\n'
              '    w.currentConfigGroup = ["General"]; w.writeConfig("launchers", l); n++; } }); });\n'
              'print(n);')
    fin = time.time() + attente
    while True:  # à l’ouverture de session, plasmashell n’est pas forcément encore prêt
        r = lancer([gdbus, 'call', '--session', '--dest', 'org.kde.plasmashell', '--object-path', '/PlasmaShell',
                    '--method', 'org.kde.PlasmaShell.evaluateScript', script], env=_bus(), delai=30)
        if r.returncode == 0:
            return not re.search(r"'0'|\(''", r.stdout)
        if time.time() > fin:
            return False
        time.sleep(5)


def epingler_gnome(ids: list[str]) -> bool:
    if not outil('gsettings'):
        return False
    v = '[' + ', '.join("'" + i + "'" for i in ids) + ']'
    return lancer(['gsettings', 'set', 'org.gnome.shell', 'favorite-apps', v], env=_bus()).returncode == 0


# ---------------------------------------------------------------- extensions

class Profil(Extension):
    nom = 'profil'
    machine = False

    def appliquer(self, ctx):
        liste = profils(ctx)
        mem = ctx.f.memoire(self.nom)
        if not liste:
            if mem.get('barre') and not ctx.simuler:
                mem.pop('barre', None)  # profil retiré : les épingles restent, comme sous Windows
            return
        p = fusionner([x[1] for x in liste])
        ctx.noter(self.nom, 'profil : ' + ', '.join(x[1]['nom'] or x[0] for x in liste))
        utiles = [i for i in dict.fromkeys(p['bureau'] + p['barre'])]
        lanceurs = _lanceurs()
        manquantes = [i for i in utiles if p['apps'][i]['type'] == 'appli' and not lanceur_de(p['apps'][i], lanceurs)]
        a_demander = self._a_demander(mem, [p['apps'][i] for i in manquantes])
        bureau = None if ctx.simuler else dossier_bureau()
        self._bureau(ctx, p, lanceurs, bureau)
        if a_demander and not ctx.simuler:
            ctx.noter(self.nom, 'à installer : ' + ', '.join(a_demander))
            if demander_installation(ctx, [s for s, _ in liste], a_demander):
                lanceurs = _lanceurs()
                self._bureau(ctx, p, lanceurs, bureau)
            mem['demandes'] = {**mem.get('demandes', {}), **{a: time.time() for a in a_demander}}
        for i in manquantes:
            if not lanceur_de(p['apps'][i], lanceurs):
                ctx.noter(self.nom, f"{p['apps'][i]['nom']} : pas encore installée")
        self._barre(ctx, p, lanceurs, mem)
        if p['fond'] and any(s == 'local' for s, _ in liste):
            self._fond(ctx, p['fond'], mem)

    @staticmethod
    def _a_demander(mem, apps) -> list[str]:
        recent = mem.get('demandes', {})
        return [a['flatpak'] for a in apps if a.get('flatpak') and time.time() - recent.get(a['flatpak'], 0) > NOUVEL_ESSAI]

    def _bureau(self, ctx, p, lanceurs, bureau):
        perso = None
        for i in p['bureau']:
            a = p['apps'][i]
            if a['type'] == 'appli':
                f = lanceur_de(a, lanceurs)
                contenu = contenu_appli(f) if f else None
            elif a['type'] == 'web':
                contenu = lien(a['nom'], a['url'], 'text-html')
            elif a['type'] == 'partage':
                contenu = lien(a['nom'], unc_vers_smb(a['chemin'], ctx.conf.domaine), 'folder-remote')
            else:
                if perso is None:
                    from .utilisateur import Lecteurs
                    d = {}
                    Lecteurs._dossier_personnel(ctx, d)
                    perso = next(iter(d.values()), ('', ''))[0]
                contenu = lien(a['nom'], perso, 'folder-home') if perso else None
            if not contenu:
                continue
            ctx.noter(self.nom, f"bureau : {a['nom']}")
            if ctx.simuler:
                continue
            fichier = os.path.join(bureau, f'linux-gpo-{i}.desktop')
            # exécutable et « de confiance » : sinon Plasma et GNOME refusent de lancer un lanceur posé sur le bureau
            if ctx.f.ecrire(fichier, contenu, self.nom, mode=0o755) and outil('gio'):
                lancer(['gio', 'set', fichier, 'metadata::trusted', 'true'], delai=10)

    def _barre(self, ctx, p, lanceurs, mem):
        if not p['barre']:
            return
        chemins = [lanceur_de(p['apps'][i], lanceurs) for i in p['barre']]
        chemins = [c for c in chemins if c]
        ids = [os.path.basename(c) for c in chemins]
        ctx.noter(self.nom, 'barre des tâches : ' + ', '.join(i[:-8] for i in ids))
        if ctx.simuler or mem.get('barre') == ids:
            return  # posées une fois par version du profil : l’utilisateur peut ensuite les changer
        fait = False
        if outil('plasmashell'):
            # lanceurs hors des dossiers du système (Flatpak) : par leur chemin, valable dès cette session
            urls = [('applications:' + os.path.basename(c)) if c.startswith(('/usr/share/', '/usr/local/share/')) else 'file://' + c
                    for c in chemins]
            fait = epingler_plasma(urls) or fait
        if outil('gnome-shell'):
            fait = epingler_gnome(ids) or fait
        if fait:
            mem['barre'] = ids

    def _fond(self, ctx, image, mem):
        """Fond d’écran du profil local (sur un poste du domaine, la GPO porte le fond par le réglage Windows)."""
        if ctx.simuler or not os.path.exists(image):
            return
        dest = os.path.expanduser('~/.cache/linux-gpo/fond-profil' + os.path.splitext(image)[1].lower())
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        shutil.copyfile(image, dest)
        empreinte = [os.path.getsize(dest), int(os.path.getmtime(image))]
        if mem.get('fond') == empreinte:
            return
        if outil('plasma-apply-wallpaperimage'):
            lancer(['plasma-apply-wallpaperimage', dest], env=_bus())
        if outil('gsettings'):
            for cle in ('picture-uri', 'picture-uri-dark'):
                lancer(['gsettings', 'set', 'org.gnome.desktop.background', cle, 'file://' + dest], env=_bus())
        mem['fond'] = empreinte


class ApplicationsProfils(Extension):
    """Côté ordinateur (root, service linux-gpo-applications) : applications des profils de bureau demandées par les
    sessions, celles du profil local, ou celles d’un profil à préinstaller pendant le déploiement (`fichier`)."""
    nom = 'applications-profils'

    def __init__(self, fichier: str = ''):
        self.fichier = fichier

    def appliquer(self, ctx):
        voulues = []
        local = charger(chemin(LOCAL))
        for p in [x for x in (local, charger(self.fichier) if self.fichier else None) if x]:
            lanceurs = _lanceurs()
            # déjà présente (paquet de la distribution, Snap…) : pas de seconde copie
            voulues += [a['flatpak'] for a in p['apps'].values()
                        if a['type'] == 'appli' and a.get('flatpak') and not lanceur_de(a, lanceurs)]
        for f, uid, demande in self._demandes():
            autorisees = self._autorisees(ctx, demande.get('sources') or [], local)
            refusees = [a for a in demande.get('apps') or [] if a not in autorisees]
            if refusees:
                ctx.noter(self.nom, f"demande de l’utilisateur {uid} : {', '.join(map(str, refusees))} absentes de ses profils, ignorées")
            voulues += [a for a in demande.get('apps') or [] if a in autorisees]
            if not ctx.simuler:
                try:
                    os.unlink(f)
                except OSError:
                    pass
        voulues = list(dict.fromkeys(voulues))
        if not voulues:
            return
        ctx.noter(self.nom, 'applications : ' + ', '.join(voulues))
        if not ctx.simuler:
            from .logiciels import installer_flatpaks
            installer_flatpaks(ctx, self.nom, voulues)

    @staticmethod
    def _demandes():
        """Demandes déposées par les sessions : fichier ordinaire, petit, appartenant bien à l’utilisateur qu’il nomme."""
        d = chemin(DEMANDES)
        try:
            os.makedirs(d, exist_ok=True)
            os.chmod(d, 0o1733)
            noms = os.listdir(d)
        except OSError:
            return []
        res = []
        for n in noms:
            f = os.path.join(d, n)
            m = re.fullmatch(r'(\d+)\.json', n)
            try:
                st = os.lstat(f)
                if not m or not os.path.isfile(f) or os.path.islink(f) or st.st_uid != int(m.group(1)) or st.st_size > 65536:
                    os.unlink(f)
                    continue
                with open(f, encoding='utf-8') as fh:
                    demande = json.load(fh)
            except (OSError, ValueError):
                continue
            if isinstance(demande, dict):
                res.append((f, int(m.group(1)), demande))
        return res

    @staticmethod
    def _autorisees(ctx, sources, local) -> set:
        """Applications Flatpak des profils cités par la demande, relus ici dans SYSVOL (ticket de l’ordinateur) : une
        session ne peut faire installer que des applications choisies par un administrateur dans un profil."""
        ok = set()
        if local:
            ok |= {a['flatpak'] for a in local['apps'].values() if a.get('flatpak')}
        for s in sources[:20]:
            if not isinstance(s, str) or not GUID.match(s) or not ctx.annuaire:
                continue
            try:
                r = ctx.annuaire.chercher('CN=Policies,CN=System,' + ctx.conf.base, f'(cn={s})', ['gPCFileSysPath'], portee='one')
            except Exception:  # noqa: BLE001 - annuaire injoignable : demande traitée au prochain passage
                continue
            racine = un(r[0], 'gPCFileSysPath') if r else ''
            if not racine:
                continue
            t = tempfile.mkdtemp(prefix='linux-gpo-profil-')
            try:
                ctx.annuaire.copier_fichier(racine.rstrip('\\') + '\\USER\\LinuxGPO\\bureau.json', os.path.join(t, 'bureau.json'))
                p = charger(os.path.join(t, 'bureau.json'))
                if p:
                    ok |= {a['flatpak'] for a in p['apps'].values() if a.get('flatpak')}
            except Exception:  # noqa: BLE001
                pass
            finally:
                shutil.rmtree(t, ignore_errors=True)
        return ok

