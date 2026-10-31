"""Profils de bureau (Console Annuaire › Profils de bureau) : icônes du bureau, épingles de la barre des tâches,
applications à installer et fond d’écran, dessinés une fois et liés comme une GPO (OU, filtrage de sécurité).

Un profil est une GPO qui contient USER/LinuxGPO/bureau.json. Les applications sont celles de la bibliothèque de
PXE Deploy, avec leurs installateurs :

    {"version": 2, "nom": "Bureau RH",
     "apps": [{"id": "std-vlc", "nom": "VLC", "type": "appli", "winget": "VideoLAN.VLC",
               "installateurs": [{"methode": "native", "paquet": "vlc", "distros": ["debian", "ubuntu", "arch"]},
                                 {"methode": "flatpak", "paquet": "org.videolan.VLC"}]},
              {"id": "web-intranet", "nom": "Intranet", "type": "web", "url": "https://intranet.exemple.local"},
              {"id": "partage-rh", "nom": "Partage RH", "type": "partage", "chemin": "\\\\dc01\\RH"},
              {"id": "perso", "nom": "Dossier personnel", "type": "perso"}],
     "bureau": ["perso", "std-vlc", "web-intranet"],     (ordre des icônes)
     "barre": ["std-vlc"],                               (applications épinglées)
     "installer": ["std-7zip"],                          (installées sans icône : menu des applications)
     "fond": "fond.png"}                                 (image à côté de bureau.json, facultative)

Choix de l’installateur, comme PXE Deploy : paquet de la distribution d’abord (Debian, Ubuntu, Arch), puis Snap ou
Flatpak (Ubuntu : Snap avant Flatpak). Une application est « présente » si l’un de ses installateurs l’est déjà.

Dans la session (extension Profil) : icônes et épingles des applications présentes ; les manquantes sont demandées au
service système (fichier dans /var/spool/linux-gpo, qui démarre linux-gpo-applications par une unité .path). Le service
relit le profil dans SYSVOL avec le ticket de l’ordinateur (une session ne fait installer que ce qu’un administrateur a
choisi), installe, puis écrit le résultat que la session attend avant de poser les icônes restantes.
Les épingles sont posées quand le profil change (l’utilisateur peut ensuite les modifier, comme la disposition de la barre
des tâches de Windows). Les icônes du bureau sont reposées à chaque passage et retirées avec le profil.

Poste hors domaine : le profil posé par PXE Deploy dans /etc/linux-gpo/bureau.json s’applique à tous les comptes locaux.
"""
from __future__ import annotations

import glob
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
from ..systeme import STYLES_GNOME, chemin, fond_plasma, lancer, os_release, outil, style_fond

journal = logging.getLogger('linux-gpo')

FICHIER = 'USER/LinuxGPO/bureau.json'
LOCAL = '/etc/linux-gpo/bureau.json'
DEMANDES = '/var/spool/linux-gpo'          # 1733 : chaque utilisateur y dépose sa demande, sans voir celles des autres
RESULTATS = '/run/linux-gpo/resultats'     # 0755 : réponse du service, lisible par la session qui attend
ID = re.compile(r'^[a-z0-9][a-z0-9._-]{0,63}$')
PAQUET = {'native': re.compile(r'^[a-z0-9][a-z0-9.+_-]{0,100}$'), 'flatpak': re.compile(r'^[A-Za-z][\w-]*(\.[\w-]+){2,}$'),
          'snap': re.compile(r'^[a-z0-9][a-z0-9-]{0,60}$')}
GUID = re.compile(r'^\{[0-9A-Fa-f-]{36}\}$')
EXPORTS = ['/var/lib/flatpak/exports/share', '~/.local/share/flatpak/exports/share']
TAILLES = ['scalable', '512x512', '256x256', '128x128', '96x96', '64x64', '48x48']
# ordre de préférence des installateurs (celui de PXE Deploy) ; distribution inconnue : Flatpak d’abord
ORDRE = {'debian': ['native', 'flatpak', 'snap'], 'ubuntu': ['native', 'snap', 'flatpak'], 'arch': ['native', 'flatpak'],
         None: ['flatpak', 'native', 'snap']}
NOUVEL_ESSAI = 30 * 60                      # application en échec : redemandée au plus toutes les 30 minutes
ATTENTE = 40 * 60                           # attente maximale du service d’installation par la session


# ---------------------------------------------------------------- lecture et fusion des profils

def _installateurs(a: dict) -> list[dict]:
    res = []
    for i in a.get('installateurs') or []:
        if not isinstance(i, dict) or i.get('methode') not in PAQUET or not PAQUET[i['methode']].match(str(i.get('paquet') or '')):
            continue
        res.append({'methode': i['methode'], 'paquet': i['paquet'], 'classic': bool(i.get('classic')),
                    'distros': [d for d in i.get('distros') or [] if d in ('debian', 'ubuntu', 'arch')]})
    if a.get('flatpak') and PAQUET['flatpak'].match(str(a['flatpak'])):  # profils de la première version
        res.append({'methode': 'flatpak', 'paquet': a['flatpak'], 'classic': False, 'distros': []})
    return res


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
        p = {'id': a['id'], 'nom': str(a['nom']).strip()[:120].replace('\n', ' '), 'type': t}
        if t == 'appli':
            p['installateurs'] = _installateurs(a)
            p['lanceurs'] = [str(x) for x in a.get('lanceurs') or [] if re.match(r'^[\w.+-]{1,120}$', str(x))][:10]
        elif t == 'web' and re.match(r'(?i)^https?://[^\s"]+$', str(a.get('url') or '')):
            p['url'] = a['url']
        elif t == 'partage' and re.match(r'^\\\\[^\\/\s]+\\[^\n"]+$', str(a.get('chemin') or '')):
            p['chemin'] = a['chemin']
        elif t != 'perso':
            continue
        apps[p['id']] = p
    bureau = []
    for b in d.get('bureau') or []:  # liste d’identifiants (ou {app, col, lig} : première version)
        i = b.get('app') if isinstance(b, dict) else b
        if i in apps and i not in bureau:
            bureau.append(i)
    appli = lambda i: i in apps and apps[i]['type'] == 'appli'
    barre = [i for i in dict.fromkeys(d.get('barre') or []) if appli(i)]
    installer = [i for i in dict.fromkeys(d.get('installer') or []) if appli(i)]
    fond = str(d.get('fond') or '')
    if fond and (os.sep in fond or fond.startswith('.') or not re.match(r'^[\w.-]+\.(png|jpe?g|svg|webp)$', fond, re.I)):
        fond = ''
    return {'nom': str(d.get('nom') or '')[:120], 'apps': apps, 'bureau': bureau, 'barre': barre, 'installer': installer,
            'fond': os.path.join(os.path.dirname(f), fond) if fond else '', 'fond_style': style_fond(d.get('fondStyle'))}


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
    """Icônes et applications : celles de tous les profils ; barre et fond : le dernier profil qui en définit l’emporte."""
    apps, bureau, barre, installer, fond, style = {}, [], [], [], '', style_fond(None)
    for p in liste:
        apps.update(p['apps'])
        bureau += [i for i in p['bureau'] if i not in bureau]
        installer += [i for i in p['installer'] if i not in installer]
        barre = p['barre'] or barre
        if p['fond']:
            fond, style = p['fond'], p['fond_style']
    return {'apps': apps, 'bureau': bureau, 'barre': barre, 'installer': installer, 'fond': fond, 'fond_style': style}


def utiles(p: dict) -> list[str]:
    """Applications à avoir sur le poste : celles du bureau, de la barre et celles à installer seulement."""
    return [i for i in dict.fromkeys(p['bureau'] + p['barre'] + p['installer']) if p['apps'][i]['type'] == 'appli']


# ---------------------------------------------------------------- applications

def distribution() -> str | None:
    """debian, ubuntu ou arch (distributions des installateurs de PXE Deploy), d’après os-release ; None sinon."""
    o = os_release()
    ids = [o.get('ID', '')] + o.get('ID_LIKE', '').split()
    for d, noms in (('ubuntu', ('ubuntu',)), ('debian', ('debian',)), ('arch', ('arch', 'archlinux'))):
        if any(i in noms for i in ids):
            return d
    return None


def choisir(app: dict, d: str | None, gestionnaire: str | None) -> dict | None:
    """Meilleur installateur de l’application pour ce poste (ordre de PXE Deploy), None s’il n’y en a pas."""
    for m in ORDRE.get(d, ORDRE[None]):
        for i in app.get('installateurs') or []:
            if i['methode'] != m or (i['distros'] and d not in i['distros']):
                continue
            if m == 'native' and not gestionnaire:
                continue
            return i
    return None


def _flatpak_present(paquet: str) -> bool:
    return any(os.path.isdir(os.path.join(os.path.expanduser(b), 'app', paquet))
               for b in ('/var/lib/flatpak', '~/.local/share/flatpak'))


_systeme: dict[str, str] | None = None


def lanceurs_systeme() -> dict[str, str]:
    """Lanceurs des applications installées (paquets, Snap, Flatpak), sans ceux que l’agent pose lui-même."""
    global _systeme
    if _systeme is None:
        _systeme = {k: v for k, v in _lanceurs().items() if not k.startswith('linux-gpo-')}
    return _systeme


def presente(app: dict, gestionnaire: str | None) -> bool:
    """Vrai si l’un des installateurs de l’application l’a déjà mise sur le poste, ou si elle y est autrement (un
    LibreOffice de la distribution alors que la bibliothèque ne propose que Flatpak) : pas de seconde copie."""
    from .logiciels import installe
    for i in app.get('installateurs') or []:
        if i['methode'] == 'flatpak' and _flatpak_present(i['paquet']):
            return True
        if i['methode'] == 'snap' and os.path.isdir(f"/snap/{i['paquet']}/current"):
            return True
        if i['methode'] == 'native' and gestionnaire and installe(gestionnaire, i['paquet']):
            return True
    return bool(lanceur_connu(app, lanceurs_systeme()))


def lanceur_connu(app: dict, lanceurs: dict[str, str]) -> str | None:
    """Lanceur trouvé par l’identifiant d’un installateur ou par le nom exact de l’application."""
    bas = {k.lower(): v for k, v in lanceurs.items()}
    for i in list(app.get('lanceurs') or []) + [x['paquet'] for x in app.get('installateurs') or []]:
        if i.lower() in bas:
            return bas[i.lower()]
    nom = app['nom'].strip().lower()
    for f in lanceurs.values():
        try:
            with open(f, encoding='utf-8', errors='replace') as fh:
                m = re.search(r'^Name=(.+)$', fh.read(), re.M)
        except OSError:
            continue
        if m and m.group(1).strip().lower() == nom and _visible(f):
            return f
    return None


_fichiers_paquet: dict[str, list[str]] = {}


def _lanceurs_paquet(paquet: str, gestionnaire: str | None) -> list[str]:
    if paquet not in _fichiers_paquet:
        cmd = {'apt': ['dpkg-query', '-L', paquet], 'pacman': ['pacman', '-Qlq', paquet]}.get(gestionnaire, ['rpm', '-ql', paquet])
        r = lancer(cmd)
        _fichiers_paquet[paquet] = [l.strip() for l in r.stdout.splitlines()
                                    if re.match(r'^/usr/(local/)?share/applications/[^/]+\.desktop$', l.strip())] if r.returncode == 0 else []
    return _fichiers_paquet[paquet]


def _visible(f: str) -> bool:
    try:
        with open(f, encoding='utf-8', errors='replace') as fh:
            t = fh.read()
    except OSError:
        return False
    return not re.search(r'^(NoDisplay|Hidden)=true', t, re.M | re.I)


def lanceur_de(app: dict, lanceurs: dict[str, str], gestionnaire: str | None = None) -> str | None:
    """Lanceur (.desktop) de l’application sur ce poste : celui de son paquet, de son application Flatpak ou de son Snap,
    sinon un lanceur connu par son identifiant ou son nom."""
    for i in app.get('installateurs') or []:
        if i['methode'] == 'native' and gestionnaire:
            fichiers = [f for f in _lanceurs_paquet(i['paquet'], gestionnaire) if _visible(f)]
            fichiers.sort(key=lambda f: (i['paquet'] not in os.path.basename(f), f))
            if fichiers:
                return fichiers[0]
        elif i['methode'] == 'flatpak':
            for b in EXPORTS:
                f = os.path.join(os.path.expanduser(b), 'applications', i['paquet'] + '.desktop')
                if os.path.exists(f):
                    return f
        elif i['methode'] == 'snap':
            f = sorted(glob.glob(f"/var/lib/snapd/desktop/applications/{i['paquet']}_*.desktop"))
            if f:
                return f[0]
    return lanceur_connu(app, lanceurs) or trouver_application(app['nom'], lanceurs)


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


def installer_apps(ctx, ext: str, apps: list[dict]) -> tuple[list[str], dict[str, str]]:
    """Installe (root) les applications absentes avec leur meilleur installateur : (installées, {id: erreur})."""
    from .logiciels import gestionnaire, installer, installer_flatpaks
    g, d = gestionnaire(), distribution()
    faites, echecs, natifs, flatpaks, snaps = [], {}, {}, {}, {}
    for a in apps:
        if presente(a, g):
            continue
        i = choisir(a, d, g)
        if i is None:
            echecs[a['id']] = f"aucun installateur pour {d or 'cette distribution'}"
            continue
        {'native': natifs, 'flatpak': flatpaks, 'snap': snaps}[i['methode']][a['id']] = i
    if ctx.simuler:
        for groupe in (natifs, flatpaks, snaps):
            for k, i in groupe.items():
                ctx.noter(ext, f"{k} : à installer ({i['methode']} {i['paquet']})")
        return [], echecs
    if natifs:
        paquets = [i['paquet'] for i in natifs.values()]
        code, msg = installer(g, paquets)
        if code:  # un nom introuvable fait échouer tout le lot : un par un pour savoir lequel
            for k, i in natifs.items():
                code, msg = installer(g, [i['paquet']])
                (faites.append(k) if code == 0 else echecs.__setitem__(k, msg))
        else:
            faites += list(natifs)
    if flatpaks:
        rates = set(installer_flatpaks(ctx, ext, [i['paquet'] for i in flatpaks.values()]))
        for k, i in flatpaks.items():
            (echecs.__setitem__(k, 'échec Flatpak') if i['paquet'] in rates else faites.append(k))
    for k, i in snaps.items():
        if not outil('snap'):
            echecs[k] = 'snapd absent'
            continue
        r = lancer(['snap', 'install', i['paquet']] + (['--classic'] if i['classic'] else []), delai=3600)
        (faites.append(k) if r.returncode == 0 else echecs.__setitem__(k, (r.stderr or r.stdout).strip()[-200:]))
    for k in faites:
        ctx.noter(ext, f'{k} : installée')
    for k, m in echecs.items():
        ctx.noter(ext, f'{k} : ÉCHEC — {m}')
    return faites, echecs


# ---------------------------------------------------------------- demande d’installation (session → service)

def _resultat_de(uid: int) -> str:
    return os.path.join(RESULTATS, f'{uid}.json')


def demander_installation(ctx, sources: list[str], apps: list[str], attente: int = ATTENTE) -> dict | None:
    """Demande au service système d’installer ces applications, puis attend son résultat ({installees, echecs})."""
    uid, debut = os.getuid(), time.time()
    f = os.path.join(DEMANDES, f'{uid}.json')
    try:
        fd = os.open(f, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, 'O_NOFOLLOW', 0), 0o644)
        with os.fdopen(fd, 'w', encoding='utf-8') as fh:
            json.dump({'sources': sources, 'apps': apps, 'date': debut}, fh)
    except OSError as e:
        ctx.noter('profil', f'demande d’installation impossible ({e})')
        return None
    # l’unité linux-gpo-applications.path démarre le service ; au cas où elle manquerait, on le demande aussi (polkit)
    lancer(['systemctl', 'start', '--no-block', 'linux-gpo-applications.service'])
    while time.time() - debut < attente:
        time.sleep(3)
        try:
            with open(_resultat_de(uid), encoding='utf-8') as fh:
                r = json.load(fh)
            if r.get('date', 0) >= debut - 1:
                return r
        except (OSError, ValueError):
            pass
    ctx.noter('profil', 'installation toujours en cours : les icônes manquantes arriveront au prochain passage')
    return None


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
        from .logiciels import gestionnaire
        liste = profils(ctx)
        mem = ctx.f.memoire(self.nom)
        if not liste:
            mem.pop('barre', None)  # profil retiré : les épingles restent, comme sous Windows
            return
        p = fusionner([x[1] for x in liste])
        g = gestionnaire()
        ctx.noter(self.nom, 'profil : ' + ', '.join(x[1]['nom'] or x[0] for x in liste))
        manquantes = [i for i in utiles(p) if not presente(p['apps'][i], g)]
        bureau = None if ctx.simuler else dossier_bureau()
        lanceurs = _lanceurs()
        self._bureau(ctx, p, lanceurs, g, bureau)
        recent = mem.get('demandes', {})
        a_demander = [i for i in manquantes if time.time() - recent.get(i, 0) > NOUVEL_ESSAI]
        if a_demander and not ctx.simuler:
            ctx.noter(self.nom, 'à installer : ' + ', '.join(p['apps'][i]['nom'] for i in a_demander))
            mem['demandes'] = {**recent, **{i: time.time() for i in a_demander}}
            r = demander_installation(ctx, [s for s, _ in liste], a_demander)
            for i, m in ((r or {}).get('echecs') or {}).items():
                ctx.noter(self.nom, f"{p['apps'].get(i, {}).get('nom', i)} : installation impossible — {m}")
            if r and r.get('erreur'):
                ctx.noter(self.nom, f"service d’installation : {r['erreur']}")
            for i in (r or {}).get('installees') or []:
                mem['demandes'].pop(i, None)
            global _systeme
            _fichiers_paquet.clear()
            _systeme = None
            lanceurs = _lanceurs()
            self._bureau(ctx, p, lanceurs, g, bureau)
        for i in manquantes:
            if not presente(p['apps'][i], g):
                ctx.noter(self.nom, f"{p['apps'][i]['nom']} : pas encore installée")
        self._barre(ctx, p, lanceurs, g, mem)
        if p['fond'] and any(s == 'local' for s, _ in liste):
            self._fond(ctx, p['fond'], mem, p['fond_style'])

    def _bureau(self, ctx, p, lanceurs, g, bureau):
        perso = None
        for n, i in enumerate(p['bureau']):
            a = p['apps'][i]
            if a['type'] == 'appli':
                f = lanceur_de(a, lanceurs, g) if presente(a, g) or not a.get('installateurs') else None
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
            # numéro d’ordre dans le nom : les bureaux qui trient par nom de fichier gardent l’ordre du profil
            fichier = os.path.join(bureau, f'linux-gpo-{n:02d}-{i}.desktop')
            # exécutable et « de confiance » : sinon Plasma et GNOME refusent de lancer un lanceur posé sur le bureau
            if ctx.f.ecrire(fichier, contenu, self.nom, mode=0o755) and outil('gio'):
                lancer(['gio', 'set', fichier, 'metadata::trusted', 'true'], delai=10)

    def _barre(self, ctx, p, lanceurs, g, mem):
        if not p['barre']:
            return
        chemins = [lanceur_de(p['apps'][i], lanceurs, g) for i in p['barre'] if presente(p['apps'][i], g)]
        chemins = [c for c in chemins if c]
        ids = [os.path.basename(c) for c in chemins]
        ctx.noter(self.nom, 'barre des tâches : ' + ', '.join(i[:-8] for i in ids))
        if ctx.simuler or not ids or mem.get('barre') == ids:
            return  # posées une fois par version du profil : l’utilisateur peut ensuite les changer
        fait = False
        if outil('plasmashell'):
            # lanceurs hors des dossiers du système (Flatpak, Snap) : par leur chemin, valable dès cette session
            urls = [('applications:' + os.path.basename(c)) if c.startswith(('/usr/share/', '/usr/local/share/')) else 'file://' + c
                    for c in chemins]
            fait = epingler_plasma(urls) or fait
        if outil('gnome-shell'):
            fait = epingler_gnome(ids) or fait
        if fait:
            mem['barre'] = ids

    def _fond(self, ctx, image, mem, style=4):
        """Fond d’écran du profil local (sur un poste du domaine, la GPO porte le fond par le réglage Windows)."""
        if ctx.simuler or not os.path.exists(image):
            return
        dest = os.path.expanduser('~/.cache/linux-gpo/fond-profil' + os.path.splitext(image)[1].lower())
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        shutil.copyfile(image, dest)
        empreinte = [os.path.getsize(dest), int(os.path.getmtime(image)), style_fond(style)]
        if mem.get('fond') == empreinte:
            return
        if outil('plasma-apply-wallpaperimage'):
            fond_plasma(dest, style, env=_bus())
        if outil('gsettings'):
            for cle in ('picture-uri', 'picture-uri-dark'):
                lancer(['gsettings', 'set', 'org.gnome.desktop.background', cle, 'file://' + dest], env=_bus())
            lancer(['gsettings', 'set', 'org.gnome.desktop.background', 'picture-options', STYLES_GNOME[style_fond(style)]], env=_bus())
        mem['fond'] = empreinte


class ApplicationsProfils(Extension):
    """Côté ordinateur (root, service linux-gpo-applications) : applications des profils de bureau demandées par les
    sessions, celles du profil local, ou celles d’un profil à préinstaller pendant le déploiement (`fichier`)."""
    nom = 'applications-profils'

    def __init__(self, fichier: str = ''):
        self.fichier = fichier

    def appliquer(self, ctx):
        local = charger(chemin(LOCAL))
        voulues = {}
        for p in [x for x in (local, charger(self.fichier) if self.fichier else None) if x]:
            voulues.update({i: p['apps'][i] for i in utiles(p)})
        demandes = self._demandes()
        par_uid = {}
        for f, uid, demande in demandes:
            autorisees = self._autorisees(ctx, demande.get('sources') or [], local)
            ids = [i for i in demande.get('apps') or [] if isinstance(i, str)]
            refusees = [i for i in ids if i not in autorisees]
            if refusees:
                ctx.noter(self.nom, f"utilisateur {uid} : {', '.join(refusees)} absentes de ses profils, ignorées")
            par_uid[uid] = [i for i in ids if i in autorisees]
            voulues.update({i: autorisees[i] for i in par_uid[uid]})
            if not ctx.simuler:
                try:
                    os.unlink(f)
                except OSError:
                    pass
        faites, echecs = installer_apps(ctx, self.nom, list(voulues.values())) if voulues else ([], {})
        if ctx.simuler:
            return
        os.makedirs(RESULTATS, mode=0o755, exist_ok=True)
        for uid, ids in par_uid.items():
            r = {'date': time.time(), 'installees': [i for i in ids if i in faites], 'echecs': {i: m for i, m in echecs.items() if i in ids}}
            if ctx.annuaire is None and not local:
                r['erreur'] = 'annuaire injoignable'
            tmp = _resultat_de(uid) + '.tmp'
            with open(tmp, 'w', encoding='utf-8') as fh:
                json.dump(r, fh)
            os.chmod(tmp, 0o644)
            os.replace(tmp, _resultat_de(uid))

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
                try:
                    os.unlink(f)
                except OSError:
                    pass
                continue
            if isinstance(demande, dict):
                res.append((f, int(m.group(1)), demande))
        return res

    @staticmethod
    def _autorisees(ctx, sources, local) -> dict:
        """Applications des profils cités par la demande, relus ici dans SYSVOL (ticket de l’ordinateur) : une session ne
        peut faire installer que des applications choisies par un administrateur, avec ses installateurs à lui."""
        ok = dict(local['apps']) if local else {}
        for s in sources[:20]:
            if not isinstance(s, str) or not GUID.match(s) or not ctx.annuaire:
                continue
            try:
                r = ctx.annuaire.chercher('CN=Policies,CN=System,' + ctx.conf.base, f'(cn={s})', ['gPCFileSysPath'], portee='one')
            except Exception:  # noqa: BLE001 - annuaire injoignable : la session redemandera
                continue
            racine = un(r[0], 'gPCFileSysPath') if r else ''
            if not racine:
                continue
            t = tempfile.mkdtemp(prefix='linux-gpo-profil-')
            try:
                ctx.annuaire.copier_fichier(racine.rstrip('\\') + '\\USER\\LinuxGPO\\bureau.json', os.path.join(t, 'bureau.json'))
                p = charger(os.path.join(t, 'bureau.json'))
                if p:
                    ok.update({i: p['apps'][i] for i in utiles(p)})
            except Exception:  # noqa: BLE001
                pass
            finally:
                shutil.rmtree(t, ignore_errors=True)
        return {i: a for i, a in ok.items() if a['type'] == 'appli'}
