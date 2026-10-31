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
     "fond": "fond.png",                                 (image à côté de bureau.json, facultative)
     "disposition": {"barre": {"position": "bas", "taille": "normale", "centree": true},
                     "icones": {"taille": "grande", "libre": true, "positions": {"std-vlc": [0, 1]}},   ([colonne, ligne])
                     "theme": {"mode": "sombre", "accent": "vert"}, "verrou": true}}
     (chaque réglage vide ou absent : celui du poste reste)

Choix de l’installateur, comme PXE Deploy : paquet de la distribution d’abord (Debian, Ubuntu, Arch), puis Snap ou
Flatpak (Ubuntu : Snap avant Flatpak). Une application est « présente » si l’un de ses installateurs l’est déjà.

Dans la session (extension Profil) : icônes et épingles des applications présentes ; les manquantes sont demandées au
service système (fichier dans /var/spool/linux-gpo, qui démarre linux-gpo-applications par une unité .path). Le service
relit le profil dans SYSVOL avec le ticket de l’ordinateur (une session ne fait installer que ce qu’un administrateur a
choisi), installe, puis écrit le résultat que la session attend avant de poser les icônes restantes.
Les épingles sont posées quand le profil change (l’utilisateur peut ensuite les modifier, comme la disposition de la barre
des tâches de Windows). Les icônes du bureau sont reposées à chaque passage et retirées avec le profil.
Disposition : barre des tâches (panneau de Plasma ; Ubuntu Dock ou Dash to Dock sous GNOME), taille et place des icônes du
bureau (Plasma ; Desktop Icons NG sous GNOME), thème clair ou sombre et couleur d’accent. Posée quand le profil change ;
verrouillée, elle est reposée à chaque passage avec les épingles, et Plasma interdit de déverrouiller les éléments graphiques.

Poste hors domaine : le profil posé par PXE Deploy dans /etc/linux-gpo/bureau.json s’applique à tous les comptes locaux.
"""
from __future__ import annotations

import glob
import hashlib
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
from ..systeme import STYLES_GNOME, bande_fond, chemin, fond_plasma, lancer, os_release, outil, style_fond

journal = logging.getLogger('linux-gpo')

FICHIER = 'USER/LinuxGPO/bureau.json'
LOCAL = '/etc/linux-gpo/bureau.json'
DEMANDES = '/var/spool/linux-gpo'          # 1733 : chaque utilisateur y dépose sa demande, sans voir celles des autres
RESULTATS = '/run/linux-gpo/resultats'     # 0755 : réponse du service, lisible par la session qui attend
ID = re.compile(r'^[a-z0-9][a-z0-9._-]{0,63}$')
PAQUET = {'native': re.compile(r'^[a-z0-9][a-z0-9.+_-]{0,100}$'), 'flatpak': re.compile(r'^[A-Za-z][\w-]*(\.[\w-]+){2,}$'),
          'snap': re.compile(r'^[a-z0-9][a-z0-9-]{0,60}$'), 'github': re.compile(r'^[A-Za-z0-9][A-Za-z0-9-]{0,38}/\w[\w.-]{0,99}$')}
GUID = re.compile(r'^\{[0-9A-Fa-f-]{36}\}$')
EXPORTS = ['/var/lib/flatpak/exports/share', '~/.local/share/flatpak/exports/share']
TAILLES = ['scalable', '512x512', '256x256', '128x128', '96x96', '64x64', '48x48']
# ordre de préférence des installateurs (celui de PXE Deploy) ; distribution inconnue : Flatpak d’abord
ORDRE = {'debian': ['native', 'flatpak', 'snap', 'github'], 'ubuntu': ['native', 'snap', 'flatpak', 'github'], 'arch': ['native', 'flatpak', 'github'],
         None: ['flatpak', 'native', 'snap', 'github']}
NOUVEL_ESSAI = 30 * 60                      # application en échec : redemandée au plus toutes les 30 minutes…
# … sauf si ses installateurs ou l’agent ont changé depuis (profil corrigé, agent mis à jour) : redemandée tout de suite
try:
    with open(__file__, 'rb') as _fh, open(os.path.join(os.path.dirname(__file__), 'logiciels.py'), 'rb') as _fh2:
        _CODE = hashlib.sha1(_fh.read() + _fh2.read()).hexdigest()[:10]
except OSError:
    _CODE = ''
ATTENTE = 40 * 60                           # attente maximale du service d’installation par la session

# disposition : valeurs du profil → Plasma (panneau, FolderView) et GNOME (Ubuntu Dock / Dash to Dock, Desktop Icons NG)
POSITIONS_BARRE = {'bas': ('bottom', 'BOTTOM'), 'haut': ('top', 'TOP'), 'gauche': ('left', 'LEFT'), 'droite': ('right', 'RIGHT')}
HAUTEUR_PANNEAU = {'petite': 32, 'normale': 44, 'grande': 56}          # pixels
ICONES_DOCK = {'petite': 32, 'normale': 48, 'grande': 64}              # dash-max-icon-size
ICONES_PLASMA = {'petite': 2, 'normale': 3, 'grande': 4}               # iconSize (32, 48, 64 pixels)
ICONES_DING = {'petite': 'small', 'normale': 'standard', 'grande': 'large'}
CASE_DING = {'tiny': (70, 80), 'small': (90, 90), 'standard': (120, 106), 'large': (130, 138)}   # case de la grille, pixels
# couleurs d’accent de GNOME (accent-color, GNOME 47 et suivants), avec leur teinte pour Plasma
ACCENTS = {'bleu': ('blue', '#3584e4'), 'sarcelle': ('teal', '#2190a4'), 'vert': ('green', '#3a944a'), 'jaune': ('yellow', '#c88800'),
           'orange': ('orange', '#ed5b00'), 'rouge': ('red', '#e62d42'), 'rose': ('pink', '#d56199'), 'violet': ('purple', '#9141ac'),
           'ardoise': ('slate', '#6f8396')}
GRILLE = (30, 20)                           # colonnes, lignes : place d’une icône du bureau


# ---------------------------------------------------------------- lecture et fusion des profils

def _installateurs(a: dict) -> list[dict]:
    res = []
    for i in a.get('installateurs') or []:
        if not isinstance(i, dict) or i.get('methode') not in PAQUET or not PAQUET[i['methode']].match(str(i.get('paquet') or '')):
            continue
        distros = [d for d in i.get('distros') or [] if d in ('debian', 'ubuntu', 'arch')]
        if (i.get('distros') and not distros) or str(i['paquet']).startswith('unstable.'):
            continue  # attribut nixpkgs (NixOS) : un paquet de ce nom n’existe pas ailleurs
        res.append({'methode': i['methode'], 'paquet': i['paquet'], 'classic': bool(i.get('classic')), 'distros': distros})
    if a.get('flatpak') and PAQUET['flatpak'].match(str(a['flatpak'])):  # profils de la première version
        res.append({'methode': 'flatpak', 'paquet': a['flatpak'], 'classic': False, 'distros': []})
    return res


def _case(x) -> list[int] | None:
    ok = isinstance(x, list) and len(x) == 2 and all(isinstance(n, int) and not isinstance(n, bool) for n in x)
    return list(x) if ok and 0 <= x[0] < GRILLE[0] and 0 <= x[1] < GRILLE[1] else None


def disposition(v, bureau=()) -> dict:
    """Disposition nettoyée ; '' ou None : réglage du poste conservé. Positions : icônes du bureau seulement, une par case."""
    v = v if isinstance(v, dict) else {}
    b, ic, th = (v.get(k) if isinstance(v.get(k), dict) else {} for k in ('barre', 'icones', 'theme'))
    positions, prises = {}, []
    for i, x in (ic.get('positions') if isinstance(ic.get('positions'), dict) else {}).items():
        c = _case(x)
        if i in bureau and c and c not in prises:
            positions[i] = c
            prises.append(c)
    choix = lambda d, k, valeurs: d.get(k) if d.get(k) in valeurs else ''
    return {'barre': {'position': choix(b, 'position', POSITIONS_BARRE), 'taille': choix(b, 'taille', HAUTEUR_PANNEAU),
                      'centree': b['centree'] if isinstance(b.get('centree'), bool) else None},
            'icones': {'taille': choix(ic, 'taille', ICONES_PLASMA), 'libre': ic.get('libre') is True and bool(positions),
                       'positions': positions if ic.get('libre') is True else {}},
            'theme': {'mode': choix(th, 'mode', ('clair', 'sombre')), 'accent': choix(th, 'accent', ACCENTS)},
            'verrou': v.get('verrou') is True}


def fusionner_disposition(liste: list[dict]) -> dict:
    """Réglage par réglage, le dernier profil qui en définit un l’emporte ; un seul profil verrouillé verrouille."""
    d = disposition(None)
    for x in liste:
        for groupe in ('barre', 'theme'):
            d[groupe].update({k: val for k, val in x[groupe].items() if val not in ('', None)})
        if x['icones']['taille']:
            d['icones']['taille'] = x['icones']['taille']
        if x['icones']['libre']:
            d['icones'].update(libre=True, positions=x['icones']['positions'])
        d['verrou'] = d['verrou'] or x['verrou']
    return d


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
            'fond': os.path.join(os.path.dirname(f), fond) if fond else '', 'fond_style': style_fond(d.get('fondStyle')),
            'fond_bande': bande_fond(d.get('fondBande')), 'disposition': disposition(d.get('disposition'), bureau)}


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
    apps, bureau, barre, installer, fond, style, bande = {}, [], [], [], '', style_fond(None), bande_fond(None)
    for p in liste:
        apps.update(p['apps'])
        bureau += [i for i in p['bureau'] if i not in bureau]
        installer += [i for i in p['installer'] if i not in installer]
        barre = p['barre'] or barre
        if p['fond']:
            fond, style, bande = p['fond'], p['fond_style'], p['fond_bande']
    return {'apps': apps, 'bureau': bureau, 'barre': barre, 'installer': installer, 'fond': fond, 'fond_style': style, 'fond_bande': bande,
            'disposition': fusionner_disposition([p.get('disposition') or disposition(None) for p in liste])}


def signature(app: dict) -> str:
    """Empreinte de ce qui décide de l’installation : installateurs de l’application et code de l’agent."""
    return hashlib.sha1((json.dumps(app.get('installateurs') or [], sort_keys=True) + _CODE).encode()).hexdigest()[:12]


def a_redemander(app: dict, essai, maintenant: float) -> bool:
    """Vrai si l’application peut être redemandée : jamais demandée, demandée il y a plus de NOUVEL_ESSAI, ou depuis que ses
    installateurs ou l’agent ont changé. `essai` : [date, signature] (ou une date seule, mémoire des versions précédentes)."""
    date, sig = essai if isinstance(essai, list) and len(essai) == 2 else (essai if isinstance(essai, (int, float)) else 0, '')
    return maintenant - date > NOUVEL_ESSAI or sig != signature(app)


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


def candidats(app: dict, d: str | None, gestionnaire: str | None) -> list[dict]:
    """Installateurs utilisables sur ce poste, du préféré au dernier recours (ordre de PXE Deploy)."""
    res = []
    for m in ORDRE.get(d, ORDRE[None]):
        for i in app.get('installateurs') or []:
            if i['methode'] != m or (i['distros'] and d not in i['distros']):
                continue
            if m == 'native' and not gestionnaire:
                continue
            if m == 'github' and gestionnaire not in ('apt', 'pacman'):
                continue  # .deb ou .pkg.tar.zst seulement
            res.append(i)
    return res


def choisir(app: dict, d: str | None, gestionnaire: str | None) -> dict | None:
    """Meilleur installateur de l’application pour ce poste, None s’il n’y en a pas."""
    return next(iter(candidats(app, d, gestionnaire)), None)


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
    from .logiciels import github_present, installe
    for i in app.get('installateurs') or []:
        if i['methode'] == 'flatpak' and _flatpak_present(i['paquet']):
            return True
        if i['methode'] == 'snap' and os.path.isdir(f"/snap/{i['paquet']}/current"):
            return True
        if i['methode'] == 'native' and gestionnaire and installe(gestionnaire, i['paquet']):
            return True
        if i['methode'] == 'github' and github_present(gestionnaire, i['paquet']):
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


def nom_icone(n: int, ident: str) -> str:
    """Lanceur posé sur le bureau ; numéro d’ordre dans le nom : les bureaux qui trient par nom gardent l’ordre du profil."""
    return f'linux-gpo-{n:02d}-{ident}.desktop'


def unc_vers_smb(unc: str, domaine: str) -> str:
    hote, _, reste = unc[2:].partition('\\')
    if '.' not in hote and domaine:
        hote += '.' + domaine  # nom court NetBIOS : non résolu sous Linux sans le suffixe du domaine
    return 'smb://' + hote + '/' + reste.replace('\\', '/')


def lien(nom: str, url: str, icone: str) -> str:
    return f'[Desktop Entry]\nType=Link\nName={nom}\nURL={url}\nIcon={icone}\n'


def installer_apps(ctx, ext: str, apps: list[dict]) -> tuple[list[str], dict[str, str]]:
    """Installe (root) les applications absentes avec leur meilleur installateur, puis le suivant si celui-ci échoue (un paquet
    qui n’existe pas dans la version de la distribution, par exemple) : (installées, {id: erreur})."""
    from .logiciels import gestionnaire as gestionnaire_paquets
    g, d = gestionnaire_paquets(), distribution()
    faites, echecs, restants = [], {}, {}
    for a in apps:
        if presente(a, g):
            continue
        liste = candidats(a, d, g)
        if not liste:
            echecs[a['id']] = f"aucun installateur pour {d or 'cette distribution'}"
            continue
        restants[a['id']] = liste
    if ctx.simuler:
        for k, liste in restants.items():
            ctx.noter(ext, f"{k} : à installer ({liste[0]['methode']} {liste[0]['paquet']})")
        return [], echecs
    while restants:
        tour = {k: liste[0] for k, liste in restants.items()}
        ok, ratees = _installer_tour(ctx, ext, g, tour)
        faites += ok
        for k, msg in ratees.items():
            restants[k].pop(0)
            if restants[k]:
                ctx.noter(ext, f"{k} : {tour[k]['methode']} {tour[k]['paquet']} impossible ({msg[-120:]}), essai suivant")
            else:
                echecs[k] = msg
        restants = {k: v for k, v in restants.items() if k not in ok and v}
    for k in faites:
        ctx.noter(ext, f'{k} : installée')
    for k, m in echecs.items():
        ctx.noter(ext, f'{k} : ÉCHEC — {m}')
    return faites, echecs


def _installer_tour(ctx, ext: str, g: str | None, choix: dict[str, dict]) -> tuple[list[str], dict[str, str]]:
    """Un installateur par application : ([installées], {id: message d’échec})."""
    from .logiciels import installer, installer_flatpaks, installer_github
    faites, echecs = [], {}
    natifs = {k: i for k, i in choix.items() if i['methode'] == 'native'}
    if natifs:
        code, msg = installer(g, [i['paquet'] for i in natifs.values()])
        if code:  # un nom introuvable fait échouer tout le lot : un par un pour savoir lequel
            for k, i in natifs.items():
                code, msg = installer(g, [i['paquet']])
                (faites.append(k) if code == 0 else echecs.__setitem__(k, msg))
        else:
            faites += list(natifs)
    flatpaks = {k: i for k, i in choix.items() if i['methode'] == 'flatpak'}
    if flatpaks:
        rates = set(installer_flatpaks(ctx, ext, [i['paquet'] for i in flatpaks.values()]))
        for k, i in flatpaks.items():
            (echecs.__setitem__(k, 'échec Flatpak') if i['paquet'] in rates else faites.append(k))
    for k, i in choix.items():
        if i['methode'] == 'snap':
            if not outil('snap'):
                echecs[k] = 'snapd absent'
                continue
            r = lancer(['snap', 'install', i['paquet']] + (['--classic'] if i['classic'] else []), delai=3600)
            (faites.append(k) if r.returncode == 0 else echecs.__setitem__(k, (r.stderr or r.stdout).strip()[-200:]))
        elif i['methode'] == 'github':
            code, msg = installer_github(g, i['paquet'])
            (faites.append(k) if code == 0 else echecs.__setitem__(k, msg))
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


def script_plasma(script: str, attente: int = 60) -> bool:
    """Script du bureau Plasma (qui affiche le nombre d’éléments modifiés) : vrai s’il a modifié quelque chose."""
    gdbus = outil('gdbus')
    if not gdbus:
        return False
    fin = time.time() + attente
    while True:  # à l’ouverture de session, plasmashell n’est pas forcément encore prêt
        r = lancer([gdbus, 'call', '--session', '--dest', 'org.kde.plasmashell', '--object-path', '/PlasmaShell',
                    '--method', 'org.kde.PlasmaShell.evaluateScript', script], env=_bus(), delai=30)
        if r.returncode == 0:
            return not re.search(r"'0'|\(''", r.stdout)
        if time.time() > fin:
            return False
        time.sleep(5)


def epingler_plasma(urls: list[str], attente: int = 90) -> bool:
    """Lanceurs épinglés du gestionnaire de tâches de Plasma (script du bureau, appliqué au panneau en cours)."""
    return script_plasma('var l = ' + json.dumps(urls) + ', n = 0;\n'
                         'panels().forEach(function (p) { p.widgets().forEach(function (w) {\n'
                         '  if (w.type == "org.kde.plasma.icontasks" || w.type == "org.kde.plasma.taskmanager") {\n'
                         '    w.currentConfigGroup = ["General"]; w.writeConfig("launchers", l); n++; } }); });\n'
                         'print(n);', attente)


def bandes_plasma(bande: dict, attente: int = 60) -> bool:
    """Couleur des bandes et flou du fond d’écran de chaque bureau Plasma (script du bureau)."""
    rvb = ','.join(str(int(bande['couleur'][i:i + 2], 16)) for i in (1, 3, 5))
    return script_plasma('var n = 0;\ndesktops().forEach(function (d) { if (d.wallpaperPlugin == "org.kde.image") {\n'
                         '  d.currentConfigGroup = ["Wallpaper", "org.kde.image", "General"];\n'
                         '  d.writeConfig("Color", "' + rvb + '"); d.writeConfig("Blur", ' + ('true' if bande['mode'] == 'flou' else 'false') + '); n++; } });\n'
                         'print(n);', attente)


# Panneaux puis bureaux (FolderView). Places des icônes : liste [colonnes, lignes, url, colonne, ligne, …] des icônes
# rangées en colonnes et non triées ; Plasma 6 la garde par définition d’écran (objet JSON « 1920x1080 »).
SCRIPT_DISPOSITION = '''var o = %s, n = 0;
panels().forEach(function (p) {
  if (o.position) p.location = o.position;
  if (o.hauteur) p.height = o.hauteur;
  if (o.centree !== null) { p.alignment = o.centree ? "center" : "left"; p.lengthMode = o.centree ? "fit" : "fill"; }
  if (o.position || o.hauteur || o.centree !== null) n++;
});
desktops().forEach(function (d) {
  d.currentConfigGroup = ["General"];
  if (o.icones !== null) d.writeConfig("iconSize", o.icones);
  if (o.verrou !== null) d.writeConfig("locked", o.verrou);
  if (o.places.length) {
    var g = screenGeometry(d.screen), cols = 1, lignes = Math.max(1, Math.floor((g.height - 60) / 110)), l = [];
    o.places.forEach(function (x) {
      cols = Math.max(cols, x[1] + 1); lignes = Math.max(lignes, x[2] + 1);
      ["desktop:/", o.dossier].forEach(function (b) { l.push(b + x[0], String(x[1]), String(x[2])); });
    });
    var v = [String(cols), String(lignes)].concat(l), avant = String(d.readConfig("positions", ""));
    d.writeConfig("sortMode", -1); d.writeConfig("arrangement", 1);
    if (avant.charAt(0) == "{" || (typeof applicationVersion != "undefined" && parseInt(applicationVersion) >= 6)) {
      var j = {}; try { j = JSON.parse(avant); } catch (e) { j = {}; }
      j[g.width + "x" + g.height] = v; d.writeConfig("positions", JSON.stringify(j));
    } else d.writeConfig("positions", v);
  }
  if (o.icones !== null || o.verrou !== null || o.places.length) n++;
});
if (o.verrou !== null) { locked = o.verrou; n++; }
print(n);'''


def disposition_plasma(d: dict, places: list, dossier: str, verrou) -> bool:
    """Panneau, icônes du bureau, verrou des éléments graphiques et thème de Plasma. `verrou` : True, False (déverrouiller
    ce que l’agent avait verrouillé) ou None (ne pas y toucher)."""
    b = d['barre']
    o = {'position': POSITIONS_BARRE[b['position']][0] if b['position'] else '', 'hauteur': HAUTEUR_PANNEAU.get(b['taille'], 0),
         'centree': b['centree'], 'icones': ICONES_PLASMA.get(d['icones']['taille']), 'verrou': verrou,
         'places': places, 'dossier': 'file://' + dossier.rstrip('/') + '/'}
    fait = False
    if o['position'] or o['hauteur'] or o['centree'] is not None or o['icones'] is not None or verrou is not None or places:
        fait = script_plasma(SCRIPT_DISPOSITION % json.dumps(o))
    th = d['theme']
    if th['mode']:
        sombre = th['mode'] == 'sombre'
        lancer(['plasma-apply-colorscheme', 'BreezeDark' if sombre else 'BreezeLight'], env=_bus())   # code 1 : déjà en place
        lancer(['plasma-apply-desktoptheme', 'breeze-dark' if sombre else 'breeze-light'], env=_bus())
        fait = True
    if th['accent']:
        lancer(['plasma-apply-colorscheme', '--accent-color', ACCENTS[th['accent']][1]], env=_bus())
        fait = True
    kw = outil('kwriteconfig6') or outil('kwriteconfig5')
    if kw and verrou is not None:  # verrouillé : « Déverrouiller les éléments graphiques » refusé à l’utilisateur
        lancer([kw, '--file', 'kdeglobals', '--group', 'KDE Action Restrictions', '--key', 'plasma/allow_configure_when_locked']
               + (['false'] if verrou else ['--delete']))
    return fait


def _gsettings(schema: str, cle: str, valeur: str) -> bool:
    return lancer(['gsettings', 'set', schema, cle, valeur], env=_bus()).returncode == 0   # schéma absent : extension non installée


def disposition_gnome(d: dict, places: list, dossier: str) -> bool:
    """Dock (Ubuntu Dock ou Dash to Dock), icônes du bureau (Desktop Icons NG), thème clair ou sombre et accent de GNOME."""
    dock, ding, interface = 'org.gnome.shell.extensions.dash-to-dock', 'org.gnome.shell.extensions.ding', 'org.gnome.desktop.interface'
    b, th, fait = d['barre'], d['theme'], False
    if b['position']:
        fait = _gsettings(dock, 'dock-position', POSITIONS_BARRE[b['position']][1]) or fait
    if b['taille']:
        fait = _gsettings(dock, 'dash-max-icon-size', str(ICONES_DOCK[b['taille']])) or fait
    if b['centree'] is not None:  # centré : dock à la taille de son contenu ; sinon sur toute la longueur de l’écran
        fait = _gsettings(dock, 'extend-height', 'false' if b['centree'] else 'true') or fait
    if d['icones']['taille']:
        fait = _gsettings(ding, 'icon-size', ICONES_DING[d['icones']['taille']]) or fait
    if th['mode']:
        sombre = th['mode'] == 'sombre'
        fait = _gsettings(interface, 'color-scheme', 'prefer-dark' if sombre else 'default') or fait
        theme = lancer(['gsettings', 'get', interface, 'gtk-theme'], env=_bus()).stdout.strip().strip("'")
        if theme.startswith('Yaru'):  # Ubuntu : le thème GTK suit le mode, comme le fait Paramètres
            base = theme[:-5] if theme.endswith('-dark') else theme
            _gsettings(interface, 'gtk-theme', base + '-dark' if sombre else base)
    if th['accent']:
        fait = _gsettings(interface, 'accent-color', ACCENTS[th['accent']][0]) or fait
    if places and outil('gio'):
        taille = ICONES_DING.get(d['icones']['taille']) or lancer(['gsettings', 'get', ding, 'icon-size'], env=_bus()).stdout.strip().strip("'")
        w, h = CASE_DING.get(taille, CASE_DING['standard'])
        for nom, col, lig in places:  # coin de la case ; Desktop Icons NG cale l’icône sur sa grille
            f = os.path.join(dossier, nom)
            if os.path.exists(f):
                lancer(['gio', 'set', f, 'metadata::nautilus-icon-position', f'{8 + col * w},{40 + lig * h}'], delai=10)
                fait = True
    return fait


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
            self._disposition(ctx, {'disposition': disposition(None), 'bureau': []}, mem, None)
            return
        p = fusionner([x[1] for x in liste])
        g = gestionnaire()
        ctx.noter(self.nom, 'profil : ' + ', '.join(x[1]['nom'] or x[0] for x in liste))
        manquantes = [i for i in utiles(p) if not presente(p['apps'][i], g)]
        bureau = None if ctx.simuler else dossier_bureau()
        lanceurs = _lanceurs()
        self._bureau(ctx, p, lanceurs, g, bureau)
        recent = mem.get('demandes', {})
        a_demander = [i for i in manquantes if a_redemander(p['apps'][i], recent.get(i), time.time())]
        if a_demander and not ctx.simuler:
            ctx.noter(self.nom, 'à installer : ' + ', '.join(p['apps'][i]['nom'] for i in a_demander))
            mem['demandes'] = {**recent, **{i: [time.time(), signature(p['apps'][i])] for i in a_demander}}
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
        self._disposition(ctx, p, mem, bureau)
        if p['fond'] and any(s == 'local' for s, _ in liste):
            self._fond(ctx, p['fond'], mem, p['fond_style'])
        if p['fond'] and p['fond_style'] == 3:
            self._bandes(ctx, p['fond_bande'], mem)  # poste du domaine ou non : l’image et le mode viennent de la GPO ou du profil local

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
            fichier = os.path.join(bureau, nom_icone(n, i))
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
        if ctx.simuler or not ids or (mem.get('barre') == ids and not p['disposition']['verrou']):
            return  # posées une fois par version du profil : l’utilisateur peut ensuite les changer (sauf disposition verrouillée)
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

    def _disposition(self, ctx, p, mem, bureau):
        """Barre des tâches, icônes du bureau, thème : posés quand le profil change, à chaque passage s’il est verrouillé."""
        d = p['disposition']
        pos = d['icones']['positions']
        places = [[nom_icone(n, i), *pos[i]] for n, i in enumerate(p['bureau']) if i in pos]
        vide = d == disposition(None)
        if vide and not mem.get('disposition'):
            return
        if not vide:
            b, th = d['barre'], d['theme']
            ctx.noter(self.nom, 'disposition : ' + ', '.join(x for x in (
                b['position'] and f"barre en {b['position']}", b['taille'] and f"barre {b['taille']}",
                b['centree'] is not None and ('icônes de la barre centrées' if b['centree'] else 'barre sur toute la longueur'),
                d['icones']['taille'] and f"icônes {d['icones']['taille']}s", places and f'{len(places)} icône(s) placée(s)',
                th['mode'] and f"thème {th['mode']}", th['accent'] and f"accent {th['accent']}", d['verrou'] and 'verrouillée') if x))
        cle = json.dumps([d, places], sort_keys=True)
        if ctx.simuler or (mem.get('disposition') == cle and not d['verrou']):
            return
        # verrou retiré (ou profil retiré) : on déverrouille ce que l’agent avait verrouillé, le reste du réglage demeure
        verrou = True if d['verrou'] else (False if mem.get('verrou') else None)
        fait = False
        dossier = bureau or dossier_bureau()
        if outil('plasmashell'):
            fait = disposition_plasma(d, places, dossier, verrou) or fait
        if outil('gnome-shell') and outil('gsettings'):
            fait = disposition_gnome(d, places, dossier) or fait
        if fait or vide:
            mem['verrou'] = d['verrou']
            if vide:
                mem.pop('disposition', None)
            else:
                mem['disposition'] = cle

    def _bandes(self, ctx, bande, mem):
        """Bandes de l’affichage « Ajuster » : couleur unie, ou couleurs de l’image prolongées (flou de Plasma ; GNOME n’a que la
        couleur unie, la couleur choisie y sert de repli)."""
        cle = [bande['mode'], bande['couleur']]
        if ctx.simuler or mem.get('bande') == cle:
            return
        fait = False
        if outil('plasmashell'):
            fait = bandes_plasma(bande) or fait
        if outil('gsettings'):
            for k, v in (('color-shading-type', 'solid'), ('primary-color', bande['couleur'])):
                fait = lancer(['gsettings', 'set', 'org.gnome.desktop.background', k, v], env=_bus()).returncode == 0 or fait
        if fait:
            mem['bande'] = cle

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
