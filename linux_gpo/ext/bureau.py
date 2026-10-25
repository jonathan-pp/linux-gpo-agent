"""Verrouillage du bureau, pour tous les bureaux présents sur le poste.

Réglages (ordinateur, valeurs de LinuxGPO\\Desktop) et équivalents Windows repris :
  DisableCommandLine     terminal et commande « Exécuter » (Alt+F2) interdits
  DisablePrinting        impression interdite
  DisableSaveToDisk      enregistrement de fichiers interdit (applications qui le respectent)
  DisableLogout          déconnexion interdite
  DisableUserSwitching   changement d’utilisateur interdit
  LockDelay              verrouillage de l’écran après N secondes d’inactivité
                         ← Windows « Ouverture de session interactive : limite d’inactivité de l’ordinateur »
  Wallpaper              image de fond (chemin sur le poste)
  HideUserList           écran de connexion sans liste des utilisateurs
                         ← Windows « Ne pas afficher le dernier nom d’utilisateur connecté »
  bannière de connexion  ← Windows « Message pour les utilisateurs qui tentent de se connecter »
et les réglages GNOME de Samba (« GNOME Settings\\Lock Down Settings »).

Moyens : dconf (GNOME, Cinnamon, MATE, Budgie, écran GDM) avec verrous ; KDE Plasma en mode Kiosk
(/etc/xdg/kdeglobals, kscreenlockerrc, entrées [$i] immuables) ; SDDM et LightDM pour l’écran de connexion.
Comme DisableCMD sous Windows, l’interdiction du terminal est une barrière d’interface, pas une sécurité absolue.
"""
import os

from . import INF_SYS, K_LGPO, K_WIN_SYS, Extension, entier, texte as en_texte, vrai
from ..systeme import chemin, est_nixos, gere_par_nix, lancer, outil

K = K_LGPO + r'\Desktop'
SAMBA_GNOME = r'GNOME Settings\Lock Down Settings'
DB = '/etc/dconf/db/linux-gpo.d'
GDM = '/etc/dconf/db/gdm.d'
LOCKDOWN = {  # réglage → clé dconf de chaque bureau (GNOME/Budgie, Cinnamon, MATE)
    'terminal': ['org/gnome/desktop/lockdown/disable-command-line', 'org/cinnamon/desktop/lockdown/disable-command-line',
                 'org/mate/desktop/lockdown/disable-command-line'],
    'impression': ['org/gnome/desktop/lockdown/disable-printing', 'org/gnome/desktop/lockdown/disable-print-setup',
                   'org/mate/desktop/lockdown/disable-printing', 'org/mate/desktop/lockdown/disable-print-setup'],
    'enregistrement': ['org/gnome/desktop/lockdown/disable-save-to-disk', 'org/mate/desktop/lockdown/disable-save-to-disk'],
    'deconnexion': ['org/gnome/desktop/lockdown/disable-log-out', 'org/cinnamon/desktop/lockdown/disable-log-out',
                    'org/mate/panel/lockdown/disable-log-out'],
    'changement': ['org/gnome/desktop/lockdown/disable-user-switching', 'org/cinnamon/desktop/lockdown/disable-user-switching',
                   'org/mate/desktop/lockdown/disable-user-switching'],
}
SAMBA_NOMS = {'Disable Command-Line Access': 'terminal', 'Disable Printing': 'impression', 'Disable File Saving': 'enregistrement',
              'Disable User Logout': 'deconnexion', 'Disable User Switching': 'changement'}
KDE = {'terminal': ['shell_access=false', 'run_command=false', 'action/run_command=false'],
       'impression': ['print=false', 'action/print=false', 'action/print_preview=false'],
       'enregistrement': ['action/file_save=false', 'action/file_save_as=false'],
       'deconnexion': ['logout=false'], 'changement': ['switch_user=false', 'action/switch_user=false']}


def reglages(pol) -> dict:
    r = {}
    for nom, cle in (('terminal', 'DisableCommandLine'), ('impression', 'DisablePrinting'), ('enregistrement', 'DisableSaveToDisk'),
                     ('deconnexion', 'DisableLogout'), ('changement', 'DisableUserSwitching')):
        if vrai(pol.valeur(K, cle)):
            r[nom] = True
    for _, nom, _, v in pol.entrees(SAMBA_GNOME):
        if nom in SAMBA_NOMS and vrai(v):
            r[SAMBA_NOMS[nom]] = True
    delai = entier(pol.valeur(K, 'LockDelay')) or entier(pol.reg_inf(INF_SYS + r'\InactivityTimeoutSecs'))
    if delai > 0:
        r['verrou'] = delai
    if str(pol.valeur(K, 'Wallpaper') or '').startswith('/'):
        r['fond'] = str(pol.valeur(K, 'Wallpaper'))
    if vrai(pol.valeur(K, 'HideUserList')) or vrai(pol.reg_inf(INF_SYS + r'\DontDisplayLastUserName')):
        r['liste_masquee'] = True
    texte = en_texte(pol.valeur(K, 'LoginBanner')) or pol.reg_inf(INF_SYS + r'\LegalNoticeText') or en_texte(pol.valeur(K_WIN_SYS, 'LegalNoticeText'))
    titre = pol.reg_inf(INF_SYS + r'\LegalNoticeCaption') or pol.valeur(K_WIN_SYS, 'LegalNoticeCaption')
    if str(texte or '').strip():
        r['banniere'] = (f'{titre}\n' if str(titre or '').strip() else '') + str(texte)
    return r


def _gv(v) -> str:
    """Valeur au format GVariant (fichiers clés de dconf)."""
    if isinstance(v, bool):
        return 'true' if v else 'false'
    if isinstance(v, tuple) and v[0] == 'uint32':
        return f'uint32 {v[1]}'
    if isinstance(v, int):
        return str(v)
    return "'" + str(v).replace('\\', '\\\\').replace("'", "\\'").replace('\n', '\\n') + "'"


def keyfile(valeurs: dict[str, object]) -> str:
    """{'org/gnome/x/clé': valeur} → fichier clé dconf."""
    groupes = {}
    for chemin_cle, v in valeurs.items():
        g, _, k = chemin_cle.rpartition('/')
        groupes.setdefault(g, []).append(f'{k}={_gv(v)}')
    return ''.join(f'[{g}]\n' + '\n'.join(l) + '\n\n' for g, l in sorted(groupes.items()))


class Bureau(Extension):
    nom = 'bureau'

    def appliquer(self, ctx):
        r = reglages(ctx.pol)
        if not r:
            return
        self.dconf = bool(outil('dconf')) or os.path.isdir(chemin('/etc/dconf'))
        for k, v in r.items():
            ctx.noter(self.nom, f'{k} : {v if not isinstance(v, bool) else "oui"}')
        if self.dconf:
            self._dconf(ctx, r)
        if outil('plasmashell') or os.path.isdir(chemin('/usr/share/plasma')):
            self._kde(ctx, r)
        if outil('xfce4-session') and ('verrou' in r or 'terminal' in r):
            ctx.noter(self.nom, 'Xfce : pas de mécanisme de verrouillage des réglages, seuls l’écran de connexion et les droits s’appliquent')
        self._ecrans_connexion(ctx, r)

    def _dconf(self, ctx, r):
        vals = {}
        for nom in ('terminal', 'impression', 'enregistrement', 'deconnexion', 'changement'):
            if r.get(nom):
                for k in LOCKDOWN[nom]:
                    vals[k] = True
        if 'verrou' in r:
            s = r['verrou']
            vals.update({'org/gnome/desktop/session/idle-delay': ('uint32', s), 'org/gnome/desktop/screensaver/lock-enabled': True,
                         'org/gnome/desktop/screensaver/lock-delay': ('uint32', 0), 'org/gnome/desktop/lockdown/disable-lock-screen': False,
                         'org/cinnamon/desktop/session/idle-delay': ('uint32', s), 'org/cinnamon/desktop/screensaver/lock-enabled': True,
                         'org/cinnamon/desktop/screensaver/lock-delay': ('uint32', 0),
                         'org/mate/session/idle-delay': max(1, (s + 59) // 60), 'org/mate/screensaver/lock-enabled': True,
                         'org/mate/screensaver/idle-activation-enabled': True})
        if 'fond' in r:
            uri = 'file://' + r['fond']
            vals.update({'org/gnome/desktop/background/picture-uri': uri, 'org/gnome/desktop/background/picture-uri-dark': uri,
                         'org/gnome/desktop/background/picture-options': 'zoom', 'org/cinnamon/desktop/background/picture-uri': uri,
                         'org/mate/desktop/background/picture-filename': r['fond']})
        if vals:
            ctx.f.ecrire(f'{DB}/00-linux-gpo', '# Stratégies de groupe (linux-gpo)\n' + keyfile(vals), self.nom)
            ctx.f.ecrire(f'{DB}/locks/00-linux-gpo', ''.join(f'/{k}\n' for k in sorted(vals)), self.nom)
            profil = '/etc/dconf/profile/user'
            if gere_par_nix(profil):
                ctx.noter(self.nom, 'NixOS : le module linux-gpo ajoute la base dconf « linux-gpo » au profil')
            elif not os.path.exists(chemin(profil)) or ctx.f.etat['fichiers'].get(profil, {}).get('ext') == self.nom:
                ctx.f.ecrire(profil, 'user-db:user\nsystem-db:linux-gpo\n', self.nom)
            else:
                ctx.f.bloc(profil, 'system-db:linux-gpo', self.nom)
        greeter = {}
        if r.get('liste_masquee'):
            greeter['org/gnome/login-screen/disable-user-list'] = True
        if r.get('banniere'):
            greeter.update({'org/gnome/login-screen/banner-message-enable': True, 'org/gnome/login-screen/banner-message-text': r['banniere']})
        if greeter and os.path.exists(chemin('/etc/dconf/profile/gdm')):
            ctx.f.ecrire(f'{GDM}/90-linux-gpo', keyfile(greeter), self.nom)
            ctx.f.ecrire(f'{GDM}/locks/90-linux-gpo', ''.join(f'/{k}\n' for k in sorted(greeter)), self.nom)

    def _kde(self, ctx, r):
        lignes = [l for nom in ('terminal', 'impression', 'enregistrement', 'deconnexion', 'changement') if r.get(nom) for l in KDE[nom]]
        if lignes:
            ctx.f.bloc('/etc/xdg/kdeglobals', '[KDE Action Restrictions][$i]\n' + '\n'.join(lignes), self.nom)
        if 'verrou' in r:
            ctx.f.bloc('/etc/xdg/kscreenlockerrc', '[Daemon][$i]\nAutolock=true\nLockOnResume=true\n'
                       f'Timeout={max(1, (r["verrou"] + 59) // 60)}\nLockGrace=0', self.nom)
        if 'fond' in r:
            ctx.noter(self.nom, 'KDE Plasma : l’image de fond ne peut pas être imposée par le mode Kiosk (réglage par utilisateur)')

    def _ecrans_connexion(self, ctx, r):
        if r.get('liste_masquee'):
            if os.path.isdir(chemin('/etc/sddm.conf.d')) or outil('sddm'):
                ctx.f.ecrire('/etc/sddm.conf.d/50-linux-gpo.conf', '[Users]\nRememberLastUser=false\nRememberLastSession=false\n', self.nom)
            if os.path.isdir(chemin('/etc/lightdm')):
                ctx.f.ecrire('/etc/lightdm/lightdm.conf.d/50-linux-gpo.conf', '[Seat:*]\ngreeter-hide-users=true\ngreeter-show-manual-login=true\n',
                             self.nom)

    def apres(self, ctx, changes):
        if ctx.simuler or not any(p.startswith(('/etc/dconf/',)) for p in changes):
            return
        if outil('dconf'):
            r = lancer(['dconf', 'update'])
            if r.returncode:
                ctx.noter(self.nom, f'dconf update : {r.stderr.strip()}')
        elif est_nixos():
            ctx.noter(self.nom, 'dconf absent : activez programs.dconf.enable')
