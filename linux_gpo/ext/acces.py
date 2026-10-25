"""Qui peut ouvrir une session sur le poste.

Sources : LinuxGPO\\Access\\Allow et \\Deny, fichiers VGP « Host Access Control » (Samba), et les droits Windows
« Permettre / Interdire l’ouverture d’une session locale » et « … par les services Bureau à distance » (ssh)
de GptTmpl.inf — sauf si sssd les applique déjà lui-même (ad_gpo_access_control = enforcing).

Les règles sont écrites dans /etc/linux-gpo/acces.json et vérifiées à chaque connexion par un module PAM
(pam_exec) ; root et les comptes locaux ne sont jamais bloqués.
"""
import json
import os
import xml.etree.ElementTree as ET

from . import K_LGPO, Extension
from ..conf import sssd_controle_gpo
from ..noms import admins_locaux
from ..systeme import chemin, est_nixos, famille, gere_par_nix, lancer

FICHIER = '/etc/linux-gpo/acces.json'
VGP = {'autoriser': 'MACHINE/VGP/VTLA/VAS/HostAccessControl/Allow/manifest.xml',
       'refuser': 'MACHINE/VGP/VTLA/VAS/HostAccessControl/Deny/manifest.xml'}
DROITS = {('interactif', 'autoriser'): 'SeInteractiveLogonRight', ('interactif', 'refuser'): 'SeDenyInteractiveLogonRight',
          ('distant', 'autoriser'): 'SeRemoteInteractiveLogonRight', ('distant', 'refuser'): 'SeDenyRemoteInteractiveLogonRight'}
PROFIL_DEBIAN = '/usr/share/pam-configs/linux-gpo'
SERVICES_PAM = ['login', 'sshd', 'gdm-password', 'gdm-autologin', 'gdm-fingerprint', 'gdm-smartcard', 'sddm', 'sddm-autologin',
                'lightdm', 'lightdm-autologin', 'lxdm', 'xrdp-sesman', 'cockpit', 'greetd']
VERIFICATEUR = '/usr/lib/linux-gpo/acces'


def ligne_pam() -> str:
    return f'account required pam_exec.so quiet {VERIFICATEUR}'


class Acces(Extension):
    nom = 'acces'

    def _entree(self, ctx, nom: str, groupe: bool | None) -> dict | None:
        if nom.startswith('@'):
            return {'special': nom}
        for g in ([groupe] if groupe is not None else [True, False]):
            loc = ctx.noms.local(nom, g)
            if loc:
                return {'nom': loc, 'groupe': g}
        ctx.noter(self.nom, f'compte inconnu sur ce poste : {nom}')
        return None

    def appliquer(self, ctx):
        pol = ctx.pol
        regles = {'interactif': {'autoriser': [], 'refuser': []}, 'distant': {'autoriser': [], 'refuser': []}}

        def ajouter(sens, e, types=('interactif', 'distant')):
            if e:
                for t in types:
                    if e not in regles[t][sens]:
                        regles[t][sens].append(e)

        for sens, cle in (('autoriser', 'Allow'), ('refuser', 'Deny')):
            for nom in pol.liste(f'{K_LGPO}\\Access\\{cle}'):
                ajouter(sens, self._entree(ctx, str(nom).strip(), None))
            for _, f in pol.fichiers(VGP[sens]):
                try:
                    data = ET.parse(f).getroot().find('policysetting/data')
                except (OSError, ET.ParseError):
                    continue
                for le in (data.findall('listelement') if data is not None else []):
                    nom = le.findtext('adobject/name') or (le.findtext('entry') or '').split('\\')[-1]
                    dom = le.findtext('adobject/domain') or ''
                    typ = (le.findtext('adobject/type') or le.findtext('type') or '').lower()
                    ajouter(sens, self._entree(ctx, f'{dom}\\{nom}' if dom else nom, typ == 'group' if typ else None))
        if sssd_controle_gpo():
            ctx.noter(self.nom, 'droits Windows d’ouverture de session : appliqués par sssd (ad_gpo_access_control)')
        else:
            for (t, sens), droit in DROITS.items():
                v = pol.inf_valeur('Privilege Rights', droit)
                if v is None:
                    continue
                for x in [x.strip() for x in v.split(',') if x.strip()]:
                    if x.startswith('*'):
                        loc = ctx.noms.local_de_sid(x) if ctx.annuaire else None
                        if loc and loc[0]:
                            ajouter(sens, {'special': loc[0]} if loc[0].startswith('@') else {'nom': loc[0], 'groupe': loc[1]}, (t,))
                    else:
                        ajouter(sens, self._entree(ctx, x, None), (t,))
                if sens == 'autoriser' and v.strip() and not regles[t]['autoriser']:
                    # droit défini mais aucun compte reconnu : comme sous Windows, personne du domaine n’est autorisé
                    regles[t]['autoriser'].append({'nom': '\x00personne', 'groupe': False})
        if not any(regles[t][s] for t in regles for s in regles[t]):
            return
        regles['admins'] = admins_locaux() + ctx.admins_domaine()
        ctx.f.ecrire(FICHIER, json.dumps(regles, indent=1, ensure_ascii=False) + '\n', self.nom)
        for t in ('interactif', 'distant'):
            for s in ('autoriser', 'refuser'):
                for e in regles[t][s]:
                    ctx.noter(self.nom, f"{t} — {s} : {e.get('special') or e.get('nom')}")
        self._brancher_pam(ctx)

    def _brancher_pam(self, ctx):
        if est_nixos():
            ctx.noter(self.nom, 'NixOS : le module linux-gpo branche le contrôle dans PAM (services.linux-gpo.controleAcces)')
            return
        if famille() == 'debian' and lancer(['pam-auth-update', '--help']).returncode != 127:
            ctx.f.ecrire(PROFIL_DEBIAN, 'Name: Contrôle d’ouverture de session des stratégies de groupe (linux-gpo)\n'
                         'Default: yes\nPriority: 0\nAccount-Type: Additional\nAccount:\n'
                         f'\trequired\t\t\tpam_exec.so quiet {VERIFICATEUR}\n', self.nom)
            return
        for s in SERVICES_PAM:
            p = f'/etc/pam.d/{s}'
            if os.path.exists(chemin(p)) and not gere_par_nix(p):
                ctx.f.bloc(p, ligne_pam(), self.nom, au_debut=True)

    def apres(self, ctx, changes):
        if PROFIL_DEBIAN in changes and not ctx.simuler:
            present = os.path.exists(chemin(PROFIL_DEBIAN))
            r = lancer(['pam-auth-update', '--enable', 'linux-gpo'] if present else ['pam-auth-update', '--package'],
                       env={'DEBIAN_FRONTEND': 'noninteractive'})
            if r.returncode:
                ctx.noter(self.nom, f'pam-auth-update : {r.stderr.strip()}')
