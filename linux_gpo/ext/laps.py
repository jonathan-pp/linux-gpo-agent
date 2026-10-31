"""LAPS : mot de passe du compte administrateur local, différent sur chaque poste, renouvelé et gardé dans l’annuaire.

Même réglage que les postes Windows (GPO « Activer la gestion du mot de passe du compte administrateur local »,
LAPS hérité, Software\\Policies\\Microsoft Services\\AdmPwd) :
  AdmPwdEnabled       1 : mot de passe géré
  PasswordComplexity  1 majuscules ; 2 + minuscules ; 3 + chiffres (défaut) ; 4 + caractères spéciaux
  PasswordLength      longueur (8 à 64, défaut 14)
  PasswordAgeDays     durée de vie en jours (1 à 365, défaut 30)
  AdminAccountName    compte géré ; vide : root. Un autre nom : compte local créé s’il manque, administrateur (sudo).

Le mot de passe est écrit d’abord sur le compte de l’ordinateur (ms-Mcs-AdmPwd, et sa date d’expiration
ms-Mcs-AdmPwdExpirationTime), par une connexion Kerberos chiffrée, puis seulement sur le poste : annuaire
injoignable, rien ne change. Il n’est jamais gardé sur le poste ni écrit dans le journal. La Console Annuaire l’affiche
(propriétés de l’ordinateur, onglet LAPS) ; une date d’expiration avancée dans l’annuaire le fait renouveler au passage
suivant.
"""
from __future__ import annotations

import pwd
import re
import secrets
import string
import time

from . import Extension, entier, vrai
from ..annuaire import echapper_filtre, un
from ..systeme import ErreurAgent, est_nixos, famille, lancer

K = r'Software\Policies\Microsoft Services\AdmPwd'
COMPTE = re.compile(r'^[a-z_][a-z0-9_-]{0,31}$')
SPECIAUX = '!#%&*+,-.=?@[]_{}'   # ni guillemets, ni barre oblique inverse, ni deux-points : faciles à taper partout
EPOQUE = 11644473600             # secondes entre 1601 (dates de l’annuaire, FILETIME) et 1970


def reglage(pol) -> dict | None:
    if not vrai(pol.valeur(K, 'AdmPwdEnabled')):
        return None
    borne = lambda nom, defaut, bas, haut: min(haut, max(bas, entier(pol.valeur(K, nom), defaut)))
    return {'complexite': borne('PasswordComplexity', 3, 1, 4), 'longueur': borne('PasswordLength', 14, 8, 64),
            'age': borne('PasswordAgeDays', 30, 1, 365), 'compte': str(pol.valeur(K, 'AdminAccountName') or '').strip() or 'root'}


def generer(longueur: int, complexite: int) -> str:
    """Mot de passe aléatoire (module secrets), avec au moins un caractère de chaque famille demandée."""
    familles = [string.ascii_uppercase, string.ascii_lowercase, string.digits, SPECIAUX][:complexite]
    tous = ''.join(familles)
    while True:
        p = ''.join(secrets.choice(tous) for _ in range(longueur))
        if all(any(c in f for c in p) for f in familles):
            return p


def vers_filetime(t: float) -> str:
    return str(int((t + EPOQUE) * 10_000_000))


def depuis_filetime(v: str) -> float | None:
    try:
        return int(v) / 10_000_000 - EPOQUE
    except (TypeError, ValueError):
        return None


def a_renouveler(expiration: float | None, age: int, maintenant: float) -> bool:
    """Jamais posé, expiré, ou expirant plus tard que la durée de vie actuelle ne le permet (durée raccourcie)."""
    return expiration is None or expiration <= maintenant or expiration > maintenant + age * 86400 + 3600


def _existe(compte: str) -> bool:
    try:
        pwd.getpwnam(compte)
        return True
    except KeyError:
        return False


class Laps(Extension):
    nom = 'laps'

    def appliquer(self, ctx):
        r = reglage(ctx.pol)
        if not r:
            return
        compte = r['compte']
        if not COMPTE.match(compte):
            ctx.noter(self.nom, f'nom de compte « {compte} » invalide sous Linux : rien de fait')
            return
        ctx.noter(self.nom, f"compte {compte} : {r['longueur']} caractères, renouvelé tous les {r['age']} jours")
        if est_nixos():
            ctx.noter(self.nom, 'NixOS : sans effet durable si la configuration fixe les comptes (users.mutableUsers = false)')
        if not ctx.annuaire:
            ctx.noter(self.nom, 'annuaire injoignable : mot de passe inchangé')
            return
        try:
            e = ctx.annuaire.chercher(ctx.conf.base, f'(&(objectClass=computer)(sAMAccountName={echapper_filtre(ctx.conf.compte)}))',
                                      ['ms-Mcs-AdmPwdExpirationTime'], portee='sub')
        except ErreurAgent as x:
            ctx.noter(self.nom, f'lecture du compte de l’ordinateur impossible : {x}')
            return
        if not e:
            ctx.noter(self.nom, f'compte de l’ordinateur {ctx.conf.compte} introuvable dans l’annuaire')
            return
        mem = ctx.f.memoire(self.nom)
        maintenant = time.time()
        expiration = depuis_filetime(un(e[0], 'ms-Mcs-AdmPwdExpirationTime'))
        if not (a_renouveler(expiration, r['age'], maintenant) or mem.get('compte') != compte or mem.get('a_refaire')):
            ctx.noter(self.nom, 'mot de passe valable jusqu’au ' + time.strftime('%d/%m/%Y %H:%M', time.localtime(expiration)))
            return
        if ctx.simuler:
            ctx.noter(self.nom, 'mot de passe à renouveler')
            return
        if compte != 'root' and not _existe(compte) and not self._creer(ctx, compte):
            return
        mdp, fin = generer(r['longueur'], r['complexite']), maintenant + r['age'] * 86400
        try:  # l’annuaire d’abord : un mot de passe posé sur le poste sans y être enregistré serait perdu
            ctx.annuaire.modifier(e[0]['dn'], [('ms-Mcs-AdmPwd', mdp), ('ms-Mcs-AdmPwdExpirationTime', vers_filetime(fin))])
        except ErreurAgent as x:
            ctx.noter(self.nom, f'enregistrement dans l’annuaire impossible, mot de passe inchangé : {x}')
            return
        ch = lancer(['chpasswd'], entree=f'{compte}:{mdp}\n')
        if ch.returncode:
            mem['a_refaire'] = True  # l’annuaire a un mot de passe que le poste n’a pas : on recommence au prochain passage
            ctx.noter(self.nom, f'chpasswd {compte} : {(ch.stderr or ch.stdout).strip()[-200:]}')
            return
        mem.pop('a_refaire', None)
        mem['compte'] = compte
        ctx.noter(self.nom, 'mot de passe renouvelé, valable jusqu’au ' + time.strftime('%d/%m/%Y %H:%M', time.localtime(fin)))

    def _creer(self, ctx, compte: str) -> bool:
        """Compte administrateur local géré par LAPS (groupe sudo, ou wheel hors Debian et Ubuntu)."""
        groupe = 'sudo' if famille() == 'debian' else 'wheel'
        r = lancer(['useradd', '-m', '-s', '/bin/bash', '-c', 'Administrateur local (LAPS)', '-G', groupe, compte])
        if r.returncode:
            ctx.noter(self.nom, f'création du compte {compte} impossible : {(r.stderr or r.stdout).strip()[-200:]}')
            return False
        ctx.noter(self.nom, f'compte {compte} créé (groupe {groupe})')
        return True
