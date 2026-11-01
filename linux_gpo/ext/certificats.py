"""Autorités de certification du domaine : celles publiées dans l’annuaire (Configuration › Services › Public Key Services ›
Certification Authorities) deviennent des autorités de confiance du poste, comme sur un poste Windows du domaine.

Machine : magasin du système (update-ca-certificates ou update-ca-trust), donc curl, Python, KDE, GNOME…, et
/etc/linux-gpo/autorites.pem (mise à jour de l’agent, Firefox, session). Rien à régler dans les GPO : seuls les
administrateurs de l’entreprise peuvent écrire dans ce conteneur.
Session : base NSS de l’utilisateur (~/.pki/nssdb), lue par Chrome, Chromium, Edge et Brave sous Linux.
"""
from __future__ import annotations

import base64
import hashlib
import os
import re
import tempfile

from . import Extension
from ..systeme import chemin, est_nixos, famille, lancer, outil

FICHIER = '/etc/linux-gpo/autorites.pem'
CONTENEUR = 'CN=Certification Authorities,CN=Public Key Services,CN=Services,'
NSS = '~/.pki/nssdb'
PREFIXE_NSS = 'linux-gpo '
PEM = re.compile(r'-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\s]+?-----END CERTIFICATE-----')


def pem(der: bytes) -> str:
    b = base64.b64encode(der).decode('ascii')
    return '-----BEGIN CERTIFICATE-----\n' + '\n'.join(b[i:i + 64] for i in range(0, len(b), 64)) + '\n-----END CERTIFICATE-----\n'


def empreinte(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest()[:16]


def magasin() -> tuple[str, list[str]] | None:
    """(dossier des autorités ajoutées, commande de reconstruction) du magasin du système."""
    f = famille()
    if f == 'suse':
        return '/etc/pki/trust/anchors', ['update-ca-certificates']
    if f == 'fedora':
        return '/etc/pki/ca-trust/source/anchors', ['update-ca-trust', 'extract']
    if f == 'arch':
        return '/etc/ca-certificates/trust-source/anchors', ['update-ca-trust']
    if os.path.isdir(chemin('/usr/local/share/ca-certificates')) or outil('update-ca-certificates'):
        return '/usr/local/share/ca-certificates/linux-gpo', ['update-ca-certificates']
    if outil('update-ca-trust'):
        return '/etc/pki/ca-trust/source/anchors', ['update-ca-trust', 'extract']
    return None


def lire_annuaire(annuaire, base: str) -> list[bytes]:
    """Certificats (DER) des autorités publiées dans l’annuaire."""
    racine = annuaire.chercher('', '(objectClass=*)', ['configurationNamingContext'])
    config = (racine[0].get('configurationnamingcontext') or [b''])[0].decode() if racine else ''
    entrees = annuaire.chercher(CONTENEUR + (config or 'CN=Configuration,' + base), '(objectClass=certificationAuthority)',
                                ['cACertificate'], portee='one')
    res = []
    for e in entrees:
        for der in e.get('cacertificate', []):
            # un certificat commence par une SEQUENCE ; les valeurs vides de certutil (un octet nul) sont ignorées
            if len(der) > 64 and der[:1] == b'\x30' and der not in res:
                res.append(der)
    return res


def lire_fichier(contenu: str) -> list[bytes]:
    return [base64.b64decode(''.join(m.group(0).splitlines()[1:-1])) for m in PEM.finditer(contenu)]


class Autorites(Extension):
    nom = 'autorites'

    def appliquer(self, ctx):
        self.commande = None
        if not ctx.annuaire:
            ctx.f.garder(self.nom)  # hors ligne : les autorités déjà installées restent
            return
        ders = lire_annuaire(ctx.annuaire, ctx.conf.base)
        m = magasin()
        self.commande = m[1] if m else None
        if not ders:
            return
        ctx.f.ecrire(FICHIER, ''.join(pem(d) for d in ders), self.nom)
        if est_nixos() or not m:
            ctx.noter(self.nom, f'{len(ders)} autorité(s) dans {FICHIER} ; magasin du système non géré '
                                '(NixOS : security.pki.certificateFiles)')
            return
        for d in ders:
            ctx.f.ecrire(f'{m[0]}/linux-gpo-{empreinte(d)}.crt', pem(d), self.nom)
        ctx.noter(self.nom, f'{len(ders)} autorité(s) du domaine dans le magasin du système ({m[0]})')

    def apres(self, ctx, changes):
        # aussi après un retrait (autorité supprimée de l’annuaire) : le magasin est reconstruit sans elle
        if ctx.simuler or not self.commande or not [p for p in changes if p.endswith('.crt')]:
            return
        r = lancer(self.commande, delai=120)
        if r.returncode:
            ctx.noter(self.nom, f"{' '.join(self.commande)} : {(r.stderr or r.stdout).strip()[-200:]}")


class AutoritesSession(Extension):
    """Autorités du domaine dans la base NSS de l’utilisateur (navigateurs Chromium)."""
    nom = 'autorites-session'
    machine = False

    def appliquer(self, ctx):
        try:
            with open(chemin(FICHIER), encoding='ascii') as fh:
                ders = lire_fichier(fh.read())
        except OSError:
            ders = []
        mem = ctx.f.memoire(self.nom)
        voulus = {PREFIXE_NSS + empreinte(d): d for d in ders}
        poses = set(mem.get('poses', []))
        if not voulus and not poses:
            return
        if not outil('certutil'):
            if voulus:
                ctx.noter(self.nom, 'certutil absent (paquet libnss3-tools ou nss-tools) : autorités non ajoutées pour Chrome')
            return
        if ctx.simuler:
            ctx.noter(self.nom, f'{len(voulus)} autorité(s) pour Chrome')
            return
        dossier = os.path.expanduser(NSS)
        base = 'sql:' + dossier
        if not os.path.exists(os.path.join(dossier, 'cert9.db')):
            os.makedirs(dossier, mode=0o700, exist_ok=True)
            lancer(['certutil', '-N', '-d', base, '--empty-password'])
        for n in poses - set(voulus):
            lancer(['certutil', '-D', '-d', base, '-n', n])
        for n, d in list(voulus.items()):
            if n in poses and lancer(['certutil', '-L', '-d', base, '-n', n]).returncode == 0:
                continue
            with tempfile.NamedTemporaryFile('w', suffix='.pem', delete=False) as t:
                t.write(pem(d))
            try:
                r = lancer(['certutil', '-A', '-d', base, '-t', 'C,,', '-n', n, '-i', t.name])
            finally:
                os.unlink(t.name)
            if r.returncode:
                ctx.noter(self.nom, f'certutil : {(r.stderr or r.stdout).strip()[-200:]}')
                voulus.pop(n)
        mem['poses'] = sorted(voulus)
        if voulus:
            ctx.noter(self.nom, f'{len(voulus)} autorité(s) du domaine pour Chrome (~/.pki/nssdb)')
