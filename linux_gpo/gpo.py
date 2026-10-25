"""Liste des GPO qui s’appliquent à un compte (ordinateur ou utilisateur), dans l’ordre d’application de Windows :
site, domaine, puis unités d’organisation du parent vers l’enfant ; dans un conteneur, l’ordre de gPLink
(la dernière liaison l’emporte) ; liaisons appliquées (« enforced ») à la fin ; blocage de l’héritage ;
liaisons et GPO désactivées ; filtrage de sécurité (lecture + « Appliquer la stratégie de groupe »).
"""
from __future__ import annotations

import ipaddress
import logging
import re
import socket
from dataclasses import dataclass

from . import sid as sids
from .annuaire import SD_DACL, Annuaire, echapper_filtre, parents, un
from .systeme import ErreurAgent

journal = logging.getLogger('linux-gpo')
LIEN_DESACTIVE, LIEN_APPLIQUE = 1, 2
BLOQUER_HERITAGE = 1
GPO_UTILISATEUR_DESACTIVE, GPO_ORDINATEUR_DESACTIVE = 1, 2


@dataclass
class Gpo:
    guid: str
    nom: str
    chemin: str          # \\domaine\SysVol\domaine\Policies\{GUID}
    version: int         # versionNumber (16 bits hauts : utilisateur, 16 bas : ordinateur)
    lien: str            # DN du conteneur lié
    applique: bool = False
    local: str = ''      # copie locale de SYSVOL

    def version_partie(self, machine: bool) -> int:
        return self.version & 0xFFFF if machine else self.version >> 16


@dataclass
class Compte:
    dn: str
    sid: str
    machine: bool
    jeton: set


def compte(a: Annuaire, sam: str, machine: bool) -> Compte:
    classe = 'computer' if machine else 'user'
    r = a.chercher(a.conf.base, f'(&(objectClass={classe})(sAMAccountName={echapper_filtre(sam)}))',
                   ['objectSid'], portee='sub')
    if not r:
        raise ErreurAgent(f'compte {sam} introuvable dans l’annuaire')
    dn, sid = r[0]['dn'], sids.sid_texte(r[0]['objectsid'][0])
    jeton = {sid, sids.TOUT_LE_MONDE, sids.UTILISATEURS_AUTHENTIFIES}
    g = a.chercher(dn, attrs=['tokenGroups'])
    for b in (g[0].get('tokengroups', []) if g else []):
        jeton.add(sids.sid_texte(b))
    return Compte(dn, sid, machine, jeton)


def _liens(gplink: str) -> list[tuple[str, int]]:
    return [(m.group(1), int(m.group(2))) for m in re.finditer(r'\[LDAP://([^;\]]+);(\d+)\]', gplink, re.I)]


def _adresses_locales(cible: str) -> list[ipaddress._BaseAddress]:
    res = []
    for fam in (socket.AF_INET, socket.AF_INET6):
        try:
            with socket.socket(fam, socket.SOCK_DGRAM) as s:
                s.connect((cible, 389))
                res.append(ipaddress.ip_address(s.getsockname()[0].split('%')[0]))
        except OSError:
            continue
    return res


def site(a: Annuaire) -> str | None:
    """DN du site du poste, d’après les sous-réseaux déclarés dans Sites et services."""
    config = 'CN=Configuration,' + a.conf.base
    try:
        sous_reseaux = a.chercher(f'CN=Subnets,CN=Sites,{config}', '(objectClass=subnet)', ['cn', 'siteObject'], portee='one')
    except ErreurAgent:
        return None
    adresses = _adresses_locales(a.controleur())
    meilleur = None
    for s in sous_reseaux:
        try:
            reseau = ipaddress.ip_network(un(s, 'cn'), strict=False)
        except ValueError:
            continue
        if any(ad.version == reseau.version and ad in reseau for ad in adresses) and un(s, 'siteobject'):
            if meilleur is None or reseau.prefixlen > meilleur[0]:
                meilleur = (reseau.prefixlen, un(s, 'siteobject'))
    return meilleur[1] if meilleur else None


def liste(a: Annuaire, c: Compte, filtres_wmi: str = 'exclure') -> list[Gpo]:
    base = a.conf.base.lower()
    conteneurs = [p for p in parents(c.dn) if p.lower().endswith(base)]
    # du plus proche (OU de l’objet) au domaine ; l’application se fait dans l’ordre inverse
    niveaux = []
    for dn in conteneurs:
        r = a.chercher(dn, attrs=['gPLink', 'gPOptions'])
        if r:
            niveaux.append((dn, un(r[0], 'gplink'), int(un(r[0], 'gpoptions', '0') or 0)))
    if c.machine:
        s = site(a)
        if s:
            r = a.chercher(s, attrs=['gPLink', 'gPOptions'])
            if r:
                niveaux.append((s, un(r[0], 'gplink'), 0))
    ordre, appliques = [], []
    bloque = False
    for dn, gplink, options in niveaux:  # enfant → parent
        liens = [(lien, opt) for lien, opt in _liens(gplink) if not opt & LIEN_DESACTIVE]
        normaux = [(l, dn) for l, opt in liens if not opt & LIEN_APPLIQUE]
        forces = [(l, dn) for l, opt in liens if opt & LIEN_APPLIQUE]
        appliques = appliques + forces  # les liaisons appliquées des parents passent après : elles l’emportent
        if not bloque:
            ordre = normaux + ordre
        if options & BLOQUER_HERITAGE:
            bloque = True
    ordre += appliques
    if not ordre:
        return []
    # détails des GPO en une requête
    guids = {}
    for lien, _ in ordre:
        m = re.match(r'cn=(\{[0-9a-f-]+\})', lien, re.I)
        if m:
            guids[m.group(1).upper()] = None
    filtre = '(|' + ''.join(f'(cn={g})' for g in guids) + ')'
    infos = {}
    for e in a.chercher(f'CN=Policies,CN=System,{a.conf.base}', filtre,
                        ['cn', 'displayName', 'gPCFileSysPath', 'versionNumber', 'flags', 'gPCWQLFilter', 'nTSecurityDescriptor'],
                        portee='one', controles=[SD_DACL]):
        infos[un(e, 'cn').upper()] = e
    res, vus = [], set()
    for lien, dn in ordre:
        m = re.match(r'cn=(\{[0-9a-f-]+\})', lien, re.I)
        e = infos.get(m.group(1).upper()) if m else None
        if e is None:
            continue
        guid = m.group(1).upper()
        nom = un(e, 'displayname', guid)
        drapeaux = int(un(e, 'flags', '0') or 0)
        if drapeaux & (GPO_ORDINATEUR_DESACTIVE if c.machine else GPO_UTILISATEUR_DESACTIVE):
            journal.debug('%s : partie %s désactivée', nom, 'ordinateur' if c.machine else 'utilisateur')
            continue
        sd = e.get('ntsecuritydescriptor', [b''])[0]
        if sd and not sids.peut_appliquer(sd, c.jeton):
            journal.debug('%s : filtrée (sécurité)', nom)
            continue
        if un(e, 'gpcwqlfilter') and filtres_wmi != 'ignorer':
            journal.info('%s : ignorée (filtre WMI, non évaluable sous Linux)', nom)
            continue
        g = Gpo(guid, nom, un(e, 'gpcfilesyspath'), int(un(e, 'versionnumber', '0') or 0), dn,
                applique=(lien, dn) in appliques)
        # une GPO liée à plusieurs niveaux s’applique à sa position la plus forte (la dernière)
        if guid in vus:
            res = [x for x in res if x.guid != guid]
        vus.add(guid)
        res.append(g)
    return res
