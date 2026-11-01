"""VPN du domaine (rôle VPN de la Console Annuaire) : client WireGuard prêt sur le poste, désactivé côté serveur tant
qu’un administrateur ne l’a pas activé dans l’onglet VPN de la console.

Pas de GPO : la console écrit l’invitation sur le compte de l’ordinateur (msDS-cloudExtensionAttribute19, JSON : clé
publique et adresse du serveur, routes, DNS, adresse du poste une fois attribuée). Le poste crée alors sa paire de clés :
la clé privée ne quitte jamais le poste (/var/lib/linux-gpo/vpn.key), la clé publique est écrite par l’ordinateur
lui-même dans msDS-cloudExtensionAttribute20 (« wg <clé> », droit donné à SELF par la console).

Connexion NetworkManager « VPN du domaine » (sinon /etc/wireguard/wg-domaine.conf, pour wg-quick). Invitation « auto » :
un script du répartiteur de NetworkManager ouvre le tunnel dès que le contrôleur ne répond plus directement (poste hors
du réseau du domaine, avant même l’ouverture de session) et le ferme au retour. Invitation retirée : connexion retirée.
"""
from __future__ import annotations

import base64
import ipaddress
import json
import os
import re
import secrets
import time
import uuid

from . import Extension
from ..annuaire import echapper_filtre, un
from ..systeme import ErreurAgent, chemin, lancer, outil

ATTR_CONFIG = 'msDS-cloudExtensionAttribute19'
ATTR_CLE = 'msDS-cloudExtensionAttribute20'
INTERFACE = 'wg-domaine'
NOM = 'VPN du domaine'
NM = '/etc/NetworkManager/system-connections/linux-gpo-vpn.nmconnection'
REPARTITEUR = '/etc/NetworkManager/dispatcher.d/90-linux-gpo-vpn'
WG_QUICK = f'/etc/wireguard/{INTERFACE}.conf'
CLE = re.compile(r'^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$')
POINT = re.compile(r'^(\[[0-9A-Fa-f:]+\]|[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?):\d{1,5}$')
DOMAINE = re.compile(r'^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$')
ATTENTE = 75   # secondes : la console attribue l’adresse du poste au passage suivant de son minuteur (chaque minute)

# ---------------------------------------------------------------- clés (X25519, RFC 7748)
P = 2 ** 255 - 19


def _x25519(k: bytes, u: int = 9) -> bytes:
    k = bytearray(k)
    k[0] &= 248
    k[31] = (k[31] & 127) | 64
    n = int.from_bytes(k, 'little')
    x1, x2, z2, x3, z3, echange = u, 1, 0, u, 1, 0
    for t in reversed(range(255)):
        b = (n >> t) & 1
        if echange ^ b:
            x2, x3, z2, z3 = x3, x2, z3, z2
        echange = b
        a, bb = x2 + z2, x2 - z2
        aa, bbb = a * a % P, bb * bb % P
        e = aa - bbb
        c, d = x3 + z3, x3 - z3
        da, cb = d * a % P, c * bb % P
        x3, z3 = (da + cb) ** 2 % P, x1 * (da - cb) ** 2 % P
        x2, z2 = aa * bbb % P, e * (aa + 121665 * e) % P
    if echange:
        x2, z2 = x3, z3
    return (x2 * pow(z2, P - 2, P) % P).to_bytes(32, 'little')


def cle_publique(privee: str) -> str:
    return base64.b64encode(_x25519(base64.b64decode(privee))).decode('ascii')


def nouvelle_cle() -> str:
    k = bytearray(secrets.token_bytes(32))
    k[0] &= 248
    k[31] = (k[31] & 127) | 64
    return base64.b64encode(bytes(k)).decode('ascii')


# ---------------------------------------------------------------- invitation
def lire_invitation(texte: str) -> dict:
    """Invitation de la console, vérifiée champ par champ (elle finit dans des fichiers de configuration et un script)."""
    try:
        d = json.loads(texte)
        assert isinstance(d, dict) and d.get('v') == 1
        ip = str(ipaddress.IPv4Address(d['ip'])) if d.get('ip') else ''
        routes = [str(ipaddress.IPv4Network(r, strict=False)) for r in d['routes']]
        res = {'ip': ip, 'cle': str(d['cle']), 'point': str(d['point']), 'routes': routes,
               'dns': str(ipaddress.IPv4Address(d['dns'])), 'controleur': str(ipaddress.IPv4Address(d['controleur'])),
               'domaine': str(d['domaine']), 'keepalive': int(d.get('keepalive') or 0), 'auto': bool(d.get('auto'))}
    except (ValueError, TypeError, KeyError, AssertionError) as e:
        raise ErreurAgent(f'invitation du VPN illisible ({e})')
    if not (CLE.match(res['cle']) and POINT.match(res['point']) and DOMAINE.match(res['domaine'])
            and 0 <= res['keepalive'] <= 300 and routes):
        raise ErreurAgent('invitation du VPN invalide')
    return res


def connexion_nm(inv: dict, privee: str, id_conn: str) -> str:
    complet = '0.0.0.0/0' in inv['routes']
    return '\n'.join([
        '# Écrit par linux-gpo (extension vpn) d’après la Console Annuaire.',
        '[connection]', f'id={NOM}', f'uuid={id_conn}', 'type=wireguard', f'interface-name={INTERFACE}',
        # ouvert par le script du répartiteur (hors du réseau du domaine) ou par l’utilisateur
        'autoconnect=false', '',
        '[wireguard]', f'private-key={privee}', '',
        f"[wireguard-peer.{inv['cle']}]", f"endpoint={inv['point']}", f"allowed-ips={';'.join(inv['routes'])};",
        *([f"persistent-keepalive={inv['keepalive']}"] if inv['keepalive'] else []), '',
        '[ipv4]', 'method=manual', f"address1={inv['ip']}/32", f"dns={inv['dns']};", f"dns-search={inv['domaine']};",
        # tunnel ouvert : DNS du domaine seulement (noms du domaine, Kerberos, enregistrements SRV des contrôleurs)
        'dns-priority=-10', *([] if complet else ['never-default=true']), '',
        '[ipv6]', 'method=disabled', ''])


def conf_wg_quick(inv: dict, privee: str) -> str:
    return '\n'.join([
        '# Écrit par linux-gpo (extension vpn) d’après la Console Annuaire. Ouverture : wg-quick up wg-domaine',
        '[Interface]', f'PrivateKey = {privee}', f"Address = {inv['ip']}/32", f"DNS = {inv['dns']}, {inv['domaine']}", '',
        '[Peer]', f"PublicKey = {inv['cle']}", f"Endpoint = {inv['point']}", f"AllowedIPs = {', '.join(inv['routes'])}",
        *([f"PersistentKeepalive = {inv['keepalive']}"] if inv['keepalive'] else []), ''])


def script_repartiteur(id_conn: str, controleur: str) -> str:
    return f"""#!/bin/sh
# Écrit par linux-gpo (extension vpn) : « {NOM} » ouvert quand le contrôleur ne répond pas directement (poste hors du
# réseau du domaine), fermé dès qu’il répond sur une carte du poste (retour au bureau).
CONN='{id_conn}'
DC='{controleur}'
[ "$1" = '{INTERFACE}' ] && exit 0
case "$2" in up|down|connectivity-change|dhcp4-change|verifier) ;; *) exit 0 ;; esac
(
  exec 9>/run/linux-gpo-vpn.lock
  flock -w 60 9 || exit 0
  sleep 3
  local=0
  for dev in $(ip -o -4 addr show up scope global | awk '{{print $2}}' | sort -u); do
    [ "$dev" = '{INTERFACE}' ] && continue
    # contrôleur sur le réseau de cette carte (sans passerelle) et qui répond : réseau du domaine
    if ! ip -4 route get "$DC" oif "$dev" 2>/dev/null | grep -q ' via ' && ping -c 1 -W 2 -I "$dev" "$DC" >/dev/null 2>&1; then
      local=1
      break
    fi
  done
  actif=$(nmcli -g GENERAL.STATE connection show "$CONN" 2>/dev/null)
  if [ "$local" = 1 ]; then
    [ -n "$actif" ] && nmcli connection down "$CONN"
  elif [ -z "$actif" ] && ip -4 route show default | grep -q .; then
    nmcli connection up "$CONN"
  fi
) </dev/null >/dev/null 2>&1 &
exit 0
"""


class Vpn(Extension):
    nom = 'vpn'

    def appliquer(self, ctx):
        self.nm = self.auto = False
        if not ctx.annuaire:
            ctx.f.garder(self.nom)   # hors du réseau : le tunnel doit justement rester là
            return
        try:
            e = self._compte(ctx)
        except ErreurAgent as x:
            ctx.f.garder(self.nom)
            ctx.noter(self.nom, f'lecture du compte de l’ordinateur impossible : {x}')
            return
        if not e or not un(e, ATTR_CONFIG):
            return   # pas d’invitation (rôle VPN absent, ou postes non préparés) : connexion retirée s’il y en avait une
        try:
            inv = lire_invitation(un(e, ATTR_CONFIG))
        except ErreurAgent as x:
            ctx.f.garder(self.nom)
            ctx.noter(self.nom, str(x))
            return
        privee = self._cle_privee(ctx)
        publique = cle_publique(privee)
        if un(e, ATTR_CLE) != f'wg {publique}':
            if ctx.simuler:
                ctx.noter(self.nom, 'clé publique à publier dans le compte de l’ordinateur')
                return
            try:
                ctx.annuaire.modifier(e['dn'], [(ATTR_CLE, f'wg {publique}')])
            except ErreurAgent as x:
                ctx.f.garder(self.nom)
                ctx.noter(self.nom, f'publication de la clé impossible (droit donné par la console ?) : {x}')
                return
            ctx.noter(self.nom, 'clé publique publiée : le poste apparaît dans l’onglet VPN de la console, désactivé')
            inv = self._attendre_adresse(ctx, inv)
        if not inv['ip']:
            ctx.f.garder(self.nom)
            ctx.noter(self.nom, 'adresse du poste pas encore attribuée par la console : au prochain passage')
            return
        id_conn = str(uuid.uuid5(uuid.NAMESPACE_DNS, f'linux-gpo-vpn.{ctx.conf.domaine}'))
        if outil('nmcli') or os.path.isdir(chemin('/etc/NetworkManager')):
            self.nm = True
            ctx.f.ecrire(NM, connexion_nm(inv, privee, id_conn), self.nom, mode=0o600)
            if inv['auto']:
                self.auto = True
                ctx.f.ecrire(REPARTITEUR, script_repartiteur(id_conn, inv['controleur']), self.nom, mode=0o755)
            ctx.noter(self.nom, f"connexion « {NOM} » ({inv['ip']}, serveur {inv['point']})"
                                + (', ouverte seule hors du réseau du domaine' if inv['auto'] else ''))
        else:
            ctx.f.ecrire(WG_QUICK, conf_wg_quick(inv, privee), self.nom, mode=0o600)
            ctx.noter(self.nom, f"configuration {WG_QUICK} ({inv['ip']}) : NetworkManager absent, ouverture par wg-quick up")

    def _compte(self, ctx) -> dict | None:
        r = ctx.annuaire.chercher(ctx.conf.base, f'(&(objectClass=computer)(sAMAccountName={echapper_filtre(ctx.conf.compte)}))',
                                  [ATTR_CONFIG, ATTR_CLE], portee='sub')
        return r[0] if r else None

    def _cle_privee(self, ctx) -> str:
        p = chemin(os.path.join(ctx.conf.etat, 'vpn.key'))
        try:
            with open(p, encoding='ascii') as f:
                k = f.read().strip()
            if CLE.match(k):
                return k
        except OSError:
            pass
        k = nouvelle_cle()
        if not ctx.simuler:
            os.makedirs(os.path.dirname(p), mode=0o700, exist_ok=True)
            fd = os.open(p + '.tmp', os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, 'w', encoding='ascii') as f:
                f.write(k + '\n')
            os.replace(p + '.tmp', p)
        return k

    def _attendre_adresse(self, ctx, inv: dict) -> dict:
        """Première publication : la console attribue l’adresse du poste dans la minute."""
        fin = time.monotonic() + ATTENTE
        while not inv['ip'] and time.monotonic() < fin:
            time.sleep(15)
            try:
                e = self._compte(ctx)
                if e and un(e, ATTR_CONFIG):
                    inv = lire_invitation(un(e, ATTR_CONFIG))
            except ErreurAgent:
                break
        return inv

    def apres(self, ctx, changes):
        if ctx.simuler:
            return
        if changes and outil('nmcli'):
            lancer(['nmcli', 'connection', 'reload'])
        if self.auto:
            # le répartiteur n’agit qu’au prochain changement de réseau : décision prise tout de suite
            lancer([chemin(REPARTITEUR), '', 'verifier'])
