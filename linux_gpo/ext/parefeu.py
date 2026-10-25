"""Pare-feu : règles des GPO appliquées avec l’outil présent sur le poste.

Sources :
  - Samba « Unix Settings\\Firewalld » : Zones (zones à créer) et Rules (JSON {zone: [règle firewalld]}) ;
  - LinuxGPO\\Firewall\\Rules : une règle par valeur, « action;port/proto ou service;source » (ex. « accept;22/tcp;10.0.0.0/8 »).

Outil : firewalld s’il tourne, sinon ufw s’il est actif, sinon une table nftables propre à l’agent
(« inet linux_gpo »). Avec nftables, une règle « accept » n’ouvre pas un port fermé par un autre pare-feu :
seules les règles de refus sont garanties.
"""
import json
import socket

from . import K_LGPO, K_SAMBA, Extension
from ..systeme import est_nixos, lancer, outil, service_actif

TABLE = 'linux_gpo'


def _regles(pol) -> tuple[list[str], list[dict]]:
    """(zones à créer, règles normalisées {zone, action, service, port, proto, source})."""
    zones = [str(v) for v in pol.valeurs(K_SAMBA + r'\Firewalld\Zones').values() if str(v).strip()]
    regles = []
    brut = pol.valeur(K_SAMBA + r'\Firewalld\Rules', 'Rules')
    try:
        par_zone = json.loads(brut) if brut else {}
    except (TypeError, ValueError):
        par_zone = {}
    for zone, liste in (par_zone.items() if isinstance(par_zone, dict) else []):
        for r in liste if isinstance(liste, list) else []:
            if not isinstance(r, dict):
                continue
            port = r.get('port') if isinstance(r.get('port'), dict) else {}
            regles.append({'zone': zone, 'action': next((a for a in ('accept', 'reject', 'drop') if a in r), 'accept'),
                           'service': (r.get('service') or {}).get('name', '') if isinstance(r.get('service'), dict) else '',
                           'port': str(port.get('port', '')), 'proto': port.get('protocol', 'tcp'),
                           'source': (r.get('source') or {}).get('address', '') if isinstance(r.get('source'), dict) else ''})
    for v in pol.liste(K_LGPO + r'\Firewall\Rules'):
        p = [x.strip() for x in str(v).split(';')]
        if len(p) < 2 or p[0].lower() not in ('accept', 'reject', 'drop'):
            continue
        cible = p[1]
        r = {'zone': '', 'action': p[0].lower(), 'service': '', 'port': '', 'proto': 'tcp', 'source': p[2] if len(p) > 2 else ''}
        if '/' in cible or cible.replace('-', '').isdigit():
            r['port'], _, proto = cible.partition('/')
            r['proto'] = proto or 'tcp'
        else:
            r['service'] = cible
        regles.append(r)
    return zones, regles


def _port_service(nom: str) -> list[tuple[str, str]]:
    """Ports d’un service nommé (ufw et nftables ne connaissent pas les services firewalld)."""
    connus = {'ssh': [('22', 'tcp')], 'http': [('80', 'tcp')], 'https': [('443', 'tcp')], 'rdp': [('3389', 'tcp')],
              'samba': [('139', 'tcp'), ('445', 'tcp')], 'dns': [('53', 'tcp'), ('53', 'udp')], 'ntp': [('123', 'udp')],
              'vnc-server': [('5900-5903', 'tcp')], 'cockpit': [('9090', 'tcp')], 'mdns': [('5353', 'udp')]}
    if nom in connus:
        return connus[nom]
    res = []
    for proto in ('tcp', 'udp'):
        try:
            res.append((str(socket.getservbyname(nom, proto)), proto))
        except OSError:
            continue
    return res


def _riche(r: dict) -> str:
    fam = 'ipv6' if ':' in r['source'] else 'ipv4'
    t = f'rule family="{fam}"' if r['source'] else 'rule'
    if r['source']:
        t += f' source address="{r["source"]}"'
    t += f' service name="{r["service"]}"' if r['service'] else f' port port="{r["port"]}" protocol="{r["proto"]}"'
    return t + ' ' + r['action']


class Parefeu(Extension):
    nom = 'parefeu'

    def appliquer(self, ctx):
        zones, regles = _regles(ctx.pol)
        mem = ctx.f.memoire(self.nom)
        if service_actif('firewalld') and outil('firewall-cmd'):
            self._firewalld(ctx, zones, regles, mem)
        elif outil('ufw') and 'Status: active' in lancer(['ufw', 'status']).stdout:
            self._ufw(ctx, regles, mem)
        elif outil('nft'):
            self._nft(ctx, regles, mem)
        elif regles:
            ctx.noter(self.nom, 'aucun pare-feu (firewalld, ufw, nftables) sur ce poste : règles ignorées')

    # ------------------------------------------------------------ firewalld
    def _firewalld(self, ctx, zones, regles, mem):
        defaut = lancer(['firewall-cmd', '--get-default-zone']).stdout.strip() or 'public'
        voulues = sorted({f"{r['zone'] or defaut}\t{_riche(r)}" for r in regles})
        avant = mem.get('firewalld', [])
        if voulues == avant:
            return
        if ctx.simuler:
            ctx.noter(self.nom, f'firewalld : {len(voulues)} règle(s)')
            return
        existantes = set(lancer(['firewall-cmd', '--permanent', '--get-zones']).stdout.split())
        for z in zones + [v.split('\t')[0] for v in voulues]:
            if z not in existantes:
                lancer(['firewall-cmd', '--permanent', '--new-zone=' + z])
                existantes.add(z)
        for v in set(avant) - set(voulues):
            z, regle = v.split('\t', 1)
            lancer(['firewall-cmd', '--permanent', '--zone=' + z, '--remove-rich-rule=' + regle])
        for v in set(voulues) - set(avant):
            z, regle = v.split('\t', 1)
            r = lancer(['firewall-cmd', '--permanent', '--zone=' + z, '--add-rich-rule=' + regle])
            if r.returncode:
                ctx.noter(self.nom, f'firewalld refuse « {regle} » : {r.stderr.strip()}')
        lancer(['firewall-cmd', '--reload'])
        mem['firewalld'] = voulues
        for v in voulues:
            ctx.noter(self.nom, 'firewalld ' + v.replace('\t', ' : '))

    # ------------------------------------------------------------ ufw
    def _ufw(self, ctx, regles, mem):
        voulues = []
        for r in regles:
            verbe = {'accept': 'allow', 'reject': 'reject', 'drop': 'deny'}[r['action']]
            ports = _port_service(r['service']) if r['service'] else [(r['port'], r['proto'])]
            for port, proto in ports:
                voulues.append([verbe, 'from', r['source'] or 'any', 'to', 'any', 'port', port.replace('-', ':'), 'proto', proto])
        avant = mem.get('ufw', [])
        if voulues == avant:
            return
        if not ctx.simuler:
            for c in avant:
                if c not in voulues:
                    lancer(['ufw', 'delete'] + c)
            for c in voulues:
                if c not in avant:
                    r = lancer(['ufw'] + c + ['comment', 'linux-gpo'])
                    if r.returncode:
                        ctx.noter(self.nom, f"ufw refuse « {' '.join(c)} » : {r.stderr.strip()}")
            mem['ufw'] = voulues
        for c in voulues:
            ctx.noter(self.nom, 'ufw ' + ' '.join(c))

    # ------------------------------------------------------------ nftables
    def _nft(self, ctx, regles, mem):
        lignes = []
        for r in regles:
            ports = _port_service(r['service']) if r['service'] else [(r['port'], r['proto'])]
            for port, proto in ports:
                src = ''
                if r['source']:
                    src = ('ip6' if ':' in r['source'] else 'ip') + f" saddr {r['source']} "
                action = {'accept': 'accept', 'reject': 'reject', 'drop': 'drop'}[r['action']]
                lignes.append(f'    {src}{proto} dport {port} {action}')
        if not lignes and not mem.get('nft'):
            return  # ni règle ni table posée auparavant
        script = f'table inet {TABLE}\ndelete table inet {TABLE}\n'
        if lignes:
            script += (f'table inet {TABLE} {{\n  chain entree {{\n    type filter hook input priority -5; policy accept;\n'
                       + '\n'.join(lignes) + '\n  }\n}\n')
        if est_nixos() and lignes:
            ctx.noter(self.nom, 'NixOS : le pare-feu de la configuration Nix reste prioritaire pour ouvrir des ports')
        if script == mem.get('nft') and lancer(['nft', 'list', 'table', 'inet', TABLE]).returncode == (0 if lignes else 1):
            return
        if not ctx.simuler:
            r = lancer(['nft', '-f', '-'], entree=script)
            if r.returncode:
                ctx.noter(self.nom, f'nftables refuse les règles : {r.stderr.strip()[-200:]}')
                return
            mem['nft'] = script if lignes else ''
        for l in lignes:
            ctx.noter(self.nom, 'nftables' + l)
