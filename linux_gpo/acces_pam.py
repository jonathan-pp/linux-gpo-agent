"""Vérification d’ouverture de session appelée par PAM (pam_exec, phase « account »).

    account required pam_exec.so quiet /usr/lib/linux-gpo/acces

Lit /etc/linux-gpo/acces.json (écrit par l’agent). Code 0 : autorisé ; 1 : refusé.
root et les comptes locaux (/etc/passwd) ne sont jamais concernés. En cas d’erreur, la session est
autorisée : un incident ne doit pas bloquer tous les comptes du poste.
"""
import grp
import json
import os
import pwd
import sys
import syslog

FICHIER = '/etc/linux-gpo/acces.json'
DISTANTS = ('sshd', 'xrdp-sesman', 'xrdp', 'cockpit')


def _local(nom: str) -> bool:
    try:
        with open('/etc/passwd', encoding='utf-8', errors='replace') as fh:
            return any(l.split(':', 1)[0] == nom for l in fh)
    except OSError:
        return False


def _correspond(e: dict, nom: str, groupes: set, admins: set) -> bool:
    if e.get('special') == '@tous':
        return True
    if e.get('special') == '@admins':
        return bool(groupes & admins)
    n = (e.get('nom') or '').lower()
    return n in groupes if e.get('groupe') else n == nom.lower()


def decision(utilisateur: str, service: str, regles: dict) -> tuple[bool, str]:
    if utilisateur == 'root' or _local(utilisateur):
        return True, 'compte local'
    liste = regles.get('distant' if service in DISTANTS else 'interactif') or {}
    autoriser, refuser = liste.get('autoriser') or [], liste.get('refuser') or []
    if not autoriser and not refuser:
        return True, 'aucune règle'
    pw = pwd.getpwnam(utilisateur)
    groupes = set()
    for gid in os.getgrouplist(pw.pw_name, pw.pw_gid):
        try:
            groupes.add(grp.getgrgid(gid).gr_name.lower())
        except KeyError:
            continue
    admins = {a.lower() for a in regles.get('admins', [])}
    for e in refuser:
        if _correspond(e, pw.pw_name, groupes, admins):
            return False, 'refusé par la stratégie de groupe'
    if autoriser and not any(_correspond(e, pw.pw_name, groupes, admins) for e in autoriser):
        return False, 'absent de la liste des comptes autorisés'
    return True, 'autorisé'


def main() -> int:
    syslog.openlog('linux-gpo', 0, syslog.LOG_AUTHPRIV)
    utilisateur, service = os.environ.get('PAM_USER', ''), os.environ.get('PAM_SERVICE', '')
    try:
        with open(FICHIER, encoding='utf-8') as fh:
            regles = json.load(fh)
        ok, raison = decision(utilisateur, service, regles)
    except FileNotFoundError:
        return 0
    except Exception as e:  # jamais de blocage sur une erreur
        syslog.syslog(syslog.LOG_WARNING, f'linux-gpo acces : {e}')
        return 0
    if not ok:
        syslog.syslog(syslog.LOG_NOTICE, f'linux-gpo : ouverture de session de {utilisateur} ({service}) refusée : {raison}')
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
