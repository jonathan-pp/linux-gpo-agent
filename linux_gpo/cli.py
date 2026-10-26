"""Commande linux-gpo.

    linux-gpo appliquer [--simuler] [--force]   applique les GPO de l’ordinateur (root ; minuteur systemd)
    linux-gpo utilisateur [--ouverture]         applique les GPO de l’utilisateur (dans sa session)
    linux-gpo resultat [--utilisateur]          GPO appliquées et réglages obtenus (comme gpresult)
    linux-gpo diagnostic                        vérifie la jonction, Kerberos, LDAP, SYSVOL et les outils
    linux-gpo retirer-tout                      retire tout ce que l’agent a posé (remet les fichiers d’origine)
    linux-gpo hors-ligne DOSSIER [--simuler]    applique des GPO copiées dans DOSSIER (tests)
    linux-gpo maj [--force]                     met l’agent à jour (Console du domaine, sinon GitHub)
"""
from __future__ import annotations

import argparse
import fcntl
import getpass
import json
import logging
import os
import shutil
import sys
import time

from . import VERSION, conf as configuration, gpo as gpos_mod, systeme
from .annuaire import Annuaire
from .ext import Contexte, extensions
from .fichiers import Fichiers
from .gpo import Gpo
from .noms import Noms
from .politique import Politique, copier_sysvol
from .systeme import ErreurAgent, famille, lancer, outil

journal = logging.getLogger('linux-gpo')
VERROU = '/run/linux-gpo.lock'


def executer(ctx: Contexte, exts) -> dict:
    for e in exts:
        try:
            e.appliquer(ctx)
        except Exception as ex:  # une extension en panne ne doit pas empêcher les autres
            journal.exception('%s : %s', e.nom, ex)
            ctx.noter(e.nom, f'ERREUR : {ex}')
            ctx.f.garder(e.nom)
    ctx.f.terminer()
    for e in exts if not systeme.RACINE else []:  # racine de test : pas d’action sur le vrai système
        try:
            e.apres(ctx, ctx.f.changes_de(e.nom))
        except Exception as ex:
            journal.exception('%s (après) : %s', e.nom, ex)
            ctx.noter(e.nom, f'ERREUR : {ex}')
    ctx.f.sauver()
    return ctx.f.changes


def _rapport(dossier: str, ctx: Contexte, gpos: list[Gpo], extra: dict) -> None:
    r = {'date': time.strftime('%Y-%m-%d %H:%M:%S'), 'version': VERSION,
         'gpo': [{'nom': g.nom, 'guid': g.guid, 'lien': g.lien, 'appliquee': g.applique} for g in gpos],
         'reglages': ctx.rapport, 'registre': ctx.pol.provenance(), **extra}
    if not ctx.f.simuler:
        os.makedirs(dossier, mode=0o700, exist_ok=True)
        with open(os.path.join(dossier, 'rapport.json'), 'w', encoding='utf-8') as fh:
            json.dump(r, fh, indent=1, ensure_ascii=False, default=str)


def _afficher(ctx: Contexte, gpos: list[Gpo]) -> None:
    print('GPO appliquées (dans l’ordre) :')
    for g in gpos:
        print(f"  {g.nom}{' [appliquée]' if g.applique else ''}")
    for ext, lignes in ctx.rapport.items():
        print(f'\n{ext} :')
        for l in lignes:
            print('  ' + l)


def machine(args) -> int:
    c = configuration.charger()
    if not c.domaine:
        raise ErreurAgent('domaine inconnu : le poste n’est pas joint (ou renseignez /etc/linux-gpo/agent.conf)')
    with Annuaire(c) as a:
        a.connexion_machine()
        compte = gpos_mod.compte(a, c.compte, True)
        liste = gpos_mod.liste(a, compte, c.options.get('filtres_wmi', 'exclure'))
        if args.force:
            shutil.rmtree(os.path.join(c.cache, 'machine'), ignore_errors=True)
        copier_sysvol(a, liste, True, os.path.join(c.cache, 'machine'))
        pol = Politique(liste, True)
        f = Fichiers(c.etat, args.simuler)
        ctx = Contexte(conf=c, pol=pol, f=f, noms=Noms(c, a), annuaire=a, simuler=args.simuler,
                       sid_domaine=compte.sid.rsplit('-', 1)[0], jeton=compte.jeton)
        changes = executer(ctx, extensions(True))
        _rapport(c.etat, ctx, liste, {'controleur': a.serveur, 'compte': c.compte})
    journal.info('%d GPO, %d fichier(s) modifié(s)', len(liste), len(changes))
    if args.simuler or args.verbeux:
        _afficher(ctx, liste)
    return 0


def _ccache_session() -> str | None:
    """Ticket Kerberos de la session. Le service utilisateur de systemd n’hérite pas de KRB5CCNAME, posé par PAM dans la
    session graphique : sssd range le ticket dans /tmp/krb5cc_<uid>_XXXXXX, que kinit ne trouve pas seul."""
    if os.environ.get('KRB5CCNAME'):
        return None
    uid = os.getuid()
    candidats = []
    for n in os.listdir('/tmp'):
        p = os.path.join('/tmp', n)
        if n == f'krb5cc_{uid}' or n.startswith(f'krb5cc_{uid}_'):
            try:
                st = os.stat(p)
            except OSError:
                continue
            if st.st_uid == uid:
                candidats.append((st.st_mtime, p))
    return 'FILE:' + max(candidats)[1] if candidats else None


def utilisateur(args) -> int:
    c = configuration.charger()
    nom = getpass.getuser()
    sam = nom.split('\\')[-1].split('@')[0]
    etat = os.path.expanduser('~/.local/state/linux-gpo')
    cache = os.path.expanduser('~/.cache/linux-gpo/gpo')
    if not c.domaine:
        return 0
    try:
        import pwd
        with open('/etc/passwd', encoding='utf-8', errors='replace') as fh:
            if any(l.split(':', 1)[0] == nom for l in fh):
                return 0  # compte local : pas de GPO
        pwd.getpwnam(nom)
    except (OSError, KeyError):
        pass
    a = Annuaire(c, _ccache_session())  # ticket de la session de l’utilisateur
    compte = gpos_mod.compte(a, sam, False)
    liste = gpos_mod.liste(a, compte, c.options.get('filtres_wmi', 'exclure'))
    copier_sysvol(a, liste, False, cache)
    pol = Politique(liste, False)
    f = Fichiers(etat, args.simuler)
    ctx = Contexte(conf=c, pol=pol, f=f, noms=Noms(c, a), annuaire=a, simuler=args.simuler, utilisateur=sam,
                   jeton=compte.jeton, ouverture=args.ouverture)
    executer(ctx, extensions(False))
    _rapport(etat, ctx, liste, {'utilisateur': sam})
    if args.simuler or args.verbeux:
        _afficher(ctx, liste)
    return 0


def hors_ligne(args) -> int:
    """GPO déjà copiées (un sous-dossier par GPO, appliquées dans l’ordre alphabétique) : pour les tests."""
    c = configuration.charger()
    c.domaine = c.domaine or 'exemple.local'
    dossiers = sorted(d for d in os.listdir(args.dossier) if os.path.isdir(os.path.join(args.dossier, d)))
    liste = [Gpo(d, d, '', 0, '', local=os.path.join(args.dossier, d)) for d in dossiers]
    machine_ = not args.utilisateur
    pol = Politique(liste, machine_)
    f = Fichiers(args.etat or c.etat, args.simuler)
    # avec une racine de test, les fichiers sont écrits mais aucune commande ne touche le vrai système
    ctx = Contexte(conf=c, pol=pol, f=f, noms=Noms(c), simuler=args.simuler or bool(systeme.RACINE), utilisateur=getpass.getuser())
    executer(ctx, extensions(machine_))
    _rapport(args.etat or c.etat, ctx, liste, {'hors_ligne': args.dossier})
    _afficher(ctx, liste)
    return 0


def resultat(args) -> int:
    dossier = os.path.expanduser('~/.local/state/linux-gpo') if args.utilisateur else configuration.charger().etat
    try:
        with open(os.path.join(dossier, 'rapport.json'), encoding='utf-8') as fh:
            r = json.load(fh)
    except OSError:
        print('Aucun passage enregistré : lancez « linux-gpo appliquer ».')
        return 1
    if args.json:
        print(json.dumps(r, indent=1, ensure_ascii=False))
        return 0
    print(f"Dernier passage : {r['date']} (linux-gpo {r['version']})"
          + (f" — contrôleur {r['controleur']}" if r.get('controleur') else ''))
    print('\nGPO appliquées (dans l’ordre, la dernière l’emporte) :')
    for g in r['gpo']:
        print(f"  {g['nom']}  {g['guid']}{'  [appliquée]' if g['appliquee'] else ''}")
    for ext, lignes in r['reglages'].items():
        print(f'\n{ext} :')
        for l in lignes:
            print('  ' + l)
    return 0


def diagnostic(args) -> int:
    ok = True

    def ligne(etat, texte):
        nonlocal ok
        ok = ok and etat is not False
        print(('  ok      ' if etat else '  ÉCHEC   ' if etat is False else '  info    ') + texte)

    c = configuration.charger()
    print(f'linux-gpo {VERSION} — {famille()} ({(lancer(["uname", "-r"]).stdout.strip())})')
    ligne(bool(c.domaine), f'domaine : {c.domaine or "inconnu"} (jonction : {configuration.jonction() or "non détectée"})')
    ligne(os.path.exists(c.keytab), f'keytab {c.keytab}, compte {c.compte}')
    for o in ('kinit', 'ldapsearch', 'smbclient'):
        ligne(bool(outil(o)), f'outil {o}')
    for o in ('visudo', 'dconf', 'firewall-cmd', 'ufw', 'nft', 'pkaction', 'flatpak', 'plasmashell', 'gnome-shell'):
        ligne(None, f"{o} : {'présent' if outil(o) else 'absent'}")
    if not ok:
        return 1
    try:
        with Annuaire(c) as a:
            a.connexion_machine()
            ligne(True, 'ticket Kerberos du compte machine')
            ligne(True, f'contrôleur : {a.controleur()}')
            compte = gpos_mod.compte(a, c.compte, True)
            ligne(True, f'compte dans l’annuaire : {compte.dn} ({len(compte.jeton)} SID)')
            liste = gpos_mod.liste(a, compte)
            ligne(True, f"{len(liste)} GPO applicable(s) : {', '.join(g.nom for g in liste) or '—'}")
            if liste:
                import tempfile
                with tempfile.TemporaryDirectory() as d:
                    a.copier_dossier(liste[0].chemin, d)
                    ligne(any(n.lower() == 'gpt.ini' for n in os.listdir(d)), f'lecture de SYSVOL ({liste[0].nom})')
    except ErreurAgent as e:
        ligne(False, str(e))
    return 0 if ok else 1


def retirer_tout(args) -> int:
    c = configuration.charger()
    f = Fichiers(c.etat)
    ctx = Contexte(conf=c, pol=Politique([], True), f=f, noms=Noms(c))
    for p in f.etat['fichiers']:
        print('retrait :', p.replace('#bloc', ' (bloc)'))
    f.tout_retirer()
    for e in extensions(True):
        try:
            e.apres(ctx, f.changes_de(e.nom))
        except Exception as ex:
            print(f'{e.nom} : {ex}')
    lancer(['nft', 'delete', 'table', 'inet', 'linux_gpo'])
    return 0


def redemarrer_si_besoin(args) -> int:
    from .ext.mises_a_jour import redemarrage_necessaire
    if redemarrage_necessaire():
        journal.warning('redémarrage demandé par les mises à jour')
        lancer(['systemctl', 'reboot'])
    return 0


def maj(args) -> int:
    from .maj import mettre_a_jour
    return mettre_a_jour(configuration.charger(), args.force)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog='linux-gpo', description='Stratégies de groupe Active Directory pour Linux')
    p.add_argument('-v', '--verbeux', action='store_true')
    p.add_argument('--version', action='version', version=f'linux-gpo {VERSION}')
    s = p.add_subparsers(dest='cmd')
    a = s.add_parser('appliquer', help='applique les GPO de l’ordinateur')
    a.add_argument('--simuler', action='store_true', help='affiche ce qui serait fait sans rien modifier')
    a.add_argument('--force', action='store_true', help='recopie toutes les GPO depuis SYSVOL')
    a.add_argument('-v', '--verbeux', action='store_true')
    u = s.add_parser('utilisateur', help='applique les GPO de l’utilisateur connecté')
    u.add_argument('--ouverture', action='store_true', help='passage d’ouverture de session (lance les scripts)')
    u.add_argument('--simuler', action='store_true')
    u.add_argument('-v', '--verbeux', action='store_true')
    r = s.add_parser('resultat', help='GPO appliquées et réglages obtenus')
    r.add_argument('--utilisateur', action='store_true')
    r.add_argument('--json', action='store_true')
    s.add_parser('diagnostic', help='vérifie la configuration du poste')
    s.add_parser('retirer-tout', help='retire tous les réglages posés par l’agent')
    s.add_parser('redemarrer-si-besoin')
    m = s.add_parser('maj', help='met l’agent à jour')
    m.add_argument('--force', action='store_true', help='réinstalle même si l’agent est déjà à jour')
    h = s.add_parser('hors-ligne', help='applique des GPO copiées dans un dossier (tests)')
    h.add_argument('dossier')
    h.add_argument('--simuler', action='store_true')
    h.add_argument('--utilisateur', action='store_true')
    h.add_argument('--etat', default='')
    args = p.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if getattr(args, 'verbeux', False) else logging.INFO,
                        format='%(levelname)s %(message)s' if sys.stderr.isatty() else '%(message)s')
    cmd = args.cmd or 'appliquer'
    if cmd == 'appliquer' and not hasattr(args, 'simuler'):
        args = p.parse_args(['appliquer'] + (argv or sys.argv[1:]))
    actions = {'appliquer': machine, 'utilisateur': utilisateur, 'resultat': resultat, 'diagnostic': diagnostic,
               'retirer-tout': retirer_tout, 'redemarrer-si-besoin': redemarrer_si_besoin, 'hors-ligne': hors_ligne, 'maj': maj}
    besoin_root = cmd in ('appliquer', 'retirer-tout', 'redemarrer-si-besoin', 'maj') and not getattr(args, 'simuler', False)
    if besoin_root and os.geteuid() != 0:
        print('linux-gpo : à lancer en root', file=sys.stderr)
        return 2
    verrou = None
    if besoin_root and cmd != 'maj':  # maj : install.sh relance lui-même un passage, qui prend le verrou
        verrou = open(VERROU, 'w')
        try:
            fcntl.flock(verrou, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            print('linux-gpo : un passage est déjà en cours', file=sys.stderr)
            return 3
    try:
        return actions[cmd](args)
    except ErreurAgent as e:
        journal.error('linux-gpo : %s', e)
        return 1
