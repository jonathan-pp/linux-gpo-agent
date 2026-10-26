"""Mise à jour de l’agent : `sudo linux-gpo maj`.

Source (dans l’ordre) : `source_maj` de /etc/linux-gpo/agent.conf (adresse d’une archive .tar.gz, ou « github ») ; sinon la
Console Annuaire du domaine (https://<contrôleur>:8443/linux/linux-gpo.tar.gz, le contrôleur étant `serveur` ou trouvé par DNS) ;
sinon GitHub. L’archive est vérifiée (agent linux-gpo complet), puis son install.sh est lancé : unités, gpupdate et configuration
sont remis à jour, la configuration et l’état du poste sont conservés. Rien n’est fait si l’archive est celle déjà installée.
"""
from __future__ import annotations

import hashlib
import io
import os
import ssl
import subprocess
import tarfile
import tempfile
import urllib.request

from . import dns
from .systeme import ErreurAgent

GITHUB = 'https://github.com/jonathan-pp/linux-gpo-agent/archive/refs/heads/main.tar.gz'
PORT_CONSOLE = 8443
TAILLE_MAX = 20 * 1024 * 1024


def sources(c) -> list[str]:
    choix = (c.options.get('source_maj') or '').strip()
    if choix.lower() == 'github':
        return [GITHUB]
    if choix:
        return [choix]
    dcs = [c.serveur] if c.serveur else (dns.controleurs(c.domaine) if c.domaine else [])
    return [f'https://{d.rstrip(".")}:{PORT_CONSOLE}/linux/linux-gpo.tar.gz' for d in dcs[:2]] + [GITHUB]


def telecharger(url: str) -> bytes:
    contexte = ssl.create_default_context()
    if 'github.com' not in url:
        # Console Annuaire : certificat auto-signé du contrôleur
        contexte.check_hostname, contexte.verify_mode = False, ssl.CERT_NONE
    req = urllib.request.Request(url, headers={'User-Agent': 'linux-gpo'})
    with urllib.request.urlopen(req, timeout=60, context=contexte) as r:  # noqa: S310 - https ou adresse choisie par l’admin
        data = r.read(TAILLE_MAX + 1)
    if len(data) > TAILLE_MAX:
        raise ErreurAgent(f'{url} : archive trop volumineuse')
    return data


def verifier(data: bytes) -> None:
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as t:
            noms = t.getnames()
    except (tarfile.TarError, OSError, EOFError) as e:
        raise ErreurAgent(f'archive illisible : {e}') from None
    if not any(n.endswith('linux_gpo/__init__.py') for n in noms) or not any(n.endswith('install.sh') for n in noms):
        raise ErreurAgent('l’archive n’est pas l’agent linux-gpo')


def mettre_a_jour(c, forcer: bool = False) -> int:
    erreurs = []
    for url in sources(c):
        try:
            data = telecharger(url)
            verifier(data)
            break
        except (OSError, ErreurAgent) as e:
            erreurs.append(f'{url} : {e}')
    else:
        raise ErreurAgent('aucune source joignable :\n  ' + '\n  '.join(erreurs))
    empreinte = hashlib.sha256(data).hexdigest()
    marque = os.path.join(c.etat, 'agent.sha256')
    try:
        with open(marque, encoding='utf-8') as fh:
            deja = fh.read().strip() == empreinte
    except OSError:
        deja = False
    if deja and not forcer:
        print(f'linux-gpo est déjà à jour ({url})')
        return 0
    print(f'Mise à jour depuis {url}')
    with tempfile.TemporaryDirectory(prefix='linux-gpo-maj-') as d:
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as t:
            t.extractall(d, filter='data') if hasattr(tarfile, 'data_filter') else t.extractall(d)  # noqa: S202
        install = next((os.path.join(r, 'install.sh') for r, ds, fs in os.walk(d)
                        if 'install.sh' in fs and 'linux_gpo' in ds), None)
        if not install:
            raise ErreurAgent('install.sh introuvable dans l’archive')
        code = subprocess.run(['sh', install], check=False).returncode
    if code:
        raise ErreurAgent(f'install.sh a échoué (code {code})')
    os.makedirs(c.etat, exist_ok=True)
    with open(marque, 'w', encoding='utf-8') as fh:
        fh.write(empreinte + '\n')
    print('linux-gpo mis à jour.')
    return 0
