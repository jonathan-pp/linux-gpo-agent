"""Navigateurs : les stratégies Firefox, Chrome, Chromium, Edge et Brave des GPO (mêmes clés que sous Windows,
écrites par leurs modèles ADMX officiels) deviennent leurs fichiers de stratégie JSON sous Linux.
"""
import json
import os

from . import Extension
from .. import chrome_types
from ..preg import REG_DWORD, REG_MULTI_SZ, REG_SZ
from ..systeme import chemin, outil

K_FIREFOX = r'Software\Policies\Mozilla\Firefox'
FIREFOX = '/etc/firefox/policies/policies.json'
# (clé de registre, dossier de stratégies, toujours écrit ?)
CHROMIUMS = [
    (r'Software\Policies\Google\Chrome', '/etc/opt/chrome/policies', True),
    (r'Software\Policies\Google\Chrome', '/etc/chromium/policies', True),
    (r'Software\Policies\Google\Chrome', '/etc/chromium-browser/policies', False),
    (r'Software\Policies\Microsoft\Edge', '/etc/opt/edge/policies', False),
    (r'Software\Policies\BraveSoftware\Brave', '/etc/brave/policies', False),
]


def _donnee_firefox(typ, v):
    if typ == REG_MULTI_SZ:
        try:
            return json.loads(''.join(v))
        except ValueError:
            return v
    if typ == REG_DWORD and v in (0, 1):
        return v == 1
    if typ == REG_SZ and isinstance(v, str) and v[:1] in '{[':
        try:
            return json.loads(v)
        except ValueError:
            pass
    return v


def firefox_json(entrees: list[tuple]) -> dict:
    """Registre (clé, nom, type, donnée) → policies.json : sous-clés = objets, noms numériques = listes."""
    res = {}
    base = K_FIREFOX.lower()
    for cle, nom, typ, v in sorted(entrees, key=lambda e: (e[0], int(e[1]) if str(e[1]).isdigit() else 0)):
        parts = [p for p in cle[len(base):].split('\\') if p]  # la clé commence par K_FIREFOX (casse comprise ou non)
        cur = res
        # une sous-clé numérique (…\Bookmarks\1) désigne un élément de liste
        i = 0
        while i < len(parts):
            p = parts[i]
            suivant_num = i + 1 < len(parts) and parts[i + 1].isdigit()
            if isinstance(cur, list):
                idx = int(p)
                while len(cur) < idx:
                    cur.append({})
                cur = cur[idx - 1]
            else:
                cur = cur.setdefault(p, [] if suivant_num or (i == len(parts) - 1 and str(nom).isdigit()) else {})
            i += 1
        val = _donnee_firefox(typ, v)
        if isinstance(cur, list):
            cur.append(val)
        else:
            cur[nom] = val
    return res


def chrome_json(entrees: list[tuple], base: str) -> tuple[dict, dict]:
    obligatoires, recommandees = {}, {}
    rec = (base + r'\Recommended').lower()
    for cle, nom, typ, v in sorted(entrees, key=lambda e: (e[0], int(e[1]) if str(e[1]).isdigit() else 0)):
        cible = recommandees if cle.lower().startswith(rec) else obligatoires
        if str(nom).isdigit():
            politique = cle.split('\\')[-1]
            val = v
            cible.setdefault(politique, []).append(val)
            continue
        if nom in chrome_types.DICTIONNAIRES or (isinstance(v, str) and v[:1] in '{[' and nom not in chrome_types.BOOLEENS):
            try:
                v = json.loads(v)
            except (TypeError, ValueError):
                pass
        elif typ == REG_DWORD and nom in chrome_types.BOOLEENS:
            v = v == 1
        cible[nom] = v
    return obligatoires, recommandees


class Navigateurs(Extension):
    nom = 'navigateurs'

    def appliquer(self, ctx):
        pol = ctx.pol
        ff = pol.entrees(K_FIREFOX)
        if ff:
            ctx.f.ecrire(FIREFOX, json.dumps({'policies': firefox_json(ff)}, indent=2, ensure_ascii=False) + '\n', self.nom)
            ctx.noter(self.nom, f'Firefox : {len(ff)} réglage(s) → {FIREFOX}')
        for cle, dossier, toujours in CHROMIUMS:
            e = pol.entrees(cle)
            if not e:
                continue
            nom_exe = dossier.split('/')[-2]
            if not toujours and not os.path.isdir(chemin(os.path.dirname(dossier))) and not outil(nom_exe):
                continue
            obl, rec = chrome_json(e, cle)
            for genre, d in (('managed', obl), ('recommended', rec)):
                if d:
                    ctx.f.ecrire(f'{dossier}/{genre}/linux-gpo.json', json.dumps(d, indent=2, ensure_ascii=False) + '\n', self.nom)
            ctx.noter(self.nom, f'{cle.split(chr(92))[-1]} : {len(e)} réglage(s) → {dossier}')
