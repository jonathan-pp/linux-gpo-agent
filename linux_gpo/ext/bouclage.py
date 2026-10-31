"""Boucle de rappel de la stratégie utilisateur (loopback) : les réglages « utilisateur » des GPO liées à l’ordinateur
s’appliquent aux sessions ouvertes sur ce poste (salles, postes partagés, profils de bureau liés à l’OU des postes).

Réglage (ordinateur) repris de Windows, « Configurer le mode de traitement par boucle de rappel » :
  Software\\Policies\\Microsoft\\Windows\\System  UserPolicyMode  1 fusionner ; 2 remplacer
Le mode est laissé dans /etc/linux-gpo/bouclage (lisible par tous) pour le passage de la session (linux-gpo utilisateur).
"""
from . import Extension, entier

K = r'Software\Policies\Microsoft\Windows\System'
FICHIER = '/etc/linux-gpo/bouclage'
MODES = {1: 'fusionner', 2: 'remplacer'}


class Bouclage(Extension):
    nom = 'bouclage'

    def appliquer(self, ctx):
        mode = entier(ctx.pol.valeur(K, 'UserPolicyMode'))
        if mode not in MODES:
            return
        ctx.f.ecrire(FICHIER, f'{mode}\n', self.nom)
        ctx.noter(self.nom, f'boucle de rappel : {MODES[mode]} (GPO liées à l’ordinateur appliquées aux sessions)')


def lire() -> int:
    from ..systeme import chemin
    try:
        with open(chemin(FICHIER), encoding='utf-8') as fh:
            mode = entier(fh.read())
    except OSError:
        return 0
    return mode if mode in MODES else 0
