"""Messages de connexion : /etc/issue (avant) et /etc/motd (après).

Sources, de la plus forte à la plus faible : LinuxGPO\\Messages, Samba « Unix Settings\\Messages » ou ses
fichiers VGP (samba-tool), puis le message légal de Windows (« Ouverture de session interactive : texte du
message ») repris dans /etc/issue.
"""
import xml.etree.ElementTree as ET

from . import INF_SYS, K_LGPO, K_SAMBA, K_WIN_SYS, Extension, texte as en_texte
from ..systeme import gere_par_nix

VGP = {'motd': 'MACHINE/VGP/VTLA/Unix/MOTD/manifest.xml', 'issue': 'MACHINE/VGP/VTLA/Unix/Issue/manifest.xml'}


class Messages(Extension):
    nom = 'messages'

    def appliquer(self, ctx):
        pol = ctx.pol
        for fichier in ('issue', 'motd'):
            texte = en_texte(pol.valeur(K_LGPO + r'\Messages', fichier)) or en_texte(pol.valeur(K_SAMBA + r'\Messages', fichier))
            if not (texte or '').strip():
                texte = ''
                for _, f in pol.fichiers(VGP[fichier]):
                    try:
                        t = ET.parse(f).getroot().findtext('policysetting/data/text')
                    except (OSError, ET.ParseError):
                        continue
                    texte = t or texte
            if not texte.strip() and fichier == 'issue':
                titre = pol.reg_inf(INF_SYS + r'\LegalNoticeCaption') or pol.valeur(K_WIN_SYS, 'LegalNoticeCaption')
                corps = pol.reg_inf(INF_SYS + r'\LegalNoticeText') or en_texte(pol.valeur(K_WIN_SYS, 'LegalNoticeText'))
                if str(corps or '').strip():
                    texte = (f'{titre}\n\n' if str(titre or '').strip() else '') + str(corps) + '\n\n'
            if texte.strip():
                p = '/etc/' + fichier
                if gere_par_nix(p):
                    ctx.noter(self.nom, f'{p} est géré par NixOS : utilisez le module linux-gpo (users.motd)')
                    continue
                ctx.f.ecrire(p, texte.replace('\r\n', '\n').rstrip('\n') + '\n', self.nom)
                ctx.noter(self.nom, f'/etc/{fichier} : {texte.strip().splitlines()[0][:60]}…')
