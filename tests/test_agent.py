"""Tests de l’agent sans domaine : python3 -m unittest discover -s tests"""
import json
import os
import shutil
import struct
import sys
import tempfile
import unittest
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.dirname(__file__))

from linux_gpo import cli, preg, sid, systeme  # noqa: E402
from linux_gpo.conf import Conf  # noqa: E402
from linux_gpo.gpo import Compte, liste  # noqa: E402
from outils_gpo import REG_DWORD, REG_MULTI_SZ, REG_SZ, ecrire, inf, pol, vgp  # noqa: E402

K = r'Software\Policies\LinuxGPO'
KS = r'Software\Policies\Samba\Unix Settings'
DOM_SID = 'S-1-5-21-1-2-3'


def ace(typ, masque, s, objet=None):
    corps = struct.pack('<I', masque)
    if typ in (5, 6):
        corps += struct.pack('<I', 1 if objet else 0) + (objet.bytes_le if objet else b'')
    corps += sid.sid_binaire(s)
    return struct.pack('<BBH', typ, 0, 4 + len(corps)) + corps


def descripteur(aces):
    acl_corps = b''.join(aces)
    acl = struct.pack('<BBHHH', 4, 0, 8 + len(acl_corps), len(aces), 0) + acl_corps
    return struct.pack('<BBHIIII', 1, 0, 0x8004, 0, 0, 0, 20) + acl


def sd_standard(filtre=sid.UTILISATEURS_AUTHENTIFIES, refus=None):
    a = [ace(0, 0x20094, sid.UTILISATEURS_AUTHENTIFIES)]
    if refus:
        a.insert(0, ace(6, 0x100, refus, sid.APPLIQUER_GPO))
    a.append(ace(5, 0x100, filtre, sid.APPLIQUER_GPO))
    return descripteur(a)


class Formats(unittest.TestCase):
    def test_registry_pol(self):
        b = pol([(K + r'\Desktop', 'DisableCommandLine', REG_DWORD, 1), (KS + r'\Messages', 'motd', REG_SZ, 'Bonjour\nà tous')])
        e = preg.lire_pol(b)
        self.assertEqual(e[0], (K + r'\Desktop', 'DisableCommandLine', REG_DWORD, 1))
        self.assertEqual(e[1][3], 'Bonjour\nà tous')

    def test_inf(self):
        d = preg.lire_inf(inf({'Privilege Rights': {'SeInteractiveLogonRight': '*S-1-5-32-544'}}))
        self.assertEqual(d['privilege rights']['seinteractivelogonright'], '*S-1-5-32-544')

    def test_sid(self):
        s = 'S-1-5-21-111-222-333-512'
        self.assertEqual(sid.sid_texte(sid.sid_binaire(s)), s)

    def test_filtrage(self):
        jeton = {'S-1-5-21-1-2-3-1105', sid.UTILISATEURS_AUTHENTIFIES, sid.TOUT_LE_MONDE}
        self.assertTrue(sid.peut_appliquer(sd_standard(), jeton))
        # filtrée sur un groupe dont le compte n’est pas membre
        self.assertFalse(sid.peut_appliquer(sd_standard(filtre='S-1-5-21-1-2-3-9999'), jeton))
        # refus explicite
        self.assertFalse(sid.peut_appliquer(sd_standard(refus='S-1-5-21-1-2-3-1105'), jeton))


class FauxAnnuaire:
    def __init__(self, objets):
        self.objets = objets
        self.conf = Conf(domaine='exemple.local')
        self.serveur = 'dc'

    def controleur(self):
        return 'dc'

    def chercher(self, base, filtre='(objectClass=*)', attrs=None, portee='base', controles=None):
        if portee == 'base':
            return [dict(self.objets[base], dn=base)] if base in self.objets else []
        if base.startswith('CN=Policies'):
            return [dict(v, dn=k) for k, v in self.objets.items() if k.startswith('CN={') and v['cn'][0].decode() in filtre]
        return []


def g(guid, nom, filtre=sid.UTILISATEURS_AUTHENTIFIES, drapeaux=0):
    return {'cn': [guid.encode()], 'displayname': [nom.encode()], 'gpcfilesyspath': [f'\\\\exemple.local\\SysVol\\{guid}'.encode()],
            'versionnumber': [b'65537'], 'flags': [str(drapeaux).encode()], 'ntsecuritydescriptor': [sd_standard(filtre)]}


def lien(guid, opt=0):
    return f'[LDAP://cn={guid},cn=policies,cn=system,DC=exemple,DC=local;{opt}]'


class Ordre(unittest.TestCase):
    def test_ordre_windows(self):
        base = 'DC=exemple,DC=local'
        A, B, C, D, E, F = ['{%s}' % str(uuid.UUID(int=i)).upper() for i in range(1, 7)]
        objets = {
            base: {'gplink': [(lien(A) + lien(F, 2)).encode()]},
            'OU=Site,' + base: {'gplink': [(lien(B) + lien(C)).encode()], 'gpoptions': [b'0']},
            'OU=Postes,OU=Site,' + base: {'gplink': [(lien(D) + lien(E, 1)).encode()], 'gpoptions': [b'1']},
        }
        for guid, nom in ((A, 'A'), (B, 'B'), (C, 'C'), (D, 'D'), (E, 'E'), (F, 'F')):
            objets[f'CN={guid},CN=Policies,CN=System,{base}'] = g(guid, nom)
        compte = Compte('CN=PC1,OU=Postes,OU=Site,' + base, 'S-1-5-21-1-2-3-1105', True, {sid.UTILISATEURS_AUTHENTIFIES})
        a = FauxAnnuaire(objets)
        import linux_gpo.gpo as m
        m.site = lambda a: None
        noms = [x.nom for x in liste(a, compte)]
        # Postes bloque l’héritage : seule F (appliquée) vient du domaine ; E est désactivée ; F passe en dernier
        self.assertEqual(noms, ['D', 'F'])
        objets['OU=Postes,OU=Site,' + base]['gpoptions'] = [b'0']
        self.assertEqual([x.nom for x in liste(a, compte)], ['A', 'B', 'C', 'D', 'F'])
        # partie ordinateur désactivée
        objets[f'CN={B},CN=Policies,CN=System,{base}']['flags'] = [b'2']
        self.assertEqual([x.nom for x in liste(a, compte)], ['A', 'C', 'D', 'F'])


class Application(unittest.TestCase):
    """Application complète dans une racine de test (aucune commande système n’est lancée)."""

    def setUp(self):
        self.racine = tempfile.mkdtemp()
        self.gpo = tempfile.mkdtemp()
        self.etat = tempfile.mkdtemp()
        systeme.RACINE = self.racine
        for p, t in (('/etc/os-release', 'ID=debian\n'), ('/etc/motd', 'motd d’origine\n'), ('/etc/sudoers', '@includedir /etc/sudoers.d\n'),
                     ('/etc/ssh/sshd_config', 'PermitRootLogin yes\n'), ('/etc/dconf/profile/gdm', 'user-db:user\nsystem-db:gdm\n'),
                     ('/etc/xdg/kdeglobals', '[General]\nfoo=1\n')):
            ecrire(self.racine, p.lstrip('/'), t)
        os.makedirs(os.path.join(self.racine, 'usr/share/plasma'))
        os.makedirs(os.path.join(self.racine, 'etc/polkit-1/rules.d'))

    def tearDown(self):
        systeme.RACINE = ''
        for d in (self.racine, self.gpo, self.etat):
            shutil.rmtree(d)

    def lire(self, p):
        with open(self.racine + p, encoding='utf-8') as fh:
            return fh.read()

    def passer(self):
        return cli.main(['hors-ligne', self.gpo, '--etat', self.etat])

    def test_cycle(self):
        g1 = os.path.join(self.gpo, '1-domaine')
        ecrire(g1, 'Machine/Registry.pol', pol([
            (KS + r'\Messages', 'motd', REG_SZ, 'Poste du domaine'),
            (KS + r'\Sudo Rights', '1', REG_SZ, 'root ALL=(ALL) NOPASSWD: /usr/bin/true'),
            (KS + r'\Daily Scripts', 'nettoyage', REG_SZ, 'rm -rf /tmp/zz-*'),
            (K + r'\Desktop', 'DisableCommandLine', REG_DWORD, 1),
            (K + r'\Desktop', 'LockDelay', REG_DWORD, 300),
            (K + r'\Permissions', 'DenySoftwareInstall', REG_DWORD, 1),
            (K + r'\Permissions', 'AdminGroups', REG_SZ, 'sudo'),
            (K + r'\SSH', 'PermitRootLogin', REG_SZ, 'no'),
            (r'Software\Policies\Mozilla\Firefox', 'DisableTelemetry', REG_DWORD, 1),
            (r'Software\Policies\Mozilla\Firefox\WebsiteFilter\Block', '1', REG_SZ, 'https://*.exemple.com/*'),
            (r'Software\Policies\Google\Chrome', 'SyncDisabled', REG_DWORD, 1),
            (r'Software\Policies\Google\Chrome', 'IncognitoModeAvailability', REG_DWORD, 1),
            (r'Software\Policies\Google\Chrome\URLBlocklist', '1', REG_SZ, 'exemple.com'),
            (r'Software\Policies\Microsoft\Windows\RemovableStorageDevices', 'Deny_All', REG_DWORD, 1),
        ]))
        ecrire(g1, 'Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf',
               inf({'Registry Values': {r'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLastUserName': '4,1',
                                        r'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeText': '7,Usage réservé,au personnel'}}))
        ecrire(g1, 'MACHINE/VGP/VTLA/Unix/Files/manifest.xml', vgp(
            '<file_properties><source>conf.txt</source><target>/etc/zz-deploye.conf</target><user>root</user><group>root</group>'
            '<permissions type="user"><read/><write/></permissions><permissions type="other"><read/></permissions></file_properties>'))
        ecrire(g1, 'MACHINE/VGP/VTLA/Unix/Files/conf.txt', 'cle=valeur\n')
        # une seconde GPO, appliquée après, remplace le message
        g2 = os.path.join(self.gpo, '2-ou')
        ecrire(g2, 'MACHINE/Registry.pol', pol([(KS + r'\Messages', 'motd', REG_SZ, 'Poste du service compta')]))
        self.assertEqual(self.passer(), 0)

        self.assertEqual(self.lire('/etc/motd'), 'Poste du service compta\n')
        self.assertIn('Usage réservé\nau personnel', self.lire('/etc/issue'))
        self.assertIn('root ALL=(ALL) NOPASSWD: /usr/bin/true', self.lire('/etc/sudoers.d/50-linux-gpo'))
        self.assertEqual(os.stat(self.racine + '/etc/sudoers.d/50-linux-gpo').st_mode & 0o777, 0o440)
        self.assertEqual(self.lire('/etc/ssh/sshd_config.d/10-linux-gpo.conf').splitlines()[-1], 'PermitRootLogin no')
        self.assertTrue(self.lire('/etc/ssh/sshd_config').startswith('# >>> linux-gpo'))
        db = self.lire('/etc/dconf/db/linux-gpo.d/00-linux-gpo')
        self.assertIn('disable-command-line=true', db)
        self.assertIn('idle-delay=uint32 300', db)
        self.assertIn('/org/gnome/desktop/lockdown/disable-command-line', self.lire('/etc/dconf/db/linux-gpo.d/locks/00-linux-gpo'))
        self.assertIn('system-db:linux-gpo', self.lire('/etc/dconf/profile/user'))
        self.assertIn('disable-user-list=true', self.lire('/etc/dconf/db/gdm.d/90-linux-gpo'))
        self.assertIn('[KDE Action Restrictions][$i]\nshell_access=false', self.lire('/etc/xdg/kdeglobals'))
        self.assertIn('foo=1', self.lire('/etc/xdg/kdeglobals'))
        self.assertIn('Timeout=5', self.lire('/etc/xdg/kscreenlockerrc'))
        regles = self.lire('/etc/polkit-1/rules.d/40-linux-gpo.rules')
        self.assertIn('org.freedesktop.packagekit.', regles)
        self.assertIn('org.freedesktop.udisks2.', regles)
        self.assertIn('install usb_storage /bin/false', self.lire('/etc/modprobe.d/linux-gpo-stockage.conf'))
        ff = json.loads(self.lire('/etc/firefox/policies/policies.json'))['policies']
        self.assertEqual(ff, {'DisableTelemetry': True, 'WebsiteFilter': {'Block': ['https://*.exemple.com/*']}})
        gc = json.loads(self.lire('/etc/opt/chrome/policies/managed/linux-gpo.json'))
        self.assertEqual(gc, {'SyncDisabled': True, 'IncognitoModeAvailability': 1, 'URLBlocklist': ['exemple.com']})
        self.assertEqual(self.lire('/etc/zz-deploye.conf'), 'cle=valeur\n')
        self.assertEqual(os.stat(self.racine + '/etc/zz-deploye.conf').st_mode & 0o777, 0o604)
        scripts = os.listdir(self.racine + '/var/lib/linux-gpo/scripts')
        self.assertEqual(len(scripts), 1)
        self.assertTrue(any(u.endswith('.timer') for u in os.listdir(self.racine + '/run/systemd/system')))

        # deuxième passage identique : rien ne change
        avant = {os.path.join(dp, p): os.stat(os.path.join(dp, p)).st_mtime_ns for dp, _, fs in os.walk(self.racine) for p in fs}
        self.assertEqual(self.passer(), 0)
        apres = {os.path.join(dp, p): os.stat(os.path.join(dp, p)).st_mtime_ns for dp, _, fs in os.walk(self.racine) for p in fs}
        self.assertEqual({k for k in avant if avant[k] != apres.get(k)}, set())

        # GPO retirées : le poste revient à l’état d’origine
        shutil.rmtree(g1)
        shutil.rmtree(g2)
        self.assertEqual(self.passer(), 0)
        self.assertEqual(self.lire('/etc/motd'), 'motd d’origine\n')
        self.assertFalse(os.path.exists(self.racine + '/etc/issue'))
        self.assertEqual(self.lire('/etc/ssh/sshd_config'), 'PermitRootLogin yes\n')
        self.assertEqual(self.lire('/etc/xdg/kdeglobals'), '[General]\nfoo=1\n')
        for p in ('/etc/sudoers.d/50-linux-gpo', '/etc/dconf/db/linux-gpo.d/00-linux-gpo', '/etc/dconf/profile/user',
                  '/etc/polkit-1/rules.d/40-linux-gpo.rules', '/etc/firefox/policies/policies.json', '/etc/zz-deploye.conf',
                  '/etc/xdg/kscreenlockerrc'):
            self.assertFalse(os.path.exists(self.racine + p), p)

    def test_format_admx(self):
        """Valeurs telles que les écrit l’éditeur de Windows avec LinuxGPO.admx."""
        ecrire(self.gpo, '1/MACHINE/Registry.pol', pol([
            (K + r'\Software\Install', '**delvals.', REG_SZ, ' '), (K + r'\Software\Install', '1', REG_SZ, 'ancien'),
            (K + r'\Messages', 'motd', REG_MULTI_SZ, ['ligne 1', 'ligne 2'])]))
        ecrire(self.gpo, '2/MACHINE/Registry.pol', pol([
            (K + r'\Software\Install', '**delvals.', REG_SZ, ' '), (K + r'\Software\Install', '1', REG_SZ, 'tree'),
            (K + r'\Desktop', 'LoginBanner', REG_MULTI_SZ, ['Bienvenue', 'Usage réservé']), (K + r'\Desktop', '**del.LockDelay', REG_SZ, ' ')]))
        self.assertEqual(self.passer(), 0)
        self.assertEqual(self.lire('/etc/motd'), 'ligne 1\nligne 2\n')
        with open(os.path.join(self.etat, 'rapport.json'), encoding='utf-8') as fh:
            r = json.load(fh)['reglages']
        self.assertEqual([l for l in r['logiciels'] if 'tree' in l or 'ancien' in l], ['tree : à installer'])
        self.assertIn('banniere : Bienvenue\nUsage réservé', r['bureau'])


class Raccourcis(unittest.TestCase):
    def test_cibles(self):
        from linux_gpo.ext import raccourcis as r
        d = tempfile.mkdtemp()
        try:
            for n, nom in (('org.mozilla.firefox', 'Firefox'), ('google-chrome', 'Google Chrome'), ('vlc', 'VLC media player')):
                ecrire(d, n + '.desktop', f'[Desktop Entry]\nType=Application\nName={nom}\nExec={n}\n')
            l = {n[:-8]: os.path.join(d, n) for n in os.listdir(d)}
            self.assertTrue(r.trouver_application('Firefox', l).endswith('org.mozilla.firefox.desktop'))
            self.assertTrue(r.trouver_application(r'C:\Program Files\Google\Chrome\Application\chrome.exe', l).endswith('google-chrome.desktop'))
            self.assertTrue(r.trouver_application('VLC media player', l).endswith('vlc.desktop'))
            self.assertIsNone(r.trouver_application('notepad++', l))
            self.assertIn('URL=smb://dc01/Commun', r.lanceur(r'\\dc01\Commun', 'Commun', '', l))
            self.assertIn('Type=Link', r.lanceur('https://intranet.exemple.local', 'Intranet', '', l))
            self.assertIn('Exec=vlc', r.lanceur('vlc', 'VLC', '', l))
        finally:
            shutil.rmtree(d)


class Maj(unittest.TestCase):
    def test_sources_et_installation(self):
        import io
        import tarfile
        from unittest import mock
        from linux_gpo import maj

        c = Conf(domaine='exemple.local', serveur='dc01.exemple.local')
        self.assertEqual(maj.sources(c), ['https://dc01.exemple.local:8443/linux/linux-gpo.tar.gz', maj.GITHUB])
        self.assertEqual(maj.sources(Conf(domaine='x', options={'source_maj': 'github'})), [maj.GITHUB])

        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        trace = os.path.join(d, 'installe')
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode='w:gz') as t:
            for nom, contenu in (('agent/linux_gpo/__init__.py', b''), ('agent/install.sh', f'echo ok >> {trace}\n'.encode())):
                i = tarfile.TarInfo(nom)
                i.size = len(contenu)
                t.addfile(i, io.BytesIO(contenu))
        c.etat = d
        with mock.patch.object(maj, 'telecharger', return_value=buf.getvalue()):
            maj.mettre_a_jour(c)
            maj.mettre_a_jour(c)  # même archive : rien à faire
        with open(trace) as fh:
            self.assertEqual(fh.read(), 'ok\n')
        with mock.patch.object(maj, 'telecharger', return_value=b'pas une archive'), \
                self.assertRaises(systeme.ErreurAgent):
            maj.mettre_a_jour(c, True)


class ProfilBureau(unittest.TestCase):
    FX = {'methode': 'flatpak', 'paquet': 'org.mozilla.firefox'}
    PROFIL = {'version': 2, 'nom': 'Bureau RH',
              'apps': [{'id': 'std-firefox', 'nom': 'Firefox', 'type': 'appli', 'winget': 'Mozilla.Firefox',
                        'installateurs': [{'methode': 'native', 'paquet': 'firefox', 'distros': ['ubuntu', 'arch']},
                                          {'methode': 'native', 'paquet': 'firefox-esr', 'distros': ['debian']}, FX]},
                       {'id': 'std-vlc', 'nom': 'VLC', 'type': 'appli',
                        'installateurs': [{'methode': 'native', 'paquet': 'vlc', 'distros': ['debian', 'ubuntu', 'arch']},
                                          {'methode': 'flatpak', 'paquet': 'org.videolan.VLC'}]},
                       {'id': 'std-7zip', 'nom': '7-Zip', 'type': 'appli', 'installateurs': [{'methode': 'snap', 'paquet': '7zip'}]},
                       {'id': 'web-intranet', 'nom': 'Intranet', 'type': 'web', 'url': 'https://intranet.exemple.local'},
                       {'id': 'partage-rh', 'nom': 'Partage RH', 'type': 'partage', 'chemin': '\\\\dc01\\RH'},
                       {'id': '../x', 'nom': 'Mauvais', 'type': 'web', 'url': 'https://x'},
                       {'id': 'pirate', 'nom': 'Pirate', 'type': 'appli', 'installateurs': [{'methode': 'native', 'paquet': 'x; rm -rf /'}]}],
              'bureau': ['std-firefox', 'partage-rh', 'std-vlc', 'web-intranet', 'inconnue'],
              'barre': ['std-firefox', 'std-vlc', 'web-intranet'], 'installer': ['std-7zip'], 'fond': '../../etc/shadow'}

    def setUp(self):
        from linux_gpo.ext import profil
        self.p = profil
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d)
        self.f = os.path.join(self.d, 'bureau.json')
        with open(self.f, 'w', encoding='utf-8') as fh:
            json.dump(self.PROFIL, fh)

    def test_affichage_du_fond(self):
        for valeur, attendu in ((0, 0), (3, 3), (5, 5), (6, 4), (-1, 4), ('2', 4), (True, 4), (None, 4)):
            with open(self.f, 'w', encoding='utf-8') as fh:
                json.dump({**self.PROFIL, 'fondStyle': valeur}, fh)
            self.assertEqual(self.p.charger(self.f)['fond_style'], attendu, valeur)
        a = {'apps': {}, 'bureau': [], 'barre': [], 'installer': [], 'fond': '/x/a.png', 'fond_style': 3,
             'fond_bande': {'mode': 'flou', 'couleur': '#112233'}}
        b = {**a, 'fond': '', 'fond_style': 0, 'fond_bande': {'mode': 'couleur', 'couleur': '#000000'}}
        r = self.p.fusionner([a, b])
        self.assertEqual((r['fond_style'], r['fond_bande']['mode']), (3, 'flou'))   # le style et les bandes suivent l’image
        for valeur, attendu in ((None, ('couleur', '#000000')), ({'mode': 'flou', 'couleur': '#ABCDEF'}, ('flou', '#abcdef')),
                                ({'mode': 'x', 'couleur': 'rouge'}, ('couleur', '#000000')), ('flou', ('couleur', '#000000'))):
            with open(self.f, 'w', encoding='utf-8') as fh:
                json.dump({**self.PROFIL, 'fondBande': valeur}, fh)
            charge = self.p.charger(self.f)['fond_bande']
            self.assertEqual((charge['mode'], charge['couleur']), attendu, valeur)

    def test_github_derniere_version(self):
        from linux_gpo.ext import logiciels
        noms = ['SHA256SUMS.txt', 'x-1-linux-aarch64.deb', 'x-1-linux-x86_64.deb', 'x-1-linux-x86_64.AppImage', 'x-1-linux-x86_64.rpm']
        self.assertEqual(logiciels.choisir_fichier(noms, 'apt', 'x86_64'), 'x-1-linux-x86_64.deb')
        self.assertEqual(logiciels.choisir_fichier(noms, 'apt', 'aarch64'), 'x-1-linux-aarch64.deb')
        self.assertIsNone(logiciels.choisir_fichier(noms, 'pacman', 'x86_64'))        # pas de .pkg.tar.zst
        self.assertIsNone(logiciels.choisir_fichier(noms, 'dnf', 'x86_64'))
        versions = ['p_1_amd64-bookworm.deb', 'p_1_amd64-noble.deb', 'p_1_amd64.deb']
        self.assertEqual(logiciels.choisir_fichier(versions, 'apt', 'x86_64', ('noble', '2404')), 'p_1_amd64-noble.deb')
        self.assertEqual(logiciels.choisir_fichier(versions, 'apt', 'x86_64', ('trixie', '13')), 'p_1_amd64.deb')   # générique avant une autre version
        self.assertEqual(logiciels.choisir_fichier(['a.deb', 'b-i386.deb'], 'apt', 'x86_64'), 'a.deb')
        self.assertIsNone(logiciels.choisir_fichier(['../x.deb'], 'apt', 'x86_64'))     # nom de fichier suspect
        self.assertFalse(logiciels.DEPOT.match('a/b/c') or logiciels.DEPOT.match('a b/c') or logiciels.DEPOT.match('../x'))
        code, message = logiciels.installer_github('apt', 'pas un dépôt')
        self.assertEqual(code, 1)
        self.assertEqual(logiciels.installer_github('dnf', 'a/b')[0], 1)

    def test_installateur_github_dans_un_profil(self):
        profil = {**self.PROFIL, 'apps': [{'id': 'deckcraft', 'nom': 'deckcraft', 'type': 'appli',
                                           'installateurs': [{'methode': 'github', 'paquet': 'storytold/deckcraft', 'distros': ['debian']},
                                                             {'methode': 'github', 'paquet': 'pas un depot'}]}]}
        with open(self.f, 'w', encoding='utf-8') as fh:
            json.dump(profil, fh)
        app = self.p.charger(self.f)['apps']['deckcraft']
        self.assertEqual([i['paquet'] for i in app['installateurs']], ['storytold/deckcraft'])
        self.assertEqual(self.p.choisir(app, 'debian', 'apt')['methode'], 'github')
        self.assertIsNone(self.p.choisir(app, 'debian', 'dnf'))     # ni .deb ni .pkg.tar.zst
        flat = {**app, 'installateurs': [*app['installateurs'], {'methode': 'flatpak', 'paquet': 'org.x.Y', 'classic': False, 'distros': []}]}
        self.assertEqual(self.p.choisir(flat, 'debian', 'apt')['methode'], 'flatpak')   # GitHub en dernier

    def test_attribut_nixos_ignore_et_repli_sur_l_installateur_suivant(self):
        profil = {**self.PROFIL, 'apps': [{'id': 'pdfcraft', 'nom': 'PdfCraft', 'type': 'appli', 'installateurs': [
            {'methode': 'native', 'paquet': 'unstable.pdfcraft', 'distros': []},                 # attribut nixpkgs, sans distribution
            {'methode': 'native', 'paquet': 'pdfcraft', 'distros': ['nixos']},                    # distribution inconnue de l’agent
            {'methode': 'snap', 'paquet': 'pdfcraft', 'distros': ['ubuntu']},
            {'methode': 'github', 'paquet': 'storytold/pdfcraft', 'distros': ['debian', 'ubuntu', 'arch']}]}]}
        with open(self.f, 'w', encoding='utf-8') as fh:
            json.dump(profil, fh)
        app = self.p.charger(self.f)['apps']['pdfcraft']
        self.assertEqual([(i['methode'], i['paquet']) for i in app['installateurs']], [('snap', 'pdfcraft'), ('github', 'storytold/pdfcraft')])
        self.assertEqual([i['methode'] for i in self.p.candidats(app, 'debian', 'apt')], ['github'])
        self.assertEqual([i['methode'] for i in self.p.candidats(app, 'ubuntu', 'apt')], ['snap', 'github'])
        # le premier installateur échoue : le suivant est essayé
        deux = {'id': 'x', 'nom': 'X', 'type': 'appli', 'installateurs': [
            {'methode': 'native', 'paquet': 'x', 'classic': False, 'distros': []}, {'methode': 'github', 'paquet': 'a/x', 'classic': False, 'distros': []}]}
        essais = []

        def tour(ctx, ext, g, choix):
            essais.extend(i['methode'] for i in choix.values())
            return ([k for k, i in choix.items() if i['methode'] == 'github'], {k: 'introuvable' for k, i in choix.items() if i['methode'] == 'native'})

        class Ctx:
            simuler = False

            def noter(self, *a):
                pass
        sauve = (self.p.presente, self.p.distribution, self.p._installer_tour)
        self.addCleanup(lambda: [setattr(self.p, n, v) for n, v in zip(('presente', 'distribution', '_installer_tour'), sauve)])
        self.p.presente, self.p.distribution, self.p._installer_tour = (lambda a, g: False), (lambda: 'debian'), tour
        from linux_gpo.ext import logiciels
        sauve_g = logiciels.gestionnaire
        self.addCleanup(setattr, logiciels, 'gestionnaire', sauve_g)
        logiciels.gestionnaire = lambda: 'apt'
        faites, echecs = self.p.installer_apps(Ctx(), 'profil', [{**deux, 'installateurs': [{**i, 'distros': []} for i in deux['installateurs']]}])
        self.assertEqual((faites, echecs, essais), (['x'], {}, ['native', 'github']))

    def test_lecture_et_choix_de_l_installateur(self):
        p = self.p.charger(self.f)
        self.assertEqual(sorted(p['apps']), ['partage-rh', 'pirate', 'std-7zip', 'std-firefox', 'std-vlc', 'web-intranet'])
        self.assertEqual(p['apps']['pirate']['installateurs'], [])   # nom de paquet invalide : ignoré
        self.assertEqual(p['fond'], '')                               # chemin hors du dossier du profil : refusé
        self.assertEqual(p['fond_style'], 4)                          # sans affichage indiqué : remplir
        self.assertEqual(p['barre'], ['std-firefox', 'std-vlc'])      # seules des applications s’épinglent
        self.assertEqual(p['bureau'], ['std-firefox', 'partage-rh', 'std-vlc', 'web-intranet'])
        self.assertEqual(self.p.utiles(p), ['std-firefox', 'std-vlc', 'std-7zip'])
        ff = p['apps']['std-firefox']
        self.assertEqual(self.p.choisir(ff, 'debian', 'apt')['paquet'], 'firefox-esr')   # paquet de la distribution d’abord
        self.assertEqual(self.p.choisir(ff, 'ubuntu', 'apt')['paquet'], 'firefox')
        self.assertEqual(self.p.choisir(ff, None, 'dnf')['methode'], 'flatpak')          # distribution inconnue : Flatpak
        self.assertEqual(self.p.choisir(ff, 'debian', None)['methode'], 'flatpak')       # pas de gestionnaire de paquets
        self.assertIsNone(self.p.choisir(p['apps']['std-7zip'], 'arch', 'pacman'))        # Snap : pas sous Arch
        self.assertEqual(self.p.unc_vers_smb('\\\\dc01\\RH\\Docs', 'exemple.local'), 'smb://dc01.exemple.local/RH/Docs')

    def test_application_deja_la_autrement(self):
        from unittest import mock
        appli = os.path.join(self.d, 'apps')
        ecrire(appli, 'libreoffice-startcenter.desktop', '[Desktop Entry]\nType=Application\nName=LibreOffice\nExec=libreoffice\n')
        lo = {'id': 'app-lo', 'nom': 'LibreOffice', 'type': 'appli', 'installateurs': [{'methode': 'flatpak', 'paquet': 'org.libreoffice.LibreOffice'}]}
        self.p._systeme = None
        with mock.patch.object(self.p, '_lanceurs', return_value={'libreoffice-startcenter': os.path.join(appli, 'libreoffice-startcenter.desktop')}):
            self.assertTrue(self.p.presente(lo, None))   # paquet de la distribution : pas de Flatpak en plus
            self.assertFalse(self.p.presente({**lo, 'nom': 'GIMP'}, None))
        self.p._systeme = None

    def test_session(self):
        from unittest import mock
        from types import SimpleNamespace
        from linux_gpo.fichiers import Fichiers
        appli = os.path.join(self.d, 'apps')
        ecrire(appli, 'firefox.desktop', '[Desktop Entry]\nType=Application\nName=Firefox\nExec=firefox\n')
        bureau = os.path.join(self.d, 'Bureau')
        g = SimpleNamespace(guid='{11111111-2222-3333-4444-555555555555}')
        pol = SimpleNamespace(fichiers=lambda rel: [(g, self.f)] if rel == self.p.FICHIER else [], fichier=lambda *a: None)
        ctx = cli.Contexte(conf=Conf(domaine='exemple.local'), pol=pol, f=Fichiers(os.path.join(self.d, 'etat')), noms=None,
                           utilisateur='jdupont')
        epingles, installees = [], set()
        demande = mock.Mock(side_effect=lambda c, s, a: installees.update(['std-vlc']) or {'installees': ['std-vlc'], 'echecs': {'std-7zip': 'snapd absent'}})
        ecrire(appli, 'vlc.desktop', '[Desktop Entry]\nType=Application\nName=VLC\nExec=vlc\n')
        lanceurs = {'firefox': os.path.join(appli, 'firefox.desktop'), 'vlc': os.path.join(appli, 'vlc.desktop')}
        with mock.patch.object(self.p, '_lanceurs', return_value=lanceurs), \
                mock.patch.object(self.p, 'dossier_bureau', return_value=bureau), \
                mock.patch.object(self.p, 'presente', side_effect=lambda a, g: a['id'] == 'std-firefox' or a['id'] in installees), \
                mock.patch.object(self.p, 'demander_installation', demande), \
                mock.patch.object(self.p, 'outil', side_effect=lambda n: n == 'plasmashell'), \
                mock.patch.object(self.p, 'epingler_plasma', side_effect=lambda u: epingles.append(u) or True), \
                mock.patch.object(self.p, 'chemin', return_value=os.path.join(self.d, 'absent')), \
                mock.patch('linux_gpo.ext.logiciels.gestionnaire', return_value=None):
            self.p.Profil().appliquer(ctx)
            ctx.f.terminer()
            self.assertEqual(demande.call_args[0][1:], ([g.guid], ['std-vlc', 'std-7zip']))
            self.assertEqual(sorted(os.listdir(bureau)), ['linux-gpo-00-std-firefox.desktop', 'linux-gpo-01-partage-rh.desktop',
                                                          'linux-gpo-02-std-vlc.desktop', 'linux-gpo-03-web-intranet.desktop'])
            self.assertEqual(epingles, [['file://' + lanceurs['firefox'], 'file://' + lanceurs['vlc']]])
            self.assertIn('installation impossible — snapd absent', '\n'.join(ctx.rapport['profil']))
            self.p.Profil().appliquer(ctx)  # même profil : épingles déjà posées, l’utilisateur garde ses changements
            self.assertEqual(len(epingles), 1)
            self.assertEqual(demande.call_count, 1)  # 7-Zip en échec : pas redemandée tout de suite
        with open(os.path.join(bureau, 'linux-gpo-01-partage-rh.desktop')) as fh:
            self.assertIn('URL=smb://dc01.exemple.local/RH', fh.read())

    def test_demandes_et_resultat(self):
        from unittest import mock
        from types import SimpleNamespace
        racine = os.path.join(self.d, 'racine')
        systeme.RACINE = racine
        self.addCleanup(setattr, systeme, 'RACINE', '')
        d = racine + self.p.DEMANDES
        os.makedirs(d)
        guid = '{AAAAAAAA-2222-3333-4444-555555555555}'
        ecrire(d, f'{os.getuid()}.json', json.dumps({'sources': [guid], 'apps': ['std-vlc', 'outil-pirate']}))
        ecrire(d, f'{os.getuid() + 1}.json', '{}')  # déposé au nom d’un autre utilisateur : supprimé
        res = self.p.ApplicationsProfils._demandes()
        self.assertEqual([(u, x['apps']) for _, u, x in res], [(os.getuid(), ['std-vlc', 'outil-pirate'])])

        # le service relit le profil dans SYSVOL : seule VLC (choisie par l’administrateur) est installée
        class Annuaire:
            def chercher(s, *a, **k):
                return [{'gpcfilesyspath': [b'\\\\exemple.local\\SysVol\\exemple.local\\Policies\\' + guid.encode()]}]

            def copier_fichier(s, unc, dest):
                shutil.copyfile(self.f, dest)
        resultats = os.path.join(self.d, 'resultats')
        ctx = SimpleNamespace(annuaire=Annuaire(), conf=Conf(domaine='exemple.local'), simuler=False, rapport={},
                              noter=lambda e, t: None)
        with mock.patch.object(self.p, 'installer_apps', return_value=(['std-vlc'], {})) as inst, \
                mock.patch.object(self.p, 'RESULTATS', resultats):
            self.p.ApplicationsProfils().appliquer(ctx)
        self.assertEqual([a['id'] for a in inst.call_args[0][2]], ['std-vlc'])
        with open(os.path.join(resultats, f'{os.getuid()}.json')) as fh:
            self.assertEqual(json.load(fh)['installees'], ['std-vlc'])
        self.assertEqual(os.listdir(d), [])


if __name__ == '__main__':
    unittest.main()
