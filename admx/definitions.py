"""Définition des paramètres de linux-gpo : source unique des modèles ADMX/ADML (fr-FR, en-US) et du catalogue
lu par d’autres consoles (definitions.json).

Types :
  bool    case Activé / Désactivé (valeur 1 / 0)
  nombre  valeur numérique (min, max, défaut)
  texte   texte d’une ligne
  multi   texte de plusieurs lignes (REG_MULTI_SZ)
  choix   liste déroulante (valeurs numériques)
  liste   liste de valeurs numérotées 1, 2, 3…
  paires  liste nom → valeur
Un paramètre peut regrouper plusieurs éléments (« elements ») sous une même case de stratégie.
"""
K = r'Software\Policies\LinuxGPO'

CATEGORIES = [
    # (id, parent, fr, en)
    ('Linux', None, 'Linux (linux-gpo)', 'Linux (linux-gpo)'),
    ('Bureau', 'Linux', 'Bureau', 'Desktop'),
    ('Droits', 'Linux', 'Droits des utilisateurs', 'User rights'),
    ('Securite', 'Linux', 'Sécurité', 'Security'),
    ('Systeme', 'Linux', 'Système', 'System'),
    ('Logiciels', 'Linux', 'Logiciels et scripts', 'Software and scripts'),
]


def p(id, classe, cat, cle, fr, en, aide_fr, aide_en, valeur=None, elements=None, type='bool'):
    return {'id': id, 'classe': classe, 'cat': cat, 'cle': cle, 'fr': fr, 'en': en, 'aide_fr': aide_fr, 'aide_en': aide_en,
            'valeur': valeur, 'type': type, 'elements': elements or []}


def e(id, type, fr, en, valeur=None, cle=None, **o):
    return {'id': id, 'type': type, 'fr': fr, 'en': en, 'valeur': valeur or id, 'cle': cle, **o}


PARAMETRES = [
    # ---------------------------------------------------------------- bureau
    p('DisableCommandLine', 'Both', 'Bureau', K + r'\Desktop', 'Interdire le terminal et la commande « Exécuter »',
      'Prohibit the terminal and the Run command',
      'Activé : les utilisateurs ne peuvent plus ouvrir de terminal ni lancer de commande (Alt+F2, KRunner). GNOME, Cinnamon, MATE, '
      'KDE Plasma. Équivalent Linux de « Désactiver l’accès à l’invite de commandes » (barrière d’interface, pas une sécurité absolue).',
      'Enabled: users can no longer open a terminal or run commands (Alt+F2, KRunner). GNOME, Cinnamon, MATE, KDE Plasma.'),
    p('DisablePrinting', 'Machine', 'Bureau', K + r'\Desktop', 'Interdire l’impression', 'Prohibit printing',
      'Activé : impression et configuration de l’impression interdites (GNOME, MATE, KDE Plasma).',
      'Enabled: printing and print setup are prohibited (GNOME, MATE, KDE Plasma).'),
    p('DisableSaveToDisk', 'Machine', 'Bureau', K + r'\Desktop', 'Interdire l’enregistrement de fichiers', 'Prohibit saving files',
      'Activé : les applications qui respectent ce réglage n’enregistrent plus de fichiers sur le disque (GNOME, MATE, KDE Plasma).',
      'Enabled: applications that honour this setting can no longer save files to disk (GNOME, MATE, KDE Plasma).'),
    p('DisableLogout', 'Machine', 'Bureau', K + r'\Desktop', 'Interdire la déconnexion', 'Prohibit log out',
      'Activé : le bouton de déconnexion disparaît (poste en libre-service, kiosque).', 'Enabled: the log out action is removed (kiosk).'),
    p('DisableUserSwitching', 'Machine', 'Bureau', K + r'\Desktop', 'Interdire le changement d’utilisateur', 'Prohibit user switching',
      'Activé : un seul utilisateur à la fois sur le poste.', 'Enabled: only one user session at a time.'),
    p('LockDelay', 'Both', 'Bureau', K + r'\Desktop', 'Verrouiller l’écran après une période d’inactivité', 'Lock the screen after inactivity',
      'Activé : l’écran se verrouille après le délai indiqué (secondes). Côté ordinateur, le réglage est imposé ; côté utilisateur, il '
      'est remis à chaque session. Repris aussi de la stratégie Windows « Ouverture de session interactive : limite d’inactivité ».',
      'Enabled: the screen locks after the given delay (seconds).', type='elements',
      elements=[e('LockDelay', 'nombre', 'Délai (secondes) :', 'Delay (seconds):', min=60, max=86400, defaut=600)]),
    p('Wallpaper', 'Both', 'Bureau', K + r'\Desktop', 'Image de fond du bureau', 'Desktop wallpaper',
      'Activé : impose l’image de fond. Côté ordinateur : chemin d’une image présente sur le poste (/usr/share/…, ou déployée par '
      '« Fichiers à copier ») ; côté utilisateur, un chemin réseau \\\\serveur\\partage\\image.jpg est aussi accepté. GNOME, Cinnamon, MATE '
      '(KDE Plasma : côté utilisateur seulement).',
      'Enabled: sets the desktop wallpaper (local path; a UNC path is accepted in User Configuration).', type='elements',
      elements=[e('Wallpaper', 'texte', 'Chemin de l’image :', 'Image path:')]),
    p('HideUserList', 'Machine', 'Bureau', K + r'\Desktop', 'Écran de connexion : ne pas afficher la liste des utilisateurs',
      'Login screen: do not show the user list',
      'Activé : l’utilisateur saisit son nom (GDM, SDDM, LightDM). Repris aussi de « Ne pas afficher le dernier nom d’utilisateur ».',
      'Enabled: users type their user name (GDM, SDDM, LightDM).'),
    p('LoginBanner', 'Machine', 'Bureau', K + r'\Desktop', 'Écran de connexion : message affiché', 'Login screen: banner message',
      'Activé : message affiché sur l’écran de connexion GNOME (GDM). Le message légal de Windows est aussi repris.',
      'Enabled: message shown on the GNOME login screen (GDM).', type='elements',
      elements=[e('LoginBanner', 'multi', 'Message :', 'Message:')]),
    # ---------------------------------------------------------------- droits
    p('DenyRemovableStorage', 'Machine', 'Droits', K + r'\Devices', 'Supports amovibles (clés USB, disques externes)',
      'Removable storage (USB keys, external drives)',
      'Activé : les utilisateurs non administrateurs ne peuvent plus monter de support amovible ; avec « bloquer aussi le pilote », '
      'le stockage USB est désactivé pour tous. La stratégie Windows « Toutes les classes de stockage amovible : refuser tout accès » '
      'a le même effet.', 'Enabled: non-administrators can no longer mount removable media; optionally the USB storage driver is blocked.',
      type='elements', elements=[e('DenyRemovableStorage', 'choix', 'Restriction :', 'Restriction:', defaut=0,
                                   choix=[(1, 'Interdire le montage', 'Prohibit mounting'),
                                          (2, 'Interdire le montage et bloquer le pilote USB', 'Prohibit mounting and block the USB driver')])]),
    p('DenyPowerOff', 'Machine', 'Droits', K + r'\Permissions', 'Interdire l’arrêt et le redémarrage', 'Prohibit shutdown and restart',
      'Activé : seuls les administrateurs du poste peuvent arrêter, redémarrer ou mettre en veille.',
      'Enabled: only local administrators can shut down, restart or suspend.'),
    p('DenySoftwareInstall', 'Machine', 'Droits', K + r'\Permissions', 'Interdire l’installation de logiciels', 'Prohibit software installation',
      'Activé : installation de logiciels interdite aux utilisateurs (Logithèque, Discover, Flatpak, Snap).',
      'Enabled: users cannot install software (GNOME Software, Discover, Flatpak, Snap).'),
    p('DenyNetworkConfig', 'Machine', 'Droits', K + r'\Permissions', 'Interdire la modification des connexions réseau',
      'Prohibit changing network connections', 'Activé : les connexions NetworkManager ne peuvent plus être modifiées par les utilisateurs.',
      'Enabled: users cannot change NetworkManager connections.'),
    p('AdminGroups', 'Machine', 'Droits', K + r'\Permissions', 'Groupes administrateurs du poste', 'Local administrator groups',
      'Groupes non concernés par les interdictions ci-dessus, séparés par « ; » (ex. sudo;wheel;DOMAINE\\Support). Par défaut : sudo, '
      'wheel, admin et les Admins du domaine.', 'Groups exempted from the restrictions above, separated by “;”.', type='elements',
      elements=[e('AdminGroups', 'texte', 'Groupes :', 'Groups:')]),
    # ---------------------------------------------------------------- sécurité
    p('SudoRules', 'Machine', 'Securite', K + r'\Sudo\Rules', 'Droits sudo', 'Sudo rights',
      'Une règle sudoers par ligne ; nommez les comptes du domaine DOMAINE\\nom (groupe : %DOMAINE\\groupe), échappez les espaces '
      '(%DOMAINE\\Admins\\ du\\ domaine). Exemple : %EXEMPLE\\Support ALL=(ALL) ALL. Les noms sont adaptés au poste (sssd ou winbind) '
      'et chaque règle est vérifiée par visudo.', 'One sudoers rule per line; name domain accounts DOMAIN\\name.', type='elements',
      elements=[e('SudoRules', 'liste', 'Règles :', 'Rules:')]),
    p('AccessAllow', 'Machine', 'Securite', K + r'\Access\Allow', 'Ouverture de session : comptes autorisés', 'Logon: allowed accounts',
      'Activé : seuls ces utilisateurs ou groupes du domaine (DOMAINE\\nom) peuvent ouvrir une session. root et les comptes locaux ne sont '
      'jamais bloqués.', 'Enabled: only these domain users or groups (DOMAIN\\name) can log on.', type='elements',
      elements=[e('AccessAllow', 'liste', 'Comptes :', 'Accounts:')]),
    p('AccessDeny', 'Machine', 'Securite', K + r'\Access\Deny', 'Ouverture de session : comptes refusés', 'Logon: denied accounts',
      'Activé : ces utilisateurs ou groupes du domaine ne peuvent pas ouvrir de session.', 'Enabled: these accounts cannot log on.',
      type='elements', elements=[e('AccessDeny', 'liste', 'Comptes :', 'Accounts:')]),
    p('Ssh', 'Machine', 'Securite', K + r'\SSH', 'Serveur SSH', 'SSH server',
      'Directives de sshd (nom → valeur), par exemple PermitRootLogin → no, PasswordAuthentication → no, AllowGroups → … '
      'Vérifiées par « sshd -t » avant d’être appliquées.', 'sshd directives (name → value), checked with “sshd -t”.', type='elements',
      elements=[e('Ssh', 'paires', 'Directives :', 'Directives:')]),
    p('FirewallRules', 'Machine', 'Securite', K + r'\Firewall\Rules', 'Pare-feu : règles', 'Firewall: rules',
      'Une règle par ligne : « action;port/protocole ou service;source », action = accept, reject ou drop. Exemples : accept;22/tcp;10.0.0.0/8 — '
      'drop;telnet; — accept;8000-8080/tcp;. Appliquées avec firewalld, ufw ou nftables selon le poste.',
      'One rule per line: “action;port/protocol or service;source”.', type='elements',
      elements=[e('FirewallRules', 'liste', 'Règles :', 'Rules:')]),
    # ---------------------------------------------------------------- système
    p('Messages', 'Machine', 'Systeme', K + r'\Messages', 'Messages de connexion', 'Logon messages',
      'Message affiché avant la connexion en console et SSH (/etc/issue) et après la connexion (/etc/motd).',
      'Message shown before logon (/etc/issue) and after logon (/etc/motd).', type='elements',
      elements=[e('issue', 'multi', 'Avant la connexion :', 'Before logon:'), e('motd', 'multi', 'Après la connexion :', 'After logon:')]),
    p('Updates', 'Machine', 'Systeme', K + r'\Updates', 'Mises à jour automatiques', 'Automatic updates',
      'Installe automatiquement les mises à jour (Debian/Ubuntu : unattended-upgrades ; Fedora : dnf ; Arch : pacman -Syu ; openSUSE : '
      'zypper). « Aucune » arrête les mises à jour automatiques ; Désactivé ou Non configuré : le réglage du poste n’est pas modifié.', 'Installs updates automatically.', type='elements',
      elements=[e('Mode', 'choix', 'Mises à jour :', 'Updates:', defaut=1, choix=[(0, 'Aucune', 'None'), (1, 'Correctifs de sécurité', 'Security fixes'),
                                                                                (2, 'Toutes', 'All')]),
                e('Time', 'texte', 'Heure (HH:MM) :', 'Time (HH:MM):', defaut='03:00'),
                e('Reboot', 'case', 'Redémarrer automatiquement si nécessaire (30 min après)', 'Restart automatically when required')]),
    p('Time', 'Machine', 'Systeme', K + r'\Time', 'Synchroniser l’heure sur le domaine', 'Synchronise time with the domain',
      'Activé : l’heure est prise sur les contrôleurs du domaine (ou les serveurs indiqués). Kerberos exige moins de 5 minutes d’écart.',
      'Enabled: time is synchronised with the domain controllers (or the given servers).', valeur='UseDomainTime', type='elements',
      elements=[e('NtpServers', 'texte', 'Serveurs (facultatif, séparés par des espaces) :', 'Servers (optional, space separated):')]),
    p('Files', 'Machine', 'Systeme', K + r'\Files', 'Fichiers à copier sur le poste', 'Files to copy to the computer',
      'Nom = chemin sur le poste (/etc/…), valeur = « \\\\serveur\\partage\\fichier;droits;propriétaire:groupe » (droits et propriétaire '
      'facultatifs, par défaut 0644 root:root). Le fichier est lu avec le compte de l’ordinateur (donnez-lui la lecture).',
      'Name = path on the computer, value = “\\\\server\\share\\file;mode;owner:group”.', type='elements',
      elements=[e('Files', 'paires', 'Fichiers :', 'Files:')]),
    # ---------------------------------------------------------------- logiciels et scripts
    p('SoftwareInstall', 'Machine', 'Logiciels', K + r'\Software\Install', 'Paquets à installer', 'Packages to install',
      'Un paquet par ligne : « nom », ou un nom par gestionnaire : « apt:libreoffice pacman:libreoffice-fresh dnf:libreoffice ».',
      'One package per line, optionally per package manager.', type='elements', elements=[e('SoftwareInstall', 'liste', 'Paquets :', 'Packages:')]),
    p('SoftwareRemove', 'Machine', 'Logiciels', K + r'\Software\Remove', 'Paquets à désinstaller', 'Packages to remove',
      'Un paquet par ligne (même format).', 'One package per line.', type='elements', elements=[e('SoftwareRemove', 'liste', 'Paquets :', 'Packages:')]),
    p('Flatpak', 'Machine', 'Logiciels', K + r'\Software\Flatpak', 'Applications Flatpak à installer', 'Flatpak applications to install',
      'Identifiants Flathub, un par ligne (ex. org.libreoffice.LibreOffice, org.mozilla.Thunderbird).', 'Flathub application IDs.',
      type='elements', elements=[e('Flatpak', 'liste', 'Applications :', 'Applications:')]),
    p('StartupScripts', 'Machine', 'Logiciels', K + r'\Scripts\Startup', 'Scripts de démarrage', 'Startup scripts',
      'Nom = libellé, valeur = commande lancée en root à chaque démarrage.', 'Name = label, value = command run as root at startup.',
      type='elements', elements=[e('StartupScripts', 'paires', 'Scripts :', 'Scripts:')]),
    p('DailyScripts', 'Machine', 'Logiciels', K + r'\Scripts\Daily', 'Scripts quotidiens', 'Daily scripts',
      'Nom = libellé, valeur = commande lancée en root une fois par jour.', 'Name = label, value = command run daily as root.',
      type='elements', elements=[e('DailyScripts', 'paires', 'Scripts :', 'Scripts:')]),
    p('LogonScripts', 'User', 'Logiciels', K + r'\Scripts\Logon', 'Scripts d’ouverture de session', 'Logon scripts',
      'Nom = libellé, valeur = commande lancée avec les droits de l’utilisateur à l’ouverture de session.',
      'Name = label, value = command run as the user at logon.', type='elements', elements=[e('LogonScripts', 'paires', 'Scripts :', 'Scripts:')]),
]
