# Module NixOS de linux-gpo.
#
#   imports = [ (builtins.fetchTarball "https://github.com/jonathan-pp/linux-gpo-agent/archive/main.tar.gz" + "/packaging/nixos/module.nix") ];
#   services.linux-gpo.enable = true;
#
# Le poste doit être joint au domaine (sssd ou winbind, /etc/krb5.keytab présent).
# Sur NixOS, la configuration Nix reste maîtresse : l'agent écrit seulement là où NixOS le permet
# (sudoers.d, polkit, dconf, modprobe.d, nftables, navigateurs, fichiers déployés…) et ce module
# branche ces emplacements (inclusion sudo, PAM, SSH). Les paquets, les mises à jour et les réglages SSH
# déjà définis dans la configuration Nix ne sont pas modifiés par les GPO.
{ config, lib, pkgs, ... }:

let
  cfg = config.services.linux-gpo;
  acces = {
    order = 0;
    control = "required";
    modulePath = "${pkgs.pam}/lib/security/pam_exec.so";
    args = [ "quiet" "${cfg.package}/lib/linux-gpo/acces" ];
  };
  regle = svc: {
    rules.account.linux-gpo = acces // {
      # avant pam_unix (les services qui n’ont pas les règles par défaut, comme gdm-password, incluent « login »)
      order = (config.security.pam.services.${svc}.rules.account.unix or { order = 10000; }).order - 10;
    };
  };
  gdm = (config.services.displayManager.gdm.enable or false) || (config.services.xserver.displayManager.gdm.enable or false);
  sddm = config.services.displayManager.sddm.enable or false;
  lightdm = config.services.xserver.displayManager.lightdm.enable or false;
in
{
  options.services.linux-gpo = {
    enable = lib.mkEnableOption "les stratégies de groupe Active Directory (linux-gpo)";
    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.callPackage ./paquet.nix { };
      description = "Paquet linux-gpo.";
    };
    domaine = lib.mkOption {
      type = lib.types.str;
      default = "";
      example = "exemple.local";
      description = "Nom DNS du domaine (détecté automatiquement s'il est vide).";
    };
    controleAcces = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Brancher dans PAM le contrôle d'ouverture de session des GPO (comptes autorisés ou refusés).";
    };
    profilDconf = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        À activer si la configuration définit programs.dconf.profiles.user : la base des GPO y est ajoutée.
        Sinon l'agent écrit lui-même /etc/dconf/profile/user.
      '';
    };
  };

  config = lib.mkIf cfg.enable (lib.mkMerge [
    {
      environment.systemPackages = [ cfg.package ];
      environment.etc."linux-gpo/agent.conf".text =
        "[agent]\n" + lib.optionalString (cfg.domaine != "") "domaine = ${cfg.domaine}\n";
      programs.dconf.enable = lib.mkDefault true;
      security.sudo.extraConfig = lib.mkAfter "@includedir /etc/sudoers.d\n";
      services.openssh.extraConfig = lib.mkOrder 1 "Include /etc/ssh/sshd_config.d/*.conf";
      systemd.tmpfiles.rules = [ "d /etc/sudoers.d 0750 root root -" "d /etc/ssh/sshd_config.d 0755 root root -" ];

      systemd.services.linux-gpo = {
        description = "Stratégies de groupe (GPO) de l'ordinateur";
        wants = [ "network-online.target" ];
        after = [ "network-online.target" "nss-lookup.target" "sssd.service" "samba-winbindd.service" ];
        before = [ "display-manager.service" "systemd-user-sessions.service" ];
        wantedBy = [ "multi-user.target" ];
        path = [ "/run/wrappers" "/run/current-system/sw" ];
        serviceConfig = {
          Type = "oneshot";
          ExecStart = "${cfg.package}/bin/linux-gpo appliquer";
          TimeoutStartSec = "10min";
        };
      };
      systemd.services.linux-gpo-applications = {
        description = "Applications des profils de bureau (GPO)";
        wants = [ "network-online.target" ];
        after = [ "network-online.target" "linux-gpo.service" ];
        path = [ "/run/wrappers" "/run/current-system/sw" ];
        serviceConfig = {
          Type = "oneshot";
          ExecStart = "${cfg.package}/bin/linux-gpo applications";
          TimeoutStartSec = "60min";
        };
      };
      systemd.tmpfiles.settings.linux-gpo."/var/spool/linux-gpo".d = { mode = "1733"; };
      systemd.timers.linux-gpo = {
        wantedBy = [ "timers.target" ];
        timerConfig = { OnBootSec = "90min"; OnUnitActiveSec = "90min"; RandomizedDelaySec = "30min"; };
      };
      systemd.user.services.linux-gpo-utilisateur = {
        description = "Stratégies de groupe (GPO) de l'utilisateur";
        wantedBy = [ "default.target" ];
        path = [ "/run/current-system/sw" ];
        serviceConfig = { Type = "oneshot"; ExecStart = "${cfg.package}/bin/linux-gpo utilisateur --ouverture"; };
      };
      systemd.user.services.linux-gpo-utilisateur-actualiser = {
        description = "Actualisation des stratégies de groupe de l'utilisateur";
        path = [ "/run/current-system/sw" ];
        serviceConfig = { Type = "oneshot"; ExecStart = "${cfg.package}/bin/linux-gpo utilisateur"; };
      };
      systemd.user.timers.linux-gpo-utilisateur-actualiser = {
        wantedBy = [ "timers.target" ];
        timerConfig = { OnActiveSec = "90min"; OnUnitActiveSec = "90min"; RandomizedDelaySec = "30min"; };
      };
    }
    (lib.mkIf cfg.profilDconf {
      programs.dconf.profiles.user.databases = lib.mkAfter [ "/etc/dconf/db/linux-gpo" ];
    })
    (lib.mkIf cfg.controleAcces {
      security.pam.services = lib.mkMerge [
        { login = regle "login"; }
        (lib.mkIf config.services.openssh.enable { sshd = regle "sshd"; })
        (lib.mkIf gdm { gdm-password = regle "gdm-password"; })
        (lib.mkIf sddm { sddm = regle "sddm"; })
        (lib.mkIf lightdm { lightdm = regle "lightdm"; })
      ];
    })
  ]);
}
