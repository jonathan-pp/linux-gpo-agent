#!/bin/sh
# Installation de linux-gpo sur Debian, Ubuntu, Linux Mint, Arch, Manjaro, Fedora, RHEL, openSUSE.
# (NixOS : utilisez le module packaging/nixos.)
#
#   sudo ./install.sh                  depuis une copie du dépôt
#   sudo ./install.sh --desinstaller   retire l'agent et tout ce qu'il a posé
#   sudo sh install.sh --archive URL --sha256 EMPREINTE
#                                      télécharge l'agent (par exemple depuis la console du domaine) et
#                                      vérifie son empreinte avant de l'installer
#
# Le poste doit déjà être joint au domaine (realm join, adcli join ou net ads join).
set -eu

LIB=/usr/lib/linux-gpo
ARCHIVE=""; EMPREINTE=""; DESINSTALLER=0; INSECURE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --archive) ARCHIVE="$2"; shift 2 ;;
    --sha256) EMPREINTE="$2"; shift 2 ;;
    --insecure) INSECURE="-k"; shift ;;
    --desinstaller) DESINSTALLER=1; shift ;;
    *) echo "option inconnue : $1" >&2; exit 2 ;;
  esac
done
[ "$(id -u)" = 0 ] || { echo "à lancer en root (sudo)" >&2; exit 1; }

. /etc/os-release
FAMILLE=autre
for i in $ID ${ID_LIKE:-}; do
  case "$i" in
    nixos) FAMILLE=nixos ;;
    debian|ubuntu) FAMILLE=debian ;;
    arch|archlinux) FAMILLE=arch ;;
    fedora|rhel|centos) FAMILLE=fedora ;;
    suse|opensuse) FAMILLE=suse ;;
  esac
  [ "$FAMILLE" != autre ] && break
done
if [ "$FAMILLE" = nixos ]; then
  echo "NixOS : ajoutez le module linux-gpo à votre configuration (voir packaging/nixos/README)." >&2
  exit 1
fi

if [ "$DESINSTALLER" = 1 ]; then
  [ -x /usr/bin/linux-gpo ] && /usr/bin/linux-gpo retirer-tout || true
  systemctl disable --now linux-gpo.timer linux-gpo.service linux-gpo-applications.path 2>/dev/null || true
  systemctl --global disable linux-gpo-utilisateur.service linux-gpo-utilisateur-actualiser.timer 2>/dev/null || true
  rm -rf "$LIB" /usr/bin/linux-gpo /usr/bin/gpupdate /usr/bin/gpupgrade /etc/polkit-1/rules.d/50-linux-gpo.rules /etc/systemd/system/linux-gpo.* /etc/systemd/system/linux-gpo-applications.* /etc/systemd/user/linux-gpo-* /var/cache/linux-gpo /var/spool/linux-gpo
  systemctl daemon-reload 2>/dev/null || true
  echo "linux-gpo désinstallé (la configuration /etc/linux-gpo et l'état /var/lib/linux-gpo sont conservés)."
  exit 0
fi

echo "== Dépendances ($FAMILLE)"
case "$FAMILLE" in
  debian) DEBIAN_FRONTEND=noninteractive apt-get install -y -q python3 krb5-user ldap-utils libsasl2-modules-gssapi-mit smbclient ;;
  arch)   pacman -S --noconfirm --needed python krb5 openldap smbclient cyrus-sasl-gssapi ;;
  fedora) dnf install -y python3 krb5-workstation openldap-clients cyrus-sasl-gssapi samba-client ;;
  suse)   zypper -n install python3 krb5-client openldap2-client cyrus-sasl-gssapi samba-client ;;
  *)      echo "distribution non reconnue : installez python3, kinit, ldapsearch (avec SASL GSSAPI) et smbclient" ;;
esac

SRC=$(cd "$(dirname "$0")" && pwd)
if [ -n "$ARCHIVE" ]; then
  T=$(mktemp -d)
  trap 'rm -rf "$T"' EXIT
  if command -v curl >/dev/null; then curl -fsSL $INSECURE -o "$T/agent.tar.gz" "$ARCHIVE"
  else wget -q ${INSECURE:+--no-check-certificate} -O "$T/agent.tar.gz" "$ARCHIVE"; fi
  if [ -n "$EMPREINTE" ]; then
    echo "$EMPREINTE  $T/agent.tar.gz" | sha256sum -c - >/dev/null || { echo "empreinte SHA-256 incorrecte : archive refusée" >&2; exit 1; }
  fi
  tar -xzf "$T/agent.tar.gz" -C "$T"
  SRC=$(dirname "$(find "$T" -maxdepth 3 -type d -name linux_gpo | head -1)")
fi
[ -d "$SRC/linux_gpo" ] || { echo "dossier linux_gpo introuvable dans $SRC" >&2; exit 1; }

echo "== Installation"
rm -rf "$LIB/linux_gpo"
mkdir -p "$LIB" /etc/linux-gpo /var/lib/linux-gpo /var/cache/linux-gpo
cp -r "$SRC/linux_gpo" "$LIB/"
find "$LIB" -name __pycache__ -prune -exec rm -rf {} +
install -m 755 "$SRC/packaging/bin/linux-gpo" /usr/bin/linux-gpo
install -m 755 "$SRC/packaging/bin/gpupdate" /usr/bin/gpupdate
install -m 755 "$SRC/packaging/bin/gpupgrade" /usr/bin/gpupgrade
if [ -d /usr/share/polkit-1/rules.d ] || [ -d /etc/polkit-1 ]; then
  install -d -m 755 /etc/polkit-1/rules.d
  install -m 644 "$SRC/packaging/polkit/50-linux-gpo.rules" /etc/polkit-1/rules.d/50-linux-gpo.rules
fi
install -m 755 "$SRC/packaging/bin/acces" "$LIB/acces"
PY=$(command -v python3)
[ "$PY" = /usr/bin/python3 ] || sed -i "1s|.*|#!$PY -I|" /usr/bin/linux-gpo "$LIB/acces"
[ -f /etc/linux-gpo/agent.conf ] || install -m 644 "$SRC/packaging/agent.conf" /etc/linux-gpo/agent.conf
chmod 700 /var/lib/linux-gpo /var/cache/linux-gpo
# demandes d'installation des sessions (profils de bureau) : chacun dépose la sienne, sans voir celles des autres
install -d -m 1733 /var/spool/linux-gpo
# Domaine écrit dans la configuration (lisible de tous) : sssd.conf n'est lisible que de root, et sans lui un utilisateur du domaine
# retombait sur le suffixe DNS reçu par DHCP (celui de la box) et cherchait ses stratégies sur un contrôleur inexistant.
DOMAINE=$(python3 -I -c "import sys; sys.path.insert(0, '$LIB'); from linux_gpo import conf; print(conf._domaine_detecte())" 2>/dev/null)
if [ -n "$DOMAINE" ] && ! grep -q '^domaine *=' /etc/linux-gpo/agent.conf; then
  sed -i "s|^# domaine = .*|domaine = $DOMAINE|" /etc/linux-gpo/agent.conf
fi
mkdir -p /etc/systemd/system /etc/systemd/user
install -m 644 "$SRC"/packaging/systemd/linux-gpo.service "$SRC"/packaging/systemd/linux-gpo.timer "$SRC"/packaging/systemd/linux-gpo-applications.service "$SRC"/packaging/systemd/linux-gpo-applications.path /etc/systemd/system/
install -m 644 "$SRC"/packaging/systemd/linux-gpo-utilisateur*.service "$SRC"/packaging/systemd/linux-gpo-utilisateur*.timer /etc/systemd/user/

# Activation des unités : aussi dans un chroot d'installation (déploiement PXE), où systemd ne tourne pas mais où « enable » suffit
# (liens créés) ; sans cela ni le minuteur de l'ordinateur ni le passage à l'ouverture de session ne démarraient jamais.
if command -v systemctl >/dev/null; then
  [ -d /run/systemd/system ] && systemctl daemon-reload
  systemctl enable linux-gpo.service linux-gpo.timer linux-gpo-applications.path >/dev/null
  systemctl --global enable linux-gpo-utilisateur.service linux-gpo-utilisateur-actualiser.timer >/dev/null
  [ -d /run/systemd/system ] && systemctl start linux-gpo.timer linux-gpo-applications.path
fi

echo "== Vérification"
if /usr/bin/linux-gpo diagnostic; then
  echo "== Premier passage"
  /usr/bin/linux-gpo appliquer && /usr/bin/linux-gpo resultat
else
  echo "Le diagnostic signale un problème : corrigez-le puis lancez « linux-gpo appliquer »."
fi
