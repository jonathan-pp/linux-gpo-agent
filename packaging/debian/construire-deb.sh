#!/bin/sh
# Construit dist/linux-gpo_VERSION_all.deb (dpkg-deb, aucune autre dépendance).
set -eu
RACINE=$(cd "$(dirname "$0")/../.." && pwd)
VERSION=$(python3 -c "import sys; sys.path.insert(0, '$RACINE'); import linux_gpo; print(linux_gpo.VERSION)")
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
P="$T/linux-gpo"
mkdir -p "$P/DEBIAN" "$P/usr/lib/linux-gpo" "$P/usr/bin" "$P/lib/systemd/system" "$P/usr/lib/systemd/user" "$P/etc/linux-gpo" \
         "$P/usr/share/doc/linux-gpo"
cp -r "$RACINE/linux_gpo" "$P/usr/lib/linux-gpo/"
find "$P" -name __pycache__ -prune -exec rm -rf {} +
install -m 755 "$RACINE/packaging/bin/linux-gpo" "$P/usr/bin/linux-gpo"
install -m 755 "$RACINE/packaging/bin/gpupdate" "$P/usr/bin/gpupdate"
install -Dm 644 "$RACINE/packaging/polkit/50-linux-gpo.rules" "$P/usr/share/polkit-1/rules.d/50-linux-gpo.rules"
install -m 755 "$RACINE/packaging/bin/acces" "$P/usr/lib/linux-gpo/acces"
install -m 644 "$RACINE"/packaging/systemd/linux-gpo.service "$RACINE"/packaging/systemd/linux-gpo.timer "$P/lib/systemd/system/"
install -m 644 "$RACINE"/packaging/systemd/linux-gpo-utilisateur* "$P/usr/lib/systemd/user/"
install -m 644 "$RACINE/packaging/agent.conf" "$P/etc/linux-gpo/agent.conf"
install -m 644 "$RACINE/README.md" "$RACINE/LICENSE" "$P/usr/share/doc/linux-gpo/"
cat > "$P/DEBIAN/control" <<FIN
Package: linux-gpo
Version: $VERSION
Architecture: all
Maintainer: jonathan-pp <84352539+jonathan-pp@users.noreply.github.com>
Depends: python3 (>= 3.9), krb5-user, ldap-utils, libsasl2-modules-gssapi-mit, smbclient
Recommends: sudo, dconf-cli
Section: admin
Priority: optional
Homepage: https://github.com/jonathan-pp/linux-gpo-agent
Description: stratégies de groupe Active Directory (GPO) pour Linux
 Applique sur un poste Linux joint à un domaine Active Directory (Windows Server
 ou Samba) les stratégies de groupe qui le concernent : sudo, SSH, pare-feu,
 ouverture de session, verrouillage du bureau (GNOME, KDE…), navigateurs,
 supports amovibles, mises à jour, logiciels, scripts, fichiers, lecteurs réseau.
FIN
echo /etc/linux-gpo/agent.conf > "$P/DEBIAN/conffiles"
cat > "$P/DEBIAN/postinst" <<'FIN'
#!/bin/sh
set -e
mkdir -p /var/lib/linux-gpo /var/cache/linux-gpo
chmod 700 /var/lib/linux-gpo /var/cache/linux-gpo
if [ -d /run/systemd/system ]; then
  systemctl daemon-reload
  systemctl enable linux-gpo.service linux-gpo.timer >/dev/null
  systemctl start linux-gpo.timer
  systemctl --global enable linux-gpo-utilisateur.service linux-gpo-utilisateur-actualiser.timer >/dev/null
fi
exit 0
FIN
cat > "$P/DEBIAN/prerm" <<'FIN'
#!/bin/sh
set -e
if [ "$1" = remove ]; then
  /usr/bin/linux-gpo retirer-tout || true
  if [ -d /run/systemd/system ]; then
    systemctl disable --now linux-gpo.timer linux-gpo.service >/dev/null 2>&1 || true
    systemctl --global disable linux-gpo-utilisateur.service linux-gpo-utilisateur-actualiser.timer >/dev/null 2>&1 || true
  fi
fi
exit 0
FIN
chmod 755 "$P/DEBIAN/postinst" "$P/DEBIAN/prerm"
mkdir -p "$RACINE/dist"
dpkg-deb --root-owner-group --build "$P" "$RACINE/dist/linux-gpo_${VERSION}_all.deb" >/dev/null
echo "$RACINE/dist/linux-gpo_${VERSION}_all.deb"
