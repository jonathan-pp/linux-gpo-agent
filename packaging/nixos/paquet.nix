# Paquet Nix de linux-gpo (utilisé par module.nix et flake.nix).
{ lib, stdenvNoCC, python3, krb5, openldap, samba, makeWrapper }:

stdenvNoCC.mkDerivation {
  pname = "linux-gpo";
  version = "0.1.0";
  src = lib.cleanSource ../..;
  nativeBuildInputs = [ makeWrapper ];
  dontBuild = true;
  installPhase = ''
    runHook preInstall
    mkdir -p $out/lib/linux-gpo $out/bin
    cp -r linux_gpo $out/lib/linux-gpo/
    for f in linux-gpo acces; do
      sed -e "1s|.*|#!${python3}/bin/python3 -I|" -e "s|/usr/lib/linux-gpo|$out/lib/linux-gpo|" packaging/bin/$f > $out/lib/linux-gpo/$f.py
      chmod 755 $out/lib/linux-gpo/$f.py
    done
    # kinit, ldapsearch et smbclient du paquet ; les outils du système (systemctl, dconf, nft…) restent trouvés dans le PATH
    makeWrapper $out/lib/linux-gpo/linux-gpo.py $out/bin/linux-gpo \
      --suffix PATH : ${lib.makeBinPath [ krb5 openldap samba ]}
    mv $out/lib/linux-gpo/acces.py $out/lib/linux-gpo/acces
    sed -E "s#linux-gpo (appliquer|utilisateur)#$out/bin/linux-gpo \1#" packaging/bin/gpupdate > $out/bin/gpupdate
    chmod 755 $out/bin/gpupdate
    runHook postInstall
  '';
  meta = {
    description = "Stratégies de groupe Active Directory (GPO) pour Linux";
    homepage = "https://github.com/jonathan-pp/linux-gpo-agent";
    license = lib.licenses.gpl3Plus;
    platforms = lib.platforms.linux;
    mainProgram = "linux-gpo";
  };
}
