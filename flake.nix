{
  description = "linux-gpo : stratégies de groupe Active Directory (GPO) pour Linux";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  outputs = { self, nixpkgs }:
    let systemes = [ "x86_64-linux" "aarch64-linux" ];
    in {
      packages = nixpkgs.lib.genAttrs systemes (s: {
        default = nixpkgs.legacyPackages.${s}.callPackage ./packaging/nixos/paquet.nix { };
      });
      nixosModules.default = import ./packaging/nixos/module.nix;
    };
}
