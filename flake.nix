{
  description = "Read-only operational and policy monitoring for AdGuard Home";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      rust-overlay,
    }:
    let
      supportedSystems = [
        "aarch64-darwin"
        "aarch64-linux"
        "x86_64-linux"
      ];
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ rust-overlay.overlays.default ];
          };
          rustToolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
          rustPlatform = pkgs.makeRustPlatform {
            cargo = rustToolchain;
            rustc = rustToolchain;
          };
          cleanSource = pkgs.lib.cleanSourceWith {
            src = ./.;
            filter =
              path: type:
              let
                name = baseNameOf path;
              in
              !builtins.elem name [
                ".direnv"
                ".git"
                "target"
              ]
              && !(type == "regular" && pkgs.lib.hasSuffix ".sqlite" name);
          };
        in
        {
          default = rustPlatform.buildRustPackage {
            pname = "adguard-sentinel";
            version = "0.1.3";
            src = cleanSource;
            cargoLock.lockFile = ./Cargo.lock;
            doCheck = true;
            meta = {
              description = "Read-only operational and policy monitoring for AdGuard Home";
              license = with pkgs.lib.licenses; [
                asl20
                mit
              ];
              mainProgram = "adguard-sentinel";
              platforms = [
                "aarch64-darwin"
                "aarch64-linux"
                "x86_64-linux"
              ];
            };
          };
        }
      );

      checks = forAllSystems (system: {
        package = self.packages.${system}.default;
      });

      devShells = forAllSystems (
        system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ rust-overlay.overlays.default ];
          };
          rustToolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
        in
        {
          default = pkgs.mkShell {
            packages = [
              pkgs.cargo-deny
              pkgs.git
              pkgs.just
              pkgs.nixfmt
              rustToolchain
            ];
          };
        }
      );

      formatter = forAllSystems (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
        in
        pkgs.nixfmt
      );
    };
}
