{
  description = "Kuda - PC monitoring harness with LLM-driven investigation";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-linux" ] (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        lib = pkgs.lib;
        cargoToml = builtins.fromTOML (builtins.readFile ./Cargo.toml);

        # ビルドに必要なファイルだけをストアに入れる（target/ などを除外）
        src = lib.fileset.toSource {
          root = ./.;
          fileset = lib.fileset.unions [
            ./Cargo.toml
            ./Cargo.lock
            ./src
            ./tests
            ./prompts
            ./config.example.toml
          ];
        };

        # p = ビルド先プラットフォームの package set（ネイティブ or pkgsCross.*）
        mkKuda = p:
          let isWindows = p.stdenv.hostPlatform.isWindows;
          in p.rustPlatform.buildRustPackage {
            pname = "kuda";
            version = cargoToml.package.version;
            inherit src;
            cargoLock.lockFile = ./Cargo.lock;

            # mingw の std が要求するスレッドライブラリ
            buildInputs = lib.optionals isWindows [ p.windows.pthreads ];

            # クロスビルドしたテストはビルド機で実行できないためスキップ
            doCheck = !isWindows;

            # 設定例とプロンプトを $out/share/kuda に同梱する
            postInstall = ''
              install -Dm644 config.example.toml $out/share/kuda/config.example.toml
              mkdir -p $out/share/kuda/prompts
              cp -r prompts/. $out/share/kuda/prompts/
            '' + lib.optionalString (!isWindows) ''
              # kudaw は Windows で窓を出さないためのもので、Linux には不要
              rm $out/bin/kudaw
            '';

            meta = {
              description = "PC monitoring harness with LLM-driven investigation";
              mainProgram = "kuda";
              platforms = lib.platforms.linux ++ lib.platforms.windows;
            };
          };
      in
      {
        packages = {
          default = mkKuda pkgs;
          kuda = mkKuda pkgs;
          # Windows 11 向け (x86_64-pc-windows-gnu)。WSL 上でクロスビルドする
          kuda-windows = mkKuda pkgs.pkgsCross.mingwW64;
        };

        apps.default = flake-utils.lib.mkApp { drv = self.packages.${system}.default; };

        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            cargo
            rustc
            rustfmt
            clippy
            rust-analyzer
            sqlite        # DB の中身確認用（ビルドには不要: rusqlite bundled）
            traceroute
          ];
        };

        formatter = pkgs.nixfmt-rfc-style;
      });
}
