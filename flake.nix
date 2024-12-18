{
  description = "Haskell Bitcoin primitives.";

  inputs = {
    ppad-sha256 = {
      type = "git";
      url  = "git://git.ppad.tech/sha256.git";
      ref  = "master";
    };
    ppad-base58 = {
      type = "git";
      url  = "git://git.ppad.tech/base58.git";
      ref  = "master";
    };
    ppad-bech32 = {
      type = "git";
      url  = "git://git.ppad.tech/bech32.git";
      ref  = "master";
    };
    ppad-ripemd160 = {
      type = "git";
      url  = "git://git.ppad.tech/ripemd160.git";
      ref  = "master";
    };
    flake-utils.follows = "ppad-sha256/flake-utils";
    nixpkgs.follows = "ppad-sha256/nixpkgs";
  };

  outputs = { self, nixpkgs, flake-utils,
              ppad-sha256, ppad-ripemd160, ppad-bech32, ppad-base58 }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        lib = "ppad-btcprim";

        pkgs = import nixpkgs { inherit system; };
        hlib = pkgs.haskell.lib;

        sha256 = ppad-sha256.packages.${system}.default;
        bech32 = ppad-bech32.packages.${system}.default;
        base58 = ppad-base58.packages.${system}.default;
        ripemd160 = ppad-ripemd160.packages.${system}.default;

        hpkgs = pkgs.haskell.packages.ghc981.extend (new: old: {
          ppad-sha256 = sha256;
          ppad-bech32 = bech32;
          ppad-base58 = base58;
          ppad-ripemd160 = ripemd160;
          ${lib} = old.callCabal2nixWithOptions lib ./. "--enable-profiling" {
            ppad-sha256 = new.ppad-sha256;
            ppad-bech32 = new.ppad-bech32;
            ppad-base58 = new.ppad-base58;
            ppad-ripemd160 = new.ppad-ripemd160;
          };
        });

        cc    = pkgs.stdenv.cc;
        ghc   = hpkgs.ghc;
        cabal = hpkgs.cabal-install;
      in
        {
          packages.default = hpkgs.${lib};

          devShells.default = hpkgs.shellFor {
            packages = p: [
              (hlib.doBenchmark p.${lib})
            ];

            buildInputs = [
              cabal
              cc
            ];

            inputsFrom = builtins.attrValues self.packages.${system};

            doBenchmark = true;

            shellHook = ''
              PS1="[${lib}] \w$ "
              echo "entering ${system} shell, using"
              echo "cc:    $(${cc}/bin/cc --version)"
              echo "ghc:   $(${ghc}/bin/ghc --version)"
              echo "cabal: $(${cabal}/bin/cabal --version)"
            '';
          };
        }
      );
}

