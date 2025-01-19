{
  description = "Primitive Script support for Haskell.";

  inputs = {
    ppad-base16 = {
      type = "git";
      url  = "git://git.ppad.tech/base16.git";
      ref  = "master";
    };
    flake-utils.follows = "ppad-base16/flake-utils";
    nixpkgs.follows = "ppad-base16/nixpkgs";
  };

  outputs = {   self, nixpkgs, flake-utils
              , ppad-base16
            }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        lib = "ppad-script";

        pkgs = import nixpkgs { inherit system; };
        hlib = pkgs.haskell.lib;

        base16 = ppad-base16.packages.${system}.default;

        hpkgs = pkgs.haskell.packages.ghc981.extend (new: old: {
          ppad-base16 = base16;
          ${lib} = old.callCabal2nixWithOptions lib ./. "--enable-profiling" {
            ppad-base16 = new.ppad-base16;
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

