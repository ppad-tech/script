# ppad-script

[![](https://img.shields.io/hackage/v/ppad-script?color=blue)](https://hackage.haskell.org/package/ppad-script)
![](https://img.shields.io/badge/license-MIT-brightgreen)

Representations for [Script](https://en.bitcoin.it/wiki/Script),
including abstract syntax, 'ByteArray', and base16-encoded 'ByteString'
versions, as well as fast conversion utilities for working with them.

## Usage

A sample GHCi session:

```
  > :set -XOverloadedStrings
  >
  > -- import qualified
  > import qualified Bitcoin.Prim.Script as S
  >
  > -- base16-encoded p2pkh scriptPubKey
  > let p2pkh = "76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac"
  >
  > -- bytearray-encoded
  > let Just script = S.from_base16 p2pkh
  > script
  Script [ 0x76, 0xa9, 0x14, 0x89, 0xab, 0xcd, 0xef
         , 0xab, 0xba, 0xab, 0xba, 0xab, 0xba, 0xab
         , 0xba, 0xab, 0xba, 0xab, 0xba, 0xab, 0xba
         , 0xab, 0xba, 0x88, 0xac
         ]
  >
  > -- abstract syntax-encoded
  > let terms = S.from_script script
  > terms
  [ OP_DUP, OP_HASH160, OP_PUSHBYTES_20, 0x89, 0xab, 0xcd, 0xef
  , 0xab, 0xba, 0xab, 0xba, 0xab, 0xba, 0xab
  , 0xba, 0xab, 0xba, 0xab, 0xba, 0xab, 0xba
  , 0xab, 0xba, OP_EQUALVERIFY, OP_CHECKSIG
  ]
  >
  > -- round-trip
  > S.to_base16 (S.to_script terms)
  "76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac"
```

## Documentation

Haddocks (API documentation, etc.) are hosted at
[docs.ppad.tech/script](https://docs.ppad.tech/script).

## Performance

The aim is best-in-class performance for highly-auditable Haskell code.

Current benchmark figures on my mid-2020 MacBook Air look like (use
`cabal bench` to run the benchmark suite):

```
  benchmarking to_script
  time                 484.9 ns   (478.3 ns .. 491.4 ns)
                       0.998 R²   (0.997 R² .. 0.999 R²)
  mean                 496.2 ns   (485.8 ns .. 508.1 ns)
  std dev              37.17 ns   (30.08 ns .. 49.95 ns)
  variance introduced by outliers: 83% (severely inflated)

  benchmarking from_script
  time                 380.8 ns   (374.3 ns .. 387.5 ns)
                       0.998 R²   (0.996 R² .. 0.999 R²)
  mean                 383.0 ns   (375.3 ns .. 395.4 ns)
  std dev              31.88 ns   (22.41 ns .. 43.86 ns)
  variance introduced by outliers: 86% (severely inflated)

  benchmarking to_base16
  time                 291.3 ns   (285.6 ns .. 297.9 ns)
                       0.996 R²   (0.995 R² .. 0.998 R²)
  mean                 298.3 ns   (291.8 ns .. 308.1 ns)
  std dev              26.38 ns   (21.25 ns .. 34.27 ns)
  variance introduced by outliers: 87% (severely inflated)

  benchmarking from_base16
  time                 439.1 ns   (429.9 ns .. 448.2 ns)
                       0.997 R²   (0.996 R² .. 0.998 R²)
  mean                 437.9 ns   (429.9 ns .. 450.0 ns)
  std dev              32.67 ns   (26.12 ns .. 44.04 ns)
  variance introduced by outliers: 83% (severely inflated)
```

where the inputs to the above functions are variations of the script found
in the 'Usage' section.

## Security

This library aims at the maximum security achievable in a
garbage-collected language under an optimizing compiler such as GHC, in
which strict constant-timeness can be challenging to achieve.

If you discover any vulnerabilities, please disclose them via
security@ppad.tech.

## Development

You'll require [Nix][nixos] with [flake][flake] support enabled. Enter a
development shell with:

```
$ nix develop
```

Then do e.g.:

```
$ cabal repl ppad-script
```

to get a REPL for the main library.

## Attribution

The list of opcodes was originally taken
verbatim from the 'opcode' crate found in
[rust-bitcoin](https://github.com/rust-bitcoin/rust-bitcoin).

[nixos]: https://nixos.org/
[flake]: https://nixos.org/manual/nix/unstable/command-ref/new-cli/nix3-flake.html
