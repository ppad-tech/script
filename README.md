# script

[![](https://img.shields.io/hackage/v/ppad-script?color=blue)](https://hackage.haskell.org/package/ppad-script)
![](https://img.shields.io/badge/license-MIT-brightgreen)
[![](https://img.shields.io/badge/haddock-script-lightblue)](https://docs.ppad.tech/script)

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

Current benchmark figures on my M4 Silicon MacBook Air look like (use
`cabal bench` to run the benchmark suite):

```
  benchmarking to_script
  time                 228.1 ns   (227.9 ns .. 228.6 ns)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 228.9 ns   (228.5 ns .. 230.0 ns)
  std dev              2.167 ns   (1.241 ns .. 3.840 ns)

  benchmarking from_script
  time                 329.3 ns   (327.4 ns .. 331.4 ns)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 331.3 ns   (330.1 ns .. 332.3 ns)
  std dev              3.502 ns   (2.723 ns .. 4.492 ns)

  benchmarking to_base16
  time                 150.3 ns   (149.6 ns .. 150.9 ns)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 149.6 ns   (149.3 ns .. 149.9 ns)
  std dev              1.101 ns   (884.2 ps .. 1.334 ns)

  benchmarking from_base16
  time                 101.1 ns   (100.8 ns .. 101.4 ns)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 100.7 ns   (100.4 ns .. 101.0 ns)
  std dev              949.7 ps   (766.3 ps .. 1.162 ns)
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
