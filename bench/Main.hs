{-# OPTIONS_GHC -fno-warn-unused-imports #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE StandaloneDeriving #-}

module Main where

import Bitcoin.Prim.Script (Term(..), Opcode(..))
import qualified Bitcoin.Prim.Script as S
import Control.DeepSeq
import Criterion.Main
import qualified Data.ByteString as BS
import qualified Data.Primitive.ByteArray as BA
import GHC.Generics

deriving stock instance Generic S.Script
deriving newtype instance NFData S.Script

ba_to_bs :: Benchmark
ba_to_bs = env setup $ \ba ->
    bench "ba_to_bs" $ nf S.ba_to_bs ba
  where
    setup = do
      let s = 1024 :: Int
      ba <- BA.newPinnedByteArray s
      let go !j
            | j == s = pure ()
            | otherwise = do
                BA.writeByteArray ba j (j `rem` 256)
                go (j + 1)
      go 0
      BA.unsafeFreezeByteArray ba

bs_to_ba :: Benchmark
bs_to_ba = bench "bs_to_ba" $ nf S.bs_to_ba (BS.replicate 1024 0x00)

to_script :: Benchmark
to_script = bench "to_script" $ nf S.to_script script where
  script = [
      OPCODE OP_DUP,OPCODE OP_HASH160,OPCODE OP_PUSHBYTES_20,BYTE 0x89,BYTE 0xab
    , BYTE 0xcd,BYTE 0xef,BYTE 0xab,BYTE 0xba,BYTE 0xab,BYTE 0xba,BYTE 0xab
    , BYTE 0xba,BYTE 0xab,BYTE 0xba,BYTE 0xab,BYTE 0xba,BYTE 0xab,BYTE 0xba
    , BYTE 0xab,BYTE 0xba,BYTE 0xab,BYTE 0xba,OPCODE OP_EQUALVERIFY
    , OPCODE OP_CHECKSIG
    ]


main :: IO ()
main = defaultMain [
    ba_to_bs
  , bs_to_ba
  ]


