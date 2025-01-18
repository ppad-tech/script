{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE PackageImports #-}
{-# LANGUAGE StandaloneDeriving #-}

module Main where

import Bitcoin.Prim.Script
import Control.DeepSeq
import qualified Data.ByteString as BS
import GHC.Generics
import qualified Weigh as W

deriving stock instance Generic Script
instance NFData Script

deriving stock instance Generic Term
instance NFData Term

deriving stock instance Generic Opcode
instance NFData Opcode

main :: IO ()
main = W.mainWith $ do
    W.func "bs_to_ba" bs_to_ba (BS.replicate 1024 0x00)
    W.func "ba_to_bs" ba_to_bs ba
    W.func "to_script" to_script terms
    W.func "from_script" from_script script
  where
    ba = bs_to_ba (BS.replicate 1024 0x00)
    script = to_script terms
    terms = [
        OPCODE OP_DUP,OPCODE OP_HASH160,OPCODE OP_PUSHBYTES_20,BYTE 0x89,BYTE 0xab
      , BYTE 0xcd,BYTE 0xef,BYTE 0xab,BYTE 0xba,BYTE 0xab,BYTE 0xba,BYTE 0xab
      , BYTE 0xba,BYTE 0xab,BYTE 0xba,BYTE 0xab,BYTE 0xba,BYTE 0xab,BYTE 0xba
      , BYTE 0xab,BYTE 0xba,BYTE 0xab,BYTE 0xba,OPCODE OP_EQUALVERIFY
      , OPCODE OP_CHECKSIG
      ]

