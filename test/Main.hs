{-# LANGUAGE OverloadedStrings #-}

module Main where

import qualified Data.ByteString as BS
import Bitcoin.Prim.Script
import Test.Tasty
import Test.Tasty.HUnit

main :: IO ()
main = pure ()

-- p2pkh

-- https://en.bitcoin.it/wiki/Script#
-- Standard_Transaction_to_Bitcoin_address_(pay-to-pubkey-hash)
script_base16 :: BS.ByteString
script_base16 = "76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac"

-- https://en.bitcoin.it/wiki/Script#
-- Standard_Transaction_to_Bitcoin_address_(pay-to-pubkey-hash)
script_terms :: [Term]
script_terms = [
    OPCODE OP_DUP,OPCODE OP_HASH160,OPCODE OP_PUSHBYTES_20,BYTE 0x89,BYTE 0xab
  , BYTE 0xcd,BYTE 0xef,BYTE 0xab,BYTE 0xba,BYTE 0xab,BYTE 0xba,BYTE 0xab
  , BYTE 0xba,BYTE 0xab,BYTE 0xba,BYTE 0xab,BYTE 0xba,BYTE 0xab,BYTE 0xba
  , BYTE 0xab,BYTE 0xba,BYTE 0xab,BYTE 0xba,OPCODE OP_EQUALVERIFY
  , OPCODE OP_CHECKSIG
  ]

-- p2sh

redeemscript_base16 :: BS.ByteString
redeemscript_base16 = "5221038282263212c609d9ea2a6e3e172de238d8c39cabe56f3f9e451d2c4c7739ba8721031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f2102b4632d08485ff1df2db55b9dafd23347d1c47a457072a1e87be26896549a873753ae"

