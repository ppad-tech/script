{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# OPTIONS_GHC -fno-warn-unused-imports #-}
{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE OverloadedStrings #-}

module Main where

import Bitcoin.Prim.Script
import qualified Crypto.Hash.SHA256 as SHA256
import qualified Crypto.Hash.RIPEMD160 as RIPEMD160
import qualified Data.ByteString as BS
import qualified Data.Primitive.ByteArray as BA
import Data.Word (Word8)
import Test.Tasty
import qualified Test.Tasty.HUnit as H
import qualified Test.Tasty.QuickCheck as Q

-- types ----------------------------------------------------------------------

newtype BS = BS BS.ByteString
  deriving (Eq, Show)

bytes_list :: Int -> Q.Gen [Word8]
bytes_list k = do
  l <- Q.chooseInt (0, k)
  Q.vectorOf l Q.arbitrary

bytes :: Int -> Q.Gen BS.ByteString
bytes k = do
  l <- Q.chooseInt (0, k)
  v <- Q.vectorOf l Q.arbitrary
  pure (BS.pack v)

instance Q.Arbitrary BS where
  arbitrary = do
    b <- bytes 10_000
    pure (BS b)

instance Q.Arbitrary BA.ByteArray where
  arbitrary = do
    b <- bytes_list 10_000
    pure (BA.byteArrayFromList b)

instance Q.Arbitrary Script where
  arbitrary = fmap Script Q.arbitrary

-- properties -----------------------------------------------------------------

from_base16_inverts_to_base16 :: Script -> Bool
from_base16_inverts_to_base16 s =
  let mscript = from_base16 (to_base16 s)
  in  case mscript of
        Nothing -> False
        Just script -> script == s

to_script_inverts_from_script :: Script -> Bool
to_script_inverts_from_script s =
  let script = to_script (from_script s)
  in  script == s

-- main -----------------------------------------------------------------------

main :: IO ()
main = defaultMain $
  testGroup "ppad-base16" [
    testGroup "property tests" [
      Q.testProperty "from_base16 . to_base16 ~ id" $
        Q.withMaxSuccess 100 from_base16_inverts_to_base16
    -- , Q.testProperty "to_script . from_script ~ id" $
    --     Q.withMaxSuccess 100 to_script_inverts_from_script
    ]
  ]







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

