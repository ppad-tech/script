{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# OPTIONS_GHC -fno-warn-unused-imports #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE OverloadedStrings #-}

module Main where

import Bitcoin.Prim.Script
import qualified Crypto.Hash.SHA256 as SHA256
import qualified Crypto.Hash.RIPEMD160 as RIPEMD160
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import qualified Data.Primitive.ByteArray as BA
import Data.Word (Word8)
import Test.Tasty
import qualified Test.Tasty.HUnit as H
import qualified Test.Tasty.QuickCheck as Q

-- types ----------------------------------------------------------------------

newtype BS = BS BS.ByteString
  deriving (Eq, Show)

bytes :: Int -> Q.Gen BS.ByteString
bytes k = do
  l <- Q.chooseInt (0, k)
  v <- Q.vectorOf l Q.arbitrary
  pure (BS.pack v)

instance Q.Arbitrary BS where
  arbitrary = do
    b <- bytes 20_000
    pure (BS b)

newtype HexBS = HexBS BS.ByteString
  deriving (Eq, Show)

instance Q.Arbitrary HexBS where
  arbitrary = do
    b <- bytes 20_000
    pure (HexBS (B16.encode b))

instance Q.Arbitrary BA.ByteArray where
  arbitrary = do
    b <- bytes 20_000
    pure (bs_to_ba b)

-- generated scripts will tend to be pathological due to pushdata
newtype RawScript = RawScript Script
  deriving (Eq, Show)

instance Q.Arbitrary RawScript where
  arbitrary = fmap (RawScript . Script) Q.arbitrary

-- XX better generators for valid and invalid redeemscripts would be nice.
--    pushdata generation needs to be handled carefully.

newtype ValidRedeemScript = ValidRedeemScript Script
  deriving (Eq, Show)

instance Q.Arbitrary ValidRedeemScript where
  arbitrary = do
    l <- Q.chooseInt (0, _MAX_REDEEM_SCRIPT_SIZE)
    -- pushdata must be added with care; easy to blow up quickcheck
    bs <- fmap BS.pack (Q.vectorOf l (Q.chooseEnum (100, 255)))
    pure (ValidRedeemScript (Script (bs_to_ba bs)))

-- too large
newtype InvalidRedeemScript = InvalidRedeemScript Script
  deriving (Eq, Show)

instance Q.Arbitrary InvalidRedeemScript where
  arbitrary = do
    l <- Q.chooseInt (_MAX_REDEEM_SCRIPT_SIZE + 1, 20_000)
    -- pushdata must be added with care; easy to blow up quickcheck
    bs <- fmap BS.pack (Q.vectorOf l (Q.chooseEnum (100, 255)))
    pure (InvalidRedeemScript (Script (bs_to_ba bs)))

-- properties -----------------------------------------------------------------

ba_to_bs_inverts_bs_to_ba :: BS -> Bool
ba_to_bs_inverts_bs_to_ba (BS bs) = ba_to_bs (bs_to_ba bs) == bs

bs_to_ba_inverts_ba_to_bs :: BA.ByteArray -> Bool
bs_to_ba_inverts_ba_to_bs ba = bs_to_ba (ba_to_bs ba) == ba

from_base16_inverts_to_base16 :: RawScript -> Bool
from_base16_inverts_to_base16 (RawScript s) =
  let mscript = from_base16 (to_base16 s)
  in  case mscript of
        Nothing -> False
        Just script -> script == s

to_base16_inverts_from_base16 :: HexBS -> Bool
to_base16_inverts_from_base16 (HexBS bs) =
  let mscript = from_base16 bs
  in  case mscript of
        Nothing -> False
        Just script -> to_base16 script == bs

-- we can only use 'from_script' on non-pathological scripts
--
-- note the converse is not true
to_script_inverts_from_script :: ValidRedeemScript -> Bool
to_script_inverts_from_script (ValidRedeemScript s) =
  let !terms  = from_script s
      !script = to_script terms
  in  script == s

valid_redeem_script_produces_hash :: ValidRedeemScript -> Bool
valid_redeem_script_produces_hash (ValidRedeemScript s) =
  case to_scripthash s of
    Just {} -> True
    _ -> False

invalid_redeem_script_doesnt_produce_hash :: InvalidRedeemScript -> Bool
invalid_redeem_script_doesnt_produce_hash (InvalidRedeemScript s) =
  case to_scripthash s of
    Nothing -> True
    _ -> False

-- assertions -----------------------------------------------------------------

base16_encoded_script_decodes_as_expected :: H.Assertion
base16_encoded_script_decodes_as_expected = do
  let mscript = from_base16 script_base16
  case mscript of
    Nothing -> H.assertFailure "invalid bytestring"
    Just script -> do
      let terms = from_script script
      H.assertEqual mempty terms script_terms

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

-- main -----------------------------------------------------------------------

main :: IO ()
main = defaultMain $
  testGroup "ppad-script" [
    testGroup "property tests" [
      testGroup "inverses" [
          Q.testProperty "ba_to_bs . bs_to_ba ~ id" $
            Q.withMaxSuccess 500 ba_to_bs_inverts_bs_to_ba
        , Q.testProperty "ba_to_bs . bs_to_ba ~ id" $
            Q.withMaxSuccess 500 bs_to_ba_inverts_ba_to_bs
        , Q.testProperty "from_base16 . to_base16 ~ id" $
            Q.withMaxSuccess 500 from_base16_inverts_to_base16
        , Q.testProperty "to_base16 . from_base16 ~ id" $
            Q.withMaxSuccess 500 to_base16_inverts_from_base16
        , Q.testProperty "to_script . from_script ~ id" $
            Q.withMaxSuccess 1000 to_script_inverts_from_script
        ]
    , testGroup "hashes" [
          Q.testProperty "valid redeem script produces scripthash" $
            Q.withMaxSuccess 100 valid_redeem_script_produces_hash
        , Q.testProperty "invalid redeem script doesn't produce scripthash" $
            Q.withMaxSuccess 100 invalid_redeem_script_doesnt_produce_hash
        ]
        ]
  , testGroup "unit tests" [
        H.testCase "base16-encoded script decodes to expected terms"
          base16_encoded_script_decodes_as_expected
      ]
  ]

redeemscript_base16 :: BS.ByteString
redeemscript_base16 = "5221038282263212c609d9ea2a6e3e172de238d8c39cabe56f3f9e451d2c4c7739ba8721031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f2102b4632d08485ff1df2db55b9dafd23347d1c47a457072a1e87be26896549a873753ae"

