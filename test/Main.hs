{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE OverloadedStrings #-}

module Main where

import Bitcoin.Prim.Script
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import qualified Data.Primitive.ByteArray as BA
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

-- XX better generators would be nice.
--    pushdata generation needs to be handled carefully.

newtype NonPathologicalScript = NonPathologicalScript Script
  deriving (Eq, Show)

instance Q.Arbitrary NonPathologicalScript where
  arbitrary = do
    l <- Q.chooseInt (0, 1_024)
    -- pushdata must be added with care; easy to blow up quickcheck
    bs <- fmap BS.pack (Q.vectorOf l (Q.chooseEnum (80, 255)))
    pure (NonPathologicalScript (Script (bs_to_ba bs)))

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
-- note the converse (from_script . to_script ~ id) is not true
to_script_inverts_from_script :: NonPathologicalScript -> Bool
to_script_inverts_from_script (NonPathologicalScript s) =
  let !terms  = from_script s
      !script = to_script terms
  in  script == s

-- assertions -----------------------------------------------------------------

decodes_to :: BS.ByteString -> [Term] -> H.Assertion
decodes_to bs ts = do
  let mscript = from_base16 bs
  case mscript of
    Nothing -> H.assertFailure "invalid bytestring"
    Just script -> do
      let terms = from_script script
      H.assertEqual mempty terms ts

-- p2pkh
p2pkh :: BS.ByteString
p2pkh = "76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac"

p2pkh_terms :: [Term]
p2pkh_terms = [
    OPCODE OP_DUP,OPCODE OP_HASH160,OPCODE OP_PUSHBYTES_20,BYTE 0x89,BYTE 0xab
  , BYTE 0xcd,BYTE 0xef,BYTE 0xab,BYTE 0xba,BYTE 0xab,BYTE 0xba,BYTE 0xab
  , BYTE 0xba,BYTE 0xab,BYTE 0xba,BYTE 0xab,BYTE 0xba,BYTE 0xab,BYTE 0xba
  , BYTE 0xab,BYTE 0xba,BYTE 0xab,BYTE 0xba,OPCODE OP_EQUALVERIFY
  , OPCODE OP_CHECKSIG
  ]

p2pkh_script_decodes_as_expected :: H.Assertion
p2pkh_script_decodes_as_expected = p2pkh `decodes_to` p2pkh_terms

-- p2sh
p2sh :: BS.ByteString
p2sh = "5221038282263212c609d9ea2a6e3e172de238d8c39cabe56f3f9e451d2c4c7739ba8721031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f2102b4632d08485ff1df2db55b9dafd23347d1c47a457072a1e87be26896549a873753ae"

p2sh_terms :: [Term]
p2sh_terms = [OPCODE OP_2,OPCODE OP_PUSHBYTES_33,BYTE 0x03,BYTE 0x82,BYTE 0x82,BYTE 0x26,BYTE 0x32,BYTE 0x12,BYTE 0xc6,BYTE 0x09,BYTE 0xd9,BYTE 0xea,BYTE 0x2a,BYTE 0x6e,BYTE 0x3e,BYTE 0x17,BYTE 0x2d,BYTE 0xe2,BYTE 0x38,BYTE 0xd8,BYTE 0xc3,BYTE 0x9c,BYTE 0xab,BYTE 0xe5,BYTE 0x6f,BYTE 0x3f,BYTE 0x9e,BYTE 0x45,BYTE 0x1d,BYTE 0x2c,BYTE 0x4c,BYTE 0x77,BYTE 0x39,BYTE 0xba,BYTE 0x87,OPCODE OP_PUSHBYTES_33,BYTE 0x03,BYTE 0x1b,BYTE 0x84,BYTE 0xc5,BYTE 0x56,BYTE 0x7b,BYTE 0x12,BYTE 0x64,BYTE 0x40,BYTE 0x99,BYTE 0x5d,BYTE 0x3e,BYTE 0xd5,BYTE 0xaa,BYTE 0xba,BYTE 0x05,BYTE 0x65,BYTE 0xd7,BYTE 0x1e,BYTE 0x18,BYTE 0x34,BYTE 0x60,BYTE 0x48,BYTE 0x19,BYTE 0xff,BYTE 0x9c,BYTE 0x17,BYTE 0xf5,BYTE 0xe9,BYTE 0xd5,BYTE 0xdd,BYTE 0x07,BYTE 0x8f,OPCODE OP_PUSHBYTES_33,BYTE 0x02,BYTE 0xb4,BYTE 0x63,BYTE 0x2d,BYTE 0x08,BYTE 0x48,BYTE 0x5f,BYTE 0xf1,BYTE 0xdf,BYTE 0x2d,BYTE 0xb5,BYTE 0x5b,BYTE 0x9d,BYTE 0xaf,BYTE 0xd2,BYTE 0x33,BYTE 0x47,BYTE 0xd1,BYTE 0xc4,BYTE 0x7a,BYTE 0x45,BYTE 0x70,BYTE 0x72,BYTE 0xa1,BYTE 0xe8,BYTE 0x7b,BYTE 0xe2,BYTE 0x68,BYTE 0x96,BYTE 0x54,BYTE 0x9a,BYTE 0x87,BYTE 0x37,OPCODE OP_3,OPCODE OP_CHECKMULTISIG]

p2sh_script_decodes_as_expected :: H.Assertion
p2sh_script_decodes_as_expected = p2sh `decodes_to` p2sh_terms

-- p2wpkh
p2wpkh :: BS.ByteString
p2wpkh = "0014b472a266d0bd89c13706a4132ccfb16f7c3b9fcb"

p2wpkh_terms :: [Term]
p2wpkh_terms = [OPCODE OP_PUSHBYTES_0,OPCODE OP_PUSHBYTES_20,BYTE 0xb4,BYTE 0x72,BYTE 0xa2,BYTE 0x66,BYTE 0xd0,BYTE 0xbd,BYTE 0x89,BYTE 0xc1,BYTE 0x37,BYTE 0x06,BYTE 0xa4,BYTE 0x13,BYTE 0x2c,BYTE 0xcf,BYTE 0xb1,BYTE 0x6f,BYTE 0x7c,BYTE 0x3b,BYTE 0x9f,BYTE 0xcb]

p2wpkh_script_decodes_as_expected :: H.Assertion
p2wpkh_script_decodes_as_expected = p2wpkh `decodes_to` p2wpkh_terms

-- p2sh-p2wpkh

p2sh_p2wpkh :: BS.ByteString
p2sh_p2wpkh = "a9149c1185a5c5e9fc54612808977ee8f548b2258d3187"

p2sh_p2wpkh_terms :: [Term]
p2sh_p2wpkh_terms = [OPCODE OP_HASH160,OPCODE OP_PUSHBYTES_20,BYTE 0x9c,BYTE 0x11,BYTE 0x85,BYTE 0xa5,BYTE 0xc5,BYTE 0xe9,BYTE 0xfc,BYTE 0x54,BYTE 0x61,BYTE 0x28,BYTE 0x08,BYTE 0x97,BYTE 0x7e,BYTE 0xe8,BYTE 0xf5,BYTE 0x48,BYTE 0xb2,BYTE 0x25,BYTE 0x8d,BYTE 0x31,OPCODE OP_EQUAL]

p2sh_p2wpkh_script_decodes_as_expected :: H.Assertion
p2sh_p2wpkh_script_decodes_as_expected =
  p2sh_p2wpkh `decodes_to` p2sh_p2wpkh_terms

-- p2wsh
p2wsh :: BS.ByteString
p2wsh = "0020e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

p2wsh_terms :: [Term]
p2wsh_terms  = [OPCODE OP_PUSHBYTES_0,OPCODE OP_PUSHBYTES_32,BYTE 0xe3,BYTE 0xb0,BYTE 0xc4,BYTE 0x42,BYTE 0x98,BYTE 0xfc,BYTE 0x1c,BYTE 0x14,BYTE 0x9a,BYTE 0xfb,BYTE 0xf4,BYTE 0xc8,BYTE 0x99,BYTE 0x6f,BYTE 0xb9,BYTE 0x24,BYTE 0x27,BYTE 0xae,BYTE 0x41,BYTE 0xe4,BYTE 0x64,BYTE 0x9b,BYTE 0x93,BYTE 0x4c,BYTE 0xa4,BYTE 0x95,BYTE 0x99,BYTE 0x1b,BYTE 0x78,BYTE 0x52,BYTE 0xb8,BYTE 0x55]

p2wsh_script_decodes_as_expected :: H.Assertion
p2wsh_script_decodes_as_expected = p2wsh `decodes_to` p2wsh_terms

-- p2sh-p2wsh

-- identical to p2sh-p2wpkh at the script level

p2sh_p2wsh :: BS.ByteString
p2sh_p2wsh = "a9149c1185a5c5e9fc54612808977ee8f548b2258d3187"

p2sh_p2wsh_terms :: [Term]
p2sh_p2wsh_terms = [OPCODE OP_HASH160,OPCODE OP_PUSHBYTES_20,BYTE 0x9c,BYTE 0x11,BYTE 0x85,BYTE 0xa5,BYTE 0xc5,BYTE 0xe9,BYTE 0xfc,BYTE 0x54,BYTE 0x61,BYTE 0x28,BYTE 0x08,BYTE 0x97,BYTE 0x7e,BYTE 0xe8,BYTE 0xf5,BYTE 0x48,BYTE 0xb2,BYTE 0x25,BYTE 0x8d,BYTE 0x31,OPCODE OP_EQUAL]

p2sh_p2wsh_script_decodes_as_expected :: H.Assertion
p2sh_p2wsh_script_decodes_as_expected =
  p2sh_p2wsh `decodes_to` p2sh_p2wsh_terms

-- main -----------------------------------------------------------------------

main :: IO ()
main = defaultMain $
  testGroup "ppad-script" [
    testGroup "property tests" [
      testGroup "inverses" [
          Q.testProperty "ba_to_bs . bs_to_ba ~ id" $
            Q.withMaxSuccess 100 ba_to_bs_inverts_bs_to_ba
        , Q.testProperty "ba_to_bs . bs_to_ba ~ id" $
            Q.withMaxSuccess 100 bs_to_ba_inverts_ba_to_bs
        , Q.testProperty "from_base16 . to_base16 ~ id" $
            Q.withMaxSuccess 100 from_base16_inverts_to_base16
        , Q.testProperty "to_base16 . from_base16 ~ id" $
            Q.withMaxSuccess 100 to_base16_inverts_from_base16
        , Q.testProperty "to_script . from_script ~ id" $
            Q.withMaxSuccess 1000 to_script_inverts_from_script
        ]
      ]
  , testGroup "unit tests" [
        H.testCase "p2pkh script decodes to expected terms"
          p2pkh_script_decodes_as_expected
      , H.testCase "p2sh script decodes to expected terms"
          p2sh_script_decodes_as_expected
      , H.testCase "p2wpkh script decodes to expected terms"
          p2wpkh_script_decodes_as_expected
      , H.testCase "p2sh-p2wpkh script decodes to expected terms"
          p2sh_p2wpkh_script_decodes_as_expected
      , H.testCase "p2wsh script decodes to expected terms"
          p2wsh_script_decodes_as_expected
      , H.testCase "p2sh-p2wsh script decodes to expected terms"
          p2sh_p2wsh_script_decodes_as_expected
      ]
  ]

