{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE BinaryLiterals #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE ViewPatterns #-}

module Bitcoin.Prim.Script where

import Control.Monad.ST
import qualified Crypto.Hash.RIPEMD160 as RIPEMD160
import qualified Crypto.Hash.SHA256 as SHA256
import qualified Data.Bits as B
import Data.Bits ((.&.), (.|.))
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Internal as BI
import qualified Data.ByteString.Builder as BSB
import qualified Data.ByteString.Unsafe as BU
import qualified Data.Char as C
import qualified Data.Primitive.ByteArray as BA
import Data.Word (Word8, Word16, Word32)

import GHC.ForeignPtr
import System.IO.Unsafe

-- max redeem script size for a P2SH output
_MAX_REDEEM_SCRIPT_SIZE :: Int
_MAX_REDEEM_SCRIPT_SIZE = 520

-- max witness script size
_MAX_WITNESS_SCRIPT_SIZE :: Int
_MAX_WITNESS_SCRIPT_SIZE = 10_000

toStrict :: BSB.Builder -> BS.ByteString
toStrict = BS.toStrict . BSB.toLazyByteString
{-# INLINE toStrict #-}

fi :: (Num a, Integral b) => b -> a
fi = fromIntegral
{-# INLINE fi #-}

newtype Script = Script BA.ByteArray
  deriving (Eq, Show)

newtype ScriptHash = ScriptHash BS.ByteString
  deriving Eq

hex_charset :: BS.ByteString
hex_charset = "0123456789abcdef"

-- split a word8 into a pair of its high and low bits
-- only used for show instances
hilo :: Word8 -> (Word8, Word8)
hilo b =
  let hi = BU.unsafeIndex hex_charset (fi b `B.shiftR` 4)
      lo = BU.unsafeIndex hex_charset (fi b .&. 0b00001111)
  in  (hi, lo)

instance Show ScriptHash where
  show (ScriptHash bs) = "ScriptHash 0x" <> go bs where
    go b = case BS.uncons b of
      Nothing -> mempty
      Just (h, t) ->
        let (hi, lo) = hilo h
        in  C.chr (fi hi) : C.chr (fi lo) : go t

newtype WitnessScriptHash = WitnessScriptHash BS.ByteString
  deriving Eq

instance Show WitnessScriptHash where
  show (WitnessScriptHash bs) = "WitnessScriptHash 0x" <> go bs where
    go b = case BS.uncons b of
      Nothing -> mempty
      Just (h, t) ->
        let (hi, lo) = hilo h
        in  C.chr (fi hi) : C.chr (fi lo) : go t

-- | Convert a 'Script' to a base16-encoded ByteString.
to_base16 :: Script -> BS.ByteString
to_base16 (Script ba) = B16.encode (ba_to_bs ba)

-- | Convert a base16-encoded ByteString to a Script.
from_base16 :: BS.ByteString -> Maybe Script
from_base16 b16 = do
  bs <- B16.decode b16
  pure (Script (bs_to_ba bs))

-- Convert a pinned ByteArray to a ByteString.
ba_to_bs :: BA.ByteArray -> BS.ByteString
ba_to_bs ba = unsafeDupablePerformIO $ do
  let l = BA.sizeofByteArray ba
  buf <- mallocPlainForeignPtrBytes l
  withForeignPtr buf $ \p ->
    BA.copyByteArrayToAddr p ba 0 l
  pure (BI.BS buf l)

-- Convert a ByteString to a pinned ByteArray.
bs_to_ba :: BS.ByteString -> BA.ByteArray
bs_to_ba bs@(BI.PS _ _ l) = runST $ do
  arr <- BA.newPinnedByteArray l
  let go !j
        | j == l = pure ()
        | otherwise = do
            let !b = BU.unsafeIndex bs j
            BA.writeByteArray arr j b
            go (succ j)
  go 0
  BA.unsafeFreezeByteArray arr

data Term =
    OPCODE Opcode
  | BYTE Word8
  deriving Eq

instance Show Term where
  show (OPCODE o) = show o
  show (BYTE w) =
    let (hi, lo) = hilo w
    in  "0x" <> (C.chr (fi hi) : C.chr (fi lo) : [])

to_script :: [Term] -> Script
to_script = Script . BA.byteArrayFromList . fmap term_to_byte where
  term_to_byte :: Term -> Word8
  term_to_byte = \case
    OPCODE op -> fi (fromEnum op)
    BYTE w8 -> w8
  {-# INLINE term_to_byte #-}

from_script :: Script -> [Term]
from_script (Script bs) = go 0 where
  l = BA.sizeofByteArray bs

  read_pay cur end
    | cur == end = go cur
    | otherwise  = BYTE (BA.indexByteArray bs cur) : read_pay (cur + 1) end

  go j
    | j == l = mempty
    | otherwise =
        let op = toEnum (fi (BA.indexByteArray bs j :: Word8)) :: Opcode
        in  case pushbytes op of
              Just i  -> OPCODE op : read_pay (j + 1) (j + 1 + i)
              Nothing -> OPCODE op : case op of
                OP_PUSHDATA1 ->
                  let len_idx = j + 1
                      pay_len = BA.indexByteArray bs len_idx :: Word8
                  in    BYTE pay_len
                      : read_pay (len_idx + 1) (len_idx + 1 + fi pay_len)

                OP_PUSHDATA2 ->
                  let len_idx = j + 1
                      w8_0 = BA.indexByteArray bs len_idx :: Word8
                      w8_1 = BA.indexByteArray bs (len_idx + 1) :: Word8
                      pay_len = fi w8_0 .|. fi w8_1 `B.shiftL` 8 :: Word16
                  in    BYTE w8_0 : BYTE w8_1
                      : read_pay (len_idx + 2) (len_idx + 2 + fi pay_len)

                OP_PUSHDATA4 ->
                  let len_idx = j + 1
                      w8_0 = BA.indexByteArray bs len_idx :: Word8
                      w8_1 = BA.indexByteArray bs (len_idx + 1) :: Word8
                      w8_2 = BA.indexByteArray bs (len_idx + 2) :: Word8
                      w8_3 = BA.indexByteArray bs (len_idx + 3) :: Word8
                      pay_len = fi w8_0
                            .|. fi w8_1 `B.shiftL` 8
                            .|. fi w8_2 `B.shiftL` 16
                            .|. fi w8_3 `B.shiftL` 24 :: Word32
                  in    BYTE w8_0 : BYTE w8_1 : BYTE w8_2 : BYTE w8_3
                      : read_pay (len_idx + 4) (len_idx + 4 + fi pay_len)

                _ -> go (succ j)

to_scripthash :: Script -> Maybe ScriptHash
to_scripthash (Script bs)
  | BA.sizeofByteArray bs > _MAX_REDEEM_SCRIPT_SIZE = Nothing
  | otherwise = Just (ScriptHash (RIPEMD160.hash (SHA256.hash (ba_to_bs bs))))

to_witness_scripthash :: Script -> Maybe WitnessScriptHash
to_witness_scripthash (Script bs)
  | BA.sizeofByteArray bs > _MAX_WITNESS_SCRIPT_SIZE = Nothing
  | otherwise = Just (WitnessScriptHash (SHA256.hash (ba_to_bs bs)))

pushbytes :: Opcode -> Maybe Int
pushbytes = \case
  OP_PUSHBYTES_0  -> Just 00
  OP_PUSHBYTES_1  -> Just 01
  OP_PUSHBYTES_2  -> Just 02
  OP_PUSHBYTES_3  -> Just 03
  OP_PUSHBYTES_4  -> Just 04
  OP_PUSHBYTES_5  -> Just 05
  OP_PUSHBYTES_6  -> Just 06
  OP_PUSHBYTES_7  -> Just 07
  OP_PUSHBYTES_8  -> Just 08
  OP_PUSHBYTES_9  -> Just 09
  OP_PUSHBYTES_10 -> Just 10
  OP_PUSHBYTES_11 -> Just 11
  OP_PUSHBYTES_12 -> Just 12
  OP_PUSHBYTES_13 -> Just 13
  OP_PUSHBYTES_14 -> Just 14
  OP_PUSHBYTES_15 -> Just 15
  OP_PUSHBYTES_16 -> Just 16
  OP_PUSHBYTES_17 -> Just 17
  OP_PUSHBYTES_18 -> Just 18
  OP_PUSHBYTES_19 -> Just 19
  OP_PUSHBYTES_20 -> Just 20
  OP_PUSHBYTES_21 -> Just 21
  OP_PUSHBYTES_22 -> Just 22
  OP_PUSHBYTES_23 -> Just 23
  OP_PUSHBYTES_24 -> Just 24
  OP_PUSHBYTES_25 -> Just 25
  OP_PUSHBYTES_26 -> Just 26
  OP_PUSHBYTES_27 -> Just 27
  OP_PUSHBYTES_28 -> Just 28
  OP_PUSHBYTES_29 -> Just 29
  OP_PUSHBYTES_30 -> Just 30
  OP_PUSHBYTES_31 -> Just 31
  OP_PUSHBYTES_32 -> Just 32
  OP_PUSHBYTES_33 -> Just 33
  OP_PUSHBYTES_34 -> Just 34
  OP_PUSHBYTES_35 -> Just 35
  OP_PUSHBYTES_36 -> Just 36
  OP_PUSHBYTES_37 -> Just 37
  OP_PUSHBYTES_38 -> Just 38
  OP_PUSHBYTES_39 -> Just 39
  OP_PUSHBYTES_40 -> Just 40
  OP_PUSHBYTES_41 -> Just 41
  OP_PUSHBYTES_42 -> Just 42
  OP_PUSHBYTES_43 -> Just 43
  OP_PUSHBYTES_44 -> Just 44
  OP_PUSHBYTES_45 -> Just 45
  OP_PUSHBYTES_46 -> Just 46
  OP_PUSHBYTES_47 -> Just 47
  OP_PUSHBYTES_48 -> Just 48
  OP_PUSHBYTES_49 -> Just 49
  OP_PUSHBYTES_50 -> Just 50
  OP_PUSHBYTES_51 -> Just 51
  OP_PUSHBYTES_52 -> Just 52
  OP_PUSHBYTES_53 -> Just 53
  OP_PUSHBYTES_54 -> Just 54
  OP_PUSHBYTES_55 -> Just 55
  OP_PUSHBYTES_56 -> Just 56
  OP_PUSHBYTES_57 -> Just 57
  OP_PUSHBYTES_58 -> Just 58
  OP_PUSHBYTES_59 -> Just 59
  OP_PUSHBYTES_60 -> Just 60
  OP_PUSHBYTES_61 -> Just 61
  OP_PUSHBYTES_62 -> Just 62
  OP_PUSHBYTES_63 -> Just 63
  OP_PUSHBYTES_64 -> Just 64
  OP_PUSHBYTES_65 -> Just 65
  OP_PUSHBYTES_66 -> Just 66
  OP_PUSHBYTES_67 -> Just 67
  OP_PUSHBYTES_68 -> Just 68
  OP_PUSHBYTES_69 -> Just 69
  OP_PUSHBYTES_70 -> Just 70
  OP_PUSHBYTES_71 -> Just 71
  OP_PUSHBYTES_72 -> Just 72
  OP_PUSHBYTES_73 -> Just 73
  OP_PUSHBYTES_74 -> Just 74
  OP_PUSHBYTES_75 -> Just 75
  _ -> Nothing

-- | Primitive opcodes.
data Opcode =
    OP_PUSHBYTES_0
  | OP_PUSHBYTES_1
  | OP_PUSHBYTES_2
  | OP_PUSHBYTES_3
  | OP_PUSHBYTES_4
  | OP_PUSHBYTES_5
  | OP_PUSHBYTES_6
  | OP_PUSHBYTES_7
  | OP_PUSHBYTES_8
  | OP_PUSHBYTES_9
  | OP_PUSHBYTES_10
  | OP_PUSHBYTES_11
  | OP_PUSHBYTES_12
  | OP_PUSHBYTES_13
  | OP_PUSHBYTES_14
  | OP_PUSHBYTES_15
  | OP_PUSHBYTES_16
  | OP_PUSHBYTES_17
  | OP_PUSHBYTES_18
  | OP_PUSHBYTES_19
  | OP_PUSHBYTES_20
  | OP_PUSHBYTES_21
  | OP_PUSHBYTES_22
  | OP_PUSHBYTES_23
  | OP_PUSHBYTES_24
  | OP_PUSHBYTES_25
  | OP_PUSHBYTES_26
  | OP_PUSHBYTES_27
  | OP_PUSHBYTES_28
  | OP_PUSHBYTES_29
  | OP_PUSHBYTES_30
  | OP_PUSHBYTES_31
  | OP_PUSHBYTES_32
  | OP_PUSHBYTES_33
  | OP_PUSHBYTES_34
  | OP_PUSHBYTES_35
  | OP_PUSHBYTES_36
  | OP_PUSHBYTES_37
  | OP_PUSHBYTES_38
  | OP_PUSHBYTES_39
  | OP_PUSHBYTES_40
  | OP_PUSHBYTES_41
  | OP_PUSHBYTES_42
  | OP_PUSHBYTES_43
  | OP_PUSHBYTES_44
  | OP_PUSHBYTES_45
  | OP_PUSHBYTES_46
  | OP_PUSHBYTES_47
  | OP_PUSHBYTES_48
  | OP_PUSHBYTES_49
  | OP_PUSHBYTES_50
  | OP_PUSHBYTES_51
  | OP_PUSHBYTES_52
  | OP_PUSHBYTES_53
  | OP_PUSHBYTES_54
  | OP_PUSHBYTES_55
  | OP_PUSHBYTES_56
  | OP_PUSHBYTES_57
  | OP_PUSHBYTES_58
  | OP_PUSHBYTES_59
  | OP_PUSHBYTES_60
  | OP_PUSHBYTES_61
  | OP_PUSHBYTES_62
  | OP_PUSHBYTES_63
  | OP_PUSHBYTES_64
  | OP_PUSHBYTES_65
  | OP_PUSHBYTES_66
  | OP_PUSHBYTES_67
  | OP_PUSHBYTES_68
  | OP_PUSHBYTES_69
  | OP_PUSHBYTES_70
  | OP_PUSHBYTES_71
  | OP_PUSHBYTES_72
  | OP_PUSHBYTES_73
  | OP_PUSHBYTES_74
  | OP_PUSHBYTES_75
  | OP_PUSHDATA1
  | OP_PUSHDATA2
  | OP_PUSHDATA4
  | OP_PUSHNUM_NEG1
  | OP_RESERVED
  | OP_PUSHNUM_1
  | OP_PUSHNUM_2
  | OP_PUSHNUM_3
  | OP_PUSHNUM_4
  | OP_PUSHNUM_5
  | OP_PUSHNUM_6
  | OP_PUSHNUM_7
  | OP_PUSHNUM_8
  | OP_PUSHNUM_9
  | OP_PUSHNUM_10
  | OP_PUSHNUM_11
  | OP_PUSHNUM_12
  | OP_PUSHNUM_13
  | OP_PUSHNUM_14
  | OP_PUSHNUM_15
  | OP_PUSHNUM_16
  | OP_NOP
  | OP_VER
  | OP_IF
  | OP_NOTIF
  | OP_VERIF
  | OP_VERNOTIF
  | OP_ELSE
  | OP_ENDIF
  | OP_VERIFY
  | OP_RETURN
  | OP_TOALTSTACK
  | OP_FROMALTSTACK
  | OP_2DROP
  | OP_2DUP
  | OP_3DUP
  | OP_2OVER
  | OP_2ROT
  | OP_2SWAP
  | OP_IFDUP
  | OP_DEPTH
  | OP_DROP
  | OP_DUP
  | OP_NIP
  | OP_OVER
  | OP_PICK
  | OP_ROLL
  | OP_ROT
  | OP_SWAP
  | OP_TUCK
  | OP_CAT
  | OP_SUBSTR
  | OP_LEFT
  | OP_RIGHT
  | OP_SIZE
  | OP_INVERT
  | OP_AND
  | OP_OR
  | OP_XOR
  | OP_EQUAL
  | OP_EQUALVERIFY
  | OP_RESERVED1
  | OP_RESERVED2
  | OP_1ADD
  | OP_1SUB
  | OP_2MUL
  | OP_2DIV
  | OP_NEGATE
  | OP_ABS
  | OP_NOT
  | OP_0NOTEQUAL
  | OP_ADD
  | OP_SUB
  | OP_MUL
  | OP_DIV
  | OP_MOD
  | OP_LSHIFT
  | OP_RSHIFT
  | OP_BOOLAND
  | OP_BOOLOR
  | OP_NUMEQUAL
  | OP_NUMEQUALVERIFY
  | OP_NUMNOTEQUAL
  | OP_LESSTHAN
  | OP_GREATERTHAN
  | OP_LESSTHANOREQUAL
  | OP_GREATERTHANOREQUAL
  | OP_MIN
  | OP_MAX
  | OP_WITHIN
  | OP_RIPEMD160
  | OP_SHA1
  | OP_SHA256
  | OP_HASH160
  | OP_HASH256
  | OP_CODESEPARATOR
  | OP_CHECKSIG
  | OP_CHECKSIGVERIFY
  | OP_CHECKMULTISIG
  | OP_CHECKMULTISIGVERIFY
  | OP_NOP1
  | OP_CLTV
  | OP_CSV
  | OP_NOP4
  | OP_NOP5
  | OP_NOP6
  | OP_NOP7
  | OP_NOP8
  | OP_NOP9
  | OP_NOP10
  | OP_CHECKSIGADD
  | OP_RETURN_187
  | OP_RETURN_188
  | OP_RETURN_189
  | OP_RETURN_190
  | OP_RETURN_191
  | OP_RETURN_192
  | OP_RETURN_193
  | OP_RETURN_194
  | OP_RETURN_195
  | OP_RETURN_196
  | OP_RETURN_197
  | OP_RETURN_198
  | OP_RETURN_199
  | OP_RETURN_200
  | OP_RETURN_201
  | OP_RETURN_202
  | OP_RETURN_203
  | OP_RETURN_204
  | OP_RETURN_205
  | OP_RETURN_206
  | OP_RETURN_207
  | OP_RETURN_208
  | OP_RETURN_209
  | OP_RETURN_210
  | OP_RETURN_211
  | OP_RETURN_212
  | OP_RETURN_213
  | OP_RETURN_214
  | OP_RETURN_215
  | OP_RETURN_216
  | OP_RETURN_217
  | OP_RETURN_218
  | OP_RETURN_219
  | OP_RETURN_220
  | OP_RETURN_221
  | OP_RETURN_222
  | OP_RETURN_223
  | OP_RETURN_224
  | OP_RETURN_225
  | OP_RETURN_226
  | OP_RETURN_227
  | OP_RETURN_228
  | OP_RETURN_229
  | OP_RETURN_230
  | OP_RETURN_231
  | OP_RETURN_232
  | OP_RETURN_233
  | OP_RETURN_234
  | OP_RETURN_235
  | OP_RETURN_236
  | OP_RETURN_237
  | OP_RETURN_238
  | OP_RETURN_239
  | OP_RETURN_240
  | OP_RETURN_241
  | OP_RETURN_242
  | OP_RETURN_243
  | OP_RETURN_244
  | OP_RETURN_245
  | OP_RETURN_246
  | OP_RETURN_247
  | OP_RETURN_248
  | OP_RETURN_249
  | OP_RETURN_250
  | OP_RETURN_251
  | OP_RETURN_252
  | OP_RETURN_253
  | OP_RETURN_254
  | OP_INVALIDOPCODE
  deriving (Eq, Show, Enum)

