{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PackageImports #-}

module Main where

import qualified Bitcoin.Prim.Script as S
import qualified Data.ByteString as BS
import qualified Weigh as W

main :: IO ()
main = W.mainWith $ do
  W.func "bs_to_ba" S.bs_to_ba (BS.replicate 1024 0x00)
