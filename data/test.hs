module Test where

import Data.List
import System.Directory
import System.FilePath
import System.Process
import Test.Framework (defaultMain, testGroup, Test)
import Test.Framework.Providers.HUnit
import Test.HUnit hiding (Test)

tests :: [Test]
tests = [
    testGroup "res" [
         testCase "data" test_data
       ]
  ]

----------------------------------------------------------------

test_data :: Assertion
test_data = do
    files <- getDirectoryContents "."
    let dsts = filter (".res" `isSuffixOf`) files
        srcs = map dropExtension dsts
        ts = zip srcs dsts
    mapM_ compareThem ts
  where
    compareThem (src,dst) = do
        putStrLn src
        ss <- readProcess "../pgpdump" ["-u", src] ""
        ds <- readFile dst
        ss @?= ds

----------------------------------------------------------------

main :: Assertion
main = defaultMain tests

