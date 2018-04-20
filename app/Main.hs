{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE RecordWildCards    #-}
{-# OPTIONS_GHC -fno-cse #-}

module Main where

import           Foreign
import           Network.Pcap
import           System.Console.CmdArgs
import qualified System.IO              as SIO

data TcpGraph = TcpGraph {
    iface  :: String,
    period :: Int,
    filt   :: [String]
} deriving (Show, Data, Typeable)

tcpGraph = TcpGraph {
    iface = def &= name "i",
    period = def,
    filt = def &= args
}

printErr = SIO.hPutStr SIO.stderr

main :: IO ()
main = do
    TcpGraph {..} <- cmdArgs tcpGraph
    dev <- if iface == ""
        then findDev
        else return iface
    p <- openLive dev 1500 True 1000
    let f = foldr (\x y -> concat [x, " ", y]) "" filt
    setFilter p f True 0
    loop p (-1) printIt
    return ()

printIt :: PktHdr -> Ptr Word8 -> IO ()
printIt ph bytep = printErr "."
    --peekArray (fromIntegral (hdrCaptureLength ph)) bytep >>= print

findDev :: IO String
findDev = ifName . head <$> findAllDevs
