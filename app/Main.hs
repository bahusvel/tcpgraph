{-# LANGUAGE DeriveDataTypeable #-}
{-# OPTIONS_GHC -fno-cse #-}

module Main where

import           Foreign
import           Network.Pcap
import           System.Console.CmdArgs

data TcpGraph = TcpGraph {
    iface  :: String,
    period :: Int
} deriving (Show, Data, Typeable)

tcpGraph = TcpGraph {
    iface = def &= name "i",
    period = def
}

main :: IO ()
main = do
    args <- cmdArgs tcpGraph
    print args
    p <- openLive "enp0s31f6" 1500 True 1000
    setFilter p "icmp" True 0
    loop p (-1) printIt
    return ()

printIt :: PktHdr -> Ptr Word8 -> IO ()
printIt ph bytep =
    peekArray (fromIntegral (hdrCaptureLength ph)) bytep >>= print

findDev :: IO String
findDev = ifName . head <$> findAllDevs
