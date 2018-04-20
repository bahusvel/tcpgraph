{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE RecordWildCards    #-}
{-# OPTIONS_GHC -fno-cse #-}

module Main where

import           Foreign
import           Network.Pcap
import           System.Console.CmdArgs
import qualified System.Console.Terminal.Size as TSIZE
import           System.Exit
import qualified System.IO                    as SIO
import qualified System.Posix                 as PO6

data TcpGraph = TcpGraph {
    iface  :: String,
    period :: Int,
    filt   :: [String],
    mode   :: String
} deriving (Show, Data, Typeable)

modePacketSize = "packetsize"
maxPacketSize = 1514

tcpGraph = TcpGraph {
    iface = def &= name "i",
    period = def,
    filt = def &= args,
    mode = modePacketSize &= name "m"
}

printErr = SIO.hPutStrLn SIO.stderr

main :: IO ()
main = do
    TcpGraph {..} <- cmdArgs tcpGraph
    dev <- if iface == ""
        then findDev
        else return iface
    p <- openLive dev 10000 True 1000
    let f = foldr (\x y -> concat [x, " ", y]) "" filt
    setFilter p f True 0
    loop p (-1) $ drawPacket mode
    return ()

drawPacket :: String -> PktHdr -> Ptr Word8 -> IO ()
drawPacket m ph _ | m == modePacketSize = dotsForSize $ fromIntegral (hdrCaptureLength ph)

    --peekArray (fromIntegral (hdrCaptureLength ph)) bytep >>= print

findDev :: IO String
findDev = ifName . head <$> findAllDevs


dotsForSize :: Int -> IO ()
dotsForSize n = do
    window <- TSIZE.size
    case window of
        Just TSIZE.Window {..} -> do
            let dots = floor $ fromIntegral width * (fromIntegral n / maxPacketSize)
            let remdots = dots - length (show n)
            let line = show n : replicate remdots "*"
            putStrLn $ concat line
        Nothing                -> printErr "Not a tty!" >> exitFailure
