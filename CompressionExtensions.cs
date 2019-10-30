//----------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//----------------------------------------------------------------

using System.IO;
using System.IO.Compression;

namespace SignAndVerifySignature
{
    /// <summary>
    /// Provides extension methods for RFC1951 compressing/decompressing strings
    /// </summary>
    public static class CompressionExtensions
    {
        /// <summary>
        /// Method for compressing a string in accordance with
        /// RFC1951
        /// </summary>
        /// <param name="input">String to be compressed</param>
        /// <returns>The compressed string</returns>
        public static byte[] RFC1951Compress(this byte[] input)
        {
            MemoryStream compressedStream = new MemoryStream();
            using (MemoryStream decompressedStream = new MemoryStream(input))
            using (DeflateStream compressor = new DeflateStream(compressedStream, CompressionMode.Compress))
            {
                decompressedStream.CopyTo(compressor);
                compressor.Close();

                return compressedStream.ToArray();
            }
        }

        /// <summary>
        /// Method for decompressing an RFC1951 compressed byte[]
        /// </summary>
        /// <param name="input">Byte[] to be decompressed</param>
        /// <returns>A byte[] containing the decompressed input</returns>
        public static byte[] RFC1951Decompress(this byte[] input)
        {
            MemoryStream compressedStream = new MemoryStream(input, true);
            using (DeflateStream decompressor = new DeflateStream(compressedStream, CompressionMode.Decompress))
            using (MemoryStream decompressedStream = new MemoryStream())
            {
                decompressor.CopyTo(decompressedStream);
                decompressor.Close();

                return decompressedStream.ToArray();
            }
        }
    }
}
