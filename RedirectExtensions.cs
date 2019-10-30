//----------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//----------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Text;

namespace SignAndVerifySignature
{
    /// <summary>
    /// Provides extension methods for compressing/decompressing strings
    /// to be used in redirects
    /// </summary>
    public static class RedirectExtensions
    {
        /// <summary>
        /// Prepares a string for including in an http redirect.
        /// String is compressed in accordance with RFC1951 and then Base64 encoded
        /// </summary>
        /// <param name="input">String to be compressed</param>
        /// <returns>A string encoded for use in a redirect</returns>
        public static string RedirectEncode(this string input)
        {
            // Compress
            byte[] compressedBytes = Encoding.UTF8.GetBytes(input).RFC1951Compress();

            // Base64 encode
            return compressedBytes.EncodeTo64();
        }

        /// <summary>
        /// Decodes a string passed in a redirect. Base64 decoded
        /// and decompressed in accordance with RFC1951
        /// </summary>
        /// <param name="input">Sting to be decoded</param>
        /// <returns>The decoded string</returns>
        public static string RedirectDecode(this string input)
        {
            // Base64 Decode
            byte[] base64DecodedBytes = input.DecodeFrom64ToBytes();

            // Decompress
            return Encoding.UTF8.GetString(base64DecodedBytes.RFC1951Decompress());
        }
    }
}
