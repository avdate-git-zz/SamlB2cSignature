//----------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//----------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;

namespace SignAndVerifySignature
{
    /// <summary>
    /// Provides extension methods for Base64 strings
    /// </summary>
    public static class Base64Extensions
    {
        public static bool EqualsOic(this string input, string compare)
        {
            return String.Equals(input, compare, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Gets the time-out to use for regex matches.
        /// </summary>
        private static readonly TimeSpan RegexTimeOut = TimeSpan.FromMilliseconds(100);

        /// <summary>
        /// Creates a Base64 encoded string from a normal string.
        /// </summary>
        /// <param name="input">The String containing the characters to encode.</param>
        /// <returns>The Base64 encoded string.</returns>
        public static string EncodeTo64(this string input)
        {
            byte[] toEncodeAsBytes = Encoding.UTF8.GetBytes(input);

            return Convert.ToBase64String(toEncodeAsBytes);
        }

        /// <summary>
        /// Creates a Base64 encoded string from a normal string.
        /// </summary>
        /// <param name="input">The byte[] containing the characters to encode.</param>
        /// <returns>The Base64 encoded string.</returns>
        public static string EncodeTo64(this byte[] input)
        {
            return Convert.ToBase64String(input);
        }

        /// <summary>
        /// Decodes Base64 strings. Add padding if missing
        /// </summary>
        /// <param name="input">The String containing the characters to decode.</param>
        /// <returns>A String containing the results of decoding the specified sequence of bytes.</returns>
        public static string DecodeFrom64(this string input)
        {
            byte[] encodedDataAsBytes = Convert.FromBase64String(input);

            return Encoding.UTF8.GetString(encodedDataAsBytes);
        }

        /// <summary>
        /// Decodes Base64 strings.
        /// </summary>
        /// <param name="input">The String containing the characters to decode.</param>
        /// <returns>A byte[] containing the results of decoding the specified sequence of bytes.</returns>
        public static byte[] DecodeFrom64ToBytes(this string input)
        {
            return Convert.FromBase64String(input);
        }

        /// <summary>
        /// Determines whether the provided string is a Base64 string
        /// </summary>
        /// <param name="input">The string to check</param>
        /// <returns>True if base64, false if not</returns>
        public static bool IsBase64String(this string input)
        {
            input = input.Trim();
            return (input.Length % 4 == 0) && Regex.IsMatch(input, @"^[a-zA-Z0-9\+/]*={0,3}$", RegexOptions.None, RegexTimeOut);
        }
    }
}
