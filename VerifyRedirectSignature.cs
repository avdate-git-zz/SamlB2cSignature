//----------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//----------------------------------------------------------------

using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Web;

namespace SignAndVerifySignature
{
    class VerifyRedirectSignature
    {
        public static bool IsRedirectSignatureValid(UrlBuilder redirectUrl, string certIdentifier)
        {
            string samlRequest = redirectUrl.QueryParameters[HttpParameters.SamlRequest];
            string detachedSignatureAlgorithm = redirectUrl.QueryParameters[HttpParameters.SignatureAlgorithm];
            string detachedSignature = redirectUrl.QueryParameters[HttpParameters.Signature];
            string relayState = redirectUrl.QueryParameters[HttpParameters.RelayState];
            string signedQueryString = GetSignedPortion(samlRequest, relayState, detachedSignatureAlgorithm, isSamlRequest: true);
            return VerifyDetachedSignature(detachedSignature, detachedSignatureAlgorithm, signedQueryString, certIdentifier);
        }

        private static string GetSignedPortion(string samlMessage, string relayState, string sigAlg, bool isSamlRequest)
        {
            // following parsing is as per saml spec [saml-bindings-2.0-os] 3.4.4.1 Line 644
            // To construct the signature, a string consisting of the concatenation of the RelayState(if present), SigAlg, and SAMLRequest(or SAMLResponse) query string parameters(each one URLencoded)
            // is constructed in one of the following ways(ordered as below): 
            // SAMLRequest = value & RelayState = value & SigAlg = value 
            // SAMLResponse = value & RelayState = value & SigAlg = value
            string signedPortion = isSamlRequest ? HttpParameters.SamlRequest + "=" + HttpUtility.UrlEncode(samlMessage) : HttpParameters.SamlResponse + "=" + HttpUtility.UrlEncode(samlMessage);
            signedPortion = signedPortion + (string.IsNullOrEmpty(relayState) ? string.Empty : "&" + HttpParameters.RelayState + "=" + HttpUtility.UrlEncode(relayState));
            signedPortion = signedPortion + (string.IsNullOrEmpty(sigAlg) ? string.Empty : "&" + HttpParameters.SignatureAlgorithm + "=" + HttpUtility.UrlEncode(sigAlg));
            return signedPortion;
        }

        internal static bool VerifyDetachedSignature(
            string detachedSignature,
            string detachedSignatureAlgorithm,
            string signedQueryString,
            string certIdentifier
            )
        {
            if (string.IsNullOrWhiteSpace(detachedSignature))
            {
                throw new ArgumentException("DetachedSignature not mentioned");
            }

            // Check that we have a signature algorithm, if not throw error
            if (string.IsNullOrWhiteSpace(detachedSignatureAlgorithm))
            {
                throw new ArgumentException("DetachedSignature not mentioned");
            }

            X509Certificate2 samlEncryptionAndSigningKey = SignMessage.GetSamlEncryptionAndSigningKey(certIdentifier);
            X509Certificate2Collection publicKeys = new X509Certificate2Collection();
            publicKeys.Add(samlEncryptionAndSigningKey);

            object hashAlgorithmProvider = GetAlgorithmProvider(detachedSignatureAlgorithm);
            try
            {
                // Now verify
                return IsValidDetachedSignature(
                    signedQueryString,
                    hashAlgorithmProvider,
                    detachedSignature,
                    publicKeys);
            }
            finally
            {
                IDisposable hashAlgorithmProviderDisp = hashAlgorithmProvider as IDisposable;
                if (hashAlgorithmProviderDisp != null)
                {
                    hashAlgorithmProviderDisp.Dispose();
                }
            }
        }

        internal static object GetAlgorithmProvider(string signatureAlgorithm)
        {
            switch (signatureAlgorithm)
            {
                case HttpParameters.RsaWithSha1:
                    return new SHA1CryptoServiceProvider();

                case HttpParameters.RsaWithSha256:
                    return new SHA256CryptoServiceProvider();

                case HttpParameters.RsaWithSha384:
                    return new SHA384CryptoServiceProvider();

                case HttpParameters.RsaWithSha512:
                    return new SHA512CryptoServiceProvider();

                case HttpParameters.DsaWithSha1:
                    return new DSACryptoServiceProvider();

                default:
                    throw new ArgumentException("signatureAlgorithm not supported");
            }
        }

        /// <summary>
        /// Determines whether a detached signature is valid for a given string input using the
        /// specified algorithm and x509 public certificate
        /// </summary>
        /// <param name="signedInput">The URL encoded content that was signed</param>
        /// <param name="hashAlgorithmProvider">The hash algorithm provider</param>
        /// <param name="detachedSignature">The detached signature </param>
        /// <param name="certificates">A <see cref="X509Certificate2Collection"/> contaning the certificates to use.</param>
        /// <returns>True if valid/False if not</returns>
        public static bool IsValidDetachedSignature(
                                    string signedInput,
                                    object hashAlgorithmProvider,
                                    string detachedSignature,
                                    X509Certificate2Collection certificates)
        {
            foreach (X509Certificate2 certificate in certificates)
            {
                // Get the certificate private key
                using (RSACryptoServiceProvider publicKey = certificate.PublicKey.Key as RSACryptoServiceProvider)
                {
                    byte[] buffer = Encoding.UTF8.GetBytes(signedInput);
                    byte[] signature = detachedSignature.DecodeFrom64ToBytes();

                    if (publicKey.VerifyData(buffer, hashAlgorithmProvider, signature))
                    {
                        return true;
                    }
                }
            }

            return false;
        }
    }
}
