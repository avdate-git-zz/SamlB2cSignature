using System;
using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;

namespace SignAndVerifySignature
{
    class SignMessage
    {
        /// <summary>
        /// Enumeration for supported signature algorithm
        /// </summary>
        public enum SignatureAlgorithm
        {
            /// <summary>
            /// Use the http://www.w3.org/2001/04/xmldsig-more#rsa-sha256
            /// </summary>
            Sha256 = 0,

            /// <summary>
            /// Use the http://www.w3.org/2001/04/xmldsig-more#rsa-sha384
            /// </summary>
            Sha384,

            /// <summary>
            /// Use the http://www.w3.org/2001/04/xmldsig-more#rsa-sha512
            /// </summary>
            Sha512,

            /// <summary>
            /// Use the http://www.w3.org/2000/09/xmldsig#rsa-sha1
            /// </summary>
            Sha1,

            /// <summary>
            /// No signature
            /// </summary>
            None
        }

        /// <summary>
        /// Gets SamlSigned RedirectUrl
        /// </summary>
        /// <param name="destination"></param>
        /// <param name="samlPayLoad"></param>
        /// <param name="relayStateInput"></param>
        /// <param name="signatureAlogrithm"></param>
        /// <param name="certSubject"></param>
        /// <returns></returns>
        public static UrlBuilder GetSamlSignedRedirectUrl
            (
            string destination,
            string samlPayLoad,
            string relayStateInput,
            string signatureAlogrithm,
            string certSubject
            )
        {
            UrlBuilder redirectUrl = new UrlBuilder()
            {
                Uri = new Uri(destination)
            };

            // Add the request parameters to the URL builder
            redirectUrl.AddOrUpdateParameter("SAMLRequest", samlPayLoad.RedirectEncode());

            if (!string.IsNullOrWhiteSpace(relayStateInput))
            {
                redirectUrl.AddOrUpdateParameter("RelayState", relayStateInput.RedirectEncode());
            }

            // Save signature algorithm
            SignMessage.SignatureAlgorithm sigAlgorithm = (SignMessage.SignatureAlgorithm)Enum.Parse(typeof(SignMessage.SignatureAlgorithm), signatureAlogrithm, true);

            AddSignatureToRequest(redirectUrl, sigAlgorithm);

            X509Certificate2 samlEncryptionAndSigningKey = SignMessage.GetSamlEncryptionAndSigningKey(certSubject);

            string signature = SignMessage.SignDetached(redirectUrl.GetQueryString(), samlEncryptionAndSigningKey, sigAlgorithm);
            redirectUrl.AddOrUpdateParameter("Signature", signature);

            string signedSamlRedirectMessage = redirectUrl.ToString();
            return redirectUrl;
        }

        /// <summary>
        /// Adds Signature to redirect request url
        /// </summary>
        /// <param name="redirectUrl">redirect Url</param>
        /// <param name="sigAlgorithm">sginature alogorithm used for signing</param>
        private static void AddSignatureToRequest(UrlBuilder redirectUrl, SignMessage.SignatureAlgorithm sigAlgorithm)
        {
            switch (sigAlgorithm)
            {
                case SignMessage.SignatureAlgorithm.Sha1:
                    redirectUrl.AddOrUpdateParameter("SigAlg", "http://www.w3.org/2000/09/xmldsig#rsa-sha1");
                    break;
                case SignMessage.SignatureAlgorithm.Sha256:
                    redirectUrl.AddOrUpdateParameter("SigAlg", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
                    break;
                case SignMessage.SignatureAlgorithm.Sha384:
                    redirectUrl.AddOrUpdateParameter("SigAlg", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384");
                    break;
                case SignMessage.SignatureAlgorithm.Sha512:
                    redirectUrl.AddOrUpdateParameter("SigAlg", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512");
                    break;
            }
        }

        /// <summary>
        /// Gets the public key for the service provider. pass in thumbprint or subject name
        /// </summary>
        public static X509Certificate2 GetSamlEncryptionAndSigningKey(string certIdentifier)
        {
            X509Certificate2 samlSPEncryptionAndSigning = null;
            X509Store store = null;

            try
            {
                store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
                store.Open(OpenFlags.ReadOnly);

                // If we haven't found any certificates in the store
                // looks like the runnign process does not have the correct
                // permissions
                if (store.Certificates.Count == 0)
                {
                    throw new InvalidOperationException("Setup has not populated certificates store or executing process does not have permissions to read from store.");
                }

                // "CN=samlsp.cpim.localhost.net, OU=AAD, C=US"
                X509Certificate2Collection certs = store.Certificates.Find(X509FindType.FindBySubjectDistinguishedName, certIdentifier, false);
                if (certs.Count == 0)
                {
                    certs = store.Certificates.Find(X509FindType.FindByThumbprint, certIdentifier, false);
                }

                // If we have can't find theencryption certficate
                if (certs.Count == 0)
                {
                    StringBuilder builder = new StringBuilder();
                    string executingServicePrincipal = WindowsIdentity.GetCurrent().Name;

                    // List the certificates in the store
                    foreach (var cert in store.Certificates)
                    {
                        builder.AppendFormat(" {0},", cert.SubjectName.Name);
                    }

                    string message = string.Format(
                        CultureInfo.InvariantCulture,
                        "The required encryption certificate with certIdentifier '{0}' cannot be located in the certficate store. Certificates in the store:{1}. Service principal '{2}' may need to be granted permissions.",
                        certIdentifier,
                        builder.ToString().TrimEnd(','),
                        executingServicePrincipal);

                    throw new InvalidOperationException(message);
                }

                samlSPEncryptionAndSigning = certs[0];
            }
            finally
            {
                if (store != null)
                {
                    store.Close();
                }
            }
            

            return samlSPEncryptionAndSigning;
        }

        /// <summary>
        /// Method for creating a detached signature. 
        /// </summary>
        /// <param name="messageToSign">The message to sign</param>
        /// <param name="signingKey">The <see cref="X509Certificate2"/> containing the private key</param>
        /// <param name="signatureAlgorithm">The <see cref="SignatureAlgorithm"/> to use for signing the message</param>
        /// <returns>A string containing the detached signature value</returns>
        public static string SignDetached(string messageToSign, X509Certificate2 signingKey, SignatureAlgorithm signatureAlgorithm)
        {
            // Get the certificate private key
            RSACryptoServiceProvider privateKey = signingKey.PrivateKey as RSACryptoServiceProvider;

            // Get the bytes and encrypt
            byte[] buffer = Encoding.UTF8.GetBytes(messageToSign);

            object algorithm = null;
            switch (signatureAlgorithm)
            {
                case SignatureAlgorithm.Sha1:
                    algorithm = new SHA1CryptoServiceProvider();
                    break;
                case SignatureAlgorithm.Sha256:
                    algorithm = new SHA256CryptoServiceProvider();
                    break;
                case SignatureAlgorithm.Sha384:
                    algorithm = new SHA384CryptoServiceProvider();
                    break;
                case SignatureAlgorithm.Sha512:
                    algorithm = new SHA512CryptoServiceProvider();
                    break;
            }

            byte[] encryptedBytes = privateKey.SignData(buffer, algorithm);

            return Convert.ToBase64String(encryptedBytes);
        }
    }
}
