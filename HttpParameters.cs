using System;
using System.Collections.Generic;
using System.Text;

namespace SignAndVerifySignature
{
    public class HttpParameters
    {
        /// <summary>
        /// Constant string for the GET/POST RelayState parameter
        /// </summary>
        public const string RelayState = "RelayState";

        /// <summary>
        /// Constant string for the GET/POST SAMLRequest parameter
        /// </summary>
        public const string SamlRequest = "SAMLRequest";

        /// <summary>
        /// Constant string for the GET/POST SAMLResponse parameter
        /// </summary>
        public const string SamlResponse = "SAMLResponse";

        /// <summary>
        /// Constant string for the GET SAMLEncoding parameter
        /// </summary>
        public const string SamlEncoding = "SAMLEncoding";

        /// <summary>
        /// Constant string for the SAML status parameter
        /// </summary>
        public const string SamlStatus = "SAMLStatus";

        /// <summary>
        /// Constant string for the SOAP Content - meaning body of the posted message
        /// </summary>
        public const string SoapContent = "SoapContent";

        /// <summary>
        /// Constant string for the GET signature algorithm parameter
        /// </summary>
        public const string SignatureAlgorithm = "SigAlg";

        /// <summary>
        /// Constant string for the GET Signature parameter
        /// </summary>
        public const string Signature = "Signature";

        /// <summary>
        /// Constant string for the default value for the SAMLEncoding parameter
        /// </summary>
        public const string SamlEncodingDefault = "urn:oasis:names:tc:SAML:2.0:bindings:URL-Encoding:DEFLATE";

        /// <summary>
        /// Constant to hold the RSA signature algorithm uri
        /// </summary>
        public const string RsaWithSha1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";

        /// <summary>
        /// Constant to hold the RSA signature algorithm uri
        /// </summary>
        public const string RsaWithSha256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

        /// <summary>
        /// Constant to hold the RSA signature algorithm uri
        /// </summary>
        public const string RsaWithSha384 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";

        /// <summary>
        /// Constant to hold the RSA signature algorithm uri
        /// </summary>
        public const string RsaWithSha512 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";

        /// <summary>
        /// Constant to hold the DSA signature algorithm uri
        /// </summary>
        public const string DsaWithSha1 = "http://www.w3.org/2000/09/xmldsig#dsa-sha1";
    }
}
