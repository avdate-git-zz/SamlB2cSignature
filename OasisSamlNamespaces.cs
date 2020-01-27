// ----------------------------------------------------------------
// Copyright (c) Microsoft Corporation. All rights reserved.
// ----------------------------------------------------------------

using System;
using System.Xml.Serialization;

namespace SignAndVerifySignature
{
    /// <summary>
    /// Flag enumeration for SAML name spaces
    /// </summary>
    [Flags]
    public enum OasisSamlNamespaceFlags
    {
        /// <summary>
        /// Flag for the assertion name space
        /// </summary>
        Assertion = 1,

        /// <summary>
        /// Flag for the protocol name space
        /// </summary>
        Protocol = 2,

        /// <summary>
        /// Flag for the meta data name space
        /// </summary>
        Metadata = 4,

        /// <summary>
        /// Flag for the XmlSchemaInstance name space
        /// </summary>
        XmlSchemaInstance = 8,

        /// <summary>
        /// Flag for the XmlSchema name space
        /// </summary>
        XmlSchema = 16
    }

    /// <summary>
    /// Constants and functions for handling name spaces
    /// </summary>
    public static class OasisSamlNamespaces
    {
        /// <summary>
        /// Constant to hold the SAML Assertion name space prefix
        /// </summary>
        public const string AssertionPrefix = "saml";

        /// <summary>
        /// Constant to hold the SAML Assertion name space
        /// </summary>
        public const string Assertion = "urn:oasis:names:tc:SAML:2.0:assertion";

        /// <summary>
        /// Constant to hold the SAML Protocol name space prefix
        /// </summary>
        public const string ProtocolPrefix = "samlp";

        /// <summary>
        /// Constant to hold the SAML protocol name space
        /// </summary>
        public const string Protocol = "urn:oasis:names:tc:SAML:2.0:protocol";

        /// <summary>
        /// Constant to hold the SAML meta data name space prefix
        /// </summary>
        public const string MetadataPrefix = "md";

        /// <summary>
        /// Constant to hold the SAML meta data name space
        /// </summary>
        public const string Metadata = "urn:oasis:names:tc:SAML:2.0:metadata";

        /// <summary>
        /// Constant to hold the W3C Schema-Instance name space prefix
        /// </summary>
        public const string XmlSchemaInstancePrefix = "xsi";

        /// <summary>
        /// Constant to hold the W3C Schema-Instance name space
        /// </summary>
        public const string XmlSchemaInstance = "http://www.w3.org/2001/XMLSchema-instance";

        /// <summary>
        /// Constant to hold the W3C Schema name space prefix
        /// </summary>
        public const string XmlSchemaPrefix = "xs";

        /// <summary>
        /// Constant to hold the W3C Schema name space
        /// </summary>
        public const string XmlSchema = "http://www.w3.org/2001/XMLSchema";

        /// <summary>
        /// Compares the provided name space to the SAML reserved name spaces and
        /// returns true if a match
        /// </summary>
        /// <param name="checkNamespace">The name space to check against the SAML reserved</param>
        /// <returns>Boolean indicating whether the name space matches a SAML name space</returns>
        public static bool IsSamlNamespace(string checkNamespace)
        {
                bool isSaml = false;

                switch (checkNamespace)
                {
                    case OasisSamlNamespaces.Assertion:
                        isSaml = true;
                        break;

                    case OasisSamlNamespaces.Protocol:
                        isSaml = true;
                        break;

                    case OasisSamlNamespaces.Metadata:
                        isSaml = true;
                        break;
                }

                return isSaml;

        }

        /// <summary>
        /// Returns the default name spaces and prefixes for SAML assertions
        /// </summary>
        /// <param name="namespacesToInclude">Flags indicating the name spaces to include</param>
        /// <returns>A <see ref="XmlSerializerNamespaces"/> containing the default SAML name spaces </returns>
        public static XmlSerializerNamespaces DefaultNamespaces(OasisSamlNamespaceFlags namespacesToInclude)
        {

                XmlSerializerNamespaces defaultNamespaces = new XmlSerializerNamespaces();

                // Reset name spaces
                defaultNamespaces.Add(string.Empty, string.Empty);

                // Check if we have the assertion flag
                if (namespacesToInclude.HasFlag(OasisSamlNamespaceFlags.Assertion))
                {
                    defaultNamespaces.Add(OasisSamlNamespaces.AssertionPrefix, OasisSamlNamespaces.Assertion);
                }

                // Check if we have the protocol flag
                if (namespacesToInclude.HasFlag(OasisSamlNamespaceFlags.Protocol))
                {
                    defaultNamespaces.Add(OasisSamlNamespaces.ProtocolPrefix, OasisSamlNamespaces.Protocol);
                }

                // Check if we have the meta data flag
                if (namespacesToInclude.HasFlag(OasisSamlNamespaceFlags.Metadata))
                {
                    defaultNamespaces.Add(OasisSamlNamespaces.MetadataPrefix, OasisSamlNamespaces.Metadata);
                }

                // Check if we have the XML schema instance flag
                if (namespacesToInclude.HasFlag(OasisSamlNamespaceFlags.XmlSchemaInstance))
                {
                    defaultNamespaces.Add(OasisSamlNamespaces.XmlSchemaInstancePrefix, OasisSamlNamespaces.XmlSchemaInstance);
                }

                // Check if we have the XML schema flag
                if (namespacesToInclude.HasFlag(OasisSamlNamespaceFlags.XmlSchema))
                {
                    defaultNamespaces.Add(OasisSamlNamespaces.XmlSchemaInstancePrefix, OasisSamlNamespaces.XmlSchemaInstance);
                }

                return defaultNamespaces;
            
        }
    }
}
