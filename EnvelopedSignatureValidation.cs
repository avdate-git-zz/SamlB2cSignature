using System;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;
using System.Security.Cryptography.Xml;
using System.Linq;
using System.Xml.Linq;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Reflection;

namespace SignAndVerifySignature
{
    public class EnvelopedSignatureValidation
    {

        public static void VerifyEnvelopedSignature()
        {
            VerifyEnvelopedSignatureType();
            VerifyEnvelopedSignatureTypeNew();
        }

        public static void VerifyEnvelopedSignatureType()
        {
            string ScaniaPublicKey = "MIIDEjCCAfqgAwIBAgIHAeJ0c9/dljANBgkqhkiG9w0BAQUFADA4MQswCQYDVQQGEwJTRTEPMA0GA1UEChMGU0NBTklBMRgwFgYDVQQDEw93YW1lLnNjYW5pYS5jb20wHhcNMTMwNTIyMTIwMDUwWhcNMzMwMjA2MTIwMDUwWjA4MQswCQYDVQQGEwJTRTEPMA0GA1UEChMGU0NBTklBMRgwFgYDVQQDEw93YW1lLnNjYW5pYS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCf6jZYOekz5KPWs1TfJDYIsVgyZ1uKC4GV2ff8QYAWmswOWMFZvwwVJ9/OVSxMjcdT0jaidkKf75R1NqjwlhtEZcYBv9eChkv7v1iYuNkvoLm2+mp7k6eLYbg3rW0xfgnclNWJNynHXcThCJZ2ckvn1s/rEwfuwz7uZrVX68BFcm7MuM2M4/BDvQZWsZ1ZaFqMrtcT+CaPytuOVDfazbw7rRMcbvKStVg4jNMJDcZ/1OFBR8CJh3VtZWdtQDkT/LW/kHMPZs21F291+GynLNp+N7RTX722489vJvVS4WN7/2Aje7GF/3iQe9KfmQ4kI/Zq4qZOxdJFmrVxoxjlrpN1AgMBAAGjITAfMB0GA1UdDgQWBBR+aPnvfheFUM4CEF1ne9y+VCthSTANBgkqhkiG9w0BAQUFAAOCAQEAgAav0cHghDfYdZh000cDxKdE8XmpiDaUCJYTrv6OasspyTWlsIiT+xJuBzVNf59C6qIkJc8m1LAgshzq6mrm9XQ6sSDFvgfOd5OMT+fHB6F+kZJtDf10z9R+Qjk7r1mh8jMQeC+6NgQMTtrW/77fdy9eMJHseufvdi2YUiaysWkZvr/96/LlAbCIcKG0V9Ms3P1vPIy2y/GiXIbhyT7u8APXIpJXp1t+MBHi5m15LiH+/62j1Ey88BP3ng1eqtflKBq0mGvwiRPDNkEVLueZVA+4oWb22S681wO4cVrzjbLVVSuOFNMc5LnvdUP+f5jCYP5sxuj3f4FtmRI9HJUYtg==";

            string path = Directory.GetCurrentDirectory();
            XmlDocument xdoc = new XmlDocument();
            xdoc.PreserveWhitespace = false;
            xdoc.Load(path + "\\Scania.xml");

            byte[] certificateBytes = Convert.FromBase64String(ScaniaPublicKey);
            X509Certificate2 publicKey = new X509Certificate2();
            publicKey.Import(certificateBytes);

            List<string> assertionIds = GetAssertionIds(xdoc);
            foreach (string assertionId in assertionIds)
            {
                XmlElement assertionElement = GetAssertionById(xdoc.DocumentElement, assertionId, useResponseattribute: false);
                IsValidEnvelopedSignature(assertionElement, new X509Certificate2Collection(publicKey));
            }
        }

        public static void VerifyEnvelopedSignatureTypeNew()
        {
            string path = Directory.GetCurrentDirectory();
            XmlDocument xdoc = new XmlDocument();
            xdoc.PreserveWhitespace = true;
            // space matters. Please make sure you copy your message with correct spacing
            xdoc.Load(path + "\\response.xml");

            XmlDocument metadata = new XmlDocument();
            metadata.Load(path + "\\metadata1.xml");
            X509Certificate2Collection certscollection = GetSigningKeys(metadata.ToXDocument());

            IsValidEnvelopedSignature(xdoc.DocumentElement, certscollection);

            List<string> assertionIds = GetAssertionIds(xdoc);
            foreach (string assertionId in assertionIds)
            {
                XmlElement assertionElement = GetAssertionById(xdoc.DocumentElement, assertionId);
                IsValidEnvelopedSignature(assertionElement, certscollection);
            }
        }

        /// <summary>
        /// Determines whether an XmlDocument signature is valid using the specified
        /// certificate
        /// </summary>
        /// <param name="input">The <see cref="XmlElement"/> to check.</param>
        /// <param name="certificates">A <see cref="X509Certificate2Collection"/> contaning the certificates to use.</param>
        /// <returns>True if valid/False if not</returns>
        /// <exception cref="ArgumentNullException">Thrown when a null <paramref name="certificates"/> is passed</exception>
        /// <exception cref="CryptographicException">Thrown when the <paramref name="input"/> does not contain a Signature</exception>
        public static bool IsValidEnvelopedSignature(XmlElement input, X509Certificate2Collection certificates)
        {
            //XmlDocument xdoc = new XmlDocument();
            //xdoc.PreserveWhitespace = true;
            //xdoc.LoadXml(input.OuterXml);


            SignedXml signedMessage = new SignedXml(input);
            XmlNodeList signatureNodes = input.GetElementsByTagName("Signature", "http://www.w3.org/2000/09/xmldsig#");

            if (signatureNodes.Count == 0)
            {
                Console.WriteLine("SignatureExtensions_SignatureNotFound in xml {0}", input);
            }

            signedMessage.LoadXml((XmlElement)signatureNodes[0]);

            // Loop through the certificates and see if at least one
            // validates the signature
            foreach (X509Certificate2 certificate in certificates)
            {
                // If signature is valid no need to process further
                if (signedMessage.CheckSignature(certificate, true))
                {
                    Console.WriteLine("IsValidEnvelopedSignature Signature is valid");
                    return true;
                }
            }

            Console.WriteLine("IsValidEnvelopedSignature Signature is not valid");
            return false;
        }

        public static XmlElement GetAssertionById(XmlElement signedElement, string assertionId, bool useResponseattribute = true)
        {
            XmlNode assertionNode = signedElement.SelectSingleNode("//*[@ID=\"" + assertionId + "\"]");

            // Check if the assertion has the SAML namespace declarations.
            // If so we need to treat the assertion as a new document
            // using a namespace manager.
            if (UseNamespaceManager(assertionNode.Attributes) || (useResponseattribute  && UseNamespaceManager(signedElement.Attributes)))
            {
                XmlDocument document = new XmlDocument()
                {
                    PreserveWhitespace = true,
                    XmlResolver = null
                };

                XmlNamespaceManager namespaceManager = new XmlNamespaceManager(signedElement.OwnerDocument.NameTable);
                document.AppendChild(document.ImportNode(assertionNode, true));
                return document.DocumentElement;
            }

            return (XmlElement)assertionNode;

        }

        private static List<string> GetAssertionIds(XmlDocument xdoc)
        {
            List<string> assertionIds = new List<string>();
            XmlNodeList xmlNodeList = xdoc.GetElementsByTagName("saml:Assertion");
            foreach (XmlNode xmlNode in xmlNodeList)
            {
                string id = xmlNode.Attributes["ID"].Value;
                assertionIds.Add(id);
            }

            return assertionIds;
        }

        private static bool UseNamespaceManager(XmlAttributeCollection attributeCollection)
        {
            foreach (XmlAttribute attribute in attributeCollection)
            {
                // Check if the SAML assertion namespace has been added to the
                // assertion and if so return true to indicate that
                // an XmlNamespaceManager should be used.
                if (attribute.Value.EqualsOic(OasisSamlNamespaces.Assertion))
                {
                    return true;
                }
            }

            return false;
        }

        public static X509Certificate2Collection GetSigningKeys(XDocument metadata)
        {
            X509Certificate2Collection certificateCollection = new X509Certificate2Collection();

            XNamespace md = OasisSamlNamespaces.Metadata;
            XNamespace ds = SignedXml.XmlDsigNamespaceUrl;

            IEnumerable<XElement> signingKeys = metadata.Descendants(md + "KeyDescriptor").Where(x => x.Attribute("use") == null || (x.Attribute("use") != null && x.Attribute("use").Value.EqualsOic("SIGNING")));

            foreach (XElement signingKey in signingKeys)
            {
                // Get the base64 string
                string base64Certificate = signingKey.Descendants(ds + "X509Certificate").First().Value;
                byte[] bytes = Convert.FromBase64String(base64Certificate);

                // Add to the collection
                certificateCollection.Add(new X509Certificate2(bytes));
            }

            return certificateCollection;
        }
    }
}
