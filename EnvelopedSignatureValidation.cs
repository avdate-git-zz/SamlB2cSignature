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
            string path = Directory.GetCurrentDirectory();

            XmlDocument xdoc = new XmlDocument();
            xdoc.PreserveWhitespace = true;
            // space matters. Please make sure you copy your message with correct spacing
            xdoc.Load(path + "\\working.xml");

            XmlDocument metadata = new XmlDocument();
            metadata.Load(path + "\\metadata.xml");
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

        public static XmlElement GetAssertionById(XmlElement signedElement, string assertionId)
        {
            XmlNode assertionNode = signedElement.SelectSingleNode("//*[@ID=\"" + assertionId + "\"]");

            // Check if the assertion has the SAML namespace declarations.
            // If so we need to treat the assertion as a new document
            // using a namespace manager.
            if (UseNamespaceManager(assertionNode.Attributes))
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
