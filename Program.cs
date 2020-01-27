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
    class Program
    {
        static void Main(string[] args)
        {
            // verify usage of messages which have Enveloped signatures in B2c
            VerifyEnvelopedSignature();

            // verify usage of messages which have detached signatures in B2c
            VerifyDetachedSignature();

            Console.ReadLine();
        }


        public static void VerifyEnvelopedSignature()
        {
            // update following with message which needs to be verified
             string samlAssertion =
            @"
<saml:Assertion
    xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" ID=""_4b6a0ed3-32af-46f0-a6eb-839490bdc24c"" Version=""2.0"" IssueInstant=""2020-01-27T02:34:11Z"">
    <saml:Issuer>http://reflector.cpim.localhost.net</saml:Issuer>
    <Signature
        xmlns=""http://www.w3.org/2000/09/xmldsig#"">
        <SignedInfo>
            <CanonicalizationMethod Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#"" />
            <SignatureMethod Algorithm=""http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"" />
            <Reference URI=""#_4b6a0ed3-32af-46f0-a6eb-839490bdc24c"">
                <Transforms>
                    <Transform Algorithm=""http://www.w3.org/2000/09/xmldsig#enveloped-signature"" />
                    <Transform Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#"">
                        <InclusiveNamespaces PrefixList=""xs saml xsi""
                            xmlns=""http://www.w3.org/2001/10/xml-exc-c14n#"" />
                        </Transform>
                    </Transforms>
                    <DigestMethod Algorithm=""http://www.w3.org/2001/04/xmlenc#sha256"" />
                    <DigestValue>3Nqh5+hDKrTYHY2bHiPhB5mkrsmZpEY9UN7f7EaTRC8=</DigestValue>
                </Reference>
            </SignedInfo>
            <SignatureValue>FawjSM2c3gMIzM/DmDTjHKFD5KkNJzEtInL6YBwZP9T7B+cdXGNyjtoskBP22h7chCWn5PGHuDvxojk1X3F3RTmru2k3/rTS8jHSrFaTbGY5OHYZh4Hm/T8byOmSL1XBdc/61/3i7r2LBB4FJh4cJ26KsL/fHCmbgLGGTOD0VNPHAR8mCs1vrkxcbr8R334zNVwYvRAgvetbvbg+xqX3ITyQlrz7q17FFCC/HWnKB8Ok3qhFRSSrF1stMDjjV93777dlEEq0b24wDe8u7p6H9aQm6TxbFWGbeJs0PR2J/vV5KzMFJM6bao3uu3W3wvs559R2YxhZXpnVI30fE+EFSA==</SignatureValue>
            <KeyInfo>
                <X509Data>
                    <X509Certificate>MIIDhDCCAmygAwIBAgIQLscbyUjpRhq3Oecx+LqxujANBgkqhkiG9w0BAQsFADA/MQswCQYDVQQGEwJVUzEMMAoGA1UECxMDQUFEMSIwIAYDVQQDExlzYW1sc3AuY3BpbS5sb2NhbGhvc3QubmV0MB4XDTE3MTEyMDIzMTQ1M1oXDTIwMTEyMDIzMjQ1M1owPzELMAkGA1UEBhMCVVMxDDAKBgNVBAsTA0FBRDEiMCAGA1UEAxMZc2FtbHNwLmNwaW0ubG9jYWxob3N0Lm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAIzntKQ3eCshrmCV15tsg6epi0yyaB7vNbrcyBWnkAwFNKvDVzgINIdu245uVMPqK5XKe14rwsRv8yhylogTEWfOtbfamq8xyp+aAmMeM2c0BLBpYMSpP1w0fpDUgtsXYaTGHvdnzWw+aW6MJSi2X/kCHlt+fhd/llfOODRpm4dxWVJr36zDMZrFD8CGwaCNzgJO4w5cjVrsu+izNYtrI4euBuVeBT9A+PbqXPssa8luAwEHP0MHfuDmsG2h4jypUa2Bg3hLxU6FfbHDBQCHzQiNf6fZfJhlGeOM3cssFk6yP03pTH//OhDQcLDI7OH6rLc8hgG3uS8jMEou63m/QfcCAwEAAaN8MHowDgYDVR0PAQH/BAQDAgWgMAkGA1UdEwQCMAAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMB8GA1UdIwQYMBaAFH/1xl2rPpxtVQoUgFDbm/92iQ8sMB0GA1UdDgQWBBR/9cZdqz6cbVUKFIBQ25v/dokPLDANBgkqhkiG9w0BAQsFAAOCAQEAZ4ZjIqr+88vbQds/3kGrGrqVI2FCznut+zhOZWVJqZAfGVr+ibwDk6B1kRuXm5A6IuQ1LgPSsZFPk6fQBH0bkn/fqhKi3phV42Rvz+Ipznf8D2Z+RWdg4bVJovhn4VbdoVZDEqW3QxIVhh5zh+TKNPLOfI+xB/s7A6ndHpaXSqtnlMhhbS6PQd2ybTSraGUlIf7Ax3L0vhnuZQi1F+b5AhiUV647IPK/U9P+/W7WAaQSvpVQursia2fZlEJ5GO1gxzl6rTfOL5/yL6FEmSeyJcc2TJIeM0NPTI5TuHLZJSGu9xJNuTga3/Ir/lSge9RPEFtICihMX6tnIuAjc+S91A==</X509Certificate>
                </X509Data>
            </KeyInfo>
        </Signature>
        <saml:Subject>
            <saml:NameID Format=""urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"">3f7b3dcf-1674-4ecd-92c8-1544f346baf8</saml:NameID>
            <saml:SubjectConfirmation Method=""urn:oasis:names:tc:SAML:2.0:cm:bearer"">
                <saml:SubjectConfirmationData InResponseTo=""_d8c067cf-a431-47b9-889c-cdb7e9e56eae"" Recipient=""https://te.cpim.localhost.net/protocolinterop.onmicrosoft.com/base/samlp/sso/assertionconsumer"" NotOnOrAfter=""2020-01-27T02:44:11Z"" />
            </saml:SubjectConfirmation>
        </saml:Subject>
        <saml:Conditions NotBefore=""2020-01-27T02:34:11Z"" NotOnOrAfter=""2020-01-27T02:44:11Z"">
            <saml:AudienceRestriction>
                <saml:Audience>https://te.cpim.localhost.net/protocolinterop.onmicrosoft.com/saml_client_b</saml:Audience>
            </saml:AudienceRestriction>
        </saml:Conditions>
        <saml:AuthnStatement AuthnInstant=""2020-01-27T02:34:11Z"" SessionIndex=""gdn3yt78fxd93rnv8e"">
            <saml:AuthnContext>
                <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
            </saml:AuthnContext>
        </saml:AuthnStatement>
        <saml:AttributeStatement
            xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance""
            xmlns:xs=""http://www.w3.org/2001/XMLSchema""
            xmlns:ida=""http://www.cabinetoffice.gov.uk/resource-library/ida/attributes"">
            <saml:Attribute NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic"" Name=""Email"" FriendlyName=""Email"">
                <saml:AttributeValue xsi:type=""xs:string"">cpimft@cpimreflector.onmicrosoft.com</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic"" Name=""ExtendedCharacters"" FriendlyName=""ExtendedCharacters"">
                <saml:AttributeValue xsi:type=""xs:string"">Arabic:بيلر</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic"" Name=""DateOfBirth"" FriendlyName=""Date of Birth"">
                <saml:AttributeValue xsi:type=""xs:date"">2000-04-19</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name=""StringCollectionMultiValue"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic"">
                <saml:AttributeValue xsi:type=""xs:string"">I have a friend!</saml:AttributeValue>
                <saml:AttributeValue xsi:type=""xs:string"">Yes we are friends!</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name=""StringCollectionSingleValue"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic"">
                <saml:AttributeValue xsi:type=""xs:string"">All by myself!</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name=""NullValueShouldAppear"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic"">
                <saml:AttributeValue xsi:nil=""true"" />
            </saml:Attribute>
            <saml:Attribute Name=""ClaimThatIsNotExpected"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic"">
                <saml:AttributeValue xsi:type=""xs:anyType"">Not Expected</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name=""MDS_firstname"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"" FriendlyName=""Firstname"">
                <saml:AttributeValue ida:Verified=""true"" xsi:type=""ida:PersonNameType"" ida:Language=""en-GB"" ida:From=""1974-01-17"">GARY</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name=""MDS_middlename"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"" FriendlyName=""Middlename(s)"">
                <saml:AttributeValue ida:Verified=""true"" xsi:type=""ida:PersonNameType"" ida:Language=""en-GB"" ida:From=""1974-01-17"">GARY</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name=""MDS_surname"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"" FriendlyName=""Surname"">
                <saml:AttributeValue ida:Verified=""true"" xsi:type=""ida:PersonNameType"" ida:Language=""en-GB"" ida:From=""1974-01-17"">GIRAFFE</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name=""MDS_dateofbirth"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"" FriendlyName=""Date of Birth"">
                <saml:AttributeValue ida:Verified=""true"" xsi:type=""ida:DateType"" ida:Language=""en-GB"" ida:From=""1974-01-17"">1974-01-17</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name=""MDS_gender"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"" FriendlyName=""Gender"">
                <saml:AttributeValue ida:Verified=""true"" xsi:type=""ida:GenderType"" ida:Language=""en-GB"">Male</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name=""UserRole"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic"" FriendlyName=""UserRole"">
                <saml:AttributeValue xsi:type=""xs:string"">Role1</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name=""UserRole"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:basic"" FriendlyName=""UserRole"">
                <saml:AttributeValue xsi:type=""xs:string"">Role2</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name=""MDS_currentaddress"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"" FriendlyName=""Current Address"">
                <saml:AttributeValue ida:Verified=""true"" xsi:type=""ida:AddressType"" ida:Language=""en-GB"" ida:From=""1999-12-01"">
                    <ida:Line>15 ZOOFIELD GROVE</ida:Line>
                    <ida:Line>TEST TOWN</ida:Line>
                    <ida:Line>GB</ida:Line>
                    <ida:PostCode>X9 9AD</ida:PostCode>
                </saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name=""http://schemas.auth0.com/picture"" NameFormat=""urn:oasis:names:tc:SAML:2.0:attrname-format:uri"">
                <saml:AttributeValue xsi:type=""xs:string"">https://s.gravatar.com/avatar/528308b323ff23a5959237005dbf82d6?s=480&amp;r=pg&amp;d=https%3A%2F%2Fcdn.auth0.com%2Favatars%2Fpa.png</saml:AttributeValue>
            </saml:Attribute>
        </saml:AttributeStatement>
    </saml:Assertion>
            ";

        // update following with certs used to verify signature
         string certificates =
            @"
<md:EntitiesDescriptor xmlns:md=""urn:oasis:names:tc:SAML:2.0:metadata"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:ds=""http://www.w3.org/2000/09/xmldsig#"" xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" ID=""_520e21f4-6aa8-40c4-ba3e-026dc2df683c"">
  <md:EntityDescriptor xmlns:md=""urn:oasis:names:tc:SAML:2.0:metadata"" entityID=""https://reflector.cpim.localhost.net/client_d"" cacheDuration=""PT10S"">
    <!--
 This first certificate is an invalid certificate used for testing multiple signingcertificates
-->
    <md:KeyDescriptor use=""signing"">
      <ds:KeyInfo>
        <ds:X509Data>
          <ds:X509Certificate>
            MIIDCzCCAfOgAwIBAgIUQAL3dR8FHcCoY+rwVaAN0O+EEiwwDQYJKoZIhvcNAQEL BQAwEzERMA8GA1UEAwwIc2hpYndpbjIwHhcNMTcwNDEwMjMzOTQ5WhcNMzcwNDEw MjMzOTQ5WjATMREwDwYDVQQDDAhzaGlid2luMjCCASIwDQYJKoZIhvcNAQEBBQAD ggEPADCCAQoCggEBAKjNDcAA69UVnNFRMRF70TufCTcG/w8nzZUtjz9jytm5LwP7 yOvKl4tOYqiQg4qXxgFn27OGwxhCWh/3M9x01nzK1i4Mdur3tF04QWc2MMmq1fIX gSRMxzcnd85gFjbVBegierYqH/gcugyODh+GcW0Jqr51Gsc7TFyyZGYINtF6BIg5 VIYc8IfHZWKyYQyY61Hh8JWO1MDWZ0Z033DeTlumLGvgpsxljHUlj4rdbS8Gd4V5 E6muedo69sqNOoac0lPeC7APQtDj5sFr2CT2uQ77OtysvgmpH9yGFX1e7gm7QHWd mWegC/hAEaogVhe4J7f1w/ZhBggjiUX/D/uV7YUCAwEAAaNXMFUwHQYDVR0OBBYE FJJZqKjPYLNM+YMg+d6TXnJlu6sVMDQGA1UdEQQtMCuCCHNoaWJ3aW4yhh9odHRw czovL3NoaWJ3aW4yL2lkcC9zaGliYm9sZXRoMA0GCSqGSIb3DQEBCwUAA4IBAQBR InvLEOoZfqqh43DcKImlU7TbsgH5+Mihx1F+1X7R7t9olmqyYySazncghYr+IbYt AAbocvaFD8Yk8ixUNQXGAHs3YGOrL5cbE3X9EaPG/uXUx2hYZY28gxlsYxMFyvxV rcjX9RgHWdd8dt3594p3kxLa1ttbms1xTff5quu8AkmhwJYtEZIP8jjFydtNoXqF Jj3VNdzE6PYKy3wodvbTTheSx/2ZBEfTbL0Y706iZYnL4iC1NxLxQXDXm95plThw 19jo+uEDUaIppceE6AjYEBjroJUPD9yYN2lKr8vBTMjRbHsU5U19rf407ezQ/CDj /NmFAaiOFDFwLoHIUxCp
          </ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:KeyDescriptor use=""signing"">
      <ds:KeyInfo>
        <ds:X509Data>
          <ds:X509Certificate>
            MIIDhDCCAmygAwIBAgIQLscbyUjpRhq3Oecx+LqxujANBgkqhkiG9w0BAQsFADA/MQswCQYDVQQGEwJVUzEMMAoGA1UECxMDQUFEMSIwIAYDVQQDExlzYW1sc3AuY3BpbS5sb2NhbGhvc3QubmV0MB4XDTE3MTEyMDIzMTQ1M1oXDTIwMTEyMDIzMjQ1M1owPzELMAkGA1UEBhMCVVMxDDAKBgNVBAsTA0FBRDEiMCAGA1UEAxMZc2FtbHNwLmNwaW0ubG9jYWxob3N0Lm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAIzntKQ3eCshrmCV15tsg6epi0yyaB7vNbrcyBWnkAwFNKvDVzgINIdu245uVMPqK5XKe14rwsRv8yhylogTEWfOtbfamq8xyp+aAmMeM2c0BLBpYMSpP1w0fpDUgtsXYaTGHvdnzWw+aW6MJSi2X/kCHlt+fhd/llfOODRpm4dxWVJr36zDMZrFD8CGwaCNzgJO4w5cjVrsu+izNYtrI4euBuVeBT9A+PbqXPssa8luAwEHP0MHfuDmsG2h4jypUa2Bg3hLxU6FfbHDBQCHzQiNf6fZfJhlGeOM3cssFk6yP03pTH//OhDQcLDI7OH6rLc8hgG3uS8jMEou63m/QfcCAwEAAaN8MHowDgYDVR0PAQH/BAQDAgWgMAkGA1UdEwQCMAAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMB8GA1UdIwQYMBaAFH/1xl2rPpxtVQoUgFDbm/92iQ8sMB0GA1UdDgQWBBR/9cZdqz6cbVUKFIBQ25v/dokPLDANBgkqhkiG9w0BAQsFAAOCAQEAZ4ZjIqr+88vbQds/3kGrGrqVI2FCznut+zhOZWVJqZAfGVr+ibwDk6B1kRuXm5A6IuQ1LgPSsZFPk6fQBH0bkn/fqhKi3phV42Rvz+Ipznf8D2Z+RWdg4bVJovhn4VbdoVZDEqW3QxIVhh5zh+TKNPLOfI+xB/s7 A6ndHpaXSqtnlMhhbS6PQd2ybTSraGUlIf7Ax3L0vhnuZQi1F+b5AhiUV647IPK/U9P+/W7WAaQSvpVQursia2fZlEJ5GO1gxzl6rTfOL5/yL6FEmSeyJcc2TJIeM0NPTI5TuHLZJSGu9xJNuTga3/Ir/lSge9RPEFtICihMX6tnIuAjc+S91A==
          </ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
  </md:EntityDescriptor>
</md:EntitiesDescriptor>
";
            XmlDocument xDoc = new XmlDocument();
            xDoc.LoadXml(samlAssertion);

            XDocument metadata = XDocument.Parse(certificates, LoadOptions.None);
            IsValidEnvelopedSignature(xDoc.DocumentElement, GetSigningKeys(metadata));
        }

        public static  X509Certificate2Collection GetSigningKeys(XDocument metadata)
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

        public static void VerifyDetachedSignature()
        {
            string tenant = "azureadb2ctests";
            string policy = "B2C_1A_SAMLAPP_demopolicy_signup_signin";
            string destination = string.Format("https://{0}.b2clogin.com/{0}.onmicrosoft.com/{1}/samlp/sso/login", tenant, policy);

            string relayStateInput = "1234";
            string signatureAlogrithm = "SHA1";

            // following can be thumbpritn or subject
            string certSubject = "CN=samlsp.cpim.localhost.net, OU=AAD, C=US";
            string certIdentifier = "84BDDFCC2BC9BB3B3E3AC594EBED3FDB1A49BD75";
            certIdentifier = certSubject;
            string samlPayLoad = "<samlp:AuthnRequest AssertionConsumerServiceURL=\"https://samltestapp2.azurewebsites.net/SP/AssertionConsumer\" Destination=\"https://login.microsoftonline.com/te/azureadb2ctests.onmicrosoft.com/B2C_1A_SAMLAPP_demopolicy_signup_signin/samlp/sso/login\" ForceAuthn=\"false\" ID=\"_1314190418\" IsPassive=\"false\" IssueInstant=\"{0}\" ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Version=\"2.0\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"> <saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">https://samltestapp2.azurewebsites.net</saml:Issuer><samlp:NameIDPolicy AllowCreate=\"true\" Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\" SPNameQualifier=\"https://samltestapp2.azurewebsites.net\" xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"/></samlp:AuthnRequest>";

            DateTime issueInstant = DateTime.UtcNow;
            samlPayLoad = string.Format(samlPayLoad, issueInstant.ToString("yyyy-MM-ddTHH:mm:ssZ"));

            UrlBuilder signedRedirectUrl = SignMessage.GetSamlSignedRedirectUrl(destination, samlPayLoad, relayStateInput, signatureAlogrithm, certIdentifier);


            if (VerifyRedirectSignature.IsRedirectSignatureValid(signedRedirectUrl, certIdentifier))
            {
                Console.WriteLine("VerifyDetachedSignature Signature is valid");
            }
            else
            {
                Console.WriteLine("VerifyDetachedSignature Signature is invalid");
            }
        }
    }
}
