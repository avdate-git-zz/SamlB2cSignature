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
            EnvelopedSignatureValidation.VerifyEnvelopedSignature();

            // verify usage of messages which have detached signatures in B2c
            VerifyDetachedSignature();

            Console.ReadLine();
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
