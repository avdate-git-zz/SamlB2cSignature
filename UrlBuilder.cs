using System;
using System.Web;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Text;

namespace SignAndVerifySignature
{
    /// <summary>
    ///  Methods for building a URL and query string in the format
    ///  scheme://domain[:port]/path?query_string#fragment_id
    /// </summary>
    public class UrlBuilder
    {
        /// <summary>
        /// Holds the name value pairs of query parameters
        /// </summary>
        private NameValueCollection queryParameters = new NameValueCollection();

        /// <summary>
        /// Initializes a new instance of the <see cref="UrlBuilder"/> class
        /// </summary>
        public UrlBuilder()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="UrlBuilder"/> class
        /// </summary>
        /// <param name="domain">The domain part of the URL</param>
        /// <param name="path">The path part of the URL</param>
        /// <param name="scheme">The optional scheme part of the URL</param>
        public UrlBuilder(string domain, string path, UriScheme scheme = UriScheme.Http)
        {
            this.Domain = domain;
            this.Path = path;
            this.Scheme = scheme;
        }

        /// <summary>
        /// Enumeration for the URI schemes supported by the <see cref="UrlBuilder"/>, default scheme
        /// is http
        /// </summary>
        public enum UriScheme
        {
            /// <summary>
            /// HTTP resources
            /// </summary>
            Http,

            /// <summary>
            /// HTTP connections secured using SSL/TLS
            /// </summary>
            Https,

            /// <summary>
            /// FTP resources
            /// </summary>
            Ftp
        }

        /// <summary>
        /// Gets or sets a complete URI in the format scheme://domain[:port]/path
        /// </summary>
        public Uri Uri
        {
            get;
            set;
        }

        /// <summary>
        /// Gets or sets the URI scheme for the URL. Although schemes are case-insensitive,
        /// the canonical form is lowercase
        /// </summary>
        public UriScheme Scheme
        {
            get;
            set;
        }

        /// <summary>
        /// Gets or sets the domain for the URL
        /// </summary>
        public string Domain
        {
            get;
            set;
        }

        /// <summary>
        /// Gets or sets the port of the URL
        /// </summary>
        public int Port
        {
            get;
            set;
        }

        /// <summary>
        /// Gets or sets the path of the URL
        /// </summary>
        public string Path
        {
            get;
            set;
        }

        /// <summary>
        /// Gets or sets the fragment part of the URL
        /// </summary>
        public string Fragment
        {
            get;
            set;
        }

        /// <summary>
        /// Gets the collection of query parameters
        /// </summary>
        public NameValueCollection QueryParameters
        {
            get
            {
                return this.queryParameters;
            }
        }

        /// <summary>
        /// Adds a parameter if not already in the collection or
        /// updates an existing parameter
        /// </summary>
        /// <param name="key">The key of the parameter</param>
        /// <param name="value">The value of the parameter</param>
        public void AddOrUpdateParameter(string key, string value)
        {
            // Check if the key exists, if exists update
            if (this.queryParameters[key] != null)
            {
                this.queryParameters[key] = value;
            }
            else
            {
                this.queryParameters.Add(key, value);
            }
            
        }

        /// <summary>
        /// Removes the <paramref name="key"/> from the query parameters collection
        /// </summary>
        /// <param name="key">The key of the parameter</param>
        public void RemoveParameter(string key)
        {
            if (this.queryParameters[key] != null)
            {
                this.queryParameters.Remove(key);
            }
        }

        /// <summary>
        /// The string representation of the <see cref="UrlBuilder"/>
        /// </summary>
        /// <returns>A string in the format scheme://domain:port/path?query_string#fragment_id</returns>
        public override string ToString()
        {
            StringBuilder stringBuilder = new StringBuilder();

            // Check the that the required properties have been set
            if (this.Uri == null)
            {

                stringBuilder.Append(Enum.GetName(typeof(UriScheme), this.Scheme).ToLowerInvariant());
                stringBuilder.Append("://" + HttpUtility.UrlEncode(this.Domain));

                // Check for port
                if (this.Port != 0)
                {
                    stringBuilder.Append(":" + this.Port);
                }

                stringBuilder.Append("/" + this.Path);
            }
            else
            {
                stringBuilder.Append(this.Uri);
            }

            // Check for parameters
            if (this.queryParameters.Count > 0)
            {
                // Check if query string already exists
                string newOrAppend = stringBuilder.ToString().Contains("?") ? "&" : "?";

                stringBuilder.Append(newOrAppend + this.GetQueryString());
            }

            if (!string.IsNullOrWhiteSpace(this.Fragment))
            {
                stringBuilder.Append("#" + HttpUtility.UrlEncode(this.Fragment));
            }

            return stringBuilder.ToString();
        }

        /// <summary>
        /// The <see cref="Uri"/> representation of the <see cref="UrlBuilder"/>
        /// </summary>
        /// <returns>A <see cref="Uri"/></returns>
        public Uri ToUri()
        {
            return new Uri(this.ToString());
        }

        /// <summary>
        /// Converts the name and values in the collection into a URL encoded query string
        /// </summary>
        /// <returns>A URL encoded string in the format key=value&amp;key=value</returns>
        public string GetQueryString()
        {
            return string.Join("&", this.queryParameters.AllKeys.Select(key => $"{HttpUtility.UrlEncode(key)}={HttpUtility.UrlEncode(this.queryParameters[key])}"));
        }
    }
}
