// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

using System.Text.RegularExpressions;
using System.Xml;

namespace IyaSec.Saml;

static class XmlUtil
{
    internal const string NsSamlp = "urn:oasis:names:tc:SAML:2.0:protocol";
    internal const string NsSaml = "urn:oasis:names:tc:SAML:2.0:assertion";
    internal const string NsMd = "urn:oasis:names:tc:SAML:2.0:metadata";
    internal const string NsDsig = "http://www.w3.org/2000/09/xmldsig#";
    internal const string NsXenc = "http://www.w3.org/2001/04/xmlenc#";
    internal const string NsXenc11 = "http://www.w3.org/2009/xmlenc11#";
    internal const string NsSoap = "http://schemas.xmlsoap.org/soap/envelope/";

    internal const string BindingRedirect = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
    internal const string BindingPost = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
    internal const string BindingArtifact = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact";
    internal const string BindingSoap = "urn:oasis:names:tc:SAML:2.0:bindings:SOAP";
    internal const string StatusSuccess = "urn:oasis:names:tc:SAML:2.0:status:Success";
    internal const string Bearer = "urn:oasis:names:tc:SAML:2.0:cm:bearer";

    internal const string RsaSha256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    internal const string RsaSha384 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";
    internal const string RsaSha512 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";

    static readonly Regex DocType = new(@"(?i)<!DOCTYPE|<!ENTITY", RegexOptions.Compiled);

    internal static XmlElement Parse(string text, string what)
    {
        if (DocType.IsMatch(text))
            throw new SamlException("xml", what + " carries a DOCTYPE or an entity declaration, which SAML never needs");
        var doc = new XmlDocument { PreserveWhitespace = true };
        try
        {
            doc.LoadXml(text);
        }
        catch (XmlException ex)
        {
            throw new SamlException("xml", what + " is not well-formed XML: " + ex.Message, ex);
        }
        if (doc.DocumentElement == null)
            throw new SamlException("xml", what + " is not well-formed XML: no document element");
        return doc.DocumentElement;
    }

    internal static bool Same(XmlNode? node, string ns, string local) =>
        node is XmlElement el && el.LocalName == local && el.NamespaceURI == ns;

    internal static List<XmlElement> Children(XmlNode? el, string ns, string local)
    {
        var list = new List<XmlElement>();
        if (el == null) return list;
        foreach (XmlNode child in el.ChildNodes)
            if (Same(child, ns, local)) list.Add((XmlElement)child);
        return list;
    }

    internal static XmlElement? One(XmlElement el, string ns, string local)
    {
        var found = Children(el, ns, local);
        if (found.Count > 1)
            throw new SamlException("validation", "<" + el.LocalName + "> has more than one <" + local + ">");
        return found.Count == 0 ? null : found[0];
    }

    internal static List<XmlElement> Descendants(XmlElement? el, string ns, string local)
    {
        var list = new List<XmlElement>();
        if (el == null) return list;
        void Walk(XmlElement node)
        {
            foreach (XmlNode child in node.ChildNodes)
            {
                if (child is not XmlElement element) continue;
                if (Same(element, ns, local)) list.Add(element);
                Walk(element);
            }
        }
        Walk(el);
        return list;
    }

    internal static string TextOf(XmlNode? el) => el == null ? "" : el.InnerText.Trim();

    internal static string IterText(XmlNode? el) => el == null ? "" : el.InnerText;

    internal static bool Attr(XmlElement? el, string name, out string value)
    {
        value = "";
        if (el == null || !el.HasAttribute(name)) return false;
        value = el.GetAttribute(name);
        return true;
    }

    internal static string AttrOr(XmlElement? el, string name) =>
        el != null && el.HasAttribute(name) ? el.GetAttribute(name) : "";

    internal static XmlElement RootOf(XmlElement el)
    {
        while (el.ParentNode is XmlElement parent) el = parent;
        return el;
    }

    internal static void AssertUniqueIds(XmlElement? root)
    {
        if (root == null) return;
        var seen = new HashSet<string>();
        void Walk(XmlElement node)
        {
            foreach (var name in new[] { "ID", "Id", "id" })
            {
                if (!Attr(node, name, out var value) || value.Length == 0) continue;
                if (!seen.Add(value))
                    throw new SamlException("signature", "two elements carry the ID " + value);
            }
            foreach (XmlNode child in node.ChildNodes)
                if (child is XmlElement element) Walk(element);
        }
        Walk(root);
    }

    internal static string Escape(string value) =>
        value.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace("\"", "&quot;").Replace("'", "&apos;");

    internal static XmlElement? ElementById(XmlElement root, string id)
    {
        XmlElement? found = null;
        void Walk(XmlElement node)
        {
            if (found != null) return;
            foreach (var name in new[] { "ID", "Id", "id" })
            {
                if (Attr(node, name, out var value) && value == id)
                {
                    found = node;
                    return;
                }
            }
            foreach (XmlNode child in node.ChildNodes)
                if (child is XmlElement element) Walk(element);
        }
        Walk(root);
        return found;
    }

    internal static string PemBody(string pem)
    {
        var b = new System.Text.StringBuilder();
        foreach (var line in pem.Replace("\r", "").Split('\n'))
        {
            var trimmed = line.Trim();
            if (trimmed.Length == 0 || trimmed.StartsWith("-----", StringComparison.Ordinal)) continue;
            b.Append(trimmed);
        }
        return b.ToString();
    }
}
