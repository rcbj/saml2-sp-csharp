// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;

namespace IyaSec.Saml;

public sealed class IdpMetadata
{
    public string EntityId { get; init; } = "";
    public Dictionary<string, string> Sso { get; init; } = new();
    public Dictionary<int, string> ArtifactResolutionServices { get; init; } = new();
    internal string FirstArs { get; init; } = "";
    public List<X509Certificate2> Certs { get; init; } = new();
    public bool WantAuthnRequestsSigned { get; init; }
}

public static class SamlMetadata
{
    static readonly string[] EncryptionMethods =
    {
        "http://www.w3.org/2009/xmlenc11#aes256-gcm",
        "http://www.w3.org/2009/xmlenc11#aes128-gcm",
        "http://www.w3.org/2009/xmlenc11#rsa-oaep",
        "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
    };

    public static IdpMetadata ReadIdpMetadata(string xml) => Read(xml, "");

    public static string MetadataDocument(Config cfg) =>
        Write(cfg.EntityId, cfg.AcsUrl, cfg.Certificate, cfg.WantAssertionsSigned, cfg.NameIdFormat);

    internal static IdpMetadata Read(string xml, string entityId)
    {
        var root = XmlUtil.Parse(xml, "the identity provider metadata");
        XmlElement? entity = null;
        if (XmlUtil.Same(root, XmlUtil.NsMd, "EntityDescriptor")) entity = root;
        else if (XmlUtil.Same(root, XmlUtil.NsMd, "EntitiesDescriptor"))
        {
            var all = XmlUtil.Descendants(root, XmlUtil.NsMd, "EntityDescriptor")
                .Where(item => XmlUtil.Descendants(item, XmlUtil.NsMd, "IDPSSODescriptor").Count > 0)
                .ToList();
            if (entityId.Length > 0) entity = all.FirstOrDefault(item => XmlUtil.AttrOr(item, "entityID") == entityId);
            else if (all.Count == 1) entity = all[0];
            if (entity == null)
            {
                if (entityId.Length > 0)
                    throw new SamlException("metadata", "the metadata aggregate has no identity provider " + entityId);
                throw new SamlException("metadata", "the metadata aggregate holds " + all.Count + " identity providers; name one with idpEntityId");
            }
        }
        else throw new SamlException("metadata", "the identity provider metadata is not an EntityDescriptor");
        var identifier = XmlUtil.AttrOr(entity, "entityID");
        if (identifier.Length == 0) throw new SamlException("metadata", "the identity provider metadata has no entityID");
        if (entityId.Length > 0 && identifier != entityId)
            throw new SamlException("metadata", "the metadata describes " + identifier + ", not " + entityId);
        var roles = XmlUtil.Children(entity, XmlUtil.NsMd, "IDPSSODescriptor");
        if (roles.Count == 0) throw new SamlException("metadata", identifier + "'s metadata has no IDPSSODescriptor");
        var role = roles[0];
        var sso = new Dictionary<string, string>();
        foreach (var item in XmlUtil.Children(role, XmlUtil.NsMd, "SingleSignOnService"))
        {
            var location = XmlUtil.AttrOr(item, "Location");
            if (location.Length == 0) continue;
            var binding = XmlUtil.AttrOr(item, "Binding");
            if (binding == XmlUtil.BindingRedirect && !sso.ContainsKey("redirect")) sso["redirect"] = location;
            if (binding == XmlUtil.BindingPost && !sso.ContainsKey("post")) sso["post"] = location;
        }
        var services = new Dictionary<int, string>();
        var first = "";
        foreach (var ars in XmlUtil.Children(role, XmlUtil.NsMd, "ArtifactResolutionService"))
        {
            var location = XmlUtil.AttrOr(ars, "Location");
            if (XmlUtil.AttrOr(ars, "Binding") == XmlUtil.BindingSoap && location.Length > 0)
            {
                _ = int.TryParse(XmlUtil.AttrOr(ars, "index"), out var index);
                if (!services.ContainsKey(index))
                {
                    services[index] = location;
                    if (first.Length == 0) first = location;
                }
            }
        }
        var signing = Certificates(role, "signing");
        if (signing.Count == 0) throw new SamlException("metadata", identifier + "'s metadata names no signing certificate");
        if (!sso.ContainsKey("redirect") && !sso.ContainsKey("post"))
            throw new SamlException("metadata", identifier + "'s metadata has no HTTP-Redirect or HTTP-POST SingleSignOnService");
        return new IdpMetadata
        {
            EntityId = identifier,
            Sso = sso,
            ArtifactResolutionServices = services,
            FirstArs = first,
            Certs = signing,
            WantAuthnRequestsSigned = XmlUtil.AttrOr(role, "WantAuthnRequestsSigned") == "true",
        };
    }

    static List<X509Certificate2> Certificates(XmlElement role, string use)
    {
        var list = new List<X509Certificate2>();
        foreach (var descriptor in XmlUtil.Children(role, XmlUtil.NsMd, "KeyDescriptor"))
        {
            var declared = XmlUtil.AttrOr(descriptor, "use");
            if (declared.Length > 0 && declared != use) continue;
            foreach (var data in XmlUtil.Descendants(descriptor, XmlUtil.NsDsig, "X509Data"))
            {
                var first = XmlUtil.Children(data, XmlUtil.NsDsig, "X509Certificate");
                if (first.Count == 0) continue;
                try
                {
                    list.Add(Keys.LoadCertificate(ToPem(XmlUtil.TextOf(first[0]))));
                }
                catch (Exception ex)
                {
                    throw new SamlException("metadata", "a " + use + " certificate in the identity provider's metadata cannot be read", ex);
                }
            }
        }
        return list;
    }

    static string ToPem(string b64)
    {
        b64 = string.Concat(b64.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));
        var lines = new List<string>();
        for (var i = 0; i < b64.Length; i += 64)
            lines.Add(b64.Substring(i, Math.Min(64, b64.Length - i)));
        return "-----BEGIN CERTIFICATE-----\n" + string.Join("\n", lines) + "\n-----END CERTIFICATE-----\n";
    }

    static string Write(string entityId, string acsUrl, X509Certificate2 cert, bool wantAssertionsSigned, string nameIdFormat)
    {
        var keyInfo = "<ds:KeyInfo><ds:X509Data><ds:X509Certificate>" + Keys.CertBody(cert) + "</ds:X509Certificate></ds:X509Data></ds:KeyInfo>";
        var methods = new StringBuilder();
        foreach (var method in EncryptionMethods)
            methods.Append("\n      <md:EncryptionMethod Algorithm=\"").Append(method).Append("\"/>");
        string Key(string use)
        {
            var extra = use == "encryption" ? methods.ToString() : "";
            return "    <md:KeyDescriptor use=\"" + use + "\">\n      " + keyInfo + extra + "\n    </md:KeyDescriptor>";
        }
        var nameId = nameIdFormat.Length == 0 ? "" : "\n    <md:NameIDFormat>" + XmlUtil.Escape(nameIdFormat) + "</md:NameIDFormat>";
        var want = wantAssertionsSigned ? "true" : "false";
        var acs = XmlUtil.Escape(acsUrl);
        return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
               "<md:EntityDescriptor xmlns:md=\"" + XmlUtil.NsMd + "\" xmlns:ds=\"" + XmlUtil.NsDsig + "\" entityID=\"" + XmlUtil.Escape(entityId) + "\">\n" +
               "  <md:SPSSODescriptor protocolSupportEnumeration=\"" + XmlUtil.NsSamlp + "\" AuthnRequestsSigned=\"true\" WantAssertionsSigned=\"" + want + "\">\n" +
               Key("signing") + "\n" + Key("encryption") + nameId + "\n" +
               "    <md:AssertionConsumerService Binding=\"" + XmlUtil.BindingPost + "\" Location=\"" + acs + "\" index=\"0\" isDefault=\"true\"/>\n" +
               "    <md:AssertionConsumerService Binding=\"" + XmlUtil.BindingRedirect + "\" Location=\"" + acs + "\" index=\"1\"/>\n" +
               "    <md:AssertionConsumerService Binding=\"" + XmlUtil.BindingArtifact + "\" Location=\"" + acs + "\" index=\"2\"/>\n" +
               "  </md:SPSSODescriptor>\n</md:EntityDescriptor>\n";
    }
}
