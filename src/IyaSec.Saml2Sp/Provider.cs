// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

namespace IyaSec.Saml;

public sealed class LoginOptions
{
    public string? RelayState { get; init; }
    public bool ForceAuthn { get; init; }
    public bool IsPassive { get; init; }
    public string? SubjectHint { get; init; }
    public string? SubjectHintFormat { get; init; }
    public string RequestBinding { get; init; } = "";
    public string ResponseBinding { get; init; } = "";
    public string Nonce { get; init; } = "";
}

public sealed class LoginRequest
{
    public string Id { get; init; } = "";
    public string Binding { get; init; } = "";
    public string ResponseBinding { get; init; } = "";
    public string Url { get; init; } = "";
    public string Xml { get; init; } = "";
    public Dictionary<string, string>? Fields { get; init; }
    public string Html { get; init; } = "";
}

public sealed class ServiceProvider
{
    public Config Config { get; }
    public IdpMetadata Idp { get; private set; } = null!;
    readonly MemoryReplayCache _replay;

    ServiceProvider(Config config, MemoryReplayCache replay)
    {
        Config = config;
        _replay = replay;
    }

    public static ServiceProvider Create(IReadOnlyDictionary<string, object?> config, string? baseDir, MemoryReplayCache? replay)
    {
        var resolved = ConfigFile.Resolve(config, baseDir);
        var sp = new ServiceProvider(resolved, replay ?? new MemoryReplayCache());
        sp.RefreshMetadata();
        return sp;
    }

    public static ServiceProvider FromFile(string path, IReadOnlyDictionary<string, object?>? overrides, MemoryReplayCache? replay)
    {
        var resolved = ConfigFile.Read(path, overrides);
        var sp = new ServiceProvider(resolved, replay ?? new MemoryReplayCache());
        sp.RefreshMetadata();
        return sp;
    }

    public static string PostFormHtml(string action, IReadOnlyDictionary<string, string> fields, string? nonce = null, string? title = null, IReadOnlyList<string>? order = null) =>
        Bindings.PostFormHtml(action, fields, nonce, title, order);

    public IdpMetadata RefreshMetadata()
    {
        var source = Config.IdpMetadata;
        string xml;
        if (source.StartsWith('<')) xml = source;
        else if (source.StartsWith("http://", StringComparison.Ordinal) || source.StartsWith("https://", StringComparison.Ordinal))
        {
            var answer = HttpSend.Send(source, "GET", new Dictionary<string, string> { ["accept"] = "application/samlmetadata+xml, application/xml, text/xml" }, "", Tls(), "metadata");
            if (answer.Status != 200)
                throw new SamlException("metadata", source + " answered HTTP " + answer.Status);
            xml = answer.Body;
        }
        else
        {
            try
            {
                xml = File.ReadAllText(source);
            }
            catch (Exception ex)
            {
                throw new SamlException("metadata", "the identity provider metadata file " + source + " cannot be read", ex);
            }
        }
        Idp = SamlMetadata.Read(xml, Config.IdpEntityId);
        return Idp;
    }

    public string Metadata() => SamlMetadata.MetadataDocument(Config);

    public LoginRequest Login(LoginOptions? options)
    {
        options ??= new LoginOptions();
        var idp = RequireIdp();
        var binding = options.RequestBinding.Length == 0 ? Config.RequestBinding : options.RequestBinding;
        var response = options.ResponseBinding.Length == 0 ? Config.ResponseBinding : options.ResponseBinding;
        if (response == "artifact" && idp.ArtifactResolutionServices.Count == 0)
            throw new SamlException("config", "the identity provider has no SOAP ArtifactResolutionService, so the Response cannot come by artifact");
        if (!idp.Sso.TryGetValue(binding, out var destination) || destination.Length == 0)
        {
            var which = binding == "post" ? "POST" : "Redirect";
            throw new SamlException("config", "the identity provider has no SingleSignOnService on HTTP-" + which);
        }
        if (options.RelayState != null && System.Text.Encoding.UTF8.GetByteCount(options.RelayState) > 80)
            throw new SamlException("config", "relayState is longer than the 80 bytes the bindings allow");
        var elementId = Ids.New();
        var force = options.ForceAuthn ? " ForceAuthn=\"true\"" : "";
        var passive = options.IsPassive ? " Is passive=\"true\"" : "";
        var subject = "";
        if (options.SubjectHint != null)
        {
            var form = options.SubjectHintFormat != null && options.SubjectHintFormat.Length > 0 ? " Format=\"" + XmlUtil.Escape(options.SubjectHintFormat) + "\"" : "";
            subject = "<saml:Subject><saml:NameID" + form + ">" + XmlUtil.Escape(options.SubjectHint) + "</saml:NameID></saml:Subject>";
        }
        var policy = Config.NameIdFormat.Length == 0
            ? "<samlp:NameIDPolicy AllowCreate=\"true\"/>"
            : "<samlp:NameIDPolicy Format=\"" + XmlUtil.Escape(Config.NameIdFormat) + "\" AllowCreate=\"true\"/>";
        var protocol = response switch
        {
            "post" => XmlUtil.BindingPost,
            "redirect" => XmlUtil.BindingRedirect,
            _ => XmlUtil.BindingArtifact,
        };
        var xml = "<samlp:AuthnRequest xmlns:samlp=\"" + XmlUtil.NsSamlp + "\" xmlns:saml=\"" + XmlUtil.NsSaml + "\" ID=\"" + elementId + "\" Version=\"2.0\" IssueInstant=\"" + Ids.Iso(default) + "\" Destination=\"" + XmlUtil.Escape(destination) + "\" AssertionConsumerServiceURL=\"" + XmlUtil.Escape(Config.AcsUrl) + "\" ProtocolBinding=\"" + protocol + "\"" + force + passive + "><saml:Issuer>" + XmlUtil.Escape(Config.EntityId) + "</saml:Issuer>" + subject + policy + "</samlp:AuthnRequest>";
        if (binding == "redirect")
        {
            var query = Bindings.RedirectQuery("SAMLRequest", xml, options.RelayState, Config.PrivateKey);
            var join = destination.Contains('?', StringComparison.Ordinal) ? "&" : "?";
            return new LoginRequest { Id = elementId, Binding = binding, ResponseBinding = response, Url = destination + join + query, Xml = xml };
        }
        var signed = Canon.SignEnveloped(xml, elementId, Config.PrivateKey, Config.Certificate);
        var fields = new Dictionary<string, string> { ["SAMLRequest"] = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(signed)) };
        var order = new List<string> { "SAMLRequest" };
        if (options.RelayState != null)
        {
            fields["RelayState"] = options.RelayState;
            order.Add("RelayState");
        }
        var html = Bindings.PostFormHtml(destination, fields, options.Nonce, "", order);
        return new LoginRequest { Id = elementId, Binding = binding, ResponseBinding = response, Url = destination, Fields = fields, Html = html, Xml = signed };
    }

    public SamlLogin Acs(string method, string rawUrl, object? body, IReadOnlyList<string>? requestIds)
    {
        var idp = RequireIdp();
        var verb = method.ToUpperInvariant();
        var rawQuery = "";
        var mark = rawUrl.IndexOf('?');
        if (mark >= 0)
        {
            rawQuery = rawUrl[(mark + 1)..];
            var hash = rawQuery.IndexOf('#');
            if (hash >= 0) rawQuery = rawQuery[..hash];
        }
        var query = FirstQuery(rawQuery);
        var form = verb == "POST" ? FormOf(body) : new Dictionary<string, string>();
        var ctx = new ResponseValidator.Context
        {
            EntityId = Config.EntityId,
            AcsUrl = Config.AcsUrl,
            IdpEntityId = idp.EntityId,
            IdpCertificates = idp.Certs,
            DecryptionKey = Config.PrivateKey,
            ClockSkewMs = Config.ClockSkewMs,
            WantAssertionsSigned = Config.WantAssertionsSigned,
            WantAssertionsEncrypted = Config.WantAssertionsEncrypted,
            AllowUnsolicited = Config.AllowUnsolicited,
            Replay = _replay,
            ExpectedRequestIds = requestIds ?? Array.Empty<string>(),
        };
        var art = First(form.TryGetValue("SAMLart", out var formArt) ? formArt : "", query.TryGetValue("SAMLart", out var queryArt) ? queryArt : "");
        if (art.Length > 0)
        {
            var resolved = Artifact.Resolve(art, Config.EntityId, idp.EntityId, idp.ArtifactResolutionServices, idp.FirstArs, idp.Certs, Config.PrivateKey, Config.Certificate, Tls());
            string? relay = null;
            if (form.TryGetValue("SAMLart", out var posted) && posted.Length > 0)
            {
                if (form.ContainsKey("RelayState")) relay = form["RelayState"];
            }
            else if (query.ContainsKey("RelayState")) relay = query["RelayState"];
            return ResponseValidator.Validate(new ResponseValidator.Received { Xml = resolved.Xml, Response = resolved.Response, Binding = "artifact", RelayState = relay, AuthenticatedByBinding = true }, ctx);
        }
        if (verb == "POST" && form.TryGetValue("SAMLResponse", out var postedResponse) && postedResponse.Length > 0)
        {
            var xml = Bindings.ReadPost(postedResponse, "SAMLResponse");
            var root = XmlUtil.Parse(xml, "the Response");
            string? relay = form.ContainsKey("RelayState") ? form["RelayState"] : null;
            return ResponseValidator.Validate(new ResponseValidator.Received { Xml = xml, Response = root, Binding = "post", RelayState = relay, AuthenticatedByBinding = false }, ctx);
        }
        if (query.TryGetValue("SAMLResponse", out var queryResponse) && queryResponse.Length > 0)
        {
            var message = Bindings.ReadRedirect(rawQuery, "SAMLResponse", idp.Certs);
            var root = XmlUtil.Parse(message.Xml, "the Response");
            return ResponseValidator.Validate(new ResponseValidator.Received { Xml = message.Xml, Response = root, Binding = "redirect", RelayState = message.RelayState, AuthenticatedByBinding = message.Signed }, ctx);
        }
        throw new SamlException("binding", "the request carries no SAMLResponse or SAMLart");
    }

    IdpMetadata RequireIdp() => Idp ?? throw new SamlException("metadata", "the identity provider's metadata has not been loaded");

    TlsOptions? Tls() => Config.IdpCa.Length == 0 ? null : new TlsOptions { Ca = Config.IdpCa };

    static string First(string left, string right) => left.Length > 0 ? left : right;

    static Dictionary<string, string> FirstQuery(string raw)
    {
        var found = new Dictionary<string, string>();
        if (raw.Length == 0) return found;
        foreach (var part in raw.Split('&'))
        {
            if (part.Length == 0) continue;
            var eq = part.IndexOf('=');
            var key = eq >= 0 ? part[..eq] : part;
            var val = eq >= 0 ? part[(eq + 1)..] : "";
            try
            {
                key = Bindings.UriUnescape(key);
                val = Bindings.UriUnescape(val);
            }
            catch (SamlException)
            {
            }
            if (!found.ContainsKey(key)) found[key] = val;
        }
        return found;
    }

    static Dictionary<string, string> FormOf(object? body)
    {
        switch (body)
        {
            case null:
                return new Dictionary<string, string>();
            case string text:
                return FirstQuery(text);
            case IReadOnlyDictionary<string, string> typed:
                return new Dictionary<string, string>(typed);
            case IReadOnlyDictionary<string, object?> boxed:
                var found = new Dictionary<string, string>();
                foreach (var pair in boxed)
                    if (pair.Value is string text) found[pair.Key] = text;
                return found;
            default:
                return new Dictionary<string, string>();
        }
    }
}
