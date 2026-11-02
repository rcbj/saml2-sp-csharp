// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

using System.Text.Json;
using IyaSec.Saml;

const string UsageText = """
Usage:
  saml2-sp generate-keys --config <saml.json> [--cn <name>] [--days <n>] [--bits <n>] [--force]
  saml2-sp generate-keys --key <file> --cert <file> [--cn <name>] [--days <n>] [--bits <n>] [--force]
      A new RSA key and a self-signed certificate, written where the configuration's privateKey and
      certificate point (or to --key and --cert). Refuses to replace existing files without --force.
      The common name defaults to the host of the configuration's entityId.

  saml2-sp metadata --config <saml.json> [--out <file>] [--entity-id <url>] [--acs-url <url>]
      This service provider's SAML metadata, from the configuration and its certificate. Written to
      --out, or to standard output. --entity-id and --acs-url replace the file's values for this run.

  saml2-sp summarize-idp
      Read identity-provider metadata on standard input. Write its entityID, its SSO URL, and one
      artifact-resolution URL per line.
""";

try
{
    Run(args);
}
catch (Exception ex)
{
    Console.Error.WriteLine(ex.Message);
    Environment.Exit(1);
}

static void Run(string[] argv)
{
    var (command, parsed) = ParseArgs(argv);
    if (command.Length == 0 || parsed.TryGetValue("help", out var help) && help == "true" || command == "help")
    {
        Console.WriteLine(UsageText);
        return;
    }
    switch (command)
    {
        case "generate-keys":
            GenerateKeys(parsed);
            return;
        case "metadata":
            WriteMetadata(parsed);
            return;
        case "summarize-idp":
            Summarize(Console.OpenStandardInput());
            return;
        default:
            throw new InvalidOperationException("unknown command " + command + "\n\n" + UsageText);
    }
}

static (string Command, Dictionary<string, string> Args) ParseArgs(string[] argv)
{
    var command = argv.Length > 0 ? argv[0] : "";
    var rest = argv.Length > 0 ? argv[1..] : argv;
    var parsed = new Dictionary<string, string>();
    for (var index = 0; index < rest.Length; index++)
    {
        var item = rest[index];
        if (!item.StartsWith("--", StringComparison.Ordinal))
            throw new InvalidOperationException("unexpected argument " + item + "\n\n" + UsageText);
        var key = item[2..];
        if (key is "force" or "help")
        {
            parsed[key] = "true";
            continue;
        }
        if (index + 1 >= rest.Length || rest[index + 1].StartsWith("--", StringComparison.Ordinal))
            throw new InvalidOperationException("--" + key + " needs a value\n\n" + UsageText);
        index++;
        parsed[key] = rest[index];
    }
    return (command, parsed);
}

static void GenerateKeys(Dictionary<string, string> parsed)
{
    var paths = KeyPaths(parsed);
    if (parsed.GetValueOrDefault("force") != "true" && (File.Exists(paths.Key) || File.Exists(paths.Cert)))
    {
        var which = File.Exists(paths.Key) ? paths.Key : paths.Cert;
        throw new InvalidOperationException(which + " already exists; pass --force to replace the key pair.\nReplacing it means giving the identity provider the new metadata before the next sign-in.");
    }
    var days = 1095;
    if (parsed.TryGetValue("days", out var rawDays) && rawDays.Length > 0)
    {
        if (!int.TryParse(rawDays, out days) || days <= 0)
            throw new InvalidOperationException("--days must be a positive whole number");
    }
    var bits = 3072;
    if (parsed.TryGetValue("bits", out var rawBits) && rawBits.Length > 0)
    {
        if (!int.TryParse(rawBits, out bits) || bits is not (2048 or 3072 or 4096))
            throw new InvalidOperationException("--bits must be 2048, 3072 or 4096");
    }
    using var pair = Keys.CreateSelfSignedKeyPair(paths.Cn, days, bits);
    WriteMode(paths.Key, pair.PrivateKeyPem, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    WriteMode(paths.Cert, pair.CertificatePem, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead);
    Console.WriteLine("Wrote the private key  " + paths.Key + " (mode 600)");
    Console.WriteLine("Wrote the certificate  " + paths.Cert);
    Console.WriteLine("  subject   CN=" + paths.Cn);
    Console.WriteLine("  valid to  " + pair.ValidTo());
    Console.WriteLine("  sha256    " + pair.Fingerprint256());
}

static (string Key, string Cert, string Cn) KeyPaths(Dictionary<string, string> parsed)
{
    var configPath = parsed.GetValueOrDefault("config") ?? "";
    var key = parsed.GetValueOrDefault("key") ?? "";
    var cert = parsed.GetValueOrDefault("cert") ?? "";
    var cn = parsed.GetValueOrDefault("cn") ?? "";
    if (configPath.Length > 0)
    {
        var raw = ReadObject(configPath);
        var baseDir = Path.GetDirectoryName(Abs(configPath)) ?? "";
        string At(string? value, string what)
        {
            if (string.IsNullOrEmpty(value) || value.Contains("-----BEGIN ", StringComparison.Ordinal) || value.StartsWith("env:", StringComparison.Ordinal))
                throw new InvalidOperationException(configPath + "'s " + what + " must be a file path for generate-keys to write to");
            if (value.StartsWith("file:", StringComparison.Ordinal)) value = value[5..];
            if (!Path.IsPathRooted(value)) value = Path.Combine(baseDir, value);
            return Path.GetFullPath(value);
        }
        if (key.Length == 0) key = At(RawString(raw, "privateKey"), "privateKey");
        if (cert.Length == 0) cert = At(RawString(raw, "certificate"), "certificate");
        if (cn.Length == 0)
        {
            var entity = RawString(raw, "entityId");
            if (entity.Length > 0)
            {
                if (Uri.TryCreate(entity, UriKind.Absolute, out var uri) && !string.IsNullOrEmpty(uri.Host)) cn = uri.Host;
                else cn = entity;
            }
        }
    }
    if (key.Length == 0 || cert.Length == 0)
        throw new InvalidOperationException("generate-keys needs --config, or --key and --cert\n\n" + UsageText);
    if (cn.Length == 0) cn = "saml2-sp service provider";
    return (Abs(key), Abs(cert), cn);
}

static void WriteMetadata(Dictionary<string, string> parsed)
{
    var configPath = parsed.GetValueOrDefault("config") ?? "";
    if (configPath.Length == 0) throw new InvalidOperationException("metadata needs --config\n\n" + UsageText);
    var raw = ReadObject(configPath);
    raw.Remove("idpCa");
    if (parsed.TryGetValue("entity-id", out var entity) && entity.Length > 0) raw["entityId"] = entity;
    if (parsed.TryGetValue("acs-url", out var acs) && acs.Length > 0) raw["acsUrl"] = acs;
    var cfg = ConfigFile.ResolveConfig(raw, Path.GetDirectoryName(Abs(configPath)));
    var xml = SamlMetadata.MetadataDocument(cfg);
    if (parsed.TryGetValue("out", out var target) && target.Length > 0)
    {
        WriteMode(Abs(target), xml, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead);
        Console.WriteLine("Wrote the service provider metadata to " + Abs(target));
        return;
    }
    Console.Write(xml);
}

static void Summarize(Stream input)
{
    using var reader = new StreamReader(input);
    var raw = reader.ReadToEnd();
    if (raw.Length > 2 * 1024 * 1024) raw = raw[..(2 * 1024 * 1024)];
    var meta = SamlMetadata.ReadIdpMetadata(raw);
    Console.WriteLine(meta.EntityId);
    var sso = meta.Sso.TryGetValue("redirect", out var redirect) && redirect.Length > 0 ? redirect : meta.Sso.GetValueOrDefault("post") ?? "";
    Console.WriteLine(sso);
    foreach (var index in meta.ArtifactResolutionServices.Keys.OrderBy(value => value))
        Console.WriteLine(meta.ArtifactResolutionServices[index]);
}

static Dictionary<string, object?> ReadObject(string path)
{
    var raw = File.ReadAllText(path);
    try
    {
        return ConfigFile.ParseObject(raw);
    }
    catch (JsonException ex)
    {
        throw new InvalidOperationException(path + " is not a JSON object", ex);
    }
    catch (SamlException ex) when (ex.Message == "the configuration must be an object")
    {
        throw new InvalidOperationException(path + " is not a JSON object", ex);
    }
}

static string RawString(Dictionary<string, object?> obj, string key) =>
    obj.TryGetValue(key, out var value) && value is string text ? text : "";

static string Abs(string path) => Path.GetFullPath(path);

static void WriteMode(string path, string text, UnixFileMode mode)
{
    var dir = Path.GetDirectoryName(path);
    if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
    File.WriteAllText(path, text);
    File.SetUnixFileMode(path, mode);
}
