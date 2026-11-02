// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using IyaSec.Saml;

const long SessionMs = 8 * 60 * 60 * 1000;

var port = 3000;
var publicUrl = "";
var publicGiven = false;
var configPath = "";
var secret = Array.Empty<byte>();
var secureCookies = true;
var signalsOff = false;
var ssfTransmitter = "";
var ssfPollMs = 0;
SignalsReceiver? receiver = null;
var receiverState = "not configured (no ssf block in the configuration file)";
ServiceProvider? spValue = null;
Exception? spErr = null;
var spReady = false;
var spGate = new object();
var sessions = new Dictionary<string, Held>();
var sessionsGate = new object();

try
{
    Configure(args);
}
catch (Exception ex)
{
    Console.Error.WriteLine(ex.Message);
    Environment.Exit(1);
}

var listener = new HttpListener();
try
{
    listener.Prefixes.Add("http://+:" + port + "/");
    listener.Start();
}
catch
{
    listener.Close();
    listener = new HttpListener();
    listener.Prefixes.Add("http://127.0.0.1:" + port + "/");
    listener.Start();
}
Console.WriteLine("saml2-sp demo on port " + port + ", configuration " + configPath);
var stopped = new ManualResetEventSlim(false);
using var term = PosixSignalRegistration.Create(PosixSignal.SIGTERM, ctx => { ctx.Cancel = true; Stop(); });
using var intr = PosixSignalRegistration.Create(PosixSignal.SIGINT, ctx => { ctx.Cancel = true; Stop(); });
var serve = Task.Run(() =>
{
    while (listener.IsListening)
    {
        HttpListenerContext ctx;
        try { ctx = listener.GetContext(); }
        catch { break; }
        try { Route(ctx); }
        catch { try { ctx.Response.Abort(); } catch { } }
    }
});
stopped.Wait();
receiver?.Stop();
try { listener.Close(); } catch { }
serve.Wait(TimeSpan.FromSeconds(2));

void Stop() => stopped.Set();

void Configure(string[] argv)
{
    if (Environment.GetEnvironmentVariable("PORT") is { Length: > 0 } rawPort)
    {
        if (!int.TryParse(rawPort, out port) || port < 1 || port > 65535)
            throw new InvalidOperationException("PORT is not a port");
    }
    var envPublic = Environment.GetEnvironmentVariable("PUBLIC_URL");
    publicUrl = (envPublic ?? "").TrimEnd('/');
    publicGiven = !string.IsNullOrEmpty(envPublic);
    configPath = Environment.GetEnvironmentVariable("SAML_CONFIG") ?? "";
    for (var i = 0; i < argv.Length; i++)
    {
        switch (argv[i])
        {
            case "--public-url":
                if (i + 1 >= argv.Length) throw new InvalidOperationException("--public-url needs a value");
                i++;
                publicUrl = argv[i].TrimEnd('/');
                publicGiven = true;
                break;
            case "--config":
                if (i + 1 >= argv.Length) throw new InvalidOperationException("--config needs a value");
                i++;
                configPath = argv[i];
                break;
            default:
                throw new InvalidOperationException("Unknown argument " + argv[i]);
        }
    }
    if (publicGiven && publicUrl.Length == 0) throw new InvalidOperationException("--public-url is empty");
    if (configPath.Length == 0) configPath = "demo/saml.json";
    configPath = Path.GetFullPath(configPath);
    var sessionSecret = Environment.GetEnvironmentVariable("SESSION_SECRET");
    if (!string.IsNullOrEmpty(sessionSecret)) secret = Encoding.UTF8.GetBytes(sessionSecret);
    else
    {
        secret = new byte[32];
        RandomNumberGenerator.Fill(secret);
    }
    var file = ReadFile();
    if (file.TryGetValue("signals", out var signals) && signals is false)
    {
        signalsOff = true;
        receiverState = "not configured (signals are off)";
    }
    if (!signalsOff && file.TryGetValue("ssf", out var ssfRaw) && ssfRaw is Dictionary<string, object?> ssf)
    {
        ssfTransmitter = ssf.TryGetValue("transmitter", out var tx) && tx is string text ? text : "";
        if (ssf.TryGetValue("pollIntervalMs", out var interval))
        {
            if (interval is long whole) ssfPollMs = (int)whole;
            else if (interval is double number) ssfPollMs = (int)number;
            else if (interval is int numberInt) ssfPollMs = numberInt;
        }
    }
    if (!signalsOff && ssfTransmitter.Length == 0)
        receiverState = "not configured (no ssf block in the configuration file)";
    secureCookies = SecureFrom(PortOverrides());
}

Dictionary<string, object?> ReadFile()
{
    try
    {
        return ConfigFile.ParseObject(File.ReadAllText(configPath));
    }
    catch
    {
        return new Dictionary<string, object?>();
    }
}

Dictionary<string, object?> PortOverrides()
{
    var file = ReadFile();
    var entity = file.TryGetValue("entityId", out var entityRaw) && entityRaw is string entityText ? entityText : "";
    var acs = file.TryGetValue("acsUrl", out var acsRaw) && acsRaw is string acsText ? acsText : "";
    if (entity.Length == 0 || acs.Length == 0) return new Dictionary<string, object?>();
    (entity, acs) = Endpoints(entity, acs);
    return new Dictionary<string, object?> { ["entityId"] = entity, ["acsUrl"] = acs };
}

(string Entity, string Acs) Endpoints(string entity, string acs)
{
    if (publicGiven && publicUrl.Length > 0) return (ReplaceOrigin(entity, publicUrl), ReplaceOrigin(acs, publicUrl));
    return (OnPort(entity, port), OnPort(acs, port));
}

static string ReplaceOrigin(string value, string publicBase)
{
    if (!Uri.TryCreate(publicBase, UriKind.Absolute, out var basis) || !Uri.TryCreate(value, UriKind.Absolute, out var parsed))
        return value;
    var builder = new UriBuilder(parsed) { Scheme = basis.Scheme, Host = basis.Host };
    builder.Port = basis.IsDefaultPort ? -1 : basis.Port;
    return builder.Uri.AbsoluteUri;
}

static string OnPort(string raw, int number)
{
    if (!Uri.TryCreate(raw, UriKind.Absolute, out var parsed)) return raw;
    var host = parsed.Host;
    if (host is not ("localhost" or "127.0.0.1" or "[::1]" or "::1")) return raw;
    var builder = new UriBuilder(parsed) { Port = number };
    return builder.Uri.AbsoluteUri;
}

bool SecureFrom(Dictionary<string, object?> overrides)
{
    var acs = overrides.TryGetValue("acsUrl", out var raw) && raw is string text && text.Length > 0 ? text : "http://localhost:" + port + "/";
    if (!Uri.TryCreate(acs, UriKind.Absolute, out var parsed)) return true;
    return parsed.Scheme == "https" || parsed.Host is "localhost" or "127.0.0.1";
}

ServiceProvider Provider()
{
    lock (spGate)
    {
        if (!spReady)
        {
            try
            {
                spValue = ServiceProvider.FromFile(configPath, PortOverrides(), null);
                StartReceiver(spValue);
            }
            catch (Exception ex)
            {
                spErr = ex;
            }
            spReady = true;
        }
    }
    if (spErr != null) throw spErr;
    return spValue!;
}

void StartReceiver(ServiceProvider sp)
{
    if (sp.Config.Signals is false)
    {
        receiverState = "not configured (signals are off)";
        return;
    }
    if (ssfTransmitter.Length == 0 || receiver != null) return;
    var tls = new TlsOptions
    {
        Cert = sp.Config.CertificatePem,
        Key = sp.Config.PrivateKeyPem,
        Ca = sp.Config.IdpCa,
    };
    SignalsReceiver built;
    try
    {
        built = SignalsReceiver.Create(new ReceiverOptions
        {
            Transmitter = ssfTransmitter,
            Tls = tls,
            Description = "saml2-sp demo (" + sp.Config.EntityId + ")",
            PollIntervalMs = ssfPollMs,
            OnEndSessions = (ids, _) =>
            {
                lock (sessionsGate)
                    foreach (var id in ids) sessions.Remove(id);
                Console.WriteLine("ssf: ended " + ids.Count + " local session(s)");
                return null;
            },
        });
    }
    catch (Exception ex)
    {
        receiverState = "not running: " + ex.Message;
        return;
    }
    receiver = built;
    Task.Run(() =>
    {
        try
        {
            built.Start();
            var stream = built.Stream.TryGetValue("stream_id", out var id) && id is string text ? text : "";
            receiverState = "polling stream " + stream + " at " + ssfTransmitter;
        }
        catch (Exception ex)
        {
            receiverState = "not running: " + ex.Message;
            Console.WriteLine("ssf: the receiver did not start: " + ex.Message);
            if (receiver == built) receiver = null;
        }
    });
}

void Route(HttpListenerContext ctx)
{
    var path = ctx.Request.Url?.AbsolutePath ?? "/";
    if (path == "/healthz")
    {
        WriteBytes(ctx, 200, "ok", "text/plain");
        return;
    }
    switch (path)
    {
        case "/styles.css":
            ServeFile(ctx, "demo/public/styles.css", "text/css");
            return;
        case "/app.js":
            ServeFile(ctx, "demo/public/app.js", "text/javascript");
            return;
        case "/saml/metadata":
            try
            {
                WriteBytes(ctx, 200, Provider().Metadata(), "application/samlmetadata+xml");
            }
            catch (Exception ex)
            {
                WriteBytes(ctx, 500, ex.Message, "text/plain");
            }
            return;
        case "/login" when ctx.Request.HttpMethod == "GET":
            Login(ctx);
            return;
        case "/saml/acs" when ctx.Request.HttpMethod is "GET" or "POST":
            Acs(ctx);
            return;
        case "/logout" when ctx.Request.HttpMethod == "POST":
            Logout(ctx);
            return;
        case "/" when ctx.Request.HttpMethod == "GET":
            Page(ctx);
            return;
    }
    WriteBytes(ctx, 404, "not found", "text/plain");
}

void Page(HttpListenerContext ctx)
{
    var problem = "";
    try { Provider(); }
    catch (Exception ex) { problem = "The service provider is not configured yet: " + ex.Message + ". Run the setup script (python scripts/configure_iya_sts.py)."; }
    var current = CurrentSession(ctx.Request);
    var body = "<h1>SAML service provider</h1>";
    if (problem.Length > 0 && current == null) body += "<p class=\"problem\">" + WebUtility.HtmlEncode(problem) + "</p>";
    body += "<p>Shared Signals: " + WebUtility.HtmlEncode(receiverState) + "</p>";
    if (current != null)
    {
        body += "<p>Signed in as <strong>" + WebUtility.HtmlEncode(current.Login.NameId) + "</strong> (" + WebUtility.HtmlEncode(current.Login.Binding) + ").</p>";
        body += "<form method=\"post\" action=\"/logout\"><button type=\"submit\">Log out</button></form>";
    }
    else if (problem.Length == 0) body += "<p><a href=\"/login\">Sign in</a></p>";
    WritePage(ctx, "saml2-sp", body, 200);
}

void Login(HttpListenerContext ctx)
{
    ServiceProvider sp;
    try { sp = Provider(); }
    catch (Exception ex)
    {
        WritePage(ctx, "Sign-in", "<h1>Sign-in is not available</h1><p class=\"problem\">" + WebUtility.HtmlEncode(ex.Message) + "</p>", 500);
        return;
    }
    var asked = ctx.Request.QueryString["binding"] ?? "";
    var responseBinding = asked is "post" or "redirect" or "artifact" ? asked : "";
    var nonce = WorldB64(Random(16));
    LoginRequest req;
    try { req = sp.Login(new LoginOptions { RelayState = "/", Nonce = nonce, ResponseBinding = responseBinding }); }
    catch (Exception ex)
    {
        WritePage(ctx, "Sign-in", "<h1>Sign-in failed</h1><p class=\"problem\">" + WebUtility.HtmlEncode(ex.Message) + "</p>", 400);
        return;
    }
    SetCookie(ctx, "saml_pending", Seal(new Dictionary<string, object?> { ["ids"] = new List<string> { req.Id } }), AcsPath(sp), 600, "None");
    if (req.Binding == "redirect")
    {
        ctx.Response.Headers.Add("referrer-policy", "no-referrer");
        ctx.Response.StatusCode = 302;
        ctx.Response.RedirectLocation = req.Url;
        ctx.Response.Close();
        return;
    }
    var origin = new Uri(req.Url);
    ctx.Response.Headers.Add("content-security-policy", "default-src 'none'; script-src 'nonce-" + nonce + "'; form-action " + origin.Scheme + "://" + origin.Host + "; frame-ancestors 'none'; base-uri 'none'");
    WriteBytes(ctx, 200, req.Html, "text/html; charset=utf-8");
}

void Acs(HttpListenerContext ctx)
{
    ServiceProvider sp;
    try { sp = Provider(); }
    catch (Exception ex)
    {
        WritePage(ctx, "Sign-in failed", "<h1>Sign-in failed</h1><p class=\"problem\">" + WebUtility.HtmlEncode(ex.Message) + "</p>", 400);
        return;
    }
    string? body = null;
    if (ctx.Request.HttpMethod == "POST")
    {
        using var reader = new StreamReader(ctx.Request.InputStream, Encoding.UTF8);
        var raw = reader.ReadToEnd();
        if (raw.Length > 512 * 1024) raw = raw[..(512 * 1024)];
        body = raw;
    }
    var pending = Unseal(CookieValue(ctx.Request, "saml_pending"));
    var ids = new List<string>();
    if (pending != null && pending.TryGetValue("ids", out var list) && list is List<object?> items)
        foreach (var item in items)
            if (item is string text) ids.Add(text);
    var rawUrl = ctx.Request.Url?.PathAndQuery ?? "/saml/acs";
    SamlLogin login;
    try { login = sp.Acs(ctx.Request.HttpMethod, rawUrl, body, ids); }
    catch (Exception ex)
    {
        SetCookie(ctx, "saml_pending", "", AcsPath(sp), 0, "None");
        WritePage(ctx, "Sign-in failed", "<h1>Sign-in failed</h1><p class=\"problem\">" + WebUtility.HtmlEncode(ex.Message) + "</p><p><a href=\"/\">Start again</a></p>", 400);
        return;
    }
    var sid = WorldB64(Random(32));
    var until = DateTimeOffset.UtcNow.AddMilliseconds(SessionMs);
    if (login.SessionNotOnOrAfter != null && login.SessionNotOnOrAfter.Value < until) until = login.SessionNotOnOrAfter.Value;
    lock (sessionsGate) sessions[sid] = new Held { Login = login, Expires = until };
    receiver?.Track(sid, login, until);
    Console.WriteLine("signed in " + login.NameId + " by " + login.Binding + " (assertion " + login.AssertionId + ")");
    SetCookie(ctx, "saml_pending", "", AcsPath(sp), 0, "None");
    SetCookie(ctx, "sid", sid, "/", (int)Math.Max(0, (until - DateTimeOffset.UtcNow).TotalSeconds), "Lax");
    ctx.Response.StatusCode = 303;
    ctx.Response.RedirectLocation = "/";
    ctx.Response.Close();
}

void Logout(HttpListenerContext ctx)
{
    var sid = CookieValue(ctx.Request, "sid");
    if (sid.Length > 0)
    {
        lock (sessionsGate) sessions.Remove(sid);
        receiver?.Untrack(sid);
    }
    SetCookie(ctx, "sid", "", "/", 0, "Lax");
    ctx.Response.StatusCode = 303;
    ctx.Response.RedirectLocation = "/";
    ctx.Response.Close();
}

Held? CurrentSession(HttpListenerRequest request)
{
    var sid = CookieValue(request, "sid");
    if (sid.Length == 0) return null;
    lock (sessionsGate)
    {
        if (!sessions.TryGetValue(sid, out var found) || DateTimeOffset.UtcNow > found.Expires)
        {
            sessions.Remove(sid);
            return null;
        }
        return found;
    }
}

static string AcsPath(ServiceProvider sp)
{
    if (!Uri.TryCreate(sp.Config.AcsUrl, UriKind.Absolute, out var parsed) || parsed.AbsolutePath.Length == 0) return "/";
    return parsed.AbsolutePath;
}

static string CookieValue(HttpListenerRequest request, string name)
{
    var header = request.Headers["Cookie"];
    if (string.IsNullOrEmpty(header)) return "";
    foreach (var part in header.Split(';'))
    {
        var piece = part.Trim();
        var eq = piece.IndexOf('=');
        if (eq < 0) continue;
        if (piece[..eq] == name) return piece[(eq + 1)..];
    }
    return "";
}

void SetCookie(HttpListenerContext ctx, string name, string value, string path, int maxAge, string sameSite)
{
    var cookie = name + "=" + value + "; Path=" + path + "; Max-Age=" + maxAge + "; HttpOnly";
    if (secureCookies) cookie += "; Secure";
    cookie += "; SameSite=" + sameSite;
    ctx.Response.AppendHeader("Set-Cookie", cookie);
}

string Seal(Dictionary<string, object?> value)
{
    var raw = Encoding.UTF8.GetBytes(JsonMaps.Stringify(value));
    var mac = HMACSHA256.HashData(secret, raw);
    return WorldB64(raw) + "." + WorldB64(mac);
}

Dictionary<string, object?>? Unseal(string value)
{
    var parts = value.Split('.');
    if (parts.Length != 2) return null;
    byte[] raw;
    byte[] sig;
    try
    {
        raw = B64(parts[0]);
        sig = B64(parts[1]);
    }
    catch (FormatException)
    {
        return null;
    }
    var mac = HMACSHA256.HashData(secret, raw);
    if (!CryptographicOperations.FixedTimeEquals(sig, mac)) return null;
    try
    {
        return JsonMaps.Parse(Encoding.UTF8.GetString(raw)) as Dictionary<string, object?>;
    }
    catch
    {
        return null;
    }
}

static byte[] Random(int n)
{
    var buf = new byte[n];
    RandomNumberGenerator.Fill(buf);
    return buf;
}

static string WorldB64(byte[] data) => Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');

static byte[] B64(string value)
{
    var text = value.Replace('-', '+').Replace('_', '/');
    text += (text.Length % 4) switch { 2 => "==", 3 => "=", _ => "" };
    return Convert.FromBase64String(text);
}

static void ServeFile(HttpListenerContext ctx, string path, string type)
{
    if (!File.Exists(path))
    {
        WriteBytes(ctx, 404, "not found", "text/plain");
        return;
    }
    WriteBytes(ctx, 200, File.ReadAllText(path), type);
}

static void WritePage(HttpListenerContext ctx, string title, string body, int status)
{
    var html = "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>" + WebUtility.HtmlEncode(title) + "</title><link rel=\"stylesheet\" href=\"/styles.css\"></head><body>" + body + "</body></html>";
    WriteBytes(ctx, status, html, "text/html; charset=utf-8");
}

static void WriteBytes(HttpListenerContext ctx, int status, string body, string type)
{
    var bytes = Encoding.UTF8.GetBytes(body);
    ctx.Response.StatusCode = status;
    ctx.Response.ContentType = type;
    ctx.Response.ContentLength64 = bytes.Length;
    ctx.Response.OutputStream.Write(bytes);
    ctx.Response.OutputStream.Close();
}

sealed class Held
{
    public SamlLogin Login { get; init; } = null!;
    public DateTimeOffset Expires { get; init; }
}
