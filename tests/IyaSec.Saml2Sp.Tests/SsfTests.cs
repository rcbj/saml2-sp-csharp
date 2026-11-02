// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

using System.Net;
using System.Security.Cryptography;
using IyaSec.Saml;

namespace IyaSec.Saml2Sp.Tests;

public class SsfTests
{
    [Fact]
    public void VerifiesASetAgainstTheJwks()
    {
        var jwk = World.Jwk(World.Tx, "k1");
        var (_, payload) = Jws.VerifyCompact(World.SignJws(new Dictionary<string, object?> { ["a"] = 1 }, World.Tx), new[] { jwk });
        Assert.Equal(1L, Convert.ToInt64(payload["a"]));
        World.Rejects(() => Jws.VerifyCompact(World.SignJws(new Dictionary<string, object?> { ["a"] = 1 }, World.Other), new[] { jwk }), "signature", "does not verify");
        World.Rejects(() => Jws.VerifyCompact(World.SignJws(new Dictionary<string, object?> { ["a"] = 1 }, World.Tx, new Dictionary<string, object?> { ["alg"] = "RS256", ["kid"] = "nope" }), new[] { jwk }), "signature", "no RSA signing key with kid nope");
        World.Rejects(() => Jws.VerifyCompact(World.SignJws(new Dictionary<string, object?> { ["a"] = 1 }, World.Tx, new Dictionary<string, object?> { ["alg"] = "none" }), new[] { jwk }), "signature", "does not verify");
        World.Rejects(() => Jws.VerifyCompact(World.SignJws(new Dictionary<string, object?> { ["a"] = 1 }, World.Tx, new Dictionary<string, object?> { ["alg"] = "HS256", ["kid"] = "k1" }), new[] { jwk }), "signature", "does not verify");
    }

    [Fact]
    public void ReadsComplexIssSubAndEmailSubjects()
    {
        var got = Events.SubjectOf(Map(
            ("format", "complex"),
            ("user", Map(("format", "iss_sub"), ("iss", "https://i"), ("sub", "urn:uuid:a"))),
            ("session", Map(("format", "opaque"), ("id", "S1")))
        ), "https://i");
        Assert.Equal("urn:uuid:a", got["person"]);
        Assert.Equal("S1", got["idp_session"]);
        Assert.Empty(Events.SubjectOf(Map(("format", "iss_sub"), ("iss", "https://other"), ("sub", "urn:uuid:a")), "https://i"));
        var email = Events.SubjectOf(Map(("format", "email"), ("email", "A@x.com")), "https://i");
        Assert.Equal("A@x.com", email["email"]);
    }

    [Fact]
    public void NamesAllEightCaepAndFourteenRiscEventTypes()
    {
        Assert.Equal(8, Events.CaepEvents().Count);
        Assert.Equal(14, Events.RiscEvents().Count);
        Assert.Contains(Events.Event["risk_level_change"], Events.CaepEvents());
        Assert.Contains(Events.Event["opt_out_effective"], Events.RiscEvents());
    }

    [Fact]
    public void SharedSignals()
    {
        using var stub = new TxStub();
        CreatesItsPollStreamOnceAndAcknowledges(stub);
        RefusesAForgedMisaddressedOrForeignSet(stub);
        AcknowledgesAValidSetWhoseHandlerThrows(stub);
        NeverRunsTwoPollsAtOnce(stub);
    }

    static void CreatesItsPollStreamOnceAndAcknowledges(TxStub stub)
    {
        var ended = new List<string>();
        var seen = new List<SignalEvent>();
        var receiver = SignalsReceiver.Create(new ReceiverOptions
        {
            Transmitter = stub.Url,
            PollIntervalMs = 60000,
            Log = new QuietLog(),
            OnEndSessions = (ids, _) => { ended.Add(string.Join(",", ids)); return null; },
        });
        receiver.On("*", ev => { seen.Add(ev); return null; });
        receiver.Start();
        receiver.Stop();
        Assert.Equal(1, stub.Created);
        Assert.Equal("s1", Text(receiver.Stream, "stream_id"));
        receiver.Track("L-a1", LoginOf("alice", "IDP-A1"), null);
        receiver.Track("L-a2", LoginOf("alice", "IDP-A2"), null);
        receiver.Track("L-b1", LoginOf("bob", "IDP-B1"), null);
        var j1 = stub.Put(Events.Event["session_revoked"], Map(("format", "complex"), ("user", Map(("format", "iss_sub"), ("iss", stub.Url), ("sub", "urn:uuid:alice"))), ("session", Map(("format", "opaque"), ("id", "IDP-A1")))));
        var j2 = stub.Put(Events.Event["credential_change"], Map(("format", "complex"), ("user", Map(("format", "iss_sub"), ("iss", stub.Url), ("sub", "urn:uuid:bob")))), Map(("credential_type", "password"), ("change_type", "update")));
        receiver.PollOnce();
        Assert.Equal(new[] { "L-a1" }, ended);
        var found = seen.FirstOrDefault(ev => ev.Jti == j2);
        Assert.NotNull(found);
        Assert.False(found!.Ended);
        Assert.Equal("L-b1", string.Join(",", found.Sessions));
        var j3 = stub.Put(Events.Event["account_disabled"], Map(("format", "iss_sub"), ("iss", stub.Url), ("sub", "urn:uuid:alice")));
        receiver.PollOnce();
        Assert.Equal(new[] { "L-a1", "L-a2" }, ended);
        receiver.PollOnce();
        Assert.Contains(j1, stub.Acked);
        Assert.Contains(j2, stub.Acked);
        stub.Put(Events.Event["credential_compromise"], Map(("format", "email"), ("email", "BOB@example.com")), Map(("credential_type", "password")));
        receiver.PollOnce();
        Assert.Equal("L-b1", ended[2]);
        receiver.PollOnce();
        Assert.Contains(j3, stub.Acked);
        var again = SignalsReceiver.Create(new ReceiverOptions { Transmitter = stub.Url, Log = new QuietLog(), OnEndSessions = (_, _) => null });
        again.Start();
        again.Stop();
        Assert.Equal(1, stub.Created);
        Assert.Equal("s1", Text(again.Stream, "stream_id"));
    }

    static void RefusesAForgedMisaddressedOrForeignSet(TxStub stub)
    {
        var ended = new List<IReadOnlyList<string>>();
        var index = new MemorySessionIndex();
        var receiver = SignalsReceiver.Create(new ReceiverOptions
        {
            Transmitter = stub.Url,
            SessionIndex = index,
            Log = new QuietLog(),
            OnEndSessions = (ids, _) => { ended.Add(ids); return null; },
        });
        receiver.Start();
        receiver.Stop();
        receiver.Track("L-c1", LoginOf("carol", "IDP-C1"), null);
        var subject = Map(("format", "complex"), ("user", Map(("format", "iss_sub"), ("iss", stub.Url), ("sub", "urn:uuid:carol"))), ("session", Map(("format", "opaque"), ("id", "IDP-C1"))));
        var forged = stub.Put(Events.Event["session_revoked"], subject, key: World.Other);
        var mis = stub.Put(Events.Event["session_revoked"], subject, aud: "someone-else");
        var foreign = stub.Put(Events.Event["session_revoked"], subject, iss: "https://evil.example");
        receiver.PollOnce();
        Assert.Empty(ended);
        Assert.Equal("L-c1", string.Join(",", index.ByPerson("urn:uuid:carol")));
        receiver.PollOnce();
        Assert.True(stub.Errs.ContainsKey(forged));
        Assert.True(stub.Errs.ContainsKey(mis));
        Assert.True(stub.Errs.ContainsKey(foreign));
    }

    static void AcknowledgesAValidSetWhoseHandlerThrows(TxStub stub)
    {
        var errors = new List<string>();
        var seen = new List<string>();
        var receiver = SignalsReceiver.Create(new ReceiverOptions
        {
            Transmitter = stub.Url,
            Log = new CollectingLog(errors),
            OnEndSessions = (_, _) => new SamlException("ssf", "store down"),
        });
        receiver.On(Events.Event["credential_change"], _ => new SamlException("ssf", "handler bug"));
        receiver.On("*", ev => { seen.Add(ev.Jti); return null; });
        receiver.Start();
        receiver.Stop();
        receiver.Track("L-d1", LoginOf("dave", "IDP-D1"), null);
        var j1 = stub.Put(Events.Event["credential_change"], Map(("format", "complex"), ("user", Map(("format", "iss_sub"), ("iss", stub.Url), ("sub", "urn:uuid:dave")))), Map(("credential_type", "password"), ("change_type", "update")));
        var j2 = stub.Put(Events.Event["session_revoked"], Map(("format", "complex"), ("user", Map(("format", "iss_sub"), ("iss", stub.Url), ("sub", "urn:uuid:dave"))), ("session", Map(("format", "opaque"), ("id", "IDP-D1")))));
        for (var i = 0; i < 3; i++) receiver.PollOnce();
        Assert.Contains(j1, stub.Acked);
        Assert.Contains(j2, stub.Acked);
        Assert.False(stub.Errs.ContainsKey(j1));
        Assert.False(stub.Errs.ContainsKey(j2));
        seen.Sort(StringComparer.Ordinal);
        var want = new List<string> { j1, j2 };
        want.Sort(StringComparer.Ordinal);
        Assert.Equal(want, seen);
        Assert.Contains(errors, message => System.Text.RegularExpressions.Regex.IsMatch(message, "handler for .*credential-change threw"));
        Assert.Contains(errors, message => message.Contains("onEndSessions threw", StringComparison.Ordinal));
    }

    static void NeverRunsTwoPollsAtOnce(TxStub stub)
    {
        var seen = new List<string>();
        var gate = new object();
        var receiver = SignalsReceiver.Create(new ReceiverOptions { Transmitter = stub.Url, Log = new QuietLog(), OnEndSessions = (_, _) => null });
        receiver.On("*", ev =>
        {
            lock (gate) seen.Add(ev.Jti);
            return null;
        });
        receiver.Start();
        receiver.Stop();
        var jti = stub.Put(Events.Event["account_enabled"], Map(("format", "iss_sub"), ("iss", stub.Url), ("sub", "urn:uuid:erin")));
        var tasks = Enumerable.Range(0, 3).Select(_ => Task.Run(() => receiver.PollOnce())).ToArray();
        Task.WaitAll(tasks);
        receiver.PollOnce();
        Assert.Equal(1, seen.Count(item => item == jti));
    }

    [Fact]
    public void RefusesATransmitterWithoutPollDelivery()
    {
        var receiver = SignalsReceiver.Create(new ReceiverOptions { Transmitter = "http://127.0.0.1:1", Log = new QuietLog(), OnEndSessions = (_, _) => null });
        var ex = Assert.Throws<SamlException>(() => receiver.Start());
        Assert.Equal("ssf", ex.Code);
    }

    [Fact]
    public void StopWaitsForAnInFlightPoll()
    {
        using var stub = new TxStub();
        var hold = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var entered = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        stub.Hold = hold;
        stub.Entered = entered;
        var receiver = SignalsReceiver.Create(new ReceiverOptions { Transmitter = stub.Url, PollIntervalMs = 60000, Log = new QuietLog(), OnEndSessions = (_, _) => null });
        var started = Task.Run(() => receiver.Start());
        Assert.True(entered.Task.Wait(TimeSpan.FromSeconds(5)), "poll did not start");
        var stopped = Task.Run(() => receiver.Stop());
        Assert.False(stopped.Wait(TimeSpan.FromMilliseconds(150)), "stop returned before the poll finished");
        hold.TrySetResult(true);
        Assert.True(stopped.Wait(TimeSpan.FromSeconds(5)), "stop did not return");
        started.Wait(TimeSpan.FromSeconds(5));
        if (started.IsFaulted) throw started.Exception!.InnerException!;
    }

    static Dictionary<string, object?> Map(params (string Key, object? Value)[] pairs)
    {
        var map = new Dictionary<string, object?>();
        foreach (var (key, value) in pairs) map[key] = value;
        return map;
    }

    static string Text(Dictionary<string, object?> obj, string key) =>
        obj.TryGetValue(key, out var value) && value is string text ? text : "";

    static SamlLogin LoginOf(string person, string session) => new()
    {
        NameId = person,
        SessionIndex = session,
        Attributes = new Dictionary<string, List<string>>
        {
            [MemorySessionIndex.DefaultSubjectAttribute] = new List<string> { "urn:uuid:" + person },
            ["urn:oid:0.9.2342.19200300.100.1.3"] = new List<string> { person + "@example.com" },
        },
    };

    sealed class QuietLog : ISignalLogger
    {
        public void Info(string message) { }
        public void Warn(string message) { }
        public void Error(string message) { }
    }

    sealed class CollectingLog : ISignalLogger
    {
        readonly List<string> _errors;
        public CollectingLog(List<string> errors) => _errors = errors;
        public void Info(string message) { }
        public void Warn(string message) { }
        public void Error(string message) => _errors.Add(message);
    }
}

sealed class TxStub : IDisposable
{
    readonly object _gate = new();
    readonly Dictionary<string, string> _queue = new();
    public readonly List<string> Acked = new();
    public readonly Dictionary<string, object?> Errs = new();
    readonly List<Dictionary<string, object?>> _streams = new();
    public int Created { get; private set; }
    public string Url { get; }
    public TaskCompletionSource<bool>? Hold { get; set; }
    public TaskCompletionSource<bool>? Entered { get; set; }
    int _enteredOnce;
    readonly LoopServer _server;
    readonly Dictionary<string, object?> _jwk;

    public TxStub()
    {
        _jwk = World.Jwk(World.Tx, "k1");
        _server = new LoopServer(Handle);
        Url = _server.Origin;
    }

    public string Put(string eventType, Dictionary<string, object?> subId, Dictionary<string, object?>? extra = null, RSA? key = null, string aud = "", string iss = "")
    {
        key ??= World.Tx;
        if (aud.Length == 0) aud = "my-app";
        if (iss.Length == 0) iss = Url;
        var jti = Ids.New().TrimStart('_');
        var ev = new Dictionary<string, object?> { ["event_timestamp"] = 1 };
        if (extra != null)
            foreach (var pair in extra) ev[pair.Key] = pair.Value;
        var token = World.SignJws(new Dictionary<string, object?>
        {
            ["iss"] = iss,
            ["aud"] = aud,
            ["jti"] = jti,
            ["iat"] = 1,
            ["sub_id"] = subId,
            ["events"] = new Dictionary<string, object?> { [eventType] = ev },
        }, key);
        lock (_gate) _queue[jti] = token;
        return jti;
    }

    void Handle(HttpListenerContext ctx)
    {
        var raw = LoopServer.ReadBody(ctx.Request);
        var path = ctx.Request.Url?.AbsolutePath ?? "/";
        if (path == "/.well-known/ssf-configuration")
        {
            Write(ctx, 200, new Dictionary<string, object?>
            {
                ["issuer"] = Url,
                ["jwks_uri"] = Url + "/jwks",
                ["configuration_endpoint"] = Url + "/ssf/stream",
                ["verification_endpoint"] = Url + "/ssf/verify",
                ["delivery_methods_supported"] = new List<string> { "urn:ietf:rfc:8936" },
            });
            return;
        }
        if (path == "/jwks")
        {
            Write(ctx, 200, new Dictionary<string, object?> { ["keys"] = new List<object?> { _jwk } });
            return;
        }
        if (path == "/ssf/stream" && ctx.Request.HttpMethod == "GET")
        {
            List<Dictionary<string, object?>> streams;
            lock (_gate) streams = _streams.ToList();
            Write(ctx, 200, streams);
            return;
        }
        if (path == "/ssf/stream" && ctx.Request.HttpMethod == "POST")
        {
            var body = JsonMaps.Parse(raw) as Dictionary<string, object?> ?? new Dictionary<string, object?>();
            Dictionary<string, object?> stream;
            lock (_gate)
            {
                Created++;
                var delivery = body.TryGetValue("delivery", out var deliveryRaw) ? deliveryRaw as Dictionary<string, object?> : null;
                stream = new Dictionary<string, object?>
                {
                    ["stream_id"] = "s" + Created,
                    ["iss"] = Url,
                    ["aud"] = "my-app",
                    ["delivery"] = new Dictionary<string, object?> { ["method"] = delivery?["method"], ["endpoint_url"] = Url + "/ssf/poll/s" + Created },
                    ["events_requested"] = body.TryGetValue("events_requested", out var requested) ? requested : null,
                    ["events_delivered"] = body.TryGetValue("events_requested", out var delivered) ? delivered : null,
                };
                _streams.Add(stream);
            }
            Write(ctx, 201, stream);
            return;
        }
        if (path.StartsWith("/ssf/poll/", StringComparison.Ordinal))
        {
            if (Hold != null)
            {
                if (Interlocked.Exchange(ref _enteredOnce, 1) == 0) Entered?.TrySetResult(true);
                Hold.Task.Wait();
            }
            var body = raw.Length == 0 ? new Dictionary<string, object?>() : JsonMaps.Parse(raw) as Dictionary<string, object?> ?? new Dictionary<string, object?>();
            Dictionary<string, string> sets;
            lock (_gate)
            {
                if (body.TryGetValue("ack", out var ackRaw) && ackRaw is List<object?> ack)
                {
                    foreach (var item in ack)
                    {
                        if (item is not string jti) continue;
                        Acked.Add(jti);
                        _queue.Remove(jti);
                    }
                }
                if (body.TryGetValue("setErrs", out var errRaw) && errRaw is Dictionary<string, object?> setErrs)
                {
                    foreach (var pair in setErrs)
                    {
                        Errs[pair.Key] = pair.Value;
                        _queue.Remove(pair.Key);
                    }
                }
                sets = new Dictionary<string, string>(_queue);
            }
            Write(ctx, 200, new Dictionary<string, object?> { ["sets"] = sets, ["moreAvailable"] = false });
            return;
        }
        Write(ctx, 404, new Dictionary<string, object?> { ["err"] = "not found" });
    }

    static void Write(HttpListenerContext ctx, int status, object body) =>
        LoopServer.Write(ctx, status, JsonMaps.Stringify(body), "application/json");

    public void Dispose() => _server.Dispose();
}
