// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

namespace IyaSec.Saml;

public interface ISignalLogger
{
    void Info(string message);
    void Warn(string message);
    void Error(string message);
}

public sealed class SignalEvent
{
    public string Type { get; init; } = "";
    public Dictionary<string, object?> Payload { get; init; } = new();
    public Dictionary<string, string> Subject { get; init; } = new();
    public string Jti { get; init; } = "";
    public List<string> Sessions { get; init; } = new();
    public bool Ended { get; set; }
    public object? Iat { get; init; }
    public string? Txn { get; init; }
}

public sealed class ReceiverOptions
{
    public string Transmitter { get; init; } = "";
    public Func<IReadOnlyList<string>, SignalEvent, Exception?>? OnEndSessions { get; init; }
    public TlsOptions? Tls { get; init; }
    public Func<Dictionary<string, string>>? Headers { get; init; }
    public IReadOnlyList<string>? EventsRequested { get; init; }
    public IReadOnlyList<string>? EndOn { get; init; }
    public MemorySessionIndex? SessionIndex { get; init; }
    public string SubjectAttribute { get; init; } = "";
    public string Description { get; init; } = "";
    public int PollIntervalMs { get; init; }
    public int MaxEvents { get; init; }
    public ISignalLogger? Log { get; init; }
}

public sealed class SignalsReceiver
{
    const string PollMethod = "urn:ietf:rfc:8936";

    readonly string _transmitter;
    readonly Func<IReadOnlyList<string>, SignalEvent, Exception?> _onEnd;
    readonly TlsOptions? _tls;
    readonly Func<Dictionary<string, string>>? _headers;
    readonly List<string> _eventsRequested;
    readonly HashSet<string> _endOn;
    readonly MemorySessionIndex _index;
    readonly string _subjectAttribute;
    readonly string _description;
    readonly int _pollIntervalMs;
    readonly int _maxEvents;
    readonly ISignalLogger _log;

    readonly object _mu = new();
    Dictionary<string, object?> _config = new();
    public Dictionary<string, object?> Stream { get; private set; } = new();
    List<Dictionary<string, object?>> _keys = new();
    DateTimeOffset _keysAt;
    List<string> _ack = new();
    Dictionary<string, Dictionary<string, string>> _errs = new();
    readonly Dictionary<string, List<Func<SignalEvent, Exception?>>> _handlers = new();

    readonly object _sched = new();
    bool _running;
    Timer? _timer;
    Flight? _inflight;
    int _busy;
    readonly ManualResetEventSlim _idle = new(true);

    sealed class Flight
    {
        public readonly ManualResetEventSlim Done = new(false);
        public bool More;
        public Exception? Error;
    }

    SignalsReceiver(ReceiverOptions opt)
    {
        _transmitter = opt.Transmitter.TrimEnd('/');
        _onEnd = opt.OnEndSessions!;
        _tls = opt.Tls;
        _headers = opt.Headers;
        _eventsRequested = new List<string>(opt.EventsRequested ?? Events.DefaultEventsRequested());
        _endOn = new HashSet<string>(opt.EndOn ?? Events.DefaultEndingEvents());
        _index = opt.SessionIndex ?? new MemorySessionIndex();
        _subjectAttribute = opt.SubjectAttribute;
        _description = opt.Description;
        _pollIntervalMs = opt.PollIntervalMs <= 0 ? 5000 : opt.PollIntervalMs;
        _maxEvents = opt.MaxEvents <= 0 ? 50 : opt.MaxEvents;
        _log = opt.Log ?? PrintLogger.Instance;
    }

    public static SignalsReceiver Create(ReceiverOptions opt)
    {
        if (opt.OnEndSessions == null) throw new SamlException("config", "onEndSessions is required");
        if (!opt.Transmitter.StartsWith("http://", StringComparison.Ordinal) && !opt.Transmitter.StartsWith("https://", StringComparison.Ordinal))
            throw new SamlException("config", "transmitter must be an http(s) URL");
        return new SignalsReceiver(opt);
    }

    public void Track(string localId, SamlLogin login, DateTimeOffset? expiresAt) =>
        _index.Add(MemorySessionIndex.TrackedFrom(localId, login, _subjectAttribute, expiresAt));

    public void Untrack(string localId) => _index.Remove(localId);

    public SignalsReceiver On(string eventType, Func<SignalEvent, Exception?> handler)
    {
        lock (_mu)
        {
            if (!_handlers.TryGetValue(eventType, out var list)) _handlers[eventType] = list = new List<Func<SignalEvent, Exception?>>();
            list.Add(handler);
        }
        return this;
    }

    public void Start()
    {
        lock (_sched)
        {
            if (_running) return;
        }
        var config = Discover();
        lock (_mu) _config = config;
        Jwks(true);
        var stream = EnsureStream();
        var delivery = AsObject(stream.TryGetValue("delivery", out var deliveryRaw) ? deliveryRaw : null);
        if (delivery == null || Text(delivery, "endpoint_url").Length == 0)
            throw new SamlException("ssf", "the stream has no poll endpoint_url");
        lock (_sched)
        {
            if (_running) return;
            lock (_mu) Stream = stream;
            _running = true;
        }
        var delivered = AsList(stream.TryGetValue("events_delivered", out var deliveredRaw) ? deliveredRaw : null);
        _log.Info("ssf: polling stream " + Text(stream, "stream_id") + " at " + Text(delivery, "endpoint_url") + ", delivering " + (delivered?.Count ?? 0) + " event type(s)");
        Iteration();
    }

    public void Stop()
    {
        lock (_sched)
        {
            _running = false;
            _timer?.Dispose();
            _timer = null;
        }
        _idle.Wait();
    }

    public bool PollOnce()
    {
        Flight? waiting = null;
        Flight? mine = null;
        lock (_sched)
        {
            if (_inflight != null) waiting = _inflight;
            else
            {
                mine = new Flight();
                _inflight = mine;
            }
        }
        if (waiting != null)
        {
            waiting.Done.Wait();
            if (waiting.Error != null) throw waiting.Error;
            return waiting.More;
        }
        try
        {
            var more = PollNow();
            mine!.More = more;
            return more;
        }
        catch (Exception ex)
        {
            mine!.Error = ex;
            throw;
        }
        finally
        {
            lock (_sched)
            {
                _inflight = null;
                mine!.Done.Set();
            }
        }
    }

    void Iteration()
    {
        lock (_sched)
        {
            if (!_running) return;
            if (Interlocked.Increment(ref _busy) == 1) _idle.Reset();
        }
        try
        {
            var delay = _pollIntervalMs;
            try
            {
                if (PollOnce()) delay = 0;
            }
            catch (Exception ex)
            {
                _log.Warn("ssf: poll failed: " + ex.Message);
                delay = Math.Min(_pollIntervalMs * 4, 60000);
            }
            lock (_sched)
            {
                if (!_running) return;
                _timer?.Dispose();
                _timer = new Timer(_ => Iteration(), null, delay, Timeout.Infinite);
            }
        }
        finally
        {
            if (Interlocked.Decrement(ref _busy) == 0) _idle.Set();
        }
    }

    bool PollNow()
    {
        List<string> ack;
        Dictionary<string, Dictionary<string, string>> setErrs;
        string url;
        lock (_mu)
        {
            var delivery = AsObject(Stream.TryGetValue("delivery", out var raw) ? raw : null);
            url = delivery == null ? "" : Text(delivery, "endpoint_url");
            ack = _ack;
            _ack = new List<string>();
            setErrs = _errs;
            _errs = new Dictionary<string, Dictionary<string, string>>();
        }
        var body = new Dictionary<string, object?>
        {
            ["maxEvents"] = _maxEvents,
            ["returnImmediately"] = true,
        };
        if (ack.Count > 0) body["ack"] = ack;
        if (setErrs.Count > 0) body["setErrs"] = setErrs;
        int status;
        object? parsed;
        try
        {
            (status, parsed) = Call("POST", url, body, true);
        }
        catch (Exception)
        {
            Restore(ack, setErrs);
            throw;
        }
        if (status != 200)
        {
            Restore(ack, setErrs);
            var text = Clip(JsonMaps.Stringify(parsed));
            throw new SamlException("ssf", "the poll answered " + status + ": " + text);
        }
        var payload = AsObject(parsed) ?? new Dictionary<string, object?>();
        var sets = AsObject(payload.TryGetValue("sets", out var setsRaw) ? setsRaw : null) ?? new Dictionary<string, object?>();
        foreach (var pair in sets)
        {
            try
            {
                Handle(pair.Key, pair.Value as string ?? "");
            }
            catch (Exception ex)
            {
                _log.Warn("ssf: SET " + pair.Key + " refused: " + ex.Message);
                var kind = ex is SamlException saml && saml.Code == "signature" ? "invalid_key" : "invalid_request";
                lock (_mu) _errs[pair.Key] = new Dictionary<string, string> { ["err"] = kind, ["description"] = ex.Message };
                continue;
            }
            lock (_mu) _ack.Add(pair.Key);
        }
        return payload.TryGetValue("moreAvailable", out var more) && more is true;
    }

    void Restore(List<string> ack, Dictionary<string, Dictionary<string, string>> setErrs)
    {
        lock (_mu)
        {
            var mergedAck = new List<string>(ack);
            mergedAck.AddRange(_ack);
            _ack = mergedAck;
            var merged = new Dictionary<string, Dictionary<string, string>>(setErrs);
            foreach (var pair in _errs) merged[pair.Key] = pair.Value;
            _errs = merged;
        }
    }

    void Handle(string jti, string token)
    {
        var keys = Jwks(false);
        Dictionary<string, object?> header;
        Dictionary<string, object?> payload;
        try
        {
            (header, payload) = Jws.VerifyCompact(token, keys);
        }
        catch (SamlException ex) when (ex.Message.Contains("publishes no", StringComparison.Ordinal) || ex.Message.Contains("does not verify", StringComparison.Ordinal))
        {
            try
            {
                keys = Jwks(true);
            }
            catch
            {
                throw ex;
            }
            (header, payload) = Jws.VerifyCompact(token, keys);
        }
        if (header.TryGetValue("typ", out var typ) && typ != null && !string.Equals(typ as string, "secevent+jwt", StringComparison.OrdinalIgnoreCase))
            throw new SamlException("validation", "the SET's typ is " + (typ as string ?? ""));
        string issuer;
        object? want;
        lock (_mu)
        {
            issuer = Text(_config, "issuer");
            Stream.TryGetValue("aud", out want);
        }
        var gotIss = payload.TryGetValue("iss", out var issRaw) && issRaw is string issText ? issText : "";
        if (gotIss != issuer)
            throw new SamlException("validation", "the SET was issued by " + gotIss + ", not " + issuer);
        var wanted = Audience(want);
        var audience = Audience(payload.TryGetValue("aud", out var audRaw) ? audRaw : null);
        if (wanted.Count > 0 && !audience.Any(item => wanted.Contains(item)))
            throw new SamlException("validation", "the SET is for " + string.Join(", ", audience) + ", not this stream");
        if (payload.TryGetValue("jti", out var jtiRaw) && jtiRaw != null && (jtiRaw as string ?? "") != jti)
            throw new SamlException("validation", "the SET's jti is not the one it was delivered under");
        if (payload.TryGetValue("events", out var eventsRaw) && eventsRaw is Dictionary<string, object?> events && events.Count > 0)
        {
            foreach (var pair in events)
            {
                var body = pair.Value as Dictionary<string, object?> ?? new Dictionary<string, object?>();
                object? subjectSource = null;
                if (payload.TryGetValue("sub_id", out var subId) && subId != null) subjectSource = subId;
                else if (pair.Value is Dictionary<string, object?> typed && typed.TryGetValue("subject", out var subject)) subjectSource = subject;
                var subjectMap = Events.SubjectOf(subjectSource, issuer);
                var sessions = SessionsFor(pair.Key, subjectMap);
                var ends = _endOn.Contains(pair.Key) && sessions.Count > 0;
                object? iat = null;
                if (payload.TryGetValue("iat", out var iatRaw) && iatRaw is long or double) iat = iatRaw;
                string? txn = payload.TryGetValue("txn", out var txnRaw) && txnRaw is string txnText ? txnText : null;
                var signal = new SignalEvent
                {
                    Type = pair.Key,
                    Payload = body,
                    Subject = subjectMap,
                    Jti = jti,
                    Sessions = sessions,
                    Ended = ends,
                    Iat = iat,
                    Txn = txn,
                };
                if (ends)
                {
                    try
                    {
                        var failure = _onEnd(sessions, signal);
                        if (failure != null)
                        {
                            _log.Error("ssf: onEndSessions threw for " + pair.Key + " (SET " + jti + " is still acknowledged): " + failure.Message);
                            signal.Ended = false;
                        }
                    }
                    catch (Exception ex)
                    {
                        _log.Error("ssf: onEndSessions threw for " + pair.Key + " (SET " + jti + " is still acknowledged): " + ex.Message);
                        signal.Ended = false;
                    }
                    if (signal.Ended)
                        foreach (var localId in sessions) _index.Remove(localId);
                }
                List<Func<SignalEvent, Exception?>> handlers;
                lock (_mu)
                {
                    handlers = new List<Func<SignalEvent, Exception?>>();
                    if (_handlers.TryGetValue(pair.Key, out var typedHandlers)) handlers.AddRange(typedHandlers);
                    if (_handlers.TryGetValue("*", out var star)) handlers.AddRange(star);
                }
                foreach (var handler in handlers)
                {
                    try
                    {
                        var failure = handler(signal);
                        if (failure != null)
                            _log.Error("ssf: a handler for " + pair.Key + " threw (SET " + jti + " is still acknowledged): " + failure.Message);
                    }
                    catch (Exception ex)
                    {
                        _log.Error("ssf: a handler for " + pair.Key + " threw (SET " + jti + " is still acknowledged): " + ex.Message);
                    }
                }
            }
            return;
        }
        throw new SamlException("validation", "the SET carries no events");
    }

    List<string> SessionsFor(string eventType, Dictionary<string, string> subject)
    {
        if (eventType == Events.Event["verification"] || eventType == Events.Event["stream_updated"]) return new List<string>();
        if (subject.TryGetValue("idp_session", out var idpSession) && idpSession.Length > 0)
        {
            var found = _index.ByIdpSession(idpSession);
            if (found.Count > 0 || eventType == Events.Event["session_revoked"]) return found;
        }
        if (subject.TryGetValue("person", out var person) && person.Length > 0) return _index.ByPerson(person);
        if (subject.TryGetValue("email", out var email) && email.Length > 0) return _index.ByEmail(email);
        return new List<string>();
    }

    public void Verify(string state)
    {
        string endpoint;
        string streamId;
        lock (_mu)
        {
            endpoint = Text(_config, "verification_endpoint");
            streamId = Text(Stream, "stream_id");
        }
        if (endpoint.Length == 0) throw new SamlException("ssf", "the transmitter publishes no verification_endpoint");
        var body = new Dictionary<string, object?> { ["stream_id"] = streamId };
        if (state.Length > 0) body["state"] = state;
        var (status, _) = Call("POST", endpoint, body, true);
        if (status != 200 && status != 204)
            throw new SamlException("ssf", "verification answered " + status);
    }

    Dictionary<string, object?> Discover()
    {
        var url = _transmitter + "/.well-known/ssf-configuration";
        var (status, parsed) = Call("GET", url, null, false);
        var config = AsObject(parsed);
        if (status != 200 || config == null || Text(config, "configuration_endpoint").Length == 0 || Text(config, "jwks_uri").Length == 0)
            throw new SamlException("ssf", url + " answered " + status + " without a usable transmitter configuration");
        if (config.TryGetValue("delivery_methods_supported", out var supported) && supported is List<object?> methods && methods.Count > 0)
        {
            if (!methods.Any(item => item is string text && text == PollMethod))
                throw new SamlException("ssf", "the transmitter does not offer poll delivery (RFC 8936)");
        }
        return config;
    }

    List<Dictionary<string, object?>> Jwks(bool force)
    {
        lock (_mu)
        {
            if (!force && _keys.Count > 0 && DateTimeOffset.UtcNow - _keysAt < TimeSpan.FromHours(1))
                return _keys;
        }
        string uri;
        lock (_mu) uri = Text(_config, "jwks_uri");
        var (status, parsed) = Call("GET", uri, null, false);
        var obj = AsObject(parsed);
        var raw = obj != null && obj.TryGetValue("keys", out var keysRaw) ? keysRaw as List<object?> : null;
        if (status != 200 || raw == null)
            throw new SamlException("ssf", "the transmitter's JWKS answered " + status);
        var keys = raw.OfType<Dictionary<string, object?>>().ToList();
        lock (_mu)
        {
            _keys = keys;
            _keysAt = DateTimeOffset.UtcNow;
        }
        return keys;
    }

    Dictionary<string, object?> EnsureStream()
    {
        var endpoint = "";
        lock (_mu) endpoint = Text(_config, "configuration_endpoint");
        var (status, parsed) = Call("GET", endpoint, null, false);
        if (status == 200)
        {
            var all = new List<object?>();
            if (parsed is List<object?> list) all = list;
            else if (parsed is Dictionary<string, object?>) all.Add(parsed);
            foreach (var item in all)
            {
                if (item is not Dictionary<string, object?> stream || Text(stream, "stream_id").Length == 0) continue;
                var delivery = AsObject(stream.TryGetValue("delivery", out var deliveryRaw) ? deliveryRaw : null);
                if (delivery != null && Text(delivery, "method") == PollMethod) return stream;
            }
        }
        else if (status != 404)
            throw new SamlException("ssf", "listing the streams at " + endpoint + " answered " + status + ": " + Clip(JsonMaps.Stringify(parsed)));
        var body = new Dictionary<string, object?>
        {
            ["delivery"] = new Dictionary<string, object?> { ["method"] = PollMethod },
            ["events_requested"] = _eventsRequested,
        };
        if (_description.Length > 0) body["description"] = _description;
        var (createdStatus, created) = Call("POST", endpoint, body, true);
        if ((createdStatus != 200 && createdStatus != 201) || created is not Dictionary<string, object?> made || Text(made, "stream_id").Length == 0)
            throw new SamlException("ssf", "creating a stream at " + endpoint + " answered " + createdStatus + ": " + Clip(JsonMaps.Stringify(created)));
        return made;
    }

    (int Status, object? Parsed) Call(string method, string url, object? body, bool hasBody)
    {
        var headers = new Dictionary<string, string> { ["accept"] = "application/json" };
        if (_headers != null)
            foreach (var pair in _headers()) headers[pair.Key] = pair.Value;
        var payload = "";
        if (hasBody)
        {
            headers["content-type"] = "application/json";
            payload = JsonMaps.Stringify(body);
        }
        var answer = HttpSend.Send(url, method, headers, payload, _tls, "ssf");
        object? parsed = null;
        if (answer.Body.Length > 0)
        {
            try { parsed = JsonMaps.Parse(answer.Body); }
            catch (Exception) { parsed = answer.Body; }
        }
        return (answer.Status, parsed);
    }

    static List<string> Audience(object? value)
    {
        var found = new List<string>();
        switch (value)
        {
            case List<object?> list:
                foreach (var item in list)
                    if (item is string text) found.Add(text);
                break;
            case string text when text.Length > 0:
                found.Add(text);
                break;
            case null:
                break;
            default:
                found.Add(Convert.ToString(value, System.Globalization.CultureInfo.InvariantCulture) ?? "");
                break;
        }
        return found;
    }

    static Dictionary<string, object?>? AsObject(object? value) => value as Dictionary<string, object?>;

    static List<object?>? AsList(object? value) => value as List<object?>;

    static string Text(Dictionary<string, object?> obj, string key) =>
        obj.TryGetValue(key, out var value) && value is string text ? text : "";

    static string Clip(string text) => text.Length > 300 ? text[..300] : text;

    sealed class PrintLogger : ISignalLogger
    {
        public static readonly PrintLogger Instance = new();
        public void Info(string message) => Console.WriteLine(message);
        public void Warn(string message) => Console.WriteLine(message);
        public void Error(string message) => Console.WriteLine(message);
    }
}
