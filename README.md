# saml2-sp

Server-side SAML 2.0 service provider for C#. It sends a signed `AuthnRequest` on HTTP-Redirect or HTTP-POST, accepts a `Response` on HTTP-POST, HTTP-Redirect, or HTTP-Artifact, verifies XML signatures, decrypts encrypted assertions, and can poll a Shared Signals transmitter for CAEP and RISC events.

Version 0.1.2. License: MIT. `develop` and `main` are one commit. Package id: `IyaSec.Saml2Sp`. A pull request merged into `main` publishes the package to nuget.org after the test workflow succeeds on that commit. A direct push does not. The key comes from nuget.org Trusted Publishing (`NuGet/login` trades the workflow's GitHub OIDC token for a one-hour API key); the `NUGET_USER` repository secret is the nuget.org profile name that owns the policy for this repository and `publish.yml`. A version already on nuget.org stays there; the next release is a new `Version` in the library's `.csproj`.

## Usage

```csharp
var sp = ServiceProvider.FromFile("saml.json", null, null);
var request = sp.Login(new LoginOptions { RelayState = "/home" });
var who = sp.Acs(method, rawUrl, body, new[] { request.Id });
```

The package is `IyaSec.Saml2Sp` and the namespace is `IyaSec.Saml`. `saml.json` uses the same keys as the Python service provider: `entityId`, `acsUrl`, `privateKey`, `certificate`, `idpMetadata`, and the optional `requestBinding`, `responseBinding`, `idpCa`, `idpEntityId`, `nameIdFormat`, `clockSkewSeconds`, `wantAssertionsSigned`, `wantAssertionsEncrypted`, `allowUnsolicited`, and `signals`. A value may be PEM text, a file path, or an `env:` / `file:` placeholder. `signals` omitted or `true` leaves the Shared Signals receiver available and is omitted from the resolved configuration. `false` turns it off, does not require transmitter metadata, and is stored as `signals: false`. Any other value is a configuration error: `signals must be true or false`. SAML does not send OAuth scopes, so the flag does not change the `AuthnRequest`.

`idpCa` is the iya-sts TLS listener CA trust chain for the HTTPS fetches (metadata, artifact resolution, the Shared Signals receiver). Every certificate in it is read: the self-signed ones are the trust anchors and the rest are intermediates the server's chain may be built through; a file with no self-signed certificate trusts every certificate in it. The chain is built from the server's leaf through the file alone, so a forged leaf sent with the real CA certificates is refused. The server's certificate must also name the host in the URL: a DNS name must match a DNS SAN and an IP literal such as `127.0.0.1` an IP address SAN. A certificate that chains to the file but names another host is refused.

**Plain http.** Identity-provider metadata from a URL, artifact resolution and every Shared Signals transmitter call (configuration, JWKS, stream and poll) use https. A plain `http://` URL is refused before any DNS lookup or connection unless its host is loopback (`127.0.0.0/8`, `::1`, `localhost`), because metadata carries the signing keys, an `ArtifactResolve` returns the assertion, and Shared Signals carry SETs and the bearer token. A URL with userinfo is never loopback. Redirects to plain http are never followed: none from a loopback http URL, and .NET never follows https to http; the 3xx is the answer, and a metadata fetch fails on it. A URL containing whitespace or a control character is refused before it is parsed, so two parsers cannot disagree about its host. The `SamlException` keeps the fetch's code (`metadata`, `artifact`, `ssf`) and names the scheme and host only. There is no opt-out. The service provider's own entityID and ACS URLs may stay http: they are never fetched.

`Login` returns a redirect URL or `PostFormHtml` fields. `Acs` accepts a POST body as a string or a map. Artifact resolution is a signed SOAP `ArtifactResolve`. HTTP-Redirect query signatures use RSA-SHA256 (`http://www.w3.org/2001/04/xmldsig-more#rsa-sha256`). Success is `urn:oasis:names:tc:SAML:2.0:status:Success`.

```sh
docker compose build
docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp \
  -v "$PWD/demo:/app/demo" \
  saml2-sp-csharp-demo \
  saml2-sp generate-keys --config demo/saml.json
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$PWD/demo:/app/demo" \
  saml2-sp-csharp-demo \
  saml2-sp metadata --config demo/saml.json
```

## Shared Signals

```csharp
var receiver = SignalsReceiver.Create(new ReceiverOptions
{
    Transmitter = "https://idp.example",
    OnEndSessions = (ids, ev) => null,
});
receiver.Track(localId, login, null);
receiver.Start();
receiver.Stop();
```

The receiver discovers the transmitter, keeps one poll stream (`urn:ietf:rfc:8936`), and verifies each Security Event Token against the published JWKS. `Stop` waits until a poll already running has finished. By default a session ends on `session-revoked`, `account-disabled`, `account-purged`, `credential-compromise`, and `sessions-revoked`.

## Tests

```bash
docker build --target test .
```

The suite runs in a container.

Signatures and decryption are real (`System.Security.Cryptography.Xml` exclusive canonicalization, RSA, and AES-GCM). The stub identity provider is in the test project. Keys are generated in the test. The suite also covers the install script writing the whole trust chain where `idpCa` points and the library taking that file as its trust store, a forged leaf sent with the real CA certificates, the host-name check, and the generated password going to a `0600` file. No live iya-sts: that is `scripts/live_iya_sts.py`, below.

## The iya-sts TLS trust chain (`idpCa`)

`idpCa` names the file that holds the iya-sts TLS listener CA trust chain; the demo's is `generated/idp-ca.pem` (relative to `demo/`). `scripts/configure_iya_sts.py`, the install script, writes it on every run: the whole chain iya-sts publishes at `GET /tls/server-certificate` (leaf, TLS issuing CA, intermediate, root), or the chain the TLS handshake presents when that path is missing. It prints the path, the trust anchor's subject and its SHA-256 fingerprint. `python3 scripts/trust_chain.py --config demo/saml.json --idp https://host:port` refreshes the file by itself.

The demo image carries the file from build time: the Dockerfile copies `demo/` after the build, and `.dockerignore` admits only `demo/generated/idp-ca.pem` from `demo/generated` (no keys, no metadata, no password). A build before the install script has run (a fresh clone, CI's `--target test`) copies nothing from `demo/generated` and still succeeds. Run the install script, then build the demo image; after running it against a different iya-sts, rebuild.

## Live sign-in

`python3 scripts/live_iya_sts.py` is the live half, on the host's standard-library Python and Docker. It starts a fresh iya-sts (main, memory mode, no persistence, no clustering) unless `IYA_STS_URL` is already set; `IYA_STS_IMAGE` starts one from an image you already have. It follows the install order: it copies the checkout to a scratch build context, points that copy's `demo/saml.json` at this iya-sts and demo port (leaving `idpCa` as written), builds the demo image, runs the install script inside it (which writes the key pair, the IdP metadata and the trust chain where `idpCa` names it), builds the image again so it carries that chain, and runs it with only the key pair and the IdP metadata mounted. The .NET SDK never runs on the host. The script signs in through `/authn-api`, emits credential-change, then session-revoked, and requires `GET /live-status` to show both. That JSON is `signedIn`, `subject`, `receiver`, and `events` of `type` (the full CAEP URI) and `jti`. It has no tokens or assertions. session-revoked leaves `signedIn` false. The last thing it prints is JSON with `"ok": true`.

```sh
python3 scripts/live_iya_sts.py
IYA_STS_IMAGE=iya-sts-live:main LIVE_STS_PORT=18526 LIVE_DEMO_PORT=18626 python3 scripts/live_iya_sts.py
```

The defaults are 18526 for iya-sts and 18626 for the demo. Do not bind host ports 3000, 8081, or 18481 to 18495. The containers are `iya-sts-live-saml2-sp-csharp` and `saml2-sp-csharp-live-demo`, and the script removes both. Secrets reach `docker run` as `-e NAME`, never on the command line. A second run against an already-registered service provider needs a fresh iya-sts.

iya-sts main may set the assertion SessionIndex to the assertion id. The CAEP session-revoked subject names the sign-on session, so the index finds nobody. The demo then ends its one session from the event handler (`Remember` in `demo/IyaSec.Saml2Sp.Demo/Program.cs`). That is demo code.

[`.github/workflows/nightly.yml`](.github/workflows/nightly.yml) runs `docker build --target test .` and then the live script at 07:42 UTC (`42 7 * * *`), and on `workflow_dispatch`. Push and pull-request CI stays in `tests.yml`.

## Demo

`docker compose up --build`. `GET /healthz` is `200` with body `ok` and does not dial an identity provider. `GET /live-status` is described under Live sign-in. Pages: sign-in, `/login` (redirect or POST form), `/saml/acs`, and logout. Loopback entityID and assertion-consumer URLs follow `PORT` (default 3000). Other hosts stay as written. `PUBLIC_URL` or `--public-url` replaces the origin and keeps the path. The default `http://localhost:3000` is not an explicit public URL. `demo/saml.json` uses `file:` placeholders and omits `signals`. Do not commit `demo/generated/`.

`scripts/configure_iya_sts.py` is standard-library Python. It calls this library's `saml2-sp` command for keys, metadata, and the identity-provider summary, so run it in the demo image, where that command, `python3` and `openssl` are installed:

```sh
docker compose build
docker run --rm --network host --user "$(id -u):$(id -g)" -e HOME=/tmp -e ADMIN_API_CLIENT_SECRET \
  -v "$PWD/demo:/app/demo" saml2-sp-csharp-demo \
  python3 scripts/configure_iya_sts.py --idp https://localhost:8081
docker compose build
```

The second build bakes the trust chain into the image. The container `PORT` wins over the shell `PORT`. A generated test-user password is never printed: it is written to `demo/generated/<user>.password` (mode `0600`) and only that path is shown.
