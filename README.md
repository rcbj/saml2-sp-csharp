# saml2-sp

Server-side SAML 2.0 service provider for C#. It sends a signed `AuthnRequest` on HTTP-Redirect or HTTP-POST, accepts a `Response` on HTTP-POST, HTTP-Redirect, or HTTP-Artifact, verifies XML signatures, decrypts encrypted assertions, and can poll a Shared Signals transmitter for CAEP and RISC events.

Version 0.1.1. License: MIT. `develop` and `main` are one commit. Package id: `IyaSec.Saml2Sp`. A pull request merged into `main` publishes the package to nuget.org after the test workflow succeeds on that commit. A direct push does not. The key comes from nuget.org Trusted Publishing (`NuGet/login` trades the workflow's GitHub OIDC token for a one-hour API key); the `NUGET_USER` repository secret is the nuget.org profile name that owns the policy for this repository and `publish.yml`. A version already on nuget.org stays there; the next release is a new `Version` in the library's `.csproj`.

## Usage

```csharp
var sp = ServiceProvider.FromFile("saml.json", null, null);
var request = sp.Login(new LoginOptions { RelayState = "/home" });
var who = sp.Acs(method, rawUrl, body, new[] { request.Id });
```

The package is `IyaSec.Saml2Sp` and the namespace is `IyaSec.Saml`. `saml.json` uses the same keys as the Python service provider: `entityId`, `acsUrl`, `privateKey`, `certificate`, `idpMetadata`, and the optional `requestBinding`, `responseBinding`, `idpCa`, `idpEntityId`, `nameIdFormat`, `clockSkewSeconds`, `wantAssertionsSigned`, `wantAssertionsEncrypted`, `allowUnsolicited`, and `signals`. A value may be PEM text, a file path, or an `env:` / `file:` placeholder. `signals` omitted or `true` leaves the Shared Signals receiver available and is omitted from the resolved configuration. `false` turns it off, does not require transmitter metadata, and is stored as `signals: false`. Any other value is a configuration error: `signals must be true or false`. SAML does not send OAuth scopes, so the flag does not change the `AuthnRequest`.

`Login` returns a redirect URL or `PostFormHtml` fields. `Acs` accepts a POST body as a string or a map. Artifact resolution is a signed SOAP `ArtifactResolve`. HTTP-Redirect query signatures use RSA-SHA256 (`http://www.w3.org/2001/04/xmldsig-more#rsa-sha256`). Success is `urn:oasis:names:tc:SAML:2.0:status:Success`.

```sh
docker compose build
docker run --rm --user "$(id -u):$(id -g)" \
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

Signatures and decryption are real (`System.Security.Cryptography.Xml` exclusive canonicalization, RSA, and AES-GCM). The stub identity provider is in the test project. No live iya-sts. Keys are generated in the test.

## Demo

`docker compose up --build`. `GET /healthz` is `200` with body `ok` and does not dial an identity provider. Pages: sign-in, `/login` (redirect or POST form), `/saml/acs`, and logout. Loopback entityID and assertion-consumer URLs follow `PORT` (default 3000). Other hosts stay as written. `PUBLIC_URL` or `--public-url` replaces the origin and keeps the path. The default `http://localhost:3000` is not an explicit public URL. `demo/saml.json` uses `file:` placeholders and omits `signals`. Do not commit `demo/generated/`.

`scripts/configure_iya_sts.py` is standard-library Python. It calls `dotnet run --project cli/IyaSec.Saml2Sp.Cli.csproj` for keys, metadata, and the identity-provider summary. The container `PORT` wins over the shell `PORT`.
