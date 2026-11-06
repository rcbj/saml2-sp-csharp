# saml2-sp

C# service provider for SAML 2.0 Web Browser SSO, plus a Shared Signals poll receiver. Version 0.1.4. MIT. `develop` and `main` are one commit. A pull request merged into `main` publishes the package to nuget.org after the test workflow succeeds on that commit. A direct push does not. The key comes from nuget.org Trusted Publishing (`NuGet/login` trades the workflow's GitHub OIDC token for a one-hour API key); the `NUGET_USER` repository secret is the nuget.org profile name that owns the policy for this repository and `publish.yml`. A version already on nuget.org stays there; the next release is a new `Version` in the library's `.csproj`.

## Usage

`ServiceProvider.FromFile("saml.json", null, null)`, then `Login` and `Acs`. JSON keys match the Python configuration (`entityId`, `acsUrl`, `privateKey`, `certificate`, `idpMetadata`, bindings, `signals`, `ssf`). Exported names are `FromFile`, `Login`, `Acs`, and `PostFormHtml`.

`signals` omitted or `true` keeps the receiver available and is omitted from the resolved configuration. `false` does not start a receiver and does not require transmitter metadata, and the resolved configuration includes `signals: false`. A non-boolean fails with `signals must be true or false`. The flag does not change the AuthnRequest: SAML does not send OAuth scopes.

Request bindings are `redirect` and `post`. Response bindings are `post`, `redirect`, and `artifact`. Artifact resolution is a signed SOAP `ArtifactResolve`. HTTP-Redirect query signatures use RSA-SHA256 (`http://www.w3.org/2001/04/xmldsig-more#rsa-sha256`). Success is `urn:oasis:names:tc:SAML:2.0:status:Success`. `saml2-sp generate-keys` writes a self-signed RSA certificate.

## Tests

```bash
docker build --target test .
```

The `test` stage runs `dotnet test --nologo` in `mcr.microsoft.com/dotnet/sdk:10.0` (with `python3` and `openssl` for the script tests). GitHub Actions uses that command. Do not run the .NET SDK on the host. The demo image does not run the suite.

Signatures and decryption are real. The stub identity provider signs with this package's exclusive canonicalization and is created inside the tests. No live iya-sts. `TlsTrustTests` runs a leaf-only HTTPS listener: `idpCa` is read whole (`HttpSend.TrustStore`; `CreateFromPem` read only the leaf), and `HttpSend.Accept` refuses a certificate that chains to it but names another host (the custom callback replaces the platform's name check; an IP literal needs an IP SAN). `Accept` builds from the presented LEAF through the file's certificates only, so a forged leaf followed by the real CA certificates is refused (tested). The same class runs the install script's `save_idp_ca` against that listener (all four certificates land where `idpCa` points and `ServiceProvider.Create` fetches metadata through the file) and `generated_file` with `write_private` (the path computed apart from the password, the file mode 0600, nothing printed).

### idpCa: the iya-sts TLS listener CA trust chain

`idpCa` (demo: `generated/idp-ca.pem`, relative to `demo/`) is the whole chain, not one certificate. `scripts/configure_iya_sts.py` writes it on every run through `save_trust_chain()` in `scripts/trust_chain.py` (`GET /tls/server-certificate`, else the handshake chain; `openssl` reads the names) and prints the path, the anchor's subject and SHA-256. The Dockerfile copies `demo/` after the publish step and `.dockerignore` admits only `demo/generated/idp-ca.pem`, so the demo image carries the chain from build time and a build without it still succeeds. Rebuild after re-running the install script against a different iya-sts. The install script never prints a generated password: `demo/generated/<user>.password`, mode 0600.

### Plain http (#19)

`HttpSend.Send` is the one place every fetch goes through (metadata URL, `ArtifactResolve`, SSF configuration, JWKS, stream and poll). `RefusePlainHttpOffLoopback` refuses plain `http://` to a host that is not loopback (`127.0.0.0/8`, `::1`, `localhost`) before the handler is built, naming only `http://host[:port]` under the fetch's own code; userinfo is never loopback. A plain (so loopback) URL gets `AllowAutoRedirect = false`, so a redirect cannot take it off the machine in the clear; .NET already never follows https to http. Redirects are refused rather than followed manually because none of these protocols needs one from a loopback http endpoint. Before any of that, `Send` refuses a URL (https too) with whitespace or a control character, without repeating it (`Uri` would trim or escape some of them). No opt-out. `PlainHttpTests` covers each fetch on `http://example.com` and on `http://0.0.0.0:<port>` (which reaches a 127.0.0.1 listener on Linux, so a zero accept count proves no connection), userinfo, loopback still working, redirects (to `0.0.0.0`, and from loopback http and from https to `http://example.com`), whitespace and control characters, and https to a closed port failing as a connection error.

### Live sign-in and nightly

`python3 scripts/live_iya_sts.py` (host stdlib Python + Docker). Fresh iya-sts (main, memory, persistence and clustering off, no workers) unless `IYA_STS_URL`; `IYA_STS_IMAGE` for a local image. Order: copy the checkout to a scratch context, rewrite the copy's `demo/saml.json` (entityId/acsUrl to the demo origin, ssf transmitter, `pollIntervalMs` 1000; never `idpCa`), build the demo image, run the install script INSIDE it (`saml2-sp` is on PATH there; the registrar never shells out to `dotnet` on the host), build again, check the image's chain equals the saved one (`idpCaInImage`), run with only `sp.key`, `sp.crt` and `idp-metadata.xml` mounted. Signs in through `/authn-api`, emits credential-change then session-revoked via `/admin-api/caep/emit`, and requires `GET /live-status` to show both with `signedIn` false at the end. No request is traced (CodeQL: nothing derived from the password is logged); secrets go to docker as `-e NAME`. Ports `LIVE_STS_PORT=18526`, `LIVE_DEMO_PORT=18626`; never 3000, 8081, 18481-18495. Containers `iya-sts-live-saml2-sp-csharp`, `saml2-sp-csharp-live-demo`. A second run against an already-registered SP needs a fresh iya-sts.

`GET /live-status` is JSON: `signedIn`, `subject`, `receiver`, `events` (`type` as the full CAEP URI, `jti`); never tokens or assertions. iya-sts main may set the assertion SessionIndex to the assertion id, so session-revoked can match no session; the demo's `Remember` then ends its one local session and untracks it. Demo code only; the library is unchanged.

`.github/workflows/nightly.yml` runs `docker build --target test .` and then the live script at 07:42 UTC (`42 7 * * *`), and on `workflow_dispatch`. `tests.yml` has no schedule.

## Layout

Package `IyaSec.Saml2Sp` in `src/IyaSec.Saml2Sp`, namespace `IyaSec.Saml`. `cli`, `demo`, `tests`, `scripts/configure_iya_sts.py` (install script), `scripts/trust_chain.py`, `scripts/live_iya_sts.py`, `Dockerfile` (SDK build stage, `dotnet/aspnet:10.0` demo image (the library references ASP.NET Core) with `python3` and `openssl` for the install script), `docker-compose.yml`. The image name is `saml2-sp-csharp-demo`. Compose uses `network_mode: host`, service `saml-demo`, and `ENV PORT=3000` in the image. The health check is `http://127.0.0.1:${PORT}/healthz`.

## Demo

`docker compose up --build`. `GET /healthz` is `200` with body `ok`. `GET /live-status` is above. Pages: sign-in, `/login` (redirect or POST form), `/saml/acs`, and logout, plus metadata. Loopback entityID and assertion-consumer URLs follow `PORT`. Other hosts stay as written. `PUBLIC_URL` or `--public-url` replaces the origin and keeps the path. The default `http://localhost:3000` is not an explicit public URL. `demo/saml.json` uses `file:` placeholders and omits `signals`. Do not commit `demo/generated/`.

## Signals

With an `ssf` block and without `"signals": false`, the demo starts one poll receiver on the service provider's certificate (mutual TLS). `Stop` waits for an in-flight poll. `scripts/configure_iya_sts.py` (run in the demo image) writes the `idpCa` chain, registers the SP metadata, pins AES-256-GCM / RSA-OAEP, turns on multiple accounts, and, unless signals are off, grants `ssf.manage`. The container `PORT` wins over the shell `PORT` at registration.
