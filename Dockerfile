# syntax=docker/dockerfile:1
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
# `docker build --target test` runs the suite in this image.
# The demo image below does not run it.
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS test
ENV DOTNET_CLI_TELEMETRY_OPTOUT=1
ENV DOTNET_NOLOGO=1
RUN apt-get update && apt-get install -y --no-install-recommends python3 openssl \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN dotnet test --nologo

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
ENV DOTNET_CLI_TELEMETRY_OPTOUT=1
ENV DOTNET_NOLOGO=1
WORKDIR /src
COPY src src
COPY cli cli
COPY demo/IyaSec.Saml2Sp.Demo demo/IyaSec.Saml2Sp.Demo
RUN dotnet publish cli/IyaSec.Saml2Sp.Cli.csproj -c Release -o /opt/cli --nologo \
 && dotnet publish demo/IyaSec.Saml2Sp.Demo/IyaSec.Saml2Sp.Demo.csproj -c Release -o /opt/demo --nologo

# python3 and openssl run scripts/configure_iya_sts.py (the install script) in this image,
# next to the saml2-sp command it calls: the .NET SDK never runs on the host.
FROM mcr.microsoft.com/dotnet/aspnet:10.0
ENV DOTNET_CLI_TELEMETRY_OPTOUT=1
RUN apt-get update && apt-get install -y --no-install-recommends python3 openssl \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /opt/cli /opt/cli
COPY --from=build /opt/demo /opt/demo
RUN printf '%s\n' '#!/bin/sh' 'exec dotnet /opt/cli/IyaSec.Saml2Sp.Cli.dll "$@"' > /usr/local/bin/saml2-sp \
 && printf '%s\n' '#!/bin/sh' 'cd /app' 'exec dotnet /opt/demo/IyaSec.Saml2Sp.Demo.dll "$@"' > /usr/local/bin/saml-demo \
 && chmod 755 /usr/local/bin/saml2-sp /usr/local/bin/saml-demo
WORKDIR /app
# demo/ comes after the build, so a new trust chain does not rebuild the binaries.
# .dockerignore admits one file of demo/generated: idp-ca.pem, the iya-sts TLS
# listener CA trust chain scripts/configure_iya_sts.py writes where idpCa names
# it. When the file exists this COPY puts it at /app/demo/generated/idp-ca.pem,
# so the image trusts that iya-sts with no mount and no fetch at start. When it
# does not (a fresh clone, CI) nothing from demo/generated is copied and the
# build still succeeds. Keys, metadata and passwords never enter the image.
COPY demo demo
COPY scripts scripts
COPY LICENSE README.md VERSION ./
ENV PORT=3000
EXPOSE 3000
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s \
  CMD ["bash", "-c", "exec 3<>/dev/tcp/127.0.0.1/${PORT} && printf 'GET /healthz HTTP/1.0\\r\\nHost: 127.0.0.1\\r\\n\\r\\n' >&3 && grep -q '^ok' <&3"]
CMD ["saml-demo"]
