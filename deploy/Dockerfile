FROM node:24-bookworm-slim AS web
WORKDIR /web
COPY src/LanGuard.Web/package*.json ./
RUN npm ci
COPY src/LanGuard.Web/ .
RUN npm run build

FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /repo
COPY Directory.Build.props ./
COPY src/LanGuard.Shared/LanGuard.Shared.csproj src/LanGuard.Shared/
COPY src/LanGuard.Server/LanGuard.Server.csproj src/LanGuard.Server/
RUN dotnet restore src/LanGuard.Server/LanGuard.Server.csproj
COPY src/LanGuard.Shared/ src/LanGuard.Shared/
COPY src/LanGuard.Server/ src/LanGuard.Server/
COPY signatures/ signatures/
COPY tests/fixtures/ tests/fixtures/
COPY --from=web /web/dist/ src/LanGuard.Server/wwwroot/
RUN dotnet publish src/LanGuard.Server/LanGuard.Server.csproj -c Release --no-restore -o /out

FROM mcr.microsoft.com/dotnet/aspnet:10.0
WORKDIR /app
RUN mkdir /data && chown "$APP_UID" /data
COPY --from=build /out/ ./
USER $APP_UID
EXPOSE 7443
ENTRYPOINT ["dotnet", "LanGuard.Server.dll"]
