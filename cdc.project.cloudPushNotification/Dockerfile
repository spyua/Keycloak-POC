ARG APP_VERSION=2.0.1

# https://hub.docker.com/_/microsoft-dotnet
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
LABEL stage=intermediate
ARG APP_VERSION

WORKDIR /source

# copy csproj and restore as distinct layers
COPY *.sln .
COPY pushNotification.service.cdp/*.csproj ./pushNotification.service.cdp/

# execute nuget dll restore, avoid testing
RUN dotnet restore "pushNotification.service.cdp/pushNotification.service.cdp.csproj"
# RUN dotnet restore "pushNotification.service.cdp/pushNotification.service.cdp.csproj" -s https://api.nuget.org/v3/index.json

# can't not include folder obj/**, use the .dockerignore or it will cause error
COPY pushNotification.service.cdp/. ./pushNotification.service.cdp/

# -c: Configuration
# -o: output file
# --no-restore: no use dotnet restore
RUN dotnet publish pushNotification.service.cdp/pushNotification.service.cdp.csproj -c release -o /app -p:Version=${APP_VERSION} -p:OpenApiCli=false --no-restore -nowarn:CS8618

# final stage/image
FROM mcr.microsoft.com/dotnet/aspnet:8.0
ARG APP_VERSION
ARG PORT=7001

ENV ASPNETCORE_URLS=http://*:${PORT}
LABEL AppVersion=${APP_VERSION}

WORKDIR /app
COPY --from=build /app ./

ENV ASPNETCORE_URLS=http://*:${PORT:-80}
ENTRYPOINT ["sh", "-c", "dotnet pushNotification.service.cdp.dll --urls=http://*:${PORT:-80}"]

