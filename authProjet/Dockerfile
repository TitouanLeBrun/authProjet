# Use the .NET 8 SDK image to build the app
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# copy csproj and restore as distinct layers
COPY ["authProjet/authProjet.csproj", "authProjet/"]
RUN dotnet restore "authProjet/authProjet.csproj"

# copy everything else and build
COPY . .
WORKDIR "/src/authProjet"
RUN dotnet publish "authProjet.csproj" -c Release -o /app/publish /p:UseAppHost=false

# runtime image
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS runtime
WORKDIR /app
COPY --from=build /app/publish .

ENV ASPNETCORE_URLS=http://+:8080
EXPOSE 8080
ENTRYPOINT ["dotnet", "authProjet.dll"]
