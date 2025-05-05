dotnet publish ./LibSodium.Net.Tests/LibSodium.Net.Tests.csproj -c Release -f net8.0-macos -r osx-arm64 /p:PublishAot=true /p:SelfContained=true /p:PublishTrimmed=true /p:DefineConstants=AOT
