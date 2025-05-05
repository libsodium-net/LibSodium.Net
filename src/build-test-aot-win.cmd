@REM dotnet restore ./LibSodium.Net.Tests/LibSodium.Net.Tests.csproj -r win-x64
dotnet publish ./LibSodium.Net.Tests/LibSodium.Net.Tests.csproj -c Release -f net8.0 -r win-x64 /p:PublishAot=true /p:SelfContained=true /p:PublishTrimmed=true /p:DefineConstants=AOT
