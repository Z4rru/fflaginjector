# FFlag Injector

A lightweight open-source Windows tool for injecting Roblox FFlags via memory.

## Download

Go to [**Releases**](https://github.com/Z4rru/fflaginjector/releases) and download `FlagInjector.exe`.

> **Run as Administrator** — required for process memory access.

## Features

- Auto-detect and attach to Roblox
- Import/export JSON flag configs
- Watchdog auto-reapply
- Grace period for game join detection
- System tray support
- Drag-and-drop JSON import

## Build from source

dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true


Requires [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0).

## License

MIT
