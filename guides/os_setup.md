# OS Guide — preparing your desktop for Vyomanaut demo network

## The Windows Guide

Start with looking for the package installer:

```bash
winget --version
```

 > Expect v1.2.xxxx

Next we require the git for cloning the repo

```bash
git --version
```

> if not present then download from

```bash
$PSVersionTable.PSVersion
```

> Expect `Major` ≥ 7
> if not:

```bash
winget install --id Microsoft.PowerShell -e --source winget
```

> Open a new window called pwsh 7.6.5

```bash
go version
```

> If not present visit <https://go.dev/dl/>
> Install go1.26.2.windows-amd64.msi Installer Windows x86-64 59MB 84826eca833548bb2beabe7429052eaaec18faa902fde723898d906b42e59a73

```bash
wsl --version

// If not installed then
wsl --install

// Docker needs WSL 2.1.5
wsl --update
```

```bash
docker --version

// Look for Docker version 29.x.x
docker compose version

// Visit docker desktop download and install for amd64
// Restart the computer once finished setting up
```

```bash
gcc --version 

// Look for 15.x.x
// If absent, download MSYS2
// After downloading open the specific MSYS2 UCRT64 - Universal C runtime
// gcc is needed to compile the C++ tests to .exe and make windows execute it

pacman -Syu

// The terminal closes the again run
pacman -Syu

// Install the 64bit GCC
pacman -S mingw-w64-ucrt-x86_64-gcc
```

```bash
// Run PWSH as administrator
[Environment]::SetEnvironmentVariable(
    "Path",
    [Environment]::GetEnvironmentVariable("Path", "Machine") + ";C:\msys64\ucrt64\bin",
    "Machine"
)

// close it and in new terminal 
where.exe gcc

// expect: C:\msys64\ucrt64\bin\gcc.exe
```

```bash
gcc --version
gcc -dumpmachine

// expect x86_64-w64-mingw32
```

```bash
// If you get -> C:\MinGW\bin\gcc.exe
// Means it is already installed

// Run as administrator 
$machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")

$machinePath = ($machinePath -split ';' |
    Where-Object { $_ -and $_ -ne 'C:\MinGW\bin' }) -join ';'

$machinePath += ';C:\msys64\ucrt64\bin'

[Environment]::SetEnvironmentVariable("Path", $machinePath, "Machine")
```

```bash
psql --version

// If absent -> Visit Dowload PostgresSQL at Enterprise DB and select
// windows x86-64
// When complete and path mismatch happens
// Check
& "C:\Program Files\PostgreSQL\18\bin\psql.exe" --version

// Run as administrator
$pgPath = "C:\Program Files\PostgreSQL\18\bin"

$machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")

if ($machinePath -notlike "*$pgPath*") {
    [Environment]::SetEnvironmentVariable(
        "Path",
        "$machinePath;$pgPath",
        "Machine"
    )
}
```

Once the setup is complete, run:

```bash
cd ~
git clone https://github.com/vyomanaut-labs/Vyomanaut_V2.git

cd .\Vyomanaut_V2\

go mod tidy
go vet ./...
go build ./...
go test -count=1 -p 1 ./...
go build -tags integration ./scripts/test/...
go vet -tags integration ./scripts/test/...
```