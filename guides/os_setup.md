# OS Guide — preparing your desktop for Vyomanaut demo network

## The Windows Guide for 'Storage Providers'

Start with looking for your package installer:

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

> Open a new terminal called pwsh from the windows button
> Check version

```bash
$PSVersionTable.PSVersion
```

> Then fix the path:

```bash
$profileDir = Split-Path $PROFILE

New-Item -ItemType Directory -Path $profileDir -Force | Out-Null

$pathBlock = @'
# --- Windows environment PATH ---
$machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
$userPath    = [Environment]::GetEnvironmentVariable("Path", "User")

$env:Path = "$machinePath;$userPath"
# --- End Windows environment PATH ---
'@

if (-not (Test-Path $PROFILE)) {
    New-Item -ItemType File -Path $PROFILE -Force | Out-Null
}

$profileContent = Get-Content $PROFILE -Raw -ErrorAction SilentlyContinue

if ($profileContent -notmatch '# --- Windows environment PATH ---') {
    Add-Content -Path $PROFILE -Value "`r`n$pathBlock"
}
```

Close pwsh and from here onwards run every command inside it only

> Now we install go for running the cloned code:

```bash
go version
```

> If not present visit <https://go.dev/dl/>
> Install go1.26.2.windows-amd64.msi Installer Windows x86-64 59MB 84826eca833548bb2beabe7429052eaaec18faa902fde723898d906b42e59a73
> Open pwsh

Next we install gcc
It is required to for the go tests to run on the system and needed to compile the C++ tests to .exe and make windows execute it

```bash
gcc --version 
```

> Look for 15.x.x
> If absent, download MSYS2
> After downloading open the specific: "MSYS2 UCRT64" - Universal C runtime

Inside MSYS2 UCRT64:

```bash
pacman -Syu
```

> Press Y when prompted
> The shell closes by itself 
> Open it again from the Windows icon and inside it run once again

```bash
pacman -Syu
```

Then:

```bash
pacman -S mingw-w64-ucrt-x86_64-gcc
```

> Now we set the path for the installation
> Click the windows icon
> Right click PWSH and run as administrator

Inside pwsh (administrator)

```bash
$machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")

if ($machinePath -notlike "*C:\msys64\ucrt64\bin*") {
    [Environment]::SetEnvironmentVariable(
        "Path",
        "$machinePath;C:\msys64\ucrt64\bin",
        "Machine"
    )
}
```

> close it and in new a new pwsh

```bash
where.exe gcc
```

> expect: C:\msys64\ucrt64\bin\gcc.exe
> then try

```bash
gcc --version
gcc -dumpmachine
```

> expect x86_64-w64-mingw32
> **NOTE:** If you get -> C:\MinGW\bin\gcc.exe. It means gcc is already installed
> As administrator you will have to fix that

```bash
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
```
