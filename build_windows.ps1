# Builds dist\IUK-NetScope.exe (GUI) and dist\iuk-netscope-cli.exe (console) with PyInstaller.  Run from the repo root.
$ErrorActionPreference = "Stop"
$root = (Get-Location).Path
$v = (python packaging/version.py).Trim()
python -m pip install --upgrade pip
python -m pip install pyinstaller reportlab
if ($LASTEXITCODE -ne 0) { throw "pip install failed" }
if (Test-Path "$root\build\win") { Remove-Item -Recurse -Force "$root\build\win" }

# NOTE: PyInstaller resolves --add-data / --icon relative to the spec folder, so absolute paths are used.
$common = @("--noconfirm", "--clean", "--onefile", "--icon", "$root\icon.ico", "--add-data", "$root\icon.png;.",
            "--distpath", "$root\dist", "--workpath", "$root\build\win", "--specpath", "$root\build\win")

python -m PyInstaller @common --windowed --name IUK-NetScope --hidden-import iuk_netscope "$root\iuk_netscope_gui.py"
if ($LASTEXITCODE -ne 0) { throw "GUI build failed" }
python -m PyInstaller @common --console --name iuk-netscope-cli --hidden-import iuk_netscope_gui "$root\iuk_netscope.py"
if ($LASTEXITCODE -ne 0) { throw "CLI build failed" }
Write-Host "Built version $v"
Get-ChildItem "$root\dist"
