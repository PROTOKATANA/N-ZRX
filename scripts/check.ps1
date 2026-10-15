#Requires -Version 7.0
# Puerta de calidad de ZEROX (PowerShell 7): el mismo recorrido que scripts/check.sh.
# Plataforma soportada: Linux x86_64. Solo mira archivos seguidos por git.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-Comando {
    param(
        [Parameter(Mandatory)][string]$Programa,
        [string[]]$Argumentos = @()
    )
    & $Programa @Argumentos
    if ($LASTEXITCODE -ne 0) {
        throw "Fallo: $Programa $($Argumentos -join ' ')"
    }
}

function Assert-Herramienta {
    param([Parameter(Mandatory)][string]$Nombre)
    if (-not (Get-Command -Name $Nombre -ErrorAction SilentlyContinue)) {
        throw "Falta la herramienta '$Nombre'"
    }
}

function Get-ArchivoSeguido {
    param([Parameter(Mandatory)][string[]]$Patron)
    $salida = & git ls-files -- @Patron
    if ($LASTEXITCODE -ne 0) {
        throw 'Fallo git ls-files'
    }
    return @($salida | Where-Object { $_ })
}

function Write-Seccion {
    param([Parameter(Mandatory)][string]$Titulo)
    Write-Output ''
    Write-Output "== $Titulo =="
}

Set-Location -Path (& git rev-parse --show-toplevel)

if ((Get-ArchivoSeguido -Patron @('Cargo.toml')).Count -gt 0) {
    Write-Seccion -Titulo 'Rust'
    Assert-Herramienta -Nombre 'cargo'
    Assert-Herramienta -Nombre 'cargo-audit'
    Invoke-Comando -Programa 'cargo' -Argumentos @('fmt', '--all', '--', '--check')
    Invoke-Comando -Programa 'cargo' -Argumentos @('clippy', '--locked', '--all-targets', '--all-features', '--', '-D', 'warnings')
    Invoke-Comando -Programa 'cargo' -Argumentos @('build', '--locked', '--all-features', '--bins')
    Invoke-Comando -Programa 'cargo' -Argumentos @('test', '--locked', '--all-features', '--no-fail-fast')
    Invoke-Comando -Programa 'cargo' -Argumentos @('build', '--locked', '--release')
    Invoke-Comando -Programa 'cargo' -Argumentos @('audit')
}

$guardianes = Get-ArchivoSeguido -Patron @('ci/*.sh')
if ($guardianes.Count -gt 0) {
    Write-Seccion -Titulo 'Guardianes del proyecto'
    foreach ($guardian in $guardianes) {
        Invoke-Comando -Programa 'bash' -Argumentos @($guardian)
    }
}

$scripts = Get-ArchivoSeguido -Patron @('*.sh', '.githooks/*')
if ($scripts.Count -gt 0) {
    Write-Seccion -Titulo 'Bash'
    Assert-Herramienta -Nombre 'shellcheck'
    Assert-Herramienta -Nombre 'shfmt'
    Invoke-Comando -Programa 'shellcheck' -Argumentos (@('-x') + $scripts)
    Invoke-Comando -Programa 'shfmt' -Argumentos (@('-d', '-i', '2') + $scripts)
}

$powershell = Get-ArchivoSeguido -Patron @('*.ps1', '*.psm1', '*.psd1')
if ($powershell.Count -gt 0) {
    Write-Seccion -Titulo 'PowerShell'
    foreach ($archivo in $powershell) {
        $avisos = Invoke-ScriptAnalyzer -Path $archivo -Severity Warning, Error
        if ($avisos) {
            $avisos | Format-Table -AutoSize | Out-String | Write-Output
            throw "PSScriptAnalyzer: avisos en $archivo"
        }
    }
    if ((Get-ArchivoSeguido -Patron @('*.Tests.ps1')).Count -gt 0) {
        Invoke-Pester -CI
    }
}

Write-Output ''
Write-Output 'Puerta de calidad superada.'
