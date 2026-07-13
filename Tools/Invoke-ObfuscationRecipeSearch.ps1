#   This file is part of the MaLDAPtive framework (community detection-research tooling).
#
#   Invoke-ObfuscationRecipeSearch.ps1
#
#   Thin standalone CLI wrapper around the exported Maldaptive function Invoke-ObfuscationRecipeSearch
#   (defined in ./Modules/Obfuscation/RecipeSearch.psm1). Imports the module, forwards all parameters
#   to the function, and prints the discovered recipe.
#
#   Usage:
#     pwsh ./Tools/Invoke-ObfuscationRecipeSearch.ps1 -SearchFilter '(&(objectCategory=person)(name=krbtgt))'
#     pwsh ./Tools/Invoke-ObfuscationRecipeSearch.ps1 -SearchFilter '...' -Strategy Genetic -ScoreCap 0 -AllowLossy

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [System.String]
    $SearchFilter,

    [Parameter(Mandatory = $false)]
    [ValidateSet('Greedy','Annealing','Genetic')]
    [System.String]
    $Strategy = 'Genetic',

    [Parameter(Mandatory = $false)]
    [System.Nullable[System.Double]]
    $ScoreCap = $null,

    [Parameter(Mandatory = $false)]
    [System.Int16]
    $MaxRecipeLength = 9,

    [Parameter(Mandatory = $false)]
    [Switch]
    $AllowLossy,

    # Pass-through for any additional Invoke-ObfuscationRecipeSearch parameters (e.g. -Generations, -PopulationSize, -AnnealSteps, -Restarts, -Quiet).
    [Parameter(ValueFromRemainingArguments = $true)]
    $RemainingArguments,

    [Parameter(Mandatory = $false)]
    [System.String]
    $ModulePath = (Join-Path $PSScriptRoot '..\Maldaptive.psd1')
)

Import-Module $ModulePath -Force -ErrorAction Stop

# Forward bound parameters (minus this wrapper's own ModulePath / RemainingArguments) to the exported function.
$forwardedParameters = @{ }
$PSBoundParameters.GetEnumerator().Where( { $_.Key -inotin @('ModulePath','RemainingArguments') } ).ForEach( { $forwardedParameters[$_.Key] = $_.Value } )

$result = Invoke-ObfuscationRecipeSearch @forwardedParameters

Write-Host ''
Write-Host 'Residual detections (what is left after a within-cap recipe):'
if ($result.Filter) { $result.Filter | Find-Evil | Select-Object Score, ID | Format-Table -AutoSize }

# Emit the result object for programmatic use.
$result
