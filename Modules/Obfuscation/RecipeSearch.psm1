#   This file is part of the MaLDAPtive framework (community detection-research tooling).
#
#   Copyright 2024 Sabajete Elezaj (aka Sabi) <@sabi_elezi>
#         and Daniel Bohannon (aka DBO) <@danielhbohannon>
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.



function Invoke-ObfuscationRecipeSearch
{
<#
.SYNOPSIS

MaLDAPtive is a framework for LDAP SearchFilter parsing, obfuscation, deobfuscation and detection.

MaLDAPtive Function: Invoke-ObfuscationRecipeSearch
Author: Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Find-Evil, Add-RandomCase, Add-RandomFilterListOrder, Add-RandomOid, Add-RandomParenthesis, Add-RandomBooleanOperator, Add-RandomBooleanOperatorInversion, Add-RandomPresenceFilter, Add-RandomFilter, Add-RandomWhitespace (and optionally Add-RandomHexValue, Add-RandomWildcard)
Optional Dependencies: None

.DESCRIPTION

Invoke-ObfuscationRecipeSearch automatically searches for an LDAP obfuscation "recipe" (an ordered sequence of Add-Random* obfuscation passes) that maximizes structural divergence (Levenshtein edit distance) from the original SearchFilter while keeping the total Find-Evil detection score at or below a hard cap. The default pass pool contains only logic-preserving transforms, so every discovered recipe is logically equivalent to the original by construction.

This is detection-research tooling: it empirically maps where the MaLDAPtive detection ruleset is blind so defenders can close the gaps. Three search strategies are available via -Strategy (Greedy, Annealing, Genetic).

.PARAMETER SearchFilter

Specifies the LDAP SearchFilter string to obfuscate.

.PARAMETER Strategy

(Optional) Specifies the search strategy: Greedy (hill-climb + restarts), Annealing (simulated annealing), or Genetic (genetic algorithm, default).

.PARAMETER ScoreCap

(Optional) Specifies the maximum total Find-Evil score the obfuscated result may reach. Defaults to the original SearchFilter's own baseline score (i.e. add zero detectable obfuscation).

.PARAMETER MaxRecipeLength

(Optional) Specifies the maximum number of passes in a recipe.

.PARAMETER AllowLossy

(Optional) Includes broadening/high-signal passes (Wildcard, Hex, OID +zeros/prefix) in the pass pool. Off by default to keep results both logically exact and quiet.

.PARAMETER Quiet

(Optional) Suppresses progress/host output and only returns the result object (for programmatic use).

.EXAMPLE

PS C:\> Invoke-ObfuscationRecipeSearch -SearchFilter '(&(objectCategory=person)(name=krbtgt))'

.EXAMPLE

PS C:\> $r = Invoke-ObfuscationRecipeSearch -SearchFilter '(&(objectCategory=person)(name=krbtgt))' -Strategy Genetic -Quiet
PS C:\> $r.Filter

.NOTES

This is a personal project developed by Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://github.com/MaLDAPtive/Invoke-Maldaptive
https://twitter.com/sabi_elezi/
https://twitter.com/danielhbohannon/
#>

    [OutputType([System.Management.Automation.PSCustomObject])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.String]
        $SearchFilter,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateSet('Greedy','Annealing','Genetic')]
        [System.String]
        $Strategy = 'Genetic',

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [System.Nullable[System.Double]]
        $ScoreCap = $null,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [System.Int16]
        $MaxRecipeLength = 9,

        # --- Greedy parameters ---
        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [System.Int16]
        $Restarts = 6,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [System.Int16]
        $Iterations = 14,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [System.Int16]
        $TriesPerPass = 3,

        # --- Annealing parameters ---
        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [System.Int16]
        $AnnealSteps = 250,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [System.Double]
        $InitialTemperature = 60,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [System.Double]
        $CoolingRate = 0.97,

        # --- Genetic parameters ---
        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [System.Int16]
        $PopulationSize = 30,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [System.Int16]
        $Generations = 16,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [System.Double]
        $MutationRate = 0.35,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [System.Int16]
        $EliteCount = 3,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [System.Int16]
        $TournamentSize = 3,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Switch]
        $AllowLossy,

        # Score candidate filters against the core ruleset PLUS the community extended detectors (Find-Evil -IncludeExtendedDetection).
        # Use this to search for recipes that evade the closed-gap (extended) ruleset rather than just the core ruleset.
        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Switch]
        $IncludeExtendedDetection,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Switch]
        $Quiet
    )

    # ===================== Nested helpers =====================

    # Build splat for Find-Evil so the -IncludeExtendedDetection switch is forwarded to scoring when requested.
    $findEvilParameters = $IncludeExtendedDetection.IsPresent ? @{ IncludeExtendedDetection = $true } : @{ }

    # Compute total Find-Evil detection score for a SearchFilter string. Returns +Infinity if the filter fails to parse/score (invalid candidate).
    function Get-EvilScore
    {
        param ([System.String] $Filter)

        try
        {
            $detection = $Filter | Find-Evil -ErrorAction Stop @findEvilParameters
            return [System.Double] (($detection | Measure-Object -Property Score -Sum).Sum)
        }
        catch
        {
            return [System.Double]::PositiveInfinity
        }
    }

    # Standard Levenshtein edit distance (case-sensitive) using two rolling single-dimension rows.
    function Get-LevenshteinDistance
    {
        param ([System.String] $A, [System.String] $B)

        $lenA = $A.Length
        $lenB = $B.Length
        if ($lenA -eq 0) { return $lenB }
        if ($lenB -eq 0) { return $lenA }

        $previousRow = New-Object 'System.Int32[]' ($lenB + 1)
        $currentRow  = New-Object 'System.Int32[]' ($lenB + 1)
        for ($j = 0; $j -le $lenB; $j++) { $previousRow[$j] = $j }

        for ($i = 1; $i -le $lenA; $i++)
        {
            $currentRow[0] = $i
            for ($j = 1; $j -le $lenB; $j++)
            {
                $substitutionCost = ($A[$i - 1] -ceq $B[$j - 1]) ? 0 : 1
                $deletion     = $previousRow[$j] + 1
                $insertion    = $currentRow[$j - 1] + 1
                $substitution = $previousRow[$j - 1] + $substitutionCost
                $currentRow[$j] = [System.Math]::Min([System.Math]::Min($deletion, $insertion), $substitution)
            }

            $tempRow = $previousRow
            $previousRow = $currentRow
            $currentRow = $tempRow
        }

        return $previousRow[$lenB]
    }

    # Apply an ordered recipe (array of pass names) to the original SearchFilter, returning the obfuscated string (or $null on failure).
    function Invoke-Recipe
    {
        param ([System.String[]] $Recipe)

        $curFilter = $SearchFilter
        foreach ($passName in $Recipe)
        {
            try { $curFilter = & $passByName[$passName] $curFilter } catch { return $null }
            if (-not $curFilter) { return $null }
        }
        return $curFilter
    }

    # Evaluate a recipe: apply it, measure score + edit distance, and compute fitness (edit distance when within cap; otherwise a large negative penalty).
    function Get-RecipeFitness
    {
        param ([System.String[]] $Recipe)

        $obfFilter = Invoke-Recipe -Recipe $Recipe
        if (-not $obfFilter)
        {
            return [PSCustomObject] @{ Recipe = $Recipe; Filter = $null; Score = [System.Double]::PositiveInfinity; Distance = 0; Fitness = [System.Double]::NegativeInfinity }
        }

        $score = Get-EvilScore -Filter $obfFilter
        $distance = Get-LevenshteinDistance -A $SearchFilter -B $obfFilter
        $fitness = ($score -le $cap) ? ([System.Double] $distance) : (-1000.0 - ($score - $cap))

        return [PSCustomObject] @{ Recipe = $Recipe; Filter = $obfFilter; Score = $score; Distance = $distance; Fitness = $fitness }
    }

    # Produce a random recipe of random length in [1, MaxRecipeLength].
    function New-RandomRecipe
    {
        $length = Get-Random -Minimum 1 -Maximum ($MaxRecipeLength + 1)
        [System.String[]] (1..$length | ForEach-Object { Get-Random -InputObject $passNames })
    }

    # Apply one small random mutation (insert / delete / substitute / swap) to a recipe, capped at MaxRecipeLength.
    function Get-MutatedRecipe
    {
        param ([System.String[]] $Recipe)

        $list = [System.Collections.Generic.List[string]] $Recipe
        switch (Get-Random -InputObject @('insert','delete','substitute','swap'))
        {
            'insert'     { $list.Insert((Get-Random -Minimum 0 -Maximum ($list.Count + 1)), (Get-Random -InputObject $passNames)) }
            'delete'     { if ($list.Count -gt 1) { $list.RemoveAt((Get-Random -Minimum 0 -Maximum $list.Count)) } }
            'substitute' { if ($list.Count -ge 1) { $list[(Get-Random -Minimum 0 -Maximum $list.Count)] = (Get-Random -InputObject $passNames) } }
            'swap'       { if ($list.Count -ge 2) { $a = Get-Random -Minimum 0 -Maximum $list.Count; $b = Get-Random -Minimum 0 -Maximum $list.Count; $t = $list[$a]; $list[$a] = $list[$b]; $list[$b] = $t } }
        }
        while ($list.Count -gt $MaxRecipeLength) { $list.RemoveAt($list.Count - 1) }
        if ($list.Count -eq 0) { $list.Add((Get-Random -InputObject $passNames)) }

        [System.String[]] $list.ToArray()
    }

    # Single-point cut-and-splice crossover of two recipes (variable length), capped at MaxRecipeLength.
    function Get-CrossoverRecipe
    {
        param ([System.String[]] $ParentA, [System.String[]] $ParentB)

        $cutA = Get-Random -Minimum 0 -Maximum ($ParentA.Count + 1)
        $cutB = Get-Random -Minimum 0 -Maximum ($ParentB.Count + 1)
        $prefix = ($cutA -gt 0) ? $ParentA[0..($cutA - 1)] : @()
        $suffix = ($cutB -lt $ParentB.Count) ? $ParentB[$cutB..($ParentB.Count - 1)] : @()
        $child = [System.String[]] (@($prefix) + @($suffix))
        if ($child.Count -eq 0) { $child = [System.String[]] @(Get-Random -InputObject $passNames) }
        if ($child.Count -gt $MaxRecipeLength) { $child = [System.String[]] ($child[0..($MaxRecipeLength - 1)]) }

        $child
    }

    # ===================== Strategies =====================

    function Invoke-GreedySearch
    {
        $globalBest = Get-RecipeFitness -Recipe @()

        for ($restart = 0; $restart -lt $Restarts; $restart++)
        {
            $curRecipe = [System.Collections.Generic.List[string]]::new()
            $curBest = Get-RecipeFitness -Recipe @()

            for ($iteration = 0; $iteration -lt $Iterations; $iteration++)
            {
                $bestStep = $null
                foreach ($passName in $passNames)
                {
                    for ($try = 0; $try -lt $TriesPerPass; $try++)
                    {
                        $candidateRecipe = [System.String[]] ($curRecipe + $passName)
                        $candidate = Get-RecipeFitness -Recipe $candidateRecipe
                        if (($candidate.Score -le $cap) -and ((-not $bestStep) -or ($candidate.Distance -gt $bestStep.Distance)))
                        {
                            $bestStep = $candidate
                        }
                    }
                }

                if ((-not $bestStep) -or ($bestStep.Distance -le $curBest.Distance)) { break }
                $curRecipe = [System.Collections.Generic.List[string]] $bestStep.Recipe
                $curBest = $bestStep
            }

            if ($curBest.Distance -gt $globalBest.Distance)
            {
                $globalBest = $curBest
                if (-not $Quiet) { Write-Host ("    restart {0,2}: distance={1,-5} score={2,-7} recipe={3}" -f $restart, $globalBest.Distance, $globalBest.Score, ($globalBest.Recipe -join ' -> ')) }
            }
        }

        $globalBest
    }

    function Invoke-AnnealingSearch
    {
        $current = Get-RecipeFitness -Recipe (New-RandomRecipe)
        $globalBest = $current
        $temperature = $InitialTemperature

        for ($step = 0; $step -lt $AnnealSteps; $step++)
        {
            $neighbor = Get-RecipeFitness -Recipe (Get-MutatedRecipe -Recipe $current.Recipe)
            $deltaFitness = $neighbor.Fitness - $current.Fitness

            if (($deltaFitness -ge 0) -or ((Get-Random -Minimum 0.0 -Maximum 1.0) -lt [System.Math]::Exp($deltaFitness / [System.Math]::Max($temperature, 0.0001))))
            {
                $current = $neighbor
            }

            if (($current.Score -le $cap) -and ($current.Distance -gt $globalBest.Distance))
            {
                $globalBest = $current
                if (-not $Quiet) { Write-Host ("    step {0,4} (T={1,6:N2}): distance={2,-5} score={3,-7} recipe={4}" -f $step, $temperature, $globalBest.Distance, $globalBest.Score, ($globalBest.Recipe -join ' -> ')) }
            }

            $temperature *= $CoolingRate
        }

        $globalBest
    }

    function Invoke-GeneticSearch
    {
        $population = 1..$PopulationSize | ForEach-Object { New-RandomRecipe }
        $globalBest = Get-RecipeFitness -Recipe @()

        for ($generation = 0; $generation -lt $Generations; $generation++)
        {
            $evaluated = $population | ForEach-Object { Get-RecipeFitness -Recipe $_ }
            $evaluatedSorted = $evaluated | Sort-Object -Property Fitness -Descending

            $genBest = $evaluatedSorted | Where-Object { $_.Score -le $cap } | Select-Object -First 1
            if ($genBest -and ($genBest.Distance -gt $globalBest.Distance))
            {
                $globalBest = $genBest
                if (-not $Quiet) { Write-Host ("    gen {0,2}: distance={1,-5} score={2,-7} recipe={3}" -f $generation, $globalBest.Distance, $globalBest.Score, ($globalBest.Recipe -join ' -> ')) }
            }

            $nextPopulation = [System.Collections.Generic.List[object]]::new()
            $evaluatedSorted | Select-Object -First $EliteCount | ForEach-Object { $nextPopulation.Add($_.Recipe) }

            while ($nextPopulation.Count -lt $PopulationSize)
            {
                $parentA = ($evaluated | Get-Random -Count ([System.Math]::Min($TournamentSize, $evaluated.Count)) | Sort-Object -Property Fitness -Descending)[0]
                $parentB = ($evaluated | Get-Random -Count ([System.Math]::Min($TournamentSize, $evaluated.Count)) | Sort-Object -Property Fitness -Descending)[0]
                $child = Get-CrossoverRecipe -ParentA $parentA.Recipe -ParentB $parentB.Recipe
                if ((Get-Random -Minimum 0.0 -Maximum 1.0) -lt $MutationRate) { $child = Get-MutatedRecipe -Recipe $child }
                $nextPopulation.Add($child)
            }

            $population = $nextPopulation.ToArray()
        }

        $globalBest
    }

    # ===================== Setup =====================

    # Define candidate obfuscation passes. Each is a label plus a ScriptBlock applying one randomized obfuscation step.
    # Default pool is exclusively logic-preserving (no broadening Wildcard, no high-signal Hex / OID-zeros).
    $passPool = [System.Collections.Generic.List[object]]::new()
    $passPool.Add([PSCustomObject] @{ Name = 'Case';         Apply = { param($f) $f | Add-RandomCase                      -RandomNodePercent 100 -RandomCharPercent (Get-Random -Minimum 30 -Maximum 101) } })
    $passPool.Add([PSCustomObject] @{ Name = 'Order';        Apply = { param($f) $f | Add-RandomFilterListOrder          -RandomNodePercent 100 } })
    $passPool.Add([PSCustomObject] @{ Name = 'OID';          Apply = { param($f) $f | Add-RandomOid                      -RandomNodePercent 100 -Type @() } })
    $passPool.Add([PSCustomObject] @{ Name = 'Parenthesis';  Apply = { param($f) $f | Add-RandomParenthesis              -RandomNodePercent (Get-Random -Minimum 30 -Maximum 101) } })
    $passPool.Add([PSCustomObject] @{ Name = 'BoolOp';       Apply = { param($f) $f | Add-RandomBooleanOperator          -RandomNodePercent (Get-Random -Minimum 30 -Maximum 101) } })
    $passPool.Add([PSCustomObject] @{ Name = 'BoolInvert';   Apply = { param($f) $f | Add-RandomBooleanOperatorInversion -RandomNodePercent (Get-Random -Minimum 20 -Maximum 70) } })
    $passPool.Add([PSCustomObject] @{ Name = 'Presence';     Apply = { param($f) $f | Add-RandomPresenceFilter           -RandomNodePercent (Get-Random -Minimum 30 -Maximum 101) } })
    $passPool.Add([PSCustomObject] @{ Name = 'FilterRandom'; Apply = { param($f) $f | Add-RandomFilter                   -RandomNodePercent (Get-Random -Minimum 30 -Maximum 101) } })
    $passPool.Add([PSCustomObject] @{ Name = 'Whitespace';   Apply = { param($f) $f | Add-RandomWhitespace               -RandomNodePercent (Get-Random -Minimum 20 -Maximum 60) -RandomLength 1 } })
    if ($AllowLossy.IsPresent)
    {
        $passPool.Add([PSCustomObject] @{ Name = 'Hex';      Apply = { param($f) $f | Add-RandomHexValue                 -RandomNodePercent 100 -RandomCharPercent (Get-Random -Minimum 5 -Maximum 25) } })
        $passPool.Add([PSCustomObject] @{ Name = 'Wildcard'; Apply = { param($f) $f | Add-RandomWildcard                 -RandomNodePercent (Get-Random -Minimum 30 -Maximum 80) -RandomCharPercent (Get-Random -Minimum 20 -Maximum 60) } })
        $passPool.Add([PSCustomObject] @{ Name = 'OIDzeros'; Apply = { param($f) $f | Add-RandomOid                      -RandomNodePercent 100 -Type Zeros,Prefix } })
    }

    # Build Name -> Apply lookup and list of pass names. Use a plain foreach loop (not $passPool.ForEach{...}) since the native .NET List.ForEach(Action) would shadow PowerShell's intrinsic and never bind $_.
    $passByName = @{ }
    foreach ($pass in $passPool) { $passByName[$pass.Name] = $pass.Apply }
    $passNames = [System.String[]] ($passPool | ForEach-Object { $_.Name })

    # Establish baseline detection score and resolve the score cap.
    $baselineScore = Get-EvilScore -Filter $SearchFilter
    $cap = ($null -ne $ScoreCap) ? ([System.Double] $ScoreCap) : $baselineScore

    if (-not $Quiet)
    {
        Write-Host ''
        Write-Host "[*] Original SearchFilter : $SearchFilter"
        Write-Host "[*] Strategy              : $Strategy"
        Write-Host "[*] Baseline Find-Evil    : $baselineScore"
        Write-Host "[*] Score cap             : $cap   (recipe may not exceed this)"
        Write-Host "[*] Pass pool             : $($passNames -join ', ')"
        Write-Host "[*] Searching..."
    }

    # ===================== Run =====================

    $result = switch ($Strategy)
    {
        'Greedy'    { Invoke-GreedySearch }
        'Annealing' { Invoke-AnnealingSearch }
        'Genetic'   { Invoke-GeneticSearch }
    }

    # Attach baseline + cap context onto the result object for the caller.
    $result | Add-Member -NotePropertyName 'Baseline' -NotePropertyValue $baselineScore -Force
    $result | Add-Member -NotePropertyName 'ScoreCap' -NotePropertyValue $cap -Force
    $result | Add-Member -NotePropertyName 'Strategy' -NotePropertyValue $Strategy -Force

    if (-not $Quiet)
    {
        Write-Host ''
        Write-Host '============================ BEST RECIPE ============================'
        Write-Host ("Strategy      : " + $Strategy)
        Write-Host ("Recipe        : " + (($result.Recipe.Count -gt 0) ? ($result.Recipe -join ' -> ') : '(none)'))
        Write-Host ("Edit distance : " + $result.Distance + "   (higher = more structurally divergent)")
        Write-Host ("Find-Evil     : " + $result.Score + "   (baseline was $baselineScore, cap $cap)")
        Write-Host ("Obfuscated    : " + $result.Filter)
        Write-Host '===================================================================='
    }

    # Return the best result object.
    $result
}
