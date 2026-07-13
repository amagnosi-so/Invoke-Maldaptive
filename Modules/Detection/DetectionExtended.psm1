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
#
#   Extended (community) detection rules that close logical-equivalence-transform gaps the core
#   MaLDAPtive artifact-based ruleset does not score. Emitted only when Find-Evil is invoked with
#   -IncludeExtendedDetection. See Invoke-ObfuscationRecipeSearch for the empirical evidence of
#   these gaps (Case / plain-OID / Presence / FilterRandom obfuscation scoring 0 against the core ruleset).



function Get-LdapFilterLogicalCore
{
<#
.SYNOPSIS

Internal helper. Reduces a Filter (or single-child FilterList chain wrapping one Filter) to its logical core: the underlying Attribute=Value identity plus the parity (0/1) of negation ('!') BooleanOperators encountered while peeling the chain. Returns $null for multi-child FilterLists (not a simple decoy half). Not exported.
#>

    [OutputType([System.Management.Automation.PSCustomObject])]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $false)]
        [Maldaptive.LdapBranch]
        $LdapBranch
    )

    $negationParity = 0
    $curBranch = $LdapBranch

    # Peel single-child FilterList chains (tracking negation parity) until reaching a Filter leaf.
    for ($guard = 0; $guard -lt 256; $guard++)
    {
        if ($curBranch.Type -eq [Maldaptive.LdapBranchType]::Filter)
        {
            $ldapFilter = $curBranch.Branch[0]
            $booleanOperatorLdapToken = $ldapFilter.TokenDict[[Maldaptive.LdapTokenType]::BooleanOperator]
            if ($booleanOperatorLdapToken -and ($booleanOperatorLdapToken.Content -ceq '!')) { $negationParity = ($negationParity + 1) % 2 }

            $attributeContent  = $ldapFilter.TokenDict[[Maldaptive.LdapTokenType]::Attribute].ContentDecoded
            $comparisonContent = $ldapFilter.TokenDict[[Maldaptive.LdapTokenType]::ComparisonOperator].Content
            $valueContent      = $ldapFilter.TokenDict[[Maldaptive.LdapTokenType]::Value].ContentDecoded

            return [PSCustomObject] @{ Core = "$attributeContent$comparisonContent$valueContent"; Parity = $negationParity }
        }
        elseif ($curBranch.Type -eq [Maldaptive.LdapBranchType]::FilterList)
        {
            $nestedBranchArr = @($curBranch.Branch.Where( { $_ -is [Maldaptive.LdapBranch] } ))
            if ($nestedBranchArr.Count -ne 1) { return $null }

            $booleanOperatorLdapToken = $curBranch.Branch.Where( { ($_ -is [Maldaptive.LdapToken]) -and ($_.Type -eq [Maldaptive.LdapTokenType]::BooleanOperator) } )[0]
            if ($booleanOperatorLdapToken -and ($booleanOperatorLdapToken.Content -ceq '!')) { $negationParity = ($negationParity + 1) % 2 }

            $curBranch = $nestedBranchArr[0]
        }
        else
        {
            return $null
        }
    }

    return $null
}


function Find-EvilExtended
{
<#
.SYNOPSIS

MaLDAPtive is a framework for LDAP SearchFilter parsing, obfuscation, deobfuscation and detection.

MaLDAPtive Function: Find-EvilExtended
Author: Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: ConvertTo-LdapObject, Invoke-LdapBranchVisitor
Optional Dependencies: None

.DESCRIPTION

Find-EvilExtended evaluates community "extended" detection rules that score logical-equivalence-transform obfuscation the core MaLDAPtive ruleset does not flag. It returns [Maldaptive.Detection] objects (with EXTENDED_* DetectionIDs) and is intended to be composed with the core Find-Evil results (see Find-Evil -IncludeExtendedDetection).

Rules:
  EXTENDED_DEFINED_ATTRIBUTE_OID_SYNTAX  - a defined attribute expressed in plain numeric OID syntax (the core ruleset only scores the OID '+zeros' and 'OID.' prefix variants).
  EXTENDED_ATTRIBUTE_NONCANONICAL_CASE   - a defined attribute whose casing differs from its canonical name (case randomization).
  EXTENDED_LOGICALLY_INERT_DECOY_FILTER  - a FilterList containing sibling X and NOT-X cores (the '(|(a=v)(!(a=v)))' / '(&(a=v)(!(a=v)))' tautology/contradiction decoy).
  EXTENDED_REDUNDANT_PRESENCE_FILTER     - an AND FilterList containing both a presence filter '(attr=*)' and a concrete filter on the same attribute.

.PARAMETER SearchFilter

Specifies the LDAP SearchFilter string(s) to evaluate.

.EXAMPLE

PS C:\> '(&(2.5.4.3=*)(2.5.4.3=sabi)(|(zzz=qqq)(!(zzz=qqq))))' | Find-EvilExtended

.NOTES

This is a personal project developed by Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://github.com/MaLDAPtive/Invoke-Maldaptive
https://twitter.com/sabi_elezi/
https://twitter.com/danielhbohannon/
#>

    [OutputType([Maldaptive.Detection[]])]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [AllowNull()]
        [AllowEmptyString()]
        [System.String[]]
        $SearchFilter
    )

    begin
    {
        $author = 'Community (Extended Ruleset)'
        $date = Get-Date
    }

    process
    {
        foreach ($curSearchFilter in $SearchFilter)
        {
            if (-not $curSearchFilter) { continue }

            $detectionArr = [System.Collections.Generic.List[Maldaptive.Detection]]::new()

            # ---------- Attribute-level rules: plain OID substitution + non-canonical case ----------
            $ldapFilterArr = [Maldaptive.LdapFilter[]] ($curSearchFilter | ConvertTo-LdapObject -Target LdapFilter)
            foreach ($ldapFilter in $ldapFilterArr)
            {
                $attributeLdapToken = $ldapFilter.TokenDict[[Maldaptive.LdapTokenType]::Attribute]
                if ((-not $attributeLdapToken) -or (-not $attributeLdapToken.IsDefined)) { continue }

                if ($attributeLdapToken.Format -eq [Maldaptive.LdapTokenFormat]::OID)
                {
                    # Plain numeric OID for a defined attribute. Exclude the prepended-zeros and 'OID.' prefix variants since the core ruleset already scores those.
                    $isPlainNumericOid = ($attributeLdapToken.Content -cmatch '^\d+(\.\d+)+$') -and -not ($attributeLdapToken.Content.Split('.').Where( { ($_.Length -gt 1) -and $_.StartsWith('0') } ))
                    if ($isPlainNumericOid)
                    {
                        $detectionArr.Add([Maldaptive.Detection]::new($ldapFilter, $author, $date, [Maldaptive.DetectionID]::EXTENDED_DEFINED_ATTRIBUTE_OID_SYNTAX, "Defined Attribute in Plain OID Syntax: $($attributeLdapToken.Content) (Name=$($attributeLdapToken.Context.Attribute.Name))", $ldapFilter.Content, 10.0))
                    }
                }
                else
                {
                    # Non-canonical case: the literal attribute text (Content) matches the canonical name ignoring case but differs in case.
                    # Use Content (not ContentDecoded) since the parser normalizes ContentDecoded to the canonical case, erasing the case-obfuscation signal.
                    $canonicalName = $attributeLdapToken.Context.Attribute.Name
                    if ($canonicalName -and ($attributeLdapToken.Content -ieq $canonicalName) -and ($attributeLdapToken.Content -cne $canonicalName))
                    {
                        $detectionArr.Add([Maldaptive.Detection]::new($ldapFilter, $author, $date, [Maldaptive.DetectionID]::EXTENDED_ATTRIBUTE_NONCANONICAL_CASE, "Defined Attribute with Non-Canonical Case: $($attributeLdapToken.Content) (Canonical=$canonicalName)", $ldapFilter.Content, 5.0))
                    }
                }
            }

            # ---------- Structural rules: logically-inert decoy + redundant presence ----------
            $ldapBranch = $curSearchFilter | ConvertTo-LdapObject -Target LdapBranch
            $scriptBlockReturnAllBranches = {
                param ([Parameter(Mandatory = $true, ValueFromPipeline = $true)] [Maldaptive.LdapBranch] $LdapBranch)
                $LdapBranch
            }
            $allBranchArr = [Maldaptive.LdapBranch[]] (Invoke-LdapBranchVisitor -LdapBranch $ldapBranch -ScriptBlock $scriptBlockReturnAllBranches -Action Return)

            foreach ($curBranch in $allBranchArr)
            {
                if ($curBranch.Type -ne [Maldaptive.LdapBranchType]::FilterList) { continue }

                $childBranchArr = @($curBranch.Branch.Where( { $_ -is [Maldaptive.LdapBranch] } ))
                if ($childBranchArr.Count -lt 2) { continue }

                # Decoy detection: group sibling logical cores; a core present with BOTH negation parities is an X / NOT-X inert decoy pair.
                $coreParityMap = @{ }
                foreach ($childBranch in $childBranchArr)
                {
                    $logicalCore = Get-LdapFilterLogicalCore -LdapBranch $childBranch
                    if (-not $logicalCore) { continue }
                    if (-not $coreParityMap.ContainsKey($logicalCore.Core)) { $coreParityMap[$logicalCore.Core] = [System.Collections.Generic.HashSet[int]]::new() }
                    [System.Void] $coreParityMap[$logicalCore.Core].Add($logicalCore.Parity)
                }
                $decoyPairCount = @($coreParityMap.Values.Where( { $_.Count -ge 2 } )).Count
                if ($decoyPairCount -ge 1)
                {
                    $detectionArr.Add([Maldaptive.Detection]::new($curBranch, $author, $date, [Maldaptive.DetectionID]::EXTENDED_LOGICALLY_INERT_DECOY_FILTER, "FilterList Contains $decoyPairCount Logically-Inert Decoy Filter(s) (sibling X and NOT-X)", $curBranch.Content, (20.0 * $decoyPairCount)))
                }

                # Redundant presence detection: an AND FilterList containing both a presence filter '(attr=*)' and a concrete filter on the same attribute.
                if ($curBranch.BooleanOperator -ceq '&')
                {
                    $presenceAttributeSet = [System.Collections.Generic.HashSet[string]]::new()
                    $concreteAttributeSet = [System.Collections.Generic.HashSet[string]]::new()
                    foreach ($childBranch in $childBranchArr)
                    {
                        if ($childBranch.Type -ne [Maldaptive.LdapBranchType]::Filter) { continue }
                        $childFilter = $childBranch.Branch[0]
                        $childAttribute = $childFilter.TokenDict[[Maldaptive.LdapTokenType]::Attribute].ContentDecoded
                        $childValue     = $childFilter.TokenDict[[Maldaptive.LdapTokenType]::Value].Content
                        if (-not $childAttribute) { continue }
                        if ($childValue -ceq '*') { [System.Void] $presenceAttributeSet.Add($childAttribute) } else { [System.Void] $concreteAttributeSet.Add($childAttribute) }
                    }
                    $redundantAttributeArr = @($presenceAttributeSet.Where( { $concreteAttributeSet.Contains($_) } ))
                    if ($redundantAttributeArr.Count -ge 1)
                    {
                        $detectionArr.Add([Maldaptive.Detection]::new($curBranch, $author, $date, [Maldaptive.DetectionID]::EXTENDED_REDUNDANT_PRESENCE_FILTER, "FilterList Contains Redundant Presence Filter(s) for Attribute(s): $($redundantAttributeArr -join ', ')", $curBranch.Content, (10.0 * $redundantAttributeArr.Count)))
                    }
                }
            }

            # Return all extended Detection hits for current SearchFilter.
            [Maldaptive.Detection[]] $detectionArr.ToArray()
        }
    }
}
