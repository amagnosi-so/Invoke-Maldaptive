#   This file is part of the MaLDAPtive framework.
#
#   Copyright 2024 Sabajete Elezaj (aka Sabi) <@sabi_elezi>
#         while at Solaris SE <https://solarisgroup.com/>
#         and Daniel Bohannon (aka DBO) <@danielhbohannon>
#         while at Permiso Security <https://permiso.io/>
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
#   NOTE: This Obfuscation module is a community reconstruction of the
#   intentionally-delayed MaLDAPtive obfuscation module. Each Add-Random*
#   function is built as the logical inverse of its Remove-Random* counterpart
#   in ./Modules/Deobfuscation/Deobfuscation.psm1, reusing the exact same
#   LdapToken/LdapBranch object model and helper functions so that obfuscation
#   and deobfuscation round-trip cleanly and remain detectable via Find-Evil.



function Get-RandomObfuscationLabel
{
<#
.SYNOPSIS

Internal helper. Generates a random lowercase ASCII label used for synthetic/undefined tokens (e.g. junk ExtensibleMatchFilter matching-rule names). Not exported.
#>

    [OutputType([System.String])]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateRange(1,64)]
        [System.Int16]
        $MinLength = 5,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateRange(1,64)]
        [System.Int16]
        $MaxLength = 8
    )

    # Select a random length in eligible range then build label one random lowercase ASCII letter ('a'-'z') at a time.
    $labelLength = Get-Random -Minimum $MinLength -Maximum ($MaxLength + 1)
    -join (1..$labelLength).ForEach( { [System.Char] (Get-Random -Minimum 97 -Maximum 123) } )
}


function Add-RandomExtensibleMatchFilter
{
<#
.SYNOPSIS

MaLDAPtive is a framework for LDAP SearchFilter parsing, obfuscation, deobfuscation and detection.

MaLDAPtive Function: Add-RandomExtensibleMatchFilter
Author: Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Join-LdapObject, ConvertTo-LdapObject, Format-LdapObject, New-LdapToken
Optional Dependencies: None

.DESCRIPTION

Add-RandomExtensibleMatchFilter inserts random undefined ExtensibleMatchFilter (matching rule) tokens into eligible equality Filters in input LDAP SearchFilter. This is the inverse of Remove-RandomExtensibleMatchFilter.

.PARAMETER InputObject

Specifies LDAP SearchFilter (in any input format) into which random undefined ExtensibleMatchFilters will be inserted.

.PARAMETER RandomNodePercent

(Optional) Specifies percentage of eligible nodes (branch, filter, token, etc.) to obfuscate.

.PARAMETER Target

(Optional) Specifies target LDAP format into which the final result will be converted.

.PARAMETER TrackModification

(Optional) Specifies custom 'Modified' property be added to all modified LDAP tokens (e.g. for highlighting where obfuscation occurred).

.EXAMPLE

PS C:\> '(name=sabi)' | Add-RandomExtensibleMatchFilter -RandomNodePercent 100

(name:qwerty:=sabi)

.EXAMPLE

PS C:\> '(&(name=sabi)(name=dbo))' | Add-RandomExtensibleMatchFilter -RandomNodePercent 100 | Remove-RandomExtensibleMatchFilter -RandomNodePercent 100

(&(name=sabi)(name=dbo))

.NOTES

This is a personal project developed by Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://github.com/MaLDAPtive/Invoke-Maldaptive
https://twitter.com/sabi_elezi/
https://twitter.com/danielhbohannon/
#>

    [OutputType(
        [System.String],
        [Maldaptive.LdapToken[]],
        [Maldaptive.LdapTokenEnriched[]],
        [Maldaptive.LdapFilter[]],
        [Maldaptive.LdapBranch]
    )]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        # Purposefully not defining parameter type since mixture of LDAP formats allowed.
        $InputObject,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateRange(0,100)]
        [System.Int16]
        $RandomNodePercent = 50,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Maldaptive.LdapFormat]
        $Target = [Maldaptive.LdapFormat]::String,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Switch]
        $TrackModification
    )

    begin
    {
        # Define current function's input object target format requirement (ensured by ConvertTo-LdapObject later in current function).
        $requiredInputObjectTarget = [Maldaptive.LdapFormat]::LdapTokenEnriched

        # Extract optional switch input parameter(s) from $PSBoundParameters into separate hashtable for consistent inclusion/exclusion in relevant functions via splatting.
        $optionalSwitchParameters = @{ }
        $PSBoundParameters.GetEnumerator().Where( { $_.Key -iin @('TrackModification') } ).ForEach( { $optionalSwitchParameters.Add($_.Key, $_.Value) } )

        # Create ArrayList to store all pipelined input before beginning final processing.
        $inputObjectArr = [System.Collections.ArrayList]::new()
    }

    process
    {
        # Add all pipelined input to $inputObjectArr before beginning final processing.
        # Join-LdapObject function performs type casting and optimizes ArrayList append operations.
        $inputObjectArr = Join-LdapObject -InputObject $InputObject -InputObjectArr $inputObjectArr
    }

    end
    {
        # Ensure input data is formatted according to current function's requirement as defined in $requiredInputObjectTarget at beginning of current function.
        # This conversion also ensures completely separate copy of input object(s) so modifications in current function do not affect original input object outside current function.
        $inputObjectArr = ConvertTo-LdapObject -InputObject $inputObjectArr -Target $requiredInputObjectTarget

        # Iterate over each input object, storing result in array for proper re-parsing before returning final result.
        $modifiedInputObjectArr = foreach ($curInputObject in $inputObjectArr)
        {
            # Set boolean for generic obfuscation eligibility.
            $isEligible = $true

            # Override above obfuscation eligibility for specific scenarios.
            if ($curInputObject.Type -ne [Maldaptive.LdapTokenType]::ComparisonOperator)
            {
                # Override obfuscation eligibility if current object is not a ComparisonOperator LdapToken.
                $isEligible = $false
            }
            elseif ($curInputObject.Content -cne '=')
            {
                # Override obfuscation eligibility if current ComparisonOperator is not a simple equality ('='), since an ExtensibleMatchFilter
                # matching rule is only syntactically valid when paired with the ':=' style comparison (e.g. attr:rule:=value).
                $isEligible = $false
            }
            elseif ($curInputObject.TypeBefore -ne [Maldaptive.LdapTokenType]::Attribute)
            {
                # Override obfuscation eligibility if current ComparisonOperator is not directly preceded by an Attribute LdapToken
                # (e.g. an ExtensibleMatchFilter already exists or whitespace separates the Attribute and ComparisonOperator).
                $isEligible = $false
            }

            # Set boolean for obfuscation eligibility based on user input -RandomNodePercent value.
            $isRandomNodePercent = (Get-Random -Minimum 1 -Maximum 100) -le $RandomNodePercent

            # Proceed if eligible for obfuscation.
            if ($isEligible -and $isRandomNodePercent)
            {
                # Generate a new undefined ExtensibleMatchFilter LdapToken with a random lowercase matching rule label encapsulated in colons (e.g. ':abcde:').
                # An undefined (non-OID) matching rule is the exact artifact targeted by Remove-RandomExtensibleMatchFilter and detected via the UNDEFINED_EXTENSIBLEMATCHFILTER rule.
                $newExtensibleMatchFilterContent = ':' + (Get-RandomObfuscationLabel) + ':'
                New-LdapToken -Type ExtensibleMatchFilter -Content $newExtensibleMatchFilterContent -Target LdapTokenEnriched @optionalSwitchParameters
            }

            # Return current object.
            $curInputObject
        }

        # Ensure result is formatted according to user input -Target and optional -TrackModification values.
        $finalResult = Format-LdapObject -InputObject $modifiedInputObjectArr -Target $Target @optionalSwitchParameters

        # Return final result.
        $finalResult
    }
}


function Add-RandomWildcard
{
<#
.SYNOPSIS

MaLDAPtive is a framework for LDAP SearchFilter parsing, obfuscation, deobfuscation and detection.

MaLDAPtive Function: Add-RandomWildcard
Author: Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Join-LdapObject, ConvertTo-LdapObject, ConvertTo-LdapParsedValue, Format-LdapObject
Optional Dependencies: None

.DESCRIPTION

Add-RandomWildcard inserts random wildcards ('*') into eligible Attribute Values in input LDAP SearchFilter. This is the inverse of Remove-RandomWildcard.

.PARAMETER InputObject

Specifies LDAP SearchFilter (in any input format) into which random wildcards ('*') will be inserted.

.PARAMETER RandomNodePercent

(Optional) Specifies percentage of eligible nodes (branch, filter, token, etc.) to obfuscate.

.PARAMETER RandomCharPercent

(Optional) Specifies percentage of eligible inter-character positions to obfuscate.

.PARAMETER Type

(Optional) Specifies eligible wildcard ('*') insertion location(s) in Attribute Values for obfuscation.

.PARAMETER Target

(Optional) Specifies target LDAP format into which the final result will be converted.

.PARAMETER TrackModification

(Optional) Specifies custom 'Modified' property be added to all modified LDAP tokens (e.g. for highlighting where obfuscation occurred).

.EXAMPLE

PS C:\> '(name=sabi)' | Add-RandomWildcard -RandomNodePercent 100 -RandomCharPercent 100

(name=*s*a*b*i*)

.EXAMPLE

PS C:\> '(&(objectCategory=Person)(name=dbo))' | Add-RandomWildcard -RandomNodePercent 100 -RandomCharPercent 100 -Type middle

(&(objectCategory=P*e*r*s*o*n)(name=d*b*o))

.NOTES

This is a personal project developed by Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://github.com/MaLDAPtive/Invoke-Maldaptive
https://twitter.com/sabi_elezi/
https://twitter.com/danielhbohannon/
#>

    [OutputType(
        [System.String],
        [Maldaptive.LdapToken[]],
        [Maldaptive.LdapTokenEnriched[]],
        [Maldaptive.LdapFilter[]],
        [Maldaptive.LdapBranch]
    )]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        # Purposefully not defining parameter type since mixture of LDAP formats allowed.
        $InputObject,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateRange(0,100)]
        [System.Int16]
        $RandomNodePercent = 50,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateRange(0,100)]
        [System.Int16]
        $RandomCharPercent = 50,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateSet('prefix','middle','suffix')]
        [System.String[]]
        $Type = @('prefix','middle','suffix'),

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Maldaptive.LdapFormat]
        $Target = [Maldaptive.LdapFormat]::String,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Switch]
        $TrackModification
    )

    begin
    {
        # Define current function's input object target format requirement (ensured by ConvertTo-LdapObject later in current function).
        $requiredInputObjectTarget = [Maldaptive.LdapFormat]::LdapTokenEnriched

        # Extract optional switch input parameter(s) from $PSBoundParameters into separate hashtable for consistent inclusion/exclusion in relevant functions via splatting.
        $optionalSwitchParameters = @{ }
        $PSBoundParameters.GetEnumerator().Where( { $_.Key -iin @('TrackModification') } ).ForEach( { $optionalSwitchParameters.Add($_.Key, $_.Value) } )

        # Create ArrayList to store all pipelined input before beginning final processing.
        $inputObjectArr = [System.Collections.ArrayList]::new()
    }

    process
    {
        # Add all pipelined input to $inputObjectArr before beginning final processing.
        # Join-LdapObject function performs type casting and optimizes ArrayList append operations.
        $inputObjectArr = Join-LdapObject -InputObject $InputObject -InputObjectArr $inputObjectArr
    }

    end
    {
        # Ensure input data is formatted according to current function's requirement as defined in $requiredInputObjectTarget at beginning of current function.
        # This conversion also ensures completely separate copy of input object(s) so modifications in current function do not affect original input object outside current function.
        $inputObjectArr = ConvertTo-LdapObject -InputObject $inputObjectArr -Target $requiredInputObjectTarget

        # Iterate over each input object, storing result in array for proper re-parsing before returning final result.
        $modifiedInputObjectArr = foreach ($curInputObject in $inputObjectArr)
        {
            # Set boolean for generic obfuscation eligibility.
            $isEligible = $true

            # Override above obfuscation eligibility for specific scenarios.
            if ($curInputObject.Type -ne [Maldaptive.LdapTokenType]::Value)
            {
                # Override obfuscation eligibility if current object is not a Value LdapToken.
                $isEligible = $false
            }
            elseif (-not $curInputObject.Content)
            {
                # Override obfuscation eligibility if current Value LdapToken is empty.
                $isEligible = $false
            }
            elseif ($curInputObject.Content -ceq '*')
            {
                # Override obfuscation eligibility if current Value LdapToken is a bare presence filter ('*').
                $isEligible = $false
            }
            elseif ($curInputObject.TokenList)
            {
                # Override obfuscation eligibility if current Value LdapToken is a structured DN (RDN sub-tokens present), since inserting wildcards
                # into a Distinguished Name would break its structural matching.
                $isEligible = $false
            }
            elseif ($curInputObject.ContentDecoded -cmatch '^\d+$')
            {
                # Override obfuscation eligibility if current Value LdapToken decodes to a pure integer, since wildcards are not meaningful for integer-syntax attributes.
                $isEligible = $false
            }

            # Set boolean for obfuscation eligibility based on user input -RandomNodePercent value.
            $isRandomNodePercent = (Get-Random -Minimum 1 -Maximum 100) -le $RandomNodePercent

            # Proceed if eligible for obfuscation.
            if ($isEligible -and $isRandomNodePercent)
            {
                # Parse current Value LdapToken content into discrete parsed characters so hex-encoded characters (e.g. '\61') and existing
                # wildcards are treated as single units and never split mid-sequence.
                $curInputObjectParsedArr = ConvertTo-LdapParsedValue -InputObject $curInputObject.Content

                # Rebuild Value content, evaluating each inter-character boundary position for wildcard insertion based on user input -Type and -RandomCharPercent parameters.
                # Boundary index 0 is the prefix position, index equal to parsed character count is the suffix position, all positions in between are middle positions.
                $valueModified = -join @(for ($i = 0; $i -le $curInputObjectParsedArr.Count; $i++)
                {
                    # Determine current boundary position type.
                    $positionType = switch ($i)
                    {
                        0                                  { 'prefix' }
                        $curInputObjectParsedArr.Count     { 'suffix' }
                        default                            { 'middle' }
                    }

                    # Evaluate wildcard insertion eligibility for current boundary position based on user input -Type and -RandomCharPercent parameters
                    # while avoiding insertion directly adjacent to an existing wildcard (which would produce a redundant contiguous wildcard sequence).
                    if (
                        ($Type -icontains $positionType) -and
                        (((Get-Random -Minimum 1 -Maximum 100) -le $RandomCharPercent)) -and
                        ((($i -eq 0) ? '' : $curInputObjectParsedArr[$i - 1].Content) -cne '*') -and
                        ((($i -eq $curInputObjectParsedArr.Count) ? '' : $curInputObjectParsedArr[$i].Content) -cne '*')
                    )
                    {
                        # Insert a single wildcard character ('*') at current boundary position.
                        '*'
                    }

                    # Return current parsed character (skipping the trailing suffix boundary which has no character).
                    if ($i -lt $curInputObjectParsedArr.Count)
                    {
                        $curInputObjectParsedArr[$i].Content
                    }
                })

                # Update current Value LdapToken if obfuscation occurred in above step.
                if ($curInputObject.Content -cne $valueModified)
                {
                    $curInputObject.Content = $valueModified
                    $curInputObject.Length = $curInputObject.Content.Length

                    # If user input -TrackModification switch parameter is defined then set Depth property of current Value LdapToken to -1 for display tracking purposes.
                    if ($PSBoundParameters['TrackModification'].IsPresent)
                    {
                        $curInputObject.Depth = -1
                    }
                }
            }

            # Return current object.
            $curInputObject
        }

        # Ensure result is formatted according to user input -Target and optional -TrackModification values.
        $finalResult = Format-LdapObject -InputObject $modifiedInputObjectArr -Target $Target @optionalSwitchParameters

        # Return final result.
        $finalResult
    }
}


function Add-RandomWhitespace
{
<#
.SYNOPSIS

MaLDAPtive is a framework for LDAP SearchFilter parsing, obfuscation, deobfuscation and detection.

MaLDAPtive Function: Add-RandomWhitespace
Author: Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Join-LdapObject, ConvertTo-LdapObject, New-LdapToken, Format-LdapObject
Optional Dependencies: None

.DESCRIPTION

Add-RandomWhitespace inserts random whitespace into eligible positions in input LDAP SearchFilter. This is the inverse of Remove-RandomWhitespace.

.PARAMETER InputObject

Specifies LDAP SearchFilter (in any input format) into which random whitespace will be inserted.

.PARAMETER RandomNodePercent

(Optional) Specifies percentage of eligible nodes (branch, filter, token, etc.) to obfuscate.

.PARAMETER RandomLength

(Optional) Specifies eligible length(s) for each random whitespace substring insertion.

.PARAMETER Type

(Optional) Specifies eligible LdapToken type(s) after which whitespace can be inserted.

.PARAMETER Target

(Optional) Specifies target LDAP format into which the final result will be converted.

.PARAMETER TrackModification

(Optional) Specifies custom 'Modified' property be added to all modified LDAP tokens (e.g. for highlighting where obfuscation occurred).

.EXAMPLE

PS C:\> '(|(name=sabi)(name=dbo))' | Add-RandomWhitespace -RandomNodePercent 100 -RandomLength 2 -Type GroupStart,BooleanOperator

(  |  (  name=sabi)(  name=dbo))

.EXAMPLE

PS C:\> '(name=sabi)' | Add-RandomWhitespace -RandomNodePercent 100 -RandomLength 3 | Remove-RandomWhitespace -RandomNodePercent 100 -RandomLength 100

(name=sabi)

.NOTES

This is a personal project developed by Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://github.com/MaLDAPtive/Invoke-Maldaptive
https://twitter.com/sabi_elezi/
https://twitter.com/danielhbohannon/
#>

    [OutputType(
        [System.String],
        [Maldaptive.LdapToken[]],
        [Maldaptive.LdapTokenEnriched[]],
        [Maldaptive.LdapFilter[]],
        [Maldaptive.LdapBranch]
    )]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        # Purposefully not defining parameter type since mixture of LDAP formats allowed.
        $InputObject,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateRange(0,100)]
        [System.Int16]
        $RandomNodePercent = 50,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateRange(1,100)]
        [System.Int16[]]
        $RandomLength = @(1,2,3),

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateSet(
            'SearchFilter_Prefix',
            'GroupStart',
            'BooleanOperator',
            'OID_Attribute',
            'ComparisonOperator',
            'RDN_Attribute',
            'RDN_ComparisonOperator',
            'RDN_Value',
            'RDN_CommaDelimiter',
            'GroupEnd',
            'SearchFilter_Suffix'
        )]
        [System.String[]]
        $Type = @(
            'SearchFilter_Prefix',
            'GroupStart',
            'BooleanOperator',
            'OID_Attribute',
            'ComparisonOperator',
            'RDN_Attribute',
            'RDN_ComparisonOperator',
            'RDN_Value',
            'RDN_CommaDelimiter',
            'GroupEnd',
            'SearchFilter_Suffix'
        ),

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Maldaptive.LdapFormat]
        $Target = [Maldaptive.LdapFormat]::String,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Switch]
        $TrackModification
    )

    begin
    {
        # Define current function's input object target format requirement (ensured by ConvertTo-LdapObject later in current function).
        $requiredInputObjectTarget = [Maldaptive.LdapFormat]::LdapTokenEnriched

        # Extract optional switch input parameter(s) from $PSBoundParameters into separate hashtable for consistent inclusion/exclusion in relevant functions via splatting.
        $optionalSwitchParameters = @{ }
        $PSBoundParameters.GetEnumerator().Where( { $_.Key -iin @('TrackModification') } ).ForEach( { $optionalSwitchParameters.Add($_.Key, $_.Value) } )

        # Create ArrayList to store all pipelined input before beginning final processing.
        $inputObjectArr = [System.Collections.ArrayList]::new()
    }

    process
    {
        # Add all pipelined input to $inputObjectArr before beginning final processing.
        # Join-LdapObject function performs type casting and optimizes ArrayList append operations.
        $inputObjectArr = Join-LdapObject -InputObject $InputObject -InputObjectArr $inputObjectArr
    }

    end
    {
        # Ensure input data is formatted according to current function's requirement as defined in $requiredInputObjectTarget at beginning of current function.
        # This conversion also ensures completely separate copy of input object(s) so modifications in current function do not affect original input object outside current function.
        $inputObjectArr = ConvertTo-LdapObject -InputObject $inputObjectArr -Target $requiredInputObjectTarget

        # Define local helper ScriptBlock to evaluate -RandomNodePercent eligibility and (if eligible) generate a new Whitespace LdapToken of random length defined in user input -RandomLength parameter.
        $newWhitespaceLdapToken = {
            # Set boolean for obfuscation eligibility based on user input -RandomNodePercent value.
            if ((Get-Random -Minimum 1 -Maximum 100) -le $RandomNodePercent)
            {
                # Generate new Whitespace LdapToken whose Content is a run of space characters with length randomly selected from user input -RandomLength parameter.
                # If optional -TrackModification switch parameter is defined then new Whitespace LdapToken's Depth property value will be set to -1 for modification tracking display purposes.
                New-LdapToken -Type Whitespace -Content (' ' * (Get-Random -InputObject $RandomLength)) -Target LdapTokenEnriched @optionalSwitchParameters
            }
        }

        # Iterate over each input object, inserting eligible Whitespace LdapTokens to produce a new token array for proper re-parsing before returning final result.
        # Track total token count to detect first (SearchFilter_Prefix) and last (SearchFilter_Suffix) token positions.
        $lastIndex = $inputObjectArr.Count - 1
        $modifiedInputObjectArr = for ($index = 0; $index -le $lastIndex; $index++)
        {
            $curInputObject = $inputObjectArr[$index]

            # If current object is the first token in the LDAP SearchFilter then evaluate SearchFilter_Prefix whitespace insertion.
            if (($index -eq 0) -and ('SearchFilter_Prefix' -iin $Type))
            {
                & $newWhitespaceLdapToken
            }

            # If current object is a structured DN Value LdapToken (RDN sub-tokens present) then evaluate RDN whitespace insertion after eligible RDN sub-tokens.
            if (
                ($curInputObject.Type -eq [Maldaptive.LdapTokenType]::Value) -and
                $curInputObject.TokenList -and
                ($Type -imatch '^RDN_')
            )
            {
                # Rebuild DN Value content, evaluating whitespace insertion after each eligible RDN sub-token type defined in user input -Type parameter (e.g. 'RDN_Attribute').
                # Track sub-token index so whitespace is never appended after the final RDN sub-token, since trailing whitespace would fall outside the DN Value
                # (reparsing as a standalone Whitespace LdapToken before the GroupEnd) and could alter the Distinguished Name value.
                $rdnLastIndex = $curInputObject.TokenList.Count - 1
                $rdnContentModified = -join @(for ($rdnIndex = 0; $rdnIndex -le $rdnLastIndex; $rdnIndex++)
                {
                    $curRdnLdapToken = $curInputObject.TokenList[$rdnIndex]

                    # Return current RDN sub-token content.
                    $curRdnLdapToken.Content

                    # Evaluate whitespace insertion after current RDN sub-token if it is not the final sub-token and its type is defined (as 'RDN_<Type>') in user input -Type parameter.
                    if (
                        ($rdnIndex -lt $rdnLastIndex) -and
                        ($curRdnLdapToken.Type -ne [Maldaptive.LdapTokenType]::Whitespace) -and
                        ($Type -icontains ('RDN_' + $curRdnLdapToken.Type)) -and
                        ((Get-Random -Minimum 1 -Maximum 100) -le $RandomNodePercent)
                    )
                    {
                        ' ' * (Get-Random -InputObject $RandomLength)
                    }
                })

                # Update current DN Value LdapToken if RDN whitespace insertion occurred above.
                if ($curInputObject.Content -cne $rdnContentModified)
                {
                    $curInputObject.Content = $rdnContentModified
                    $curInputObject.Length = $curInputObject.Content.Length

                    # If user input -TrackModification switch parameter is defined then set Depth property of current Value LdapToken to -1 for display tracking purposes.
                    if ($PSBoundParameters['TrackModification'].IsPresent)
                    {
                        $curInputObject.Depth = -1
                    }
                }
            }

            # Return current object.
            $curInputObject

            # Determine whitespace insertion position type (if any) eligible for insertion directly after current LdapToken based on its type.
            # Whitespace is only inserted after token types whose trailing position is tolerated by the LDAP parser/server model (mirrors Remove-RandomWhitespace's -Type ValidateSet).
            $positionType = switch ($curInputObject.Type)
            {
                ([Maldaptive.LdapTokenType]::GroupStart)         { 'GroupStart' }
                ([Maldaptive.LdapTokenType]::BooleanOperator)    { 'BooleanOperator' }
                ([Maldaptive.LdapTokenType]::ComparisonOperator) { 'ComparisonOperator' }
                ([Maldaptive.LdapTokenType]::GroupEnd)           { 'GroupEnd' }
                ([Maldaptive.LdapTokenType]::Attribute)          {
                    # Whitespace directly after an Attribute is only tolerated when the Attribute uses OID syntax.
                    ($curInputObject.Format -eq [Maldaptive.LdapTokenFormat]::OID) ? 'OID_Attribute' : $null
                }
                default { $null }
            }

            # Evaluate whitespace insertion directly after current LdapToken if its position type is eligible and defined in user input -Type parameter.
            if ($positionType -and ($Type -icontains $positionType))
            {
                & $newWhitespaceLdapToken
            }

            # If current object is the last token in the LDAP SearchFilter then evaluate SearchFilter_Suffix whitespace insertion.
            if (($index -eq $lastIndex) -and ('SearchFilter_Suffix' -iin $Type))
            {
                & $newWhitespaceLdapToken
            }
        }

        # Ensure result is formatted according to user input -Target and optional -TrackModification values.
        $finalResult = Format-LdapObject -InputObject $modifiedInputObjectArr -Target $Target @optionalSwitchParameters

        # Return final result.
        $finalResult
    }
}


function Add-RandomParenthesis
{
<#
.SYNOPSIS

MaLDAPtive is a framework for LDAP SearchFilter parsing, obfuscation, deobfuscation and detection.

MaLDAPtive Function: Add-RandomParenthesis
Author: Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Join-LdapObject, ConvertTo-LdapObject, Format-LdapObject, New-LdapToken
Optional Dependencies: None

.DESCRIPTION

Add-RandomParenthesis adds redundant encapsulating parentheses to eligible Filter and/or FilterList branches in input LDAP SearchFilter. This is the inverse of Remove-RandomParenthesis.

.PARAMETER InputObject

Specifies LDAP SearchFilter (in any input format) into which redundant encapsulating parentheses will be inserted.

.PARAMETER RandomNodePercent

(Optional) Specifies percentage of eligible nodes (branch, filter, token, etc.) to obfuscate.

.PARAMETER Scope

(Optional) Specifies eligible scopes (Filter and/or FilterList) for adding encapsulating parentheses to diversify obfuscation styles.

.PARAMETER Target

(Optional) Specifies target LDAP format into which the final result will be converted.

.PARAMETER TrackModification

(Optional) Specifies custom 'Modified' property be added to all modified LDAP tokens (e.g. for highlighting where obfuscation occurred).

.EXAMPLE

PS C:\> '(name=sabi)' | Add-RandomParenthesis -RandomNodePercent 100

((name=sabi))

.EXAMPLE

PS C:\> '(|(name=sabi)(name=dbo))' | Add-RandomParenthesis -RandomNodePercent 100 -Scope Filter

(|((name=sabi))((name=dbo)))

.NOTES

This is a personal project developed by Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://github.com/MaLDAPtive/Invoke-Maldaptive
https://twitter.com/sabi_elezi/
https://twitter.com/danielhbohannon/
#>

    [OutputType(
        [System.String],
        [Maldaptive.LdapToken[]],
        [Maldaptive.LdapTokenEnriched[]],
        [Maldaptive.LdapFilter[]],
        [Maldaptive.LdapBranch]
    )]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        # Purposefully not defining parameter type since mixture of LDAP formats allowed.
        $InputObject,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateRange(0,100)]
        [System.Int16]
        $RandomNodePercent = 50,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Maldaptive.LdapBranchType[]]
        $Scope = @([Maldaptive.LdapBranchType]::Filter,[Maldaptive.LdapBranchType]::FilterList),

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Maldaptive.LdapFormat]
        $Target = [Maldaptive.LdapFormat]::String,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Switch]
        $TrackModification
    )

    begin
    {
        # Define current function's input object target format requirement (ensured by ConvertTo-LdapObject later in current function).
        $requiredInputObjectTarget = [Maldaptive.LdapFormat]::LdapBranch

        # Set boolean to capture if current function invocation is recursive (i.e. current function is called by itself).
        $isRecursive = ($MyInvocation.MyCommand.Name -eq (Get-Variable -Name MyInvocation -Scope 1 -ValueOnly).MyCommand.Name) ? $true : $false

        # Extract optional switch input parameter(s) from $PSBoundParameters into separate hashtable for consistent inclusion/exclusion in relevant functions via splatting.
        $optionalSwitchParameters = @{ }
        $PSBoundParameters.GetEnumerator().Where( { $_.Key -iin @('TrackModification') } ).ForEach( { $optionalSwitchParameters.Add($_.Key, $_.Value) } )

        # Create defined input parameter hashtable, not differentiating between bound parameters and default parameter values.
        # Default input parameters for all PowerShell functions (i.e. not defined in function's param block) are excluded via default Position property value of -2147483648.
        # This hashtable will be used for splatting later in function for any potential trampoline helper function invocations.
        $allDefinedParameters = @{ }
        (Get-Command -CommandType Function -Name $MyInvocation.MyCommand.Name).ParameterSets.Parameters.Where(
        {
            (($_.Position -ne -2147483648) -or ($_.ParameterType.Name -eq 'SwitchParameter')) -and (Test-Path -Path "variable:local:$($_.Name)")
        } ).ForEach( { $allDefinedParameters.Add($_.Name, (Get-Variable -Name $_.Name -Scope local -ValueOnly)) } )

        # Create ArrayList to store all pipelined input before beginning final processing.
        $inputObjectArr = [System.Collections.ArrayList]::new()
    }

    process
    {
        # Add all pipelined input to $inputObjectArr before beginning final processing.
        # Join-LdapObject function performs type casting and optimizes ArrayList append operations.
        $inputObjectArr = Join-LdapObject -InputObject $InputObject -InputObjectArr $inputObjectArr
    }

    end
    {
        # If non-recursive function invocation then ensure input data is formatted according to current function's requirement as defined in $requiredInputObjectTarget at beginning of current function.
        # This conversion also ensures completely separate copy of input object(s) so modifications in current function do not affect original input object outside current function.
        if (-not $isRecursive)
        {
            $inputObjectArr = ConvertTo-LdapObject -InputObject $inputObjectArr -Target $requiredInputObjectTarget
        }

        # Define core obfuscation logic in local trampoline helper function to avoid recursion-specific Call Depth Overflow exception.
        # Helper function has access to all variables in current function's scope, but primary -LdapBranch input is explicitly defined for readability.
        function local:Add-RandomParenthesisHelper
        {
            [OutputType([System.Object[]])]
            param (
                [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
                [Maldaptive.LdapBranch]
                $LdapBranch
            )

            # Set boolean for generic obfuscation eligibility.
            $isEligible = $true

            # Override above obfuscation eligibility for specific scenarios.
            if ($Scope -inotcontains $LdapBranch.Type.ToString())
            {
                # Override obfuscation eligibility if current LdapBranch's type (Filter or FilterList) is not defined in user input -Scope parameter.
                $isEligible = $false
            }

            # Set boolean for obfuscation eligibility based on user input -RandomNodePercent value.
            $isRandomNodePercent = (Get-Random -Minimum 1 -Maximum 100) -le $RandomNodePercent

            # Proceed if eligible for obfuscation.
            if ($isEligible -and $isRandomNodePercent)
            {
                # Generate a new redundant encapsulating GroupStart ('(') and GroupEnd (')') pair surrounding current LdapBranch.
                # The new wrapping FilterList contains no BooleanOperator and is therefore logically inert and exactly the artifact targeted by Remove-RandomParenthesis.
                # If optional -TrackModification switch parameter is defined then each new LdapToken's Depth property value will be set to -1 for modification tracking display purposes.
                New-LdapToken -Type GroupStart -Content '(' -Target LdapTokenEnriched @optionalSwitchParameters
                $LdapBranch
                New-LdapToken -Type GroupEnd -Content ')' -Target LdapTokenEnriched @optionalSwitchParameters
            }
            else
            {
                # Return input LdapBranch unmodified.
                $LdapBranch
            }
        }

        # Iterate over each input object, storing result in array for proper re-parsing before returning final result in non-recursive function invocation.
        $modifiedInputObjectArr = foreach ($curInputObject in $inputObjectArr)
        {
            # Step into current object for further processing if it is an LdapBranch of type FilterList, recursively traversing its nested contents in descending order.
            if (($curInputObject -is [Maldaptive.LdapBranch]) -and ($curInputObject.Type -eq [Maldaptive.LdapBranchType]::FilterList))
            {
                # Update current FilterList LdapBranch with the recursive invocation of its contents to properly traverse nested branches in descending order.
                # Modify -InputObject parameter in defined input parameter hashtable to reflect current nested branch contents.
                $allDefinedParameters['InputObject'] = $curInputObject.Branch
                $curInputObject.Branch = & $MyInvocation.MyCommand.Name @allDefinedParameters
            }

            # Invoke local trampoline helper function for current LdapBranch (Filter or FilterList) to perform actual obfuscation logic while avoiding recursion-specific Call Depth Overflow exception.
            # Helper may return the current LdapBranch wrapped between a new GroupStart and GroupEnd LdapToken pair (i.e. three objects).
            if ($curInputObject -is [Maldaptive.LdapBranch])
            {
                $curInputObject = & ($MyInvocation.MyCommand.Name + 'Helper') -LdapBranch $curInputObject
            }

            # Return current object.
            $curInputObject
        }

        # Format result for current function invocation. If recursive function invocation then return current modified input object array as-is.
        # Otherwise ensure array is formatted according to user input -Target and optional -TrackModification values.
        $finalResult = $isRecursive ? $modifiedInputObjectArr : (Format-LdapObject -InputObject $modifiedInputObjectArr -Target $Target @optionalSwitchParameters)

        # Return final result.
        $finalResult
    }
}


function Add-RandomBooleanOperator
{
<#
.SYNOPSIS

MaLDAPtive is a framework for LDAP SearchFilter parsing, obfuscation, deobfuscation and detection.

MaLDAPtive Function: Add-RandomBooleanOperator
Author: Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Join-LdapObject, ConvertTo-LdapObject, Format-LdapObject, New-LdapToken, Add-LdapToken
Optional Dependencies: None

.DESCRIPTION

Add-RandomBooleanOperator inserts redundant logic-preserving BooleanOperators ('&' or '|') into eligible Filter and/or FilterList branches that do not already contain a directly-defined BooleanOperator in input LDAP SearchFilter. This is the inverse of Remove-RandomBooleanOperator.

For a Filter branch this produces a Filter-scope BooleanOperator (e.g. '(name=sabi)' -> '(&name=sabi)') which is logically inert. For a FilterList branch wrapping a single nested branch this produces a redundant FilterList-scope BooleanOperator (e.g. '((name=sabi))' -> '(&(name=sabi))') which is likewise logically inert. To guarantee logical equivalence this function intentionally does not insert into multi-child FilterList branches that lack a BooleanOperator, nor does it insert negation ('!') BooleanOperators (see Add-RandomBooleanOperatorInversion for logic-preserving negation).

.PARAMETER InputObject

Specifies LDAP SearchFilter (in any input format) into which redundant BooleanOperators will be inserted.

.PARAMETER RandomNodePercent

(Optional) Specifies percentage of eligible nodes (branch, filter, token, etc.) to obfuscate.

.PARAMETER Type

(Optional) Specifies eligible BooleanOperator(s) to insert to diversify obfuscation styles.

.PARAMETER Scope

(Optional) Specifies eligible scopes (Filter and/or FilterList) for inserting BooleanOperator(s) to diversify obfuscation styles.

.PARAMETER Target

(Optional) Specifies target LDAP format into which the final result will be converted.

.PARAMETER TrackModification

(Optional) Specifies custom 'Modified' property be added to all modified LDAP tokens (e.g. for highlighting where obfuscation occurred).

.EXAMPLE

PS C:\> '(|(name=sabi)(name=dbo))' | Add-RandomBooleanOperator -RandomNodePercent 100 -Scope Filter

(|(&name=sabi)(&name=dbo))

.EXAMPLE

PS C:\> '(name=sabi)' | Add-RandomBooleanOperator -RandomNodePercent 100 -Type '&' | Remove-RandomBooleanOperator -RandomNodePercent 100

(name=sabi)

.NOTES

This is a personal project developed by Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://github.com/MaLDAPtive/Invoke-Maldaptive
https://twitter.com/sabi_elezi/
https://twitter.com/danielhbohannon/
#>

    [OutputType(
        [System.String],
        [Maldaptive.LdapToken[]],
        [Maldaptive.LdapTokenEnriched[]],
        [Maldaptive.LdapFilter[]],
        [Maldaptive.LdapBranch]
    )]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        # Purposefully not defining parameter type since mixture of LDAP formats allowed.
        $InputObject,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateRange(0,100)]
        [System.Int16]
        $RandomNodePercent = 50,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateSet('&','|')]
        [System.Char[]]
        $Type = @('&','|'),

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Maldaptive.LdapBranchType[]]
        $Scope = @([Maldaptive.LdapBranchType]::Filter,[Maldaptive.LdapBranchType]::FilterList),

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Maldaptive.LdapFormat]
        $Target = [Maldaptive.LdapFormat]::String,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Switch]
        $TrackModification
    )

    begin
    {
        # Define current function's input object target format requirement (ensured by ConvertTo-LdapObject later in current function).
        $requiredInputObjectTarget = [Maldaptive.LdapFormat]::LdapBranch

        # Set boolean to capture if current function invocation is recursive (i.e. current function is called by itself).
        $isRecursive = ($MyInvocation.MyCommand.Name -eq (Get-Variable -Name MyInvocation -Scope 1 -ValueOnly).MyCommand.Name) ? $true : $false

        # Extract optional switch input parameter(s) from $PSBoundParameters into separate hashtable for consistent inclusion/exclusion in relevant functions via splatting.
        $optionalSwitchParameters = @{ }
        $PSBoundParameters.GetEnumerator().Where( { $_.Key -iin @('TrackModification') } ).ForEach( { $optionalSwitchParameters.Add($_.Key, $_.Value) } )

        # Create defined input parameter hashtable, not differentiating between bound parameters and default parameter values.
        # Default input parameters for all PowerShell functions (i.e. not defined in function's param block) are excluded via default Position property value of -2147483648.
        # This hashtable will be used for splatting later in function for any potential trampoline helper function invocations.
        $allDefinedParameters = @{ }
        (Get-Command -CommandType Function -Name $MyInvocation.MyCommand.Name).ParameterSets.Parameters.Where(
        {
            (($_.Position -ne -2147483648) -or ($_.ParameterType.Name -eq 'SwitchParameter')) -and (Test-Path -Path "variable:local:$($_.Name)")
        } ).ForEach( { $allDefinedParameters.Add($_.Name, (Get-Variable -Name $_.Name -Scope local -ValueOnly)) } )

        # Create ArrayList to store all pipelined input before beginning final processing.
        $inputObjectArr = [System.Collections.ArrayList]::new()
    }

    process
    {
        # Add all pipelined input to $inputObjectArr before beginning final processing.
        # Join-LdapObject function performs type casting and optimizes ArrayList append operations.
        $inputObjectArr = Join-LdapObject -InputObject $InputObject -InputObjectArr $inputObjectArr
    }

    end
    {
        # If non-recursive function invocation then ensure input data is formatted according to current function's requirement as defined in $requiredInputObjectTarget at beginning of current function.
        # This conversion also ensures completely separate copy of input object(s) so modifications in current function do not affect original input object outside current function.
        if (-not $isRecursive)
        {
            $inputObjectArr = ConvertTo-LdapObject -InputObject $inputObjectArr -Target $requiredInputObjectTarget
        }

        # Define core obfuscation logic in local trampoline helper function to avoid recursion-specific Call Depth Overflow exception.
        # Helper function has access to all variables in current function's scope, but primary -LdapBranch input is explicitly defined for readability.
        function local:Add-RandomBooleanOperatorHelper
        {
            [OutputType([Maldaptive.LdapBranch])]
            param (
                [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
                [Maldaptive.LdapBranch]
                $LdapBranch
            )

            # Extract directly-defined BooleanOperator LdapToken (if any) from current LdapBranch based on its type.
            $directBooleanOperatorLdapToken = switch ($LdapBranch.Type)
            {
                ([Maldaptive.LdapBranchType]::Filter) {
                    $LdapBranch.Branch[0].TokenList.Where( { ($_ -is [Maldaptive.LdapToken]) -and ($_.Type -eq [Maldaptive.LdapTokenType]::BooleanOperator) } )[0]
                }
                ([Maldaptive.LdapBranchType]::FilterList) {
                    $LdapBranch.Branch.Where( { ($_ -is [Maldaptive.LdapToken]) -and ($_.Type -eq [Maldaptive.LdapTokenType]::BooleanOperator) } )[0]
                }
            }

            # Extract any nested LdapBranch object(s) directly contained in current LdapBranch.
            $nestedLdapBranchArr = $LdapBranch.Branch.Where( { $_ -is [Maldaptive.LdapBranch] } )

            # Set boolean for generic obfuscation eligibility.
            $isEligible = $true

            # Override above obfuscation eligibility for specific scenarios.
            if ($Scope -inotcontains $LdapBranch.Type.ToString())
            {
                # Override obfuscation eligibility if current LdapBranch's type (Filter or FilterList) is not defined in user input -Scope parameter.
                $isEligible = $false
            }
            elseif ($directBooleanOperatorLdapToken)
            {
                # Override obfuscation eligibility if current LdapBranch already contains a directly-defined BooleanOperator LdapToken, since inserting a second
                # adjacent BooleanOperator (a double-BooleanOperator scenario) is not guaranteed to be logic-preserving and is intentionally excluded here.
                $isEligible = $false
            }
            elseif (($LdapBranch.Type -eq [Maldaptive.LdapBranchType]::FilterList) -and -not ($LdapBranch.Branch.Where( { ($_ -is [Maldaptive.LdapToken]) -and ($_.Type -eq [Maldaptive.LdapTokenType]::GroupStart) } )))
            {
                # Override obfuscation eligibility if current FilterList LdapBranch does not directly contain a GroupStart LdapToken, which identifies the synthetic
                # base container that ConvertTo-LdapObject wraps around the entire SearchFilter. This container is traversed for recursion but never receives a BooleanOperator.
                $isEligible = $false
            }
            elseif (($LdapBranch.Type -eq [Maldaptive.LdapBranchType]::FilterList) -and ($nestedLdapBranchArr.Count -ne 1))
            {
                # Override obfuscation eligibility if current LdapBranch is a FilterList that does not wrap exactly one nested branch, since inserting a
                # BooleanOperator into a multi-child FilterList that lacks one could change the SearchFilter's logical evaluation.
                $isEligible = $false
            }

            # Set boolean for obfuscation eligibility based on user input -RandomNodePercent value.
            $isRandomNodePercent = (Get-Random -Minimum 1 -Maximum 100) -le $RandomNodePercent

            # Proceed if eligible for obfuscation.
            if ($isEligible -and $isRandomNodePercent)
            {
                # Randomly select an eligible single-character BooleanOperator value ('&' or '|') to insert.
                $randomBooleanOperator = Get-Random -InputObject $Type

                # Generate new BooleanOperator LdapToken.
                # If optional -TrackModification switch parameter is defined then new BooleanOperator's Depth property value will be set to -1 for modification tracking display purposes.
                $newBooleanOperatorLdapToken = New-LdapToken -Type BooleanOperator -Content $randomBooleanOperator -Target LdapTokenEnriched @optionalSwitchParameters

                # Define insertion location based on current LdapBranch type, placing the new BooleanOperator directly after the opening GroupStart token.
                $insertionLocation = ($LdapBranch.Type -eq [Maldaptive.LdapBranchType]::Filter) ? @('after_groupstart','before_attribute') : @('after_groupstart','before_branch')

                # Add new BooleanOperator LdapToken to current LdapBranch.
                Add-LdapToken -LdapBranch $LdapBranch -LdapToken $newBooleanOperatorLdapToken -Location $insertionLocation @optionalSwitchParameters
            }

            # Return input LdapBranch since end of trampoline helper function.
            $LdapBranch
        }

        # Iterate over each input object, storing result in array for proper re-parsing before returning final result in non-recursive function invocation.
        $modifiedInputObjectArr = foreach ($curInputObject in $inputObjectArr)
        {
            # Step into current object for further processing if it is an LdapBranch of type FilterList, recursively traversing its nested contents in descending order.
            if (($curInputObject -is [Maldaptive.LdapBranch]) -and ($curInputObject.Type -eq [Maldaptive.LdapBranchType]::FilterList))
            {
                # Update current FilterList LdapBranch with the recursive invocation of its contents to properly traverse nested branches in descending order.
                # Modify -InputObject parameter in defined input parameter hashtable to reflect current nested branch contents.
                $allDefinedParameters['InputObject'] = $curInputObject.Branch
                $curInputObject.Branch = & $MyInvocation.MyCommand.Name @allDefinedParameters
            }

            # Invoke local trampoline helper function for current LdapBranch (Filter or FilterList) to perform actual obfuscation logic while avoiding recursion-specific Call Depth Overflow exception.
            if ($curInputObject -is [Maldaptive.LdapBranch])
            {
                $curInputObject = & ($MyInvocation.MyCommand.Name + 'Helper') -LdapBranch $curInputObject
            }

            # Return current object.
            $curInputObject
        }

        # Format result for current function invocation. If recursive function invocation then return current modified input object array as-is.
        # Otherwise ensure array is formatted according to user input -Target and optional -TrackModification values.
        $finalResult = $isRecursive ? $modifiedInputObjectArr : (Format-LdapObject -InputObject $modifiedInputObjectArr -Target $Target @optionalSwitchParameters)

        # Return final result.
        $finalResult
    }
}


function Add-RandomBooleanOperatorInversion
{
<#
.SYNOPSIS

MaLDAPtive is a framework for LDAP SearchFilter parsing, obfuscation, deobfuscation and detection.

MaLDAPtive Function: Add-RandomBooleanOperatorInversion
Author: Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Join-LdapObject, ConvertTo-LdapObject, Format-LdapObject, Invoke-LdapBranchVisitor, New-LdapToken, Add-LdapToken, Remove-LdapToken, Edit-LdapToken
Optional Dependencies: None

.DESCRIPTION

Add-RandomBooleanOperatorInversion wraps eligible Filter and/or FilterList branches in a negation BooleanOperator ('!') while applying De Morgan inversion to the wrapped subtree so the overall BooleanOperator logic is preserved in input LDAP SearchFilter. This is the inverse of Remove-RandomBooleanOperatorInversion.

For example a branch B is rewritten as '(!X)' where X is the full De Morgan negation of B (every '&' becomes '|' and vice versa, and each leaf Filter's negation is toggled), making '(!X)' logically equivalent to B (e.g. '(|(name=sabi)(name=dbo))' -> '(!(&(!name=sabi)(!name=dbo)))').

.PARAMETER InputObject

Specifies LDAP SearchFilter (in any input format) into which logic-preserving negation BooleanOperators ('!') will be inserted.

.PARAMETER RandomNodePercent

(Optional) Specifies percentage of eligible nodes (branch, filter, token, etc.) to obfuscate.

.PARAMETER Type

(Optional) Specifies eligible BooleanOperator(s) of target branches to invert to diversify obfuscation styles.

.PARAMETER Scope

(Optional) Specifies eligible scopes (Filter and/or FilterList) to target for BooleanOperator inversion to diversify obfuscation styles.

.PARAMETER Target

(Optional) Specifies target LDAP format into which the final result will be converted.

.PARAMETER TrackModification

(Optional) Specifies custom 'Modified' property be added to all modified LDAP tokens (e.g. for highlighting where obfuscation occurred).

.EXAMPLE

PS C:\> '(|(name=sabi)(name=dbo))' | Add-RandomBooleanOperatorInversion -RandomNodePercent 100 -Scope FilterList

(!(&(!name=sabi)(!name=dbo)))

.EXAMPLE

PS C:\> '(&(objectCategory=Person)(name=dbo))' | Add-RandomBooleanOperatorInversion -RandomNodePercent 100 -Scope FilterList | Remove-RandomBooleanOperatorInversion -RandomNodePercent 100

((&(objectCategory=Person)(name=dbo)))

.NOTES

This is a personal project developed by Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://github.com/MaLDAPtive/Invoke-Maldaptive
https://twitter.com/sabi_elezi/
https://twitter.com/danielhbohannon/
#>

    [OutputType(
        [System.String],
        [Maldaptive.LdapToken[]],
        [Maldaptive.LdapTokenEnriched[]],
        [Maldaptive.LdapFilter[]],
        [Maldaptive.LdapBranch]
    )]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        # Purposefully not defining parameter type since mixture of LDAP formats allowed.
        $InputObject,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateRange(0,100)]
        [System.Int16]
        $RandomNodePercent = 50,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateSet('&','|','!')]
        [System.Char[]]
        $Type = @('&','|','!'),

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Maldaptive.LdapBranchType[]]
        $Scope = @([Maldaptive.LdapBranchType]::Filter,[Maldaptive.LdapBranchType]::FilterList),

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Maldaptive.LdapFormat]
        $Target = [Maldaptive.LdapFormat]::String,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Switch]
        $TrackModification
    )

    begin
    {
        # Define current function's input object target format requirement (ensured by ConvertTo-LdapObject later in current function).
        $requiredInputObjectTarget = [Maldaptive.LdapFormat]::LdapBranch

        # Extract optional switch input parameter(s) from $PSBoundParameters into separate hashtable for consistent inclusion/exclusion in relevant functions via splatting.
        $optionalSwitchParameters = @{ }
        $PSBoundParameters.GetEnumerator().Where( { $_.Key -iin @('TrackModification') } ).ForEach( { $optionalSwitchParameters.Add($_.Key, $_.Value) } )

        # Create ArrayList to store all pipelined input before beginning final processing.
        $inputObjectArr = [System.Collections.ArrayList]::new()
    }

    process
    {
        # Add all pipelined input to $inputObjectArr before beginning final processing.
        # Join-LdapObject function performs type casting and optimizes ArrayList append operations.
        $inputObjectArr = Join-LdapObject -InputObject $InputObject -InputObjectArr $inputObjectArr
    }

    end
    {
        # Ensure input data is formatted according to current function's requirement as defined in $requiredInputObjectTarget at beginning of current function.
        # This conversion also ensures completely separate copy of input object(s) so modifications in current function do not affect original input object outside current function.
        $inputObjectArr = ConvertTo-LdapObject -InputObject $inputObjectArr -Target $requiredInputObjectTarget

        # Define ScriptBlock logic for Invoke-LdapBranchVisitor function to recursively invert all eligible nested LdapBranch BooleanOperators (De Morgan inversion).
        # All Filter and FilterList LdapBranch non-negation BooleanOperators ('&' or '|') will be inverted, and Filter LdapBranch negation BooleanOperators ('!') will be removed
        # and any Filter LdapBranch without a BooleanOperator defined or with a non-negation BooleanOperator ('&' or '|') defined will have a negation BooleanOperator ('!') added.
        # This is the same inversion logic applied (in reverse) by Remove-RandomBooleanOperatorInversion.
        $scriptBlockBooleanOperatorInversion = {
            [OutputType([System.Void])]
            param (
                [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
                [Maldaptive.LdapBranch]
                $LdapBranch,

                [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
                [Switch]
                $TrackModification
            )

            # Extract optional switch input parameter(s) from $PSBoundParameters into separate hashtable for consistent inclusion/exclusion in relevant functions via splatting.
            $optionalSwitchParameters = @{ }
            $PSBoundParameters.GetEnumerator().Where( { $_.Key -iin @('TrackModification') } ).ForEach( { $optionalSwitchParameters.Add($_.Key, $_.Value) } )

            # Proceed if user input -LdapBranch is either a FilterList LdapBranch with a non-negation BooleanOperator directly defined or a Filter LdapBranch.
            if (
                (($LdapBranch.Type -eq [Maldaptive.LdapBranchType]::FilterList) -and ($LdapBranch.BooleanOperator -cin @('&','|'))) -or
                ($LdapBranch.Type -eq [Maldaptive.LdapBranchType]::Filter)
            )
            {
                # Define inverted BooleanOperator value based on current BooleanOperator value, inverting the absence of a BooleanOperator with '!' and vice versa.
                $invertedBooleanOperator = switch ($LdapBranch.BooleanOperator)
                {
                    '&' { '|' }
                    '|' { '&' }
                    '!' { ''  }
                    ''  { '!' }
                    default {
                        Write-Warning "Unhandled switch block option in function $($MyInvocation.MyCommand.Name): $_"
                    }
                }

                # Perform inversion logic based on input LdapBranch type.
                switch ($LdapBranch.Type)
                {
                    ([Maldaptive.LdapBranchType]::FilterList) {
                        # Extract existing BooleanOperator LdapToken from input LdapBranch.
                        $curBooleanOperatorLdapToken = $LdapBranch.Branch.Where( { ($_ -is [Maldaptive.LdapToken]) -and ($_.Type -eq [Maldaptive.LdapTokenType]::BooleanOperator) } )[0]

                        # Modify existing BooleanOperator LdapToken in input LdapBranch.
                        Edit-LdapToken -LdapBranch $LdapBranch -LdapToken $curBooleanOperatorLdapToken -Content $invertedBooleanOperator @optionalSwitchParameters
                    }
                    ([Maldaptive.LdapBranchType]::Filter) {
                        # If Filter LdapBranch does not contain a BooleanOperator LdapToken then create and add it.
                        if (-not $LdapBranch.BooleanOperator)
                        {
                            # Generate new BooleanOperator LdapToken.
                            $newBooleanOperatorLdapToken = New-LdapToken -Type BooleanOperator -Content $invertedBooleanOperator @optionalSwitchParameters

                            # Add new BooleanOperator LdapToken to input LdapBranch.
                            Add-LdapToken -LdapBranch $LdapBranch -LdapToken $newBooleanOperatorLdapToken -Location after_groupstart,before_attribute
                        }
                        elseif (-not $invertedBooleanOperator)
                        {
                            # If Filter LdapBranch contains a BooleanOperator and inverted BooleanOperator value is not defined then remove BooleanOperator.
                            $curBooleanOperatorLdapToken = $LdapBranch.Branch[0].TokenList.Where( { ($_ -is [Maldaptive.LdapToken]) -and ($_.Type -eq [Maldaptive.LdapTokenType]::BooleanOperator) } )[0]

                            # Remove existing BooleanOperator LdapToken from input LdapBranch.
                            Remove-LdapToken -LdapBranch $LdapBranch -LdapToken $curBooleanOperatorLdapToken
                        }
                        else
                        {
                            # If Filter LdapBranch contains a non-negation BooleanOperator ('&' or '|') then invert the value by replacing it with a negation BooleanOperator ('!').
                            $invertedBooleanOperator = '!'

                            # Extract existing BooleanOperator LdapToken from input LdapBranch.
                            $curBooleanOperatorLdapToken = $LdapBranch.Branch[0].TokenList.Where( { ($_ -is [Maldaptive.LdapToken]) -and ($_.Type -eq [Maldaptive.LdapTokenType]::BooleanOperator) } )[0]

                            # Modify existing BooleanOperator LdapToken in input LdapBranch.
                            Edit-LdapToken -LdapBranch $LdapBranch -LdapToken $curBooleanOperatorLdapToken -Content $invertedBooleanOperator @optionalSwitchParameters
                        }
                    }
                }
            }
        }

        # Define local recursive helper function that performs a single top-down pass over the LdapBranch tree.
        # For each eligible branch it either (a) wraps the branch in a negation BooleanOperator ('!') and De Morgan-inverts the wrapped subtree (returning four objects: GroupStart, '!', inverted branch, GroupEnd),
        # or (b) descends into the branch's nested children. A branch is never both wrapped and independently descended, which guarantees logical equivalence.
        function local:Invoke-AddRandomBooleanOperatorInversion
        {
            [OutputType([System.Object[]])]
            param (
                [Parameter(Mandatory = $true, ValueFromPipeline = $false)]
                [Maldaptive.LdapBranch]
                $LdapBranch
            )

            # Determine whether current LdapBranch is a real (parenthesized) branch versus the synthetic base container that ConvertTo-LdapObject wraps around the entire SearchFilter.
            $isRealBranch = ($LdapBranch.Type -eq [Maldaptive.LdapBranchType]::Filter) -or
                (($LdapBranch.Type -eq [Maldaptive.LdapBranchType]::FilterList) -and ($LdapBranch.Branch.Where( { ($_ -is [Maldaptive.LdapToken]) -and ($_.Type -eq [Maldaptive.LdapTokenType]::GroupStart) } )))

            # Map current LdapBranch's directly-defined BooleanOperator to the value compared against user input -Type parameter, treating the absence of a BooleanOperator (a positive Filter) as a negation ('!') target since wrapping it introduces a negation.
            $branchOperatorForType = $LdapBranch.BooleanOperator ? $LdapBranch.BooleanOperator : '!'

            # Set boolean for generic obfuscation eligibility.
            $isEligible = $true

            # Override above obfuscation eligibility for specific scenarios.
            if (-not $isRealBranch)
            {
                # Override obfuscation eligibility for the synthetic base container (traversed for recursion only).
                $isEligible = $false
            }
            elseif ($Scope -inotcontains $LdapBranch.Type.ToString())
            {
                # Override obfuscation eligibility if current LdapBranch's type (Filter or FilterList) is not defined in user input -Scope parameter.
                $isEligible = $false
            }
            elseif ($Type -cnotcontains $branchOperatorForType)
            {
                # Override obfuscation eligibility if current LdapBranch's BooleanOperator target value is not defined in user input -Type parameter.
                $isEligible = $false
            }

            # Set boolean for obfuscation eligibility based on user input -RandomNodePercent value.
            $isRandomNodePercent = (Get-Random -Minimum 1 -Maximum 100) -le $RandomNodePercent

            # Proceed if eligible for obfuscation.
            if ($isEligible -and $isRandomNodePercent)
            {
                # Recursively De Morgan-invert all BooleanOperators in current LdapBranch's subtree.
                Invoke-LdapBranchVisitor -LdapBranch $LdapBranch -ScriptBlock $scriptBlockBooleanOperatorInversion -Action Modify @optionalSwitchParameters

                # Generate a new encapsulating negation: GroupStart ('('), negation BooleanOperator ('!') and GroupEnd (')') surrounding the inverted subtree.
                # If optional -TrackModification switch parameter is defined then each new LdapToken's Depth property value will be set to -1 for modification tracking display purposes.
                New-LdapToken -Type GroupStart -Content '(' -Target LdapTokenEnriched @optionalSwitchParameters
                New-LdapToken -Type BooleanOperator -Content '!' -Target LdapTokenEnriched @optionalSwitchParameters
                $LdapBranch
                New-LdapToken -Type GroupEnd -Content ')' -Target LdapTokenEnriched @optionalSwitchParameters
            }
            else
            {
                # Current LdapBranch not transformed; descend into its nested children (if it is a FilterList) and transform each in turn.
                if ($LdapBranch.Type -eq [Maldaptive.LdapBranchType]::FilterList)
                {
                    $LdapBranch.Branch = foreach ($curChild in $LdapBranch.Branch)
                    {
                        if ($curChild -is [Maldaptive.LdapBranch])
                        {
                            Invoke-AddRandomBooleanOperatorInversion -LdapBranch $curChild
                        }
                        else
                        {
                            $curChild
                        }
                    }
                }

                # Return current (untransformed) LdapBranch.
                $LdapBranch
            }
        }

        # Iterate over each input object, applying the recursive inversion-insertion pass to each top-level LdapBranch.
        $modifiedInputObjectArr = foreach ($curInputObject in $inputObjectArr)
        {
            if ($curInputObject -is [Maldaptive.LdapBranch])
            {
                Invoke-AddRandomBooleanOperatorInversion -LdapBranch $curInputObject
            }
            else
            {
                $curInputObject
            }
        }

        # Ensure result is formatted according to user input -Target and optional -TrackModification values.
        $finalResult = Format-LdapObject -InputObject $modifiedInputObjectArr -Target $Target @optionalSwitchParameters

        # Return final result.
        $finalResult
    }
}


function Get-RandomCaseContent
{
<#
.SYNOPSIS

Internal helper. Randomly flips the case of eligible unescaped alphabetic characters in input content. Not exported.
#>

    [OutputType([System.String])]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $false)]
        [System.String]
        $Content,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateRange(0,100)]
        [System.Int16]
        $RandomCharPercent = 50
    )

    # Parse content into discrete parsed characters so hex-encoded ('\61') and protected ('*') characters are never modified mid-sequence.
    $parsedArr = ConvertTo-LdapParsedValue -InputObject $Content

    # Rebuild content, flipping the case of eligible unescaped alphabetic characters based on user input -RandomCharPercent parameter.
    -join $parsedArr.ForEach(
    {
        $curParsedChar = $_

        if (
            ($curParsedChar.Format -eq [Maldaptive.LdapValueParsedFormat]::Default) -and
            ($curParsedChar.Class -eq [Maldaptive.CharClass]::Alpha) -and
            ((Get-Random -Minimum 1 -Maximum 100) -le $RandomCharPercent)
        )
        {
            # Flip case of current alphabetic character.
            ($curParsedChar.Case -eq [Maldaptive.CharCase]::Upper) ? $curParsedChar.Content.ToLower() : $curParsedChar.Content.ToUpper()
        }
        else
        {
            # Return current parsed character unmodified.
            $curParsedChar.Content
        }
    } )
}


function Get-RandomHexContent
{
<#
.SYNOPSIS

Internal helper. Randomly hex-encodes ('\xx') eligible unescaped characters in input content using per-UTF8-byte LDAP escaping. Not exported.
#>

    [OutputType([System.String])]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $false)]
        [System.String]
        $Content,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateRange(0,100)]
        [System.Int16]
        $RandomCharPercent = 50
    )

    # Parse content into discrete parsed characters so already hex-encoded ('\61') and protected ('*') characters are never re-encoded.
    $parsedArr = ConvertTo-LdapParsedValue -InputObject $Content

    # Rebuild content, hex-encoding eligible unescaped characters based on user input -RandomCharPercent parameter.
    -join $parsedArr.ForEach(
    {
        $curParsedChar = $_

        if (
            ($curParsedChar.Format -eq [Maldaptive.LdapValueParsedFormat]::Default) -and
            ((Get-Random -Minimum 1 -Maximum 100) -le $RandomCharPercent)
        )
        {
            # Hex-encode current character one UTF-8 byte at a time, randomizing the case of each hex digit to diversify obfuscation styles.
            -join ([System.Text.Encoding]::UTF8.GetBytes($curParsedChar.ContentDecoded)).ForEach(
            {
                $hexByte = $_.ToString('x2')
                '\' + (-join ([System.Char[]] $hexByte).ForEach( { ((Get-Random -Minimum 0 -Maximum 2) -eq 0) ? ([System.Char]::ToUpper($_)) : $_ } ))
            } )
        }
        else
        {
            # Return current parsed character unmodified.
            $curParsedChar.Content
        }
    } )
}


function Add-RandomCase
{
<#
.SYNOPSIS

MaLDAPtive is a framework for LDAP SearchFilter parsing, obfuscation, deobfuscation and detection.

MaLDAPtive Function: Add-RandomCase
Author: Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Join-LdapObject, ConvertTo-LdapObject, ConvertTo-LdapParsedValue, Format-LdapObject
Optional Dependencies: None

.DESCRIPTION

Add-RandomCase randomly flips the case of eligible Attribute and/or Value characters in input LDAP SearchFilter. Attribute name casing is always logic-preserving (LDAP attribute names are case-insensitive); Value casing is only modified for attributes whose matching rule is case-insensitive (or undefined attributes, where the filter does not match regardless).

.PARAMETER InputObject

Specifies LDAP SearchFilter (in any input format) in which character casing will be randomized.

.PARAMETER RandomNodePercent

(Optional) Specifies percentage of eligible nodes (branch, filter, token, etc.) to obfuscate.

.PARAMETER RandomCharPercent

(Optional) Specifies percentage of eligible characters to obfuscate.

.PARAMETER Type

(Optional) Specifies eligible LdapToken type(s) (Attribute and/or Value) whose casing can be randomized.

.PARAMETER Target

(Optional) Specifies target LDAP format into which the final result will be converted.

.PARAMETER TrackModification

(Optional) Specifies custom 'Modified' property be added to all modified LDAP tokens (e.g. for highlighting where obfuscation occurred).

.EXAMPLE

PS C:\> '(name=sabi)' | Add-RandomCase -RandomNodePercent 100 -RandomCharPercent 100

(NAME=SABI)

.NOTES

This is a personal project developed by Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://github.com/MaLDAPtive/Invoke-Maldaptive
https://twitter.com/sabi_elezi/
https://twitter.com/danielhbohannon/
#>

    [OutputType(
        [System.String],
        [Maldaptive.LdapToken[]],
        [Maldaptive.LdapTokenEnriched[]],
        [Maldaptive.LdapFilter[]],
        [Maldaptive.LdapBranch]
    )]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        # Purposefully not defining parameter type since mixture of LDAP formats allowed.
        $InputObject,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateRange(0,100)]
        [System.Int16]
        $RandomNodePercent = 50,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateRange(0,100)]
        [System.Int16]
        $RandomCharPercent = 50,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateSet('Attribute','Value')]
        [System.String[]]
        $Type = @('Attribute','Value'),

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Maldaptive.LdapFormat]
        $Target = [Maldaptive.LdapFormat]::String,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Switch]
        $TrackModification
    )

    begin
    {
        # Define current function's input object target format requirement (ensured by ConvertTo-LdapObject later in current function).
        $requiredInputObjectTarget = [Maldaptive.LdapFormat]::LdapTokenEnriched

        # Extract optional switch input parameter(s) from $PSBoundParameters into separate hashtable for consistent inclusion/exclusion in relevant functions via splatting.
        $optionalSwitchParameters = @{ }
        $PSBoundParameters.GetEnumerator().Where( { $_.Key -iin @('TrackModification') } ).ForEach( { $optionalSwitchParameters.Add($_.Key, $_.Value) } )

        # Create ArrayList to store all pipelined input before beginning final processing.
        $inputObjectArr = [System.Collections.ArrayList]::new()
    }

    process
    {
        # Add all pipelined input to $inputObjectArr before beginning final processing.
        $inputObjectArr = Join-LdapObject -InputObject $InputObject -InputObjectArr $inputObjectArr
    }

    end
    {
        # Ensure input data is formatted according to current function's requirement as defined in $requiredInputObjectTarget at beginning of current function.
        $inputObjectArr = ConvertTo-LdapObject -InputObject $inputObjectArr -Target $requiredInputObjectTarget

        # Track the matching-rule case-sensitivity of the most recently encountered Attribute LdapToken so eligibility of Value casing can be determined.
        $curAttributeContext = $null

        # Iterate over each input object, storing result in array for proper re-parsing before returning final result.
        $modifiedInputObjectArr = foreach ($curInputObject in $inputObjectArr)
        {
            # Update tracked Attribute context when an Attribute LdapToken is encountered.
            if ($curInputObject.Type -eq [Maldaptive.LdapTokenType]::Attribute)
            {
                $curAttributeContext = $curInputObject.Context.Attribute
            }

            # Set boolean for generic obfuscation eligibility.
            $isEligible = $true

            # Override above obfuscation eligibility for specific scenarios.
            if ($curInputObject.Type -eq [Maldaptive.LdapTokenType]::Attribute)
            {
                # Attribute LdapToken casing is always logic-preserving but only eligible if 'Attribute' is defined in user input -Type parameter.
                if ($Type -inotcontains 'Attribute')
                {
                    $isEligible = $false
                }
            }
            elseif ($curInputObject.Type -eq [Maldaptive.LdapTokenType]::Value)
            {
                # Value LdapToken casing is only logic-preserving for case-insensitive (or undefined) attributes and only eligible if 'Value' is defined in user input -Type parameter.
                $isValueCaseInsensitive = (-not $curAttributeContext) -or ($curAttributeContext.SyntaxDescription -imatch 'case-insensitive')
                if (($Type -inotcontains 'Value') -or (-not $isValueCaseInsensitive))
                {
                    $isEligible = $false
                }
            }
            else
            {
                # All other LdapToken types are ineligible for case randomization.
                $isEligible = $false
            }

            # Set boolean for obfuscation eligibility based on user input -RandomNodePercent value.
            $isRandomNodePercent = (Get-Random -Minimum 1 -Maximum 100) -le $RandomNodePercent

            # Proceed if eligible for obfuscation.
            if ($isEligible -and $isRandomNodePercent)
            {
                # Generate case-randomized content for current LdapToken.
                $modifiedContent = Get-RandomCaseContent -Content $curInputObject.Content -RandomCharPercent $RandomCharPercent

                # Update current LdapToken if case randomization occurred above.
                if ($curInputObject.Content -cne $modifiedContent)
                {
                    $curInputObject.Content = $modifiedContent
                    $curInputObject.Length = $curInputObject.Content.Length

                    # If user input -TrackModification switch parameter is defined then set Depth property of current LdapToken to -1 for display tracking purposes.
                    if ($PSBoundParameters['TrackModification'].IsPresent)
                    {
                        $curInputObject.Depth = -1
                    }
                }
            }

            # Return current object.
            $curInputObject
        }

        # Ensure result is formatted according to user input -Target and optional -TrackModification values.
        Format-LdapObject -InputObject $modifiedInputObjectArr -Target $Target @optionalSwitchParameters
    }
}


function Add-RandomHexValue
{
<#
.SYNOPSIS

MaLDAPtive is a framework for LDAP SearchFilter parsing, obfuscation, deobfuscation and detection.

MaLDAPtive Function: Add-RandomHexValue
Author: Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Join-LdapObject, ConvertTo-LdapObject, ConvertTo-LdapParsedValue, Format-LdapObject
Optional Dependencies: None

.DESCRIPTION

Add-RandomHexValue randomly hex-encodes ('\xx') eligible characters in Attribute Values (including RDN/DN sub-components) in input LDAP SearchFilter. Hex encoding is decoded by the LDAP server so the filter remains logically equivalent.

.PARAMETER InputObject

Specifies LDAP SearchFilter (in any input format) in which Value characters will be hex-encoded.

.PARAMETER RandomNodePercent

(Optional) Specifies percentage of eligible nodes (branch, filter, token, etc.) to obfuscate.

.PARAMETER RandomCharPercent

(Optional) Specifies percentage of eligible characters to obfuscate.

.PARAMETER Target

(Optional) Specifies target LDAP format into which the final result will be converted.

.PARAMETER TrackModification

(Optional) Specifies custom 'Modified' property be added to all modified LDAP tokens (e.g. for highlighting where obfuscation occurred).

.EXAMPLE

PS C:\> '(name=sabi)' | Add-RandomHexValue -RandomNodePercent 100 -RandomCharPercent 100

(name=\73\61\62\69)

.NOTES

This is a personal project developed by Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://github.com/MaLDAPtive/Invoke-Maldaptive
https://twitter.com/sabi_elezi/
https://twitter.com/danielhbohannon/
#>

    [OutputType(
        [System.String],
        [Maldaptive.LdapToken[]],
        [Maldaptive.LdapTokenEnriched[]],
        [Maldaptive.LdapFilter[]],
        [Maldaptive.LdapBranch]
    )]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        # Purposefully not defining parameter type since mixture of LDAP formats allowed.
        $InputObject,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateRange(0,100)]
        [System.Int16]
        $RandomNodePercent = 50,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateRange(0,100)]
        [System.Int16]
        $RandomCharPercent = 50,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Maldaptive.LdapFormat]
        $Target = [Maldaptive.LdapFormat]::String,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Switch]
        $TrackModification
    )

    begin
    {
        # Define current function's input object target format requirement (ensured by ConvertTo-LdapObject later in current function).
        $requiredInputObjectTarget = [Maldaptive.LdapFormat]::LdapTokenEnriched

        # Extract optional switch input parameter(s) from $PSBoundParameters into separate hashtable for consistent inclusion/exclusion in relevant functions via splatting.
        $optionalSwitchParameters = @{ }
        $PSBoundParameters.GetEnumerator().Where( { $_.Key -iin @('TrackModification') } ).ForEach( { $optionalSwitchParameters.Add($_.Key, $_.Value) } )

        # Create ArrayList to store all pipelined input before beginning final processing.
        $inputObjectArr = [System.Collections.ArrayList]::new()
    }

    process
    {
        # Add all pipelined input to $inputObjectArr before beginning final processing.
        $inputObjectArr = Join-LdapObject -InputObject $InputObject -InputObjectArr $inputObjectArr
    }

    end
    {
        # Ensure input data is formatted according to current function's requirement as defined in $requiredInputObjectTarget at beginning of current function.
        $inputObjectArr = ConvertTo-LdapObject -InputObject $inputObjectArr -Target $requiredInputObjectTarget

        # Iterate over each input object, storing result in array for proper re-parsing before returning final result.
        $modifiedInputObjectArr = foreach ($curInputObject in $inputObjectArr)
        {
            # Set boolean for generic obfuscation eligibility.
            $isEligible = $true

            # Override above obfuscation eligibility for specific scenarios.
            if ($curInputObject.Type -ne [Maldaptive.LdapTokenType]::Value)
            {
                # Override obfuscation eligibility if current object is not a Value LdapToken.
                $isEligible = $false
            }
            elseif (-not $curInputObject.Content)
            {
                # Override obfuscation eligibility if current Value LdapToken is empty.
                $isEligible = $false
            }

            # Set boolean for obfuscation eligibility based on user input -RandomNodePercent value.
            $isRandomNodePercent = (Get-Random -Minimum 1 -Maximum 100) -le $RandomNodePercent

            # Proceed if eligible for obfuscation.
            if ($isEligible -and $isRandomNodePercent)
            {
                # Generate hex-encoded content for current Value LdapToken.
                $modifiedContent = Get-RandomHexContent -Content $curInputObject.Content -RandomCharPercent $RandomCharPercent

                # Update current Value LdapToken if hex encoding occurred above.
                if ($curInputObject.Content -cne $modifiedContent)
                {
                    $curInputObject.Content = $modifiedContent
                    $curInputObject.Length = $curInputObject.Content.Length

                    # If user input -TrackModification switch parameter is defined then set Depth property of current Value LdapToken to -1 for display tracking purposes.
                    if ($PSBoundParameters['TrackModification'].IsPresent)
                    {
                        $curInputObject.Depth = -1
                    }
                }
            }

            # Return current object.
            $curInputObject
        }

        # Ensure result is formatted according to user input -Target and optional -TrackModification values.
        Format-LdapObject -InputObject $modifiedInputObjectArr -Target $Target @optionalSwitchParameters
    }
}


function Add-RandomOid
{
<#
.SYNOPSIS

MaLDAPtive is a framework for LDAP SearchFilter parsing, obfuscation, deobfuscation and detection.

MaLDAPtive Function: Add-RandomOid
Author: Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Join-LdapObject, ConvertTo-LdapObject, Format-LdapObject
Optional Dependencies: None

.DESCRIPTION

Add-RandomOid substitutes eligible defined named Attributes with their numeric OID syntax in input LDAP SearchFilter, optionally adding an 'OID.' prefix and/or prepended zeros to OID octets. An attribute's OID is an equivalent identifier so the filter remains logically equivalent.

.PARAMETER InputObject

Specifies LDAP SearchFilter (in any input format) in which named Attributes will be substituted with OID syntax.

.PARAMETER RandomNodePercent

(Optional) Specifies percentage of eligible nodes (branch, filter, token, etc.) to obfuscate.

.PARAMETER Type

(Optional) Specifies eligible OID style modifier(s) ('Prefix' for an 'OID.' prefix and/or 'Zeros' for prepended octet zeros) to diversify obfuscation styles.

.PARAMETER Target

(Optional) Specifies target LDAP format into which the final result will be converted.

.PARAMETER TrackModification

(Optional) Specifies custom 'Modified' property be added to all modified LDAP tokens (e.g. for highlighting where obfuscation occurred).

.EXAMPLE

PS C:\> '(name=sabi)' | Add-RandomOid -RandomNodePercent 100 -Type @()

(1.2.840.113556.1.4.1=sabi)

.NOTES

This is a personal project developed by Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://github.com/MaLDAPtive/Invoke-Maldaptive
https://twitter.com/sabi_elezi/
https://twitter.com/danielhbohannon/
#>

    [OutputType(
        [System.String],
        [Maldaptive.LdapToken[]],
        [Maldaptive.LdapTokenEnriched[]],
        [Maldaptive.LdapFilter[]],
        [Maldaptive.LdapBranch]
    )]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        # Purposefully not defining parameter type since mixture of LDAP formats allowed.
        $InputObject,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateRange(0,100)]
        [System.Int16]
        $RandomNodePercent = 50,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateSet('Prefix','Zeros')]
        [System.String[]]
        $Type = @('Prefix','Zeros'),

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Maldaptive.LdapFormat]
        $Target = [Maldaptive.LdapFormat]::String,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Switch]
        $TrackModification
    )

    begin
    {
        # Define current function's input object target format requirement (ensured by ConvertTo-LdapObject later in current function).
        $requiredInputObjectTarget = [Maldaptive.LdapFormat]::LdapTokenEnriched

        # Extract optional switch input parameter(s) from $PSBoundParameters into separate hashtable for consistent inclusion/exclusion in relevant functions via splatting.
        $optionalSwitchParameters = @{ }
        $PSBoundParameters.GetEnumerator().Where( { $_.Key -iin @('TrackModification') } ).ForEach( { $optionalSwitchParameters.Add($_.Key, $_.Value) } )

        # Create ArrayList to store all pipelined input before beginning final processing.
        $inputObjectArr = [System.Collections.ArrayList]::new()
    }

    process
    {
        # Add all pipelined input to $inputObjectArr before beginning final processing.
        $inputObjectArr = Join-LdapObject -InputObject $InputObject -InputObjectArr $inputObjectArr
    }

    end
    {
        # Ensure input data is formatted according to current function's requirement as defined in $requiredInputObjectTarget at beginning of current function.
        $inputObjectArr = ConvertTo-LdapObject -InputObject $inputObjectArr -Target $requiredInputObjectTarget

        # Iterate over each input object, storing result in array for proper re-parsing before returning final result.
        $modifiedInputObjectArr = foreach ($curInputObject in $inputObjectArr)
        {
            # Set boolean for generic obfuscation eligibility.
            $isEligible = $true

            # Override above obfuscation eligibility for specific scenarios.
            if ($curInputObject.Type -ne [Maldaptive.LdapTokenType]::Attribute)
            {
                # Override obfuscation eligibility if current object is not an Attribute LdapToken.
                $isEligible = $false
            }
            elseif ($curInputObject.Format -eq [Maldaptive.LdapTokenFormat]::OID)
            {
                # Override obfuscation eligibility if current Attribute LdapToken is already in OID syntax.
                $isEligible = $false
            }
            elseif ((-not $curInputObject.IsDefined) -or ($curInputObject.Context.Attribute.OID -inotmatch '^\d+(\.\d+)+$'))
            {
                # Override obfuscation eligibility if current Attribute LdapToken is not a defined attribute or does not have a valid numeric OID.
                # An undefined attribute reports a placeholder OID value of 'Undefined' (not $null), so an explicit numeric OID format check is required.
                $isEligible = $false
            }

            # Set boolean for obfuscation eligibility based on user input -RandomNodePercent value.
            $isRandomNodePercent = (Get-Random -Minimum 1 -Maximum 100) -le $RandomNodePercent

            # Proceed if eligible for obfuscation.
            if ($isEligible -and $isRandomNodePercent)
            {
                # Start from the attribute's defined numeric OID.
                $oid = $curInputObject.Context.Attribute.OID

                # Optionally prepend a random number (1-3) of zeros to each OID octet if 'Zeros' is defined in user input -Type parameter (detected via DEFINED_ATTRIBUTE_OID_SYNTAX_WITH_ZEROS).
                if (($Type -icontains 'Zeros') -and ((Get-Random -Minimum 0 -Maximum 2) -eq 0))
                {
                    $oid = ($oid.Split('.').ForEach( { ('0' * (Get-Random -Minimum 1 -Maximum 4)) + $_ } )) -join '.'
                }

                # Optionally prepend a (case-randomized) 'OID.' prefix if 'Prefix' is defined in user input -Type parameter (detected via DEFINED_ATTRIBUTE_OID_SYNTAX_WITH_OID_PREFIX).
                if (($Type -icontains 'Prefix') -and ((Get-Random -Minimum 0 -Maximum 2) -eq 0))
                {
                    $oid = (-join ([System.Char[]] 'OID').ForEach( { ((Get-Random -Minimum 0 -Maximum 2) -eq 0) ? ([System.Char]::ToLower($_)) : $_ } )) + '.' + $oid
                }

                # Update current Attribute LdapToken with OID syntax.
                $curInputObject.Content = $oid
                $curInputObject.Length = $curInputObject.Content.Length

                # If user input -TrackModification switch parameter is defined then set Depth property of current Attribute LdapToken to -1 for display tracking purposes.
                if ($PSBoundParameters['TrackModification'].IsPresent)
                {
                    $curInputObject.Depth = -1
                }
            }

            # Return current object.
            $curInputObject
        }

        # Ensure result is formatted according to user input -Target and optional -TrackModification values.
        Format-LdapObject -InputObject $modifiedInputObjectArr -Target $Target @optionalSwitchParameters
    }
}


function Add-RandomPresenceFilter
{
<#
.SYNOPSIS

MaLDAPtive is a framework for LDAP SearchFilter parsing, obfuscation, deobfuscation and detection.

MaLDAPtive Function: Add-RandomPresenceFilter
Author: Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Join-LdapObject, ConvertTo-LdapObject, Format-LdapObject, New-LdapToken
Optional Dependencies: None

.DESCRIPTION

Add-RandomPresenceFilter wraps eligible Filters with a redundant attribute presence filter joined by a logical AND in input LDAP SearchFilter (e.g. '(name=sabi)' -> '(&(name=*)(name=sabi))'). A concrete attribute value always implies the attribute is present, so the added presence filter is logically inert.

.PARAMETER InputObject

Specifies LDAP SearchFilter (in any input format) in which redundant presence filters will be inserted.

.PARAMETER RandomNodePercent

(Optional) Specifies percentage of eligible nodes (branch, filter, token, etc.) to obfuscate.

.PARAMETER Target

(Optional) Specifies target LDAP format into which the final result will be converted.

.PARAMETER TrackModification

(Optional) Specifies custom 'Modified' property be added to all modified LDAP tokens (e.g. for highlighting where obfuscation occurred).

.EXAMPLE

PS C:\> '(name=sabi)' | Add-RandomPresenceFilter -RandomNodePercent 100

(&(name=*)(name=sabi))

.NOTES

This is a personal project developed by Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://github.com/MaLDAPtive/Invoke-Maldaptive
https://twitter.com/sabi_elezi/
https://twitter.com/danielhbohannon/
#>

    [OutputType(
        [System.String],
        [Maldaptive.LdapToken[]],
        [Maldaptive.LdapTokenEnriched[]],
        [Maldaptive.LdapFilter[]],
        [Maldaptive.LdapBranch]
    )]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        # Purposefully not defining parameter type since mixture of LDAP formats allowed.
        $InputObject,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateRange(0,100)]
        [System.Int16]
        $RandomNodePercent = 50,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Maldaptive.LdapFormat]
        $Target = [Maldaptive.LdapFormat]::String,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Switch]
        $TrackModification
    )

    begin
    {
        # Define current function's input object target format requirement (ensured by ConvertTo-LdapObject later in current function).
        $requiredInputObjectTarget = [Maldaptive.LdapFormat]::LdapBranch

        # Extract optional switch input parameter(s) from $PSBoundParameters into separate hashtable for consistent inclusion/exclusion in relevant functions via splatting.
        $optionalSwitchParameters = @{ }
        $PSBoundParameters.GetEnumerator().Where( { $_.Key -iin @('TrackModification') } ).ForEach( { $optionalSwitchParameters.Add($_.Key, $_.Value) } )

        # Create ArrayList to store all pipelined input before beginning final processing.
        $inputObjectArr = [System.Collections.ArrayList]::new()
    }

    process
    {
        # Add all pipelined input to $inputObjectArr before beginning final processing.
        $inputObjectArr = Join-LdapObject -InputObject $InputObject -InputObjectArr $inputObjectArr
    }

    end
    {
        # Ensure input data is formatted according to current function's requirement as defined in $requiredInputObjectTarget at beginning of current function.
        $inputObjectArr = ConvertTo-LdapObject -InputObject $inputObjectArr -Target $requiredInputObjectTarget

        # Define local recursive helper function performing a single top-down pass. For each eligible Filter branch it wraps the Filter in a logical AND alongside a
        # redundant attribute presence filter (returning four+ objects); otherwise it descends into nested FilterList children. Filters are leaves so are never double-processed.
        function local:Invoke-AddRandomPresenceFilter
        {
            [OutputType([System.Object[]])]
            param (
                [Parameter(Mandatory = $true, ValueFromPipeline = $false)]
                [Maldaptive.LdapBranch]
                $LdapBranch
            )

            if ($LdapBranch.Type -eq [Maldaptive.LdapBranchType]::Filter)
            {
                # Extract Attribute and Value LdapTokens from current Filter branch.
                $attributeLdapToken = $LdapBranch.Branch[0].TokenList.Where( { $_.Type -eq [Maldaptive.LdapTokenType]::Attribute } )[0]
                $valueLdapToken     = $LdapBranch.Branch[0].TokenList.Where( { $_.Type -eq [Maldaptive.LdapTokenType]::Value     } )[0]

                # Set boolean for generic obfuscation eligibility.
                $isEligible = $true

                # Override above obfuscation eligibility for specific scenarios.
                if (-not $attributeLdapToken)
                {
                    # Override obfuscation eligibility if current Filter has no Attribute LdapToken.
                    $isEligible = $false
                }
                elseif ((-not $valueLdapToken) -or ($valueLdapToken.Content -ceq '*'))
                {
                    # Override obfuscation eligibility if current Filter has no Value LdapToken or is already a bare presence filter ('*').
                    $isEligible = $false
                }

                # Set boolean for obfuscation eligibility based on user input -RandomNodePercent value.
                $isRandomNodePercent = (Get-Random -Minimum 1 -Maximum 100) -le $RandomNodePercent

                # Proceed if eligible for obfuscation.
                if ($isEligible -and $isRandomNodePercent)
                {
                    # Build a redundant presence filter ('(<attr>=*)') for the current Filter's attribute by tokenizing it directly.
                    $presenceFilterTokenArr = ('(' + $attributeLdapToken.Content + '=*)') | ConvertTo-LdapObject -Target LdapTokenEnriched @optionalSwitchParameters

                    # Emit a new encapsulating logical AND FilterList wrapping the redundant presence filter and the original Filter: '(' '&' '(<attr>=*)' <original> ')'.
                    New-LdapToken -Type GroupStart -Content '(' -Target LdapTokenEnriched @optionalSwitchParameters
                    New-LdapToken -Type BooleanOperator -Content '&' -Target LdapTokenEnriched @optionalSwitchParameters
                    $presenceFilterTokenArr
                    $LdapBranch
                    New-LdapToken -Type GroupEnd -Content ')' -Target LdapTokenEnriched @optionalSwitchParameters
                }
                else
                {
                    # Return current Filter branch unmodified.
                    $LdapBranch
                }
            }
            elseif ($LdapBranch.Type -eq [Maldaptive.LdapBranchType]::FilterList)
            {
                # Descend into nested children, transforming each in turn.
                $LdapBranch.Branch = foreach ($curChild in $LdapBranch.Branch)
                {
                    ($curChild -is [Maldaptive.LdapBranch]) ? (Invoke-AddRandomPresenceFilter -LdapBranch $curChild) : $curChild
                }

                # Return current FilterList branch.
                $LdapBranch
            }
            else
            {
                # Return current object unmodified.
                $LdapBranch
            }
        }

        # Iterate over each input object, applying the recursive presence-filter pass to each top-level LdapBranch.
        $modifiedInputObjectArr = foreach ($curInputObject in $inputObjectArr)
        {
            ($curInputObject -is [Maldaptive.LdapBranch]) ? (Invoke-AddRandomPresenceFilter -LdapBranch $curInputObject) : $curInputObject
        }

        # Ensure result is formatted according to user input -Target and optional -TrackModification values.
        Format-LdapObject -InputObject $modifiedInputObjectArr -Target $Target @optionalSwitchParameters
    }
}


function Add-RandomFilter
{
<#
.SYNOPSIS

MaLDAPtive is a framework for LDAP SearchFilter parsing, obfuscation, deobfuscation and detection.

MaLDAPtive Function: Add-RandomFilter
Author: Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Join-LdapObject, ConvertTo-LdapObject, Format-LdapObject
Optional Dependencies: None

.DESCRIPTION

Add-RandomFilter inserts logically-inert junk Filters into eligible FilterList branches in input LDAP SearchFilter. Into a logical AND FilterList it inserts an always-true junk Filter ('(|(<rand>=<randVal>)(!(<rand>=<randVal>)))'); into a logical OR FilterList it inserts an always-false junk Filter ('(&(<rand>=<randVal>)(!(<rand>=<randVal>)))'). Both use a random undefined attribute and a random non-matching value (no presence wildcard), and the tautology/contradiction structure is logic-preserving regardless of the random value so the SearchFilter's logical evaluation does not change.

.PARAMETER InputObject

Specifies LDAP SearchFilter (in any input format) into which logically-inert junk Filters will be inserted.

.PARAMETER RandomNodePercent

(Optional) Specifies percentage of eligible nodes (branch, filter, token, etc.) to obfuscate.

.PARAMETER Target

(Optional) Specifies target LDAP format into which the final result will be converted.

.PARAMETER TrackModification

(Optional) Specifies custom 'Modified' property be added to all modified LDAP tokens (e.g. for highlighting where obfuscation occurred).

.EXAMPLE

PS C:\> '(&(name=sabi)(name=dbo))' | Add-RandomFilter -RandomNodePercent 100

(&(name=sabi)(name=dbo)(|(qwerty=k3p9zq1)(!(qwerty=k3p9zq1))))

.NOTES

This is a personal project developed by Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://github.com/MaLDAPtive/Invoke-Maldaptive
https://twitter.com/sabi_elezi/
https://twitter.com/danielhbohannon/
#>

    [OutputType(
        [System.String],
        [Maldaptive.LdapToken[]],
        [Maldaptive.LdapTokenEnriched[]],
        [Maldaptive.LdapFilter[]],
        [Maldaptive.LdapBranch]
    )]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        # Purposefully not defining parameter type since mixture of LDAP formats allowed.
        $InputObject,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateRange(0,100)]
        [System.Int16]
        $RandomNodePercent = 50,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Maldaptive.LdapFormat]
        $Target = [Maldaptive.LdapFormat]::String,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Switch]
        $TrackModification
    )

    begin
    {
        # Define current function's input object target format requirement (ensured by ConvertTo-LdapObject later in current function).
        $requiredInputObjectTarget = [Maldaptive.LdapFormat]::LdapBranch

        # Extract optional switch input parameter(s) from $PSBoundParameters into separate hashtable for consistent inclusion/exclusion in relevant functions via splatting.
        $optionalSwitchParameters = @{ }
        $PSBoundParameters.GetEnumerator().Where( { $_.Key -iin @('TrackModification') } ).ForEach( { $optionalSwitchParameters.Add($_.Key, $_.Value) } )

        # Create ArrayList to store all pipelined input before beginning final processing.
        $inputObjectArr = [System.Collections.ArrayList]::new()
    }

    process
    {
        # Add all pipelined input to $inputObjectArr before beginning final processing.
        $inputObjectArr = Join-LdapObject -InputObject $InputObject -InputObjectArr $inputObjectArr
    }

    end
    {
        # Ensure input data is formatted according to current function's requirement as defined in $requiredInputObjectTarget at beginning of current function.
        $inputObjectArr = ConvertTo-LdapObject -InputObject $inputObjectArr -Target $requiredInputObjectTarget

        # Define local recursive helper function performing a single top-down pass, descending into nested children first then optionally inserting one logically-inert junk Filter into the current FilterList.
        function local:Invoke-AddRandomFilter
        {
            [OutputType([Maldaptive.LdapBranch])]
            param (
                [Parameter(Mandatory = $true, ValueFromPipeline = $false)]
                [Maldaptive.LdapBranch]
                $LdapBranch
            )

            # Descend into nested children first so inserted junk Filters are never re-processed.
            if ($LdapBranch.Type -eq [Maldaptive.LdapBranchType]::FilterList)
            {
                $LdapBranch.Branch = foreach ($curChild in $LdapBranch.Branch)
                {
                    ($curChild -is [Maldaptive.LdapBranch]) ? (Invoke-AddRandomFilter -LdapBranch $curChild) : $curChild
                }
            }

            # Determine whether current LdapBranch is a real (parenthesized) FilterList with a directly-defined non-negation BooleanOperator ('&' or '|').
            $hasGroupStart = [bool] ($LdapBranch.Branch.Where( { ($_ -is [Maldaptive.LdapToken]) -and ($_.Type -eq [Maldaptive.LdapTokenType]::GroupStart) } ))

            # Set boolean for obfuscation eligibility based on user input -RandomNodePercent value.
            $isRandomNodePercent = (Get-Random -Minimum 1 -Maximum 100) -le $RandomNodePercent

            # Proceed if eligible for obfuscation.
            if (
                ($LdapBranch.Type -eq [Maldaptive.LdapBranchType]::FilterList) -and
                $hasGroupStart -and
                ($LdapBranch.BooleanOperator -cin @('&','|')) -and
                $isRandomNodePercent
            )
            {
                # Build a logically-inert junk Filter using a random undefined attribute label and a random non-matching alphanumeric value (resembling the original module's
                # random-value decoy style rather than a presence wildcard). The tautology '(|(attr=val)(!(attr=val)))' is always true and the contradiction
                # '(&(attr=val)(!(attr=val)))' is always false regardless of the random value, so the junk Filter is provably logic-preserving and contains no wildcards ('*').
                $randomLabel = Get-RandomObfuscationLabel
                $randomValue = -join (1..(Get-Random -Minimum 8 -Maximum 18)).ForEach(
                {
                    # Build random value one character at a time from lowercase ASCII letters ('a'-'z') and digits ('0'-'9').
                    $curCharCode = Get-Random -Minimum 0 -Maximum 36
                    ($curCharCode -lt 26) ? ([System.Char] (97 + $curCharCode)) : ([System.Char] (48 + ($curCharCode - 26)))
                } )
                $junkFilterStr = ($LdapBranch.BooleanOperator -ceq '&') ? "(|($randomLabel=$randomValue)(!($randomLabel=$randomValue)))" : "(&($randomLabel=$randomValue)(!($randomLabel=$randomValue)))"
                $junkFilterTokenArr = $junkFilterStr | ConvertTo-LdapObject -Target LdapTokenEnriched @optionalSwitchParameters

                # Insert the junk Filter tokens directly before the current FilterList's closing GroupEnd token (i.e. as the final nested child).
                $branchObjArr = [System.Collections.Generic.List[System.Object]] $LdapBranch.Branch
                $branchObjArr.InsertRange($branchObjArr.Count - 1, [System.Object[]] $junkFilterTokenArr)
                $LdapBranch.Branch = $branchObjArr.ToArray()
            }

            # Return current LdapBranch.
            $LdapBranch
        }

        # Iterate over each input object, applying the recursive junk-filter pass to each top-level LdapBranch.
        $modifiedInputObjectArr = foreach ($curInputObject in $inputObjectArr)
        {
            ($curInputObject -is [Maldaptive.LdapBranch]) ? (Invoke-AddRandomFilter -LdapBranch $curInputObject) : $curInputObject
        }

        # Ensure result is formatted according to user input -Target and optional -TrackModification values.
        Format-LdapObject -InputObject $modifiedInputObjectArr -Target $Target @optionalSwitchParameters
    }
}


function Add-RandomFilterListOrder
{
<#
.SYNOPSIS

MaLDAPtive is a framework for LDAP SearchFilter parsing, obfuscation, deobfuscation and detection.

MaLDAPtive Function: Add-RandomFilterListOrder
Author: Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Join-LdapObject, ConvertTo-LdapObject, Format-LdapObject
Optional Dependencies: None

.DESCRIPTION

Add-RandomFilterListOrder randomly reorders the sibling branches within eligible commutative FilterList branches (logical AND '&' or OR '|') in input LDAP SearchFilter. Because AND and OR are commutative, reordering their operands preserves the SearchFilter's logical evaluation.

.PARAMETER InputObject

Specifies LDAP SearchFilter (in any input format) in which commutative FilterList sibling branches will be reordered.

.PARAMETER RandomNodePercent

(Optional) Specifies percentage of eligible nodes (branch, filter, token, etc.) to obfuscate.

.PARAMETER Target

(Optional) Specifies target LDAP format into which the final result will be converted.

.PARAMETER TrackModification

(Optional) Specifies custom 'Modified' property be added to all modified LDAP tokens (e.g. for highlighting where obfuscation occurred).

.EXAMPLE

PS C:\> '(&(name=sabi)(name=dbo)(name=krbtgt))' | Add-RandomFilterListOrder -RandomNodePercent 100

(&(name=dbo)(name=krbtgt)(name=sabi))

.NOTES

This is a personal project developed by Sabajete Elezaj, aka Sabi (@sabi_elezi) & Daniel Bohannon, aka DBO (@danielhbohannon).

.LINK

https://github.com/MaLDAPtive/Invoke-Maldaptive
https://twitter.com/sabi_elezi/
https://twitter.com/danielhbohannon/
#>

    [OutputType(
        [System.String],
        [Maldaptive.LdapToken[]],
        [Maldaptive.LdapTokenEnriched[]],
        [Maldaptive.LdapFilter[]],
        [Maldaptive.LdapBranch]
    )]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        # Purposefully not defining parameter type since mixture of LDAP formats allowed.
        $InputObject,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [ValidateRange(0,100)]
        [System.Int16]
        $RandomNodePercent = 50,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Maldaptive.LdapFormat]
        $Target = [Maldaptive.LdapFormat]::String,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [Switch]
        $TrackModification
    )

    begin
    {
        # Define current function's input object target format requirement (ensured by ConvertTo-LdapObject later in current function).
        $requiredInputObjectTarget = [Maldaptive.LdapFormat]::LdapBranch

        # Extract optional switch input parameter(s) from $PSBoundParameters into separate hashtable for consistent inclusion/exclusion in relevant functions via splatting.
        $optionalSwitchParameters = @{ }
        $PSBoundParameters.GetEnumerator().Where( { $_.Key -iin @('TrackModification') } ).ForEach( { $optionalSwitchParameters.Add($_.Key, $_.Value) } )

        # Create ArrayList to store all pipelined input before beginning final processing.
        $inputObjectArr = [System.Collections.ArrayList]::new()
    }

    process
    {
        # Add all pipelined input to $inputObjectArr before beginning final processing.
        $inputObjectArr = Join-LdapObject -InputObject $InputObject -InputObjectArr $inputObjectArr
    }

    end
    {
        # Ensure input data is formatted according to current function's requirement as defined in $requiredInputObjectTarget at beginning of current function.
        $inputObjectArr = ConvertTo-LdapObject -InputObject $inputObjectArr -Target $requiredInputObjectTarget

        # Define local recursive helper function performing a single top-down pass, descending into nested children first then optionally reordering the current commutative FilterList's sibling branches.
        function local:Invoke-AddRandomFilterListOrder
        {
            [OutputType([Maldaptive.LdapBranch])]
            param (
                [Parameter(Mandatory = $true, ValueFromPipeline = $false)]
                [Maldaptive.LdapBranch]
                $LdapBranch
            )

            # Descend into nested children first so reordering operates on already-transformed branches.
            if ($LdapBranch.Type -eq [Maldaptive.LdapBranchType]::FilterList)
            {
                $LdapBranch.Branch = foreach ($curChild in $LdapBranch.Branch)
                {
                    ($curChild -is [Maldaptive.LdapBranch]) ? (Invoke-AddRandomFilterListOrder -LdapBranch $curChild) : $curChild
                }
            }

            # Extract directly-nested child branches of current LdapBranch.
            $childBranchArr = @($LdapBranch.Branch.Where( { $_ -is [Maldaptive.LdapBranch] } ))

            # Set boolean for obfuscation eligibility based on user input -RandomNodePercent value.
            $isRandomNodePercent = (Get-Random -Minimum 1 -Maximum 100) -le $RandomNodePercent

            # Proceed if eligible for obfuscation (commutative FilterList with at least two sibling branches).
            if (
                ($LdapBranch.Type -eq [Maldaptive.LdapBranchType]::FilterList) -and
                ($LdapBranch.BooleanOperator -cin @('&','|')) -and
                ($childBranchArr.Count -ge 2) -and
                $isRandomNodePercent
            )
            {
                # Randomly shuffle the sibling branches, then re-insert them into their original branch positions, leaving all structural tokens (GroupStart, BooleanOperator, GroupEnd, Whitespace) in place.
                $shuffledChildBranchArr = @($childBranchArr | Get-Random -Count $childBranchArr.Count)
                $shuffleIndex = 0
                $LdapBranch.Branch = for ($curIndex = 0; $curIndex -lt $LdapBranch.Branch.Count; $curIndex++)
                {
                    $curBranchObject = $LdapBranch.Branch[$curIndex]
                    if ($curBranchObject -is [Maldaptive.LdapBranch])
                    {
                        $shuffledChildBranchArr[$shuffleIndex]
                        $shuffleIndex++
                    }
                    else
                    {
                        $curBranchObject
                    }
                }
            }

            # Return current LdapBranch.
            $LdapBranch
        }

        # Iterate over each input object, applying the recursive reordering pass to each top-level LdapBranch.
        $modifiedInputObjectArr = foreach ($curInputObject in $inputObjectArr)
        {
            ($curInputObject -is [Maldaptive.LdapBranch]) ? (Invoke-AddRandomFilterListOrder -LdapBranch $curInputObject) : $curInputObject
        }

        # Ensure result is formatted according to user input -Target and optional -TrackModification values.
        Format-LdapObject -InputObject $modifiedInputObjectArr -Target $Target @optionalSwitchParameters
    }
}
