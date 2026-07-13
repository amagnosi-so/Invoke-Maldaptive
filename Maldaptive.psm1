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



# Get location of this script no matter what the current directory is for the process executing this script.
$scriptDir = [System.IO.Path]::GetDirectoryName($myInvocation.MyCommand.Definition)

# Load CSharp LDAP Parser.
# Only compile the C# types if they are not already loaded in the current session. Add-Type cannot redefine an
# already-loaded type, and Remove-Module does not unload a compiled assembly, so re-importing the module in the same
# session would otherwise throw one "type already exists" error per Maldaptive type. This guard makes remove/re-import idempotent.
# NOTE: because of this (and the .NET inability to reload an assembly in the same AppDomain), edits to LdapParser.cs only
# take effect in a fresh PowerShell session, not via Import-Module -Force in an existing session.
$csharpFile = Join-Path -Path $scriptDir -ChildPath 'CSharp\LdapParser.cs'
if (-not ('Maldaptive.LdapParser' -as [System.Type]))
{
    Add-Type -Path $csharpFile
}

# Set default SearchRoot (based on relevant environment variables if defined), AttributeList
# and Scope variables for consistent usage across numerous functions.
$global:defaultSearchRoot = [System.String] ($null -eq $env:USERDNSDOMAIN ? 'LDAP://DC=contoso,DC=com' : ('LDAP://' + ($env:LOGONSERVER ? $env:LOGONSERVER.Trim('\') : '') + '.' + $env:USERDNSDOMAIN + '/' + ($env:USERDNSDOMAIN ? ($env:USERDNSDOMAIN.Split('.').ForEach( { "DC=$_" } ) -join ',') : '')))
$global:defaultAttributeList = [System.String[]] @('*')
$global:defaultScope = [System.String] 'Subtree'