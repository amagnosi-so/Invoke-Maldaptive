# About Rebuilding MaLDAPtive's Obfuscation and Searching for Evasions Automatically

## TL;DR

This blog is meant to be a walk through reconstructing the never-released MaLDAPtive obfuscation module, use it to understand 
detection blindspots, and building detectors for them. We will also show how it is possible to use the scoring function implemented 
in the detection module to automatically search for obfucation strategies that bypass the implemented detection.

--

## Table of Contents

1. [Background](#1-background)
2. [The object model](#2-the-object-model)

3. [Part I - Rebuilding the obfuscation module](#3-part-i---rebuilding-the-obfuscation-module)
   - [3.1 De-Deobfuscation, aka Obfuscation](#31-de-deobfuscation-aka-obfuscation)
   - [3.2 Reversing the REMOVE functions](#32-reversing-the-remove-functions)
   - [3.3 The additional obfuscation techniques](#33-the-additional-deobfuscation-techniques)

4. [Potential Detection blind spots](#4-potential-detection-blind-spots)

5. [Adding detection](#5-adding-detection)

6. [Automatic recipe search](#6-automatic-recipe-search)
   - [6.1 Formalizing the problem](#61-formalizing-the-problem)
   - [6.2 Objective function](#62-objective-function)
   - [6.2.1 Algorithm 1: Greedy hill-climbing](#621-algorithm-1-greedy-hill-climbing)
   - [6.2.2 Algorithm 2: Simulated annealing](#622-algorithm-2-simulated-annealing)
   - [6.2.3 Algorithm 3: Genetic algorithm](#623-algorithm-3-genetic-algorithm)
   - [6.3 Understanding good results: Noisy fitness](#63-understanding-good-results-noisy-fitness)
   - [6.4 Results](#64-results)
---

## 1. Background

[MaLDAPtive](https://github.com/MaLDAPtive/Invoke-Maldaptive) (Sabajete Elezaj & Daniel Bohannon, Black Hat USA / DEF CON 2024) is a framework for **LDAP SearchFilter parsing, obfuscation, deobfuscation, and detection**. Its core is a 100% custom C# LDAP parser; everything else is a PowerShell wrapper.

The authors made a deliberate, responsible **two-stage release**: at launch they published everything except the obfuscation module. The repository contains the parser, the deobfuscation module, the detection module and its full ruleset, the telemetry module, and a corpus of 1,337 obfuscated filters.
This was done explicitly, so defenders could build telemetry and detections with a multi-month head start before the offensive half landed. However, after more than 24 months, there is still no trace of the obfuscation module.

This write-up is about trying to reconstruct that missing offensive half by looking at the released defensive half. If we succeed, we will then use the Obfuscation module to stress-test the very detection ruleset it ships with, and build detectors to close potential gaps we may find. 


## 2. The object model

The C# parser exposes primarily three Objects via `ConvertTo-LdapObject -Target <fmt>`:

* **`LdapToken` / `LdapTokenEnriched`** - Represents a flat stream of typed LDAP filter tokens. Token types include `GroupStart` (`(`), `GroupEnd` (`)`), `BooleanOperator` (`&`, `|`, `!`), `Attribute`, `ComparisonOperator` (`=`, `~=`, `>=`, `<=`), `Value`, `ExtensibleMatchFilter` (`:rule:`), and `Whitespace`. `LdapTokenEnriched` extends the base token model with additional metadata such as `IsDefined`, `Format` (for example, `OID`), `ContentDecoded`, and attribute context information (canonical name, numeric OID, and matching-rule case sensitivity).
* **`LdapFilter`** - Represents a single leaf filter expression (for example, `(attr=value)`). Internally, its components are stored in a `TokenDict`, allowing constant time access to individual filter elements.
* **`LdapBranch`** - Represents the LDAP filter syntax tree. A **Filter** branch contains a single `LdapFilter`, while a **FilterList** branch contains a `BooleanOperator` and one or more child branches. 

The obfuscators manipulate these objects (insert/edit/remove tokens, restructure branches) and then re-serialize with `Format-LdapObject`, which re-parses and so re-derives every depth/offset.


## 3. Part I - Rebuilding the obfuscation module

### 3.1 De-Deobfuscation, aka Obfuscation

The released **deobfuscation** module includes six `Remove-Random*` functions. As Deobfuscation is the inverse of obfuscation, the idea is to take each `Remove-Random*` and extract the specification of the inverse `Add-Random*` we need to build. 
These will share the same object model, same helper functions (`New-LdapToken`, `Add-LdapToken`, `Edit-LdapToken`, `Remove-LdapToken`, `Get-LdapCompatibleBooleanOperator`, `Invoke-LdapBranchVisitor`), and same parameters (`-RandomNodePercent`, `-Scope`, `-Type`, `-Target`, `-TrackModification`).

So the plan Is simple, where the deobfuscator removes a redundant parenthesis, the obfuscator will add one; where it collapses contiguous wildcards, the obfuscator will insert them; so on... 

As we don't want to break anything while deobfuscating, we will try to maintain an invariant: every transform needs to be logic-preserving by construction (meaning  the obfuscated filter must match exactly the same directory objects as the original). 
But how to ensure that? Well, we can verify it in mainly two ways: 
1. round-trip through the `Remove-Random*` inverse, and 
2. structural reasoning (below). 

The one technique that intentionally broadens the match set (wildcard insertion) is flagged "lossy".

### 3.2 Reversing the REMOVE functions

As we said, six REMOVE functions are exposed, which direct inversions will be:

| Function                             | Technique                                                                                                    | Logic-preservation argument                      |
|--------------------------------------|--------------------------------------------------------------------------------------------------------------|--------------------------------------------------|
| `Add-RandomWhitespace`               | inserts spaces at parser-tolerated positions (after `(`, operators, OID attributes, `=`, `)`, inside DN/RDN) | the server ignores whitespace in these positions |
| `Add-RandomParenthesis`              | wraps eligible branches in redundant `( )`                                                                   | `(X) ≡ X`                                        |
| `Add-RandomBooleanOperator`          | inserts logic-inert `&`/` \| ` on operator-less filters / single-child lists                                 | `(&X) ≡ (\|X) ≡ X` for a single operand          |
| `Add-RandomBooleanOperatorInversion` | adds a `!` and **De Morgan**-pushes it down                                                                  | see below                                        |
| `Add-RandomWildcard`                 | inserts `*` into string values (lossy)                                                                       | substring superset still contains the original   |
| `Add-RandomExtensibleMatchFilter`    | inserts undefined `:junk:` matching-rule tokens                                                              | decoy the server/parser tolerates                |

Logical inversion can be obtained applying De Morgan's laws:

```
¬(A ∧ B) ≡ (¬A) ∨ (¬B)
¬(A ∨ B) ≡ (¬A) ∧ (¬B)
```

So to introduce a "semantically-preserving" negation, we rewrite a branch `B` as `(! D(B))` where `D(B)` is the De-Morgan dual. This means we flip every `&`↔`|` in the subtree and toggle each leaf's negation. Then `(! D(B)) ≡ B`. An example:

```
(|(name=sabi)(name=dbo))   →   (!(&(!name=sabi)(!name=dbo)))
```

The reconstruction reuses the deobfuscator's exact inversion scriptblock (applied via `Invoke-LdapBranchVisitor -Action Modify`) and a top-down recursion that, per branch, either wraps-and-inverts or descends, which guarantees each subtree is transformed exactly once.

In the next paragraphs, we will go through each of the six functions and extract the obfuscation specification, run the deobfuscator to observe what it strips, implement and run the obfuscation logic to verify that it is consistent.

#### `Remove-RandomParenthesis` ⟶ `Add-RandomParenthesis`

The deobfuscator finds a redundant `FilterList` wrapper (a parenthesis group with no boolean operator of its own) and deletes its `(` / `)` pair:

```powershell
# Remove-RandomParenthesis (helper) - strip the encapsulating ( ) of a redundant wrapper branch.
$curGroupStartLdapToken = $LdapBranch.Branch.Where( { $_.Type -eq [Maldaptive.LdapTokenType]::GroupStart } )[0]
$curGroupEndLdapToken   = $LdapBranch.Branch.Where( { $_.Type -eq [Maldaptive.LdapTokenType]::GroupEnd   } )[-1]
Remove-LdapToken -LdapBranch $LdapBranch -LdapToken $curGroupStartLdapToken
Remove-LdapToken -LdapBranch $LdapBranch -LdapToken $curGroupEndLdapToken
```

We can confirm it with:

```powershell
PS> '(|(((name=sabi)))(((name=dbo))))' | Remove-RandomParenthesis -RandomNodePercent 100
(|(name=sabi)(name=dbo))
```

Our `Add-RandomParenthesis` should do the reverse: for an eligible Filter/FilterList branch it should create a new `GroupStart`/`GroupEnd` pair (a wrapper with no operator) around it. Since `(X) ≡ X`, this obfuscation pass is semantically the same:

```powershell
PS> '(|(name=sabi)(name=dbo))' | Add-RandomParenthesis -RandomNodePercent 100 -Scope Filter
(|((name=sabi))((name=dbo)))
```

#### `Remove-RandomBooleanOperator` ⟶ `Add-RandomBooleanOperator`

The deobfuscator removes a boolean operator only when removing it preserves the logical value. Internally, it uses `Get-LdapCompatibleBooleanOperator` to collect which operators are safe to drop, then drops one:

```powershell
# Remove-RandomBooleanOperator - keep only logic-preserving removals, then delete one operator token.
$eligible = Get-LdapCompatibleBooleanOperator -LdapBranch $curBranch -Type current_branch_only -Action remove -BooleanOperator $candidates
$randomEligibleBooleanOperator = Get-Random -InputObject $eligible
Remove-LdapToken -LdapBranch $curBranch -LdapToken $curBranchBooleanOperatorLdapToken
```

We can observce the inert filter-scope `&`/`|` being collapsed away with:

```powershell
PS> '(|(|name=sabi)(&name=dbo))' | Remove-RandomBooleanOperator -RandomNodePercent 100
(|(name=sabi)(name=dbo))
```

Our `Add-RandomBooleanOperator` should then insert a logic-inert operator. We will target branches with no direct operator (e.g., a bare filter, or a single-child list) where `(&X) ≡ (|X) ≡ X`, so the insertion never changes meaning:

```powershell
PS> '(|(name=sabi)(name=dbo))' | Add-RandomBooleanOperator -RandomNodePercent 100 -Scope Filter
(|(&name=sabi)(|name=dbo))
```

#### `Remove-RandomBooleanOperatorInversion` ⟶ `Add-RandomBooleanOperatorInversion`

In this case, the deobfuscator removes a De Morgan negation. First, it inverts every operator in the subtree under a 
`!` (flip `&`↔`|`, toggle leaf negations) and then deletes the `!` that started it:

```powershell
# Remove-RandomBooleanOperatorInversion - invert the negated subtree, then delete the leading '!'.
Invoke-LdapBranchVisitor -LdapBranch $ldapBranchToInvert -ScriptBlock $scriptBlockBooleanOperatorInversion -Action Modify
Remove-LdapToken -LdapBranch $curBranch -LdapToken $curBooleanOperatorLdapToken   # the '!' that initiated it
```

We can proove that `!(&(!a)(!b))` collapses to `(|(a)(b))` with:

```powershell
PS> '(!(&(!name=sabi)(!name=dbo)))' | Remove-RandomBooleanOperatorInversion -RandomNodePercent 100
((|(name=sabi)(name=dbo)))
```

Our implementation of `Add-RandomBooleanOperatorInversion` will reuse the same inversion scriptblock but in the other direction. 
We wrap a branch in a new `!` and apply De Morgan on it. Since `(! D(B)) ≡ B`, it is exact:

```powershell
PS> '(|(name=sabi)(name=dbo))' | Add-RandomBooleanOperatorInversion -RandomNodePercent 100 -Scope FilterList
(!(&(!name=sabi)(!name=dbo)))
```

#### `Remove-RandomWhitespace` ⟶ `Add-RandomWhitespace`

The deobfuscator shrinks each eligible `Whitespace` token by a random amount (possibly to nothing), parsing it first so hex-encoded spaces (`\20`) count correctly:

```powershell
# Remove-RandomWhitespace - shorten a Whitespace token, keeping a random prefix/suffix of it.
$newWhitespaceLength = $curInputObjectParsedArr.Count - (Get-Random -InputObject $RandomLength)
$newWhitespaceLength = $newWhitespaceLength -gt 0 ? $newWhitespaceLength : 0
$curInputObject.Content = -join($curInputObjectParsedArr | Select-Object @firstOrLastWhitespaceCharsToRetain).Content
```

Watch it remove (with a large `-RandomLength`, every run is erased):

```powershell
PS> '  ( |   (  name=   sabi)  (  name=  dbo)  )  ' | Remove-RandomWhitespace -RandomNodePercent 100 -RandomLength 10
(|(name=sabi)(name=dbo))
```

`Add-RandomWhitespace` should then create new `Whitespace` tokens at the same parser-tolerated positions the deobfuscator classifies. 
We can use the `-Type` parameter to mirror the eligibility list: after `(`, boolean operators, OID attributes, `=`, `)`, and inside DN/RDN values:

```powershell
PS> '(|(name=sabi)(name=dbo))' | Add-RandomWhitespace -RandomNodePercent 100 -RandomLength 2 -Type GroupStart,BooleanOperator,ComparisonOperator
(  |  (  name=  sabi)(  name=  dbo))
```

#### `Remove-RandomWildcard` ⟶ `Add-RandomWildcard`

The deobfuscator only collapses two-or-more wildcards, and always keeps at least one. For this reason, it never fully undo wildcard insertions. 
As such, this is a partial deobfuscation (single wildcards are not safely removable):

```powershell
# Remove-RandomWildcard - only RUNS of 2+ '*' are eligible; never drop the last one.
if ($curInputObject.Content -cnotmatch '\*{2,}') { $isEligible = $false }     # nothing to collapse
...
if ($isRandomCharPercent) { $curChar = '' }                                   # drop a redundant '*'
$substringObj.Content = $substringObj.Content.Length -eq 0 ? '*' : $substringObj.Content   # keep one
```

We can confirm the behavior against a test value like `***sa**bi***`, observing it collapses to single wildcards:

```powershell
PS> '(name=***sa**bi***)' | Remove-RandomWildcard -RandomNodePercent 100 -RandomCharPercent 100
(name=*sa*bi*)
```

The implementation of `Add-RandomWildcard` should then insert `*` between value characters. We decided to mark this technique as lossy for this reason. 
The result (`s*a*b*i`) matches a superset that still includes the original, so it is not a strict equivalent. 
This is also why `Remove-RandomWildcard` cannot fully undo it:

```powershell
PS> '(name=sabi)' | Add-RandomWildcard -RandomNodePercent 100 -RandomCharPercent 100 -Type middle
(name=s*a*b*i)
```

#### `Remove-RandomExtensibleMatchFilter` ⟶ `Add-RandomExtensibleMatchFilter`

The deobfuscator targets only undefined matching rules (i.e., anything that is not one of AD's four real OIDs); 
it nulls them, or redacts to `:.:` when they contain a `.` (which would otherwise make the filter never match):

```powershell
# Remove-RandomExtensibleMatchFilter - null an undefined matching rule, or redact to ':.:' if it contains '.'.
$curInputObject.Content = $curInputObject.Content.Contains('.') ? ':.:' : $null
```

We can test it on example values. As observable, `:timeSaved:` gets dropped; `:1.3.3.7:` gets redacted to `:.:`:

```powershell
PS> '(&(name:timeSaved:=sabi)(name:1.3.3.7:=dbo))' | Remove-RandomExtensibleMatchFilter -RandomNodePercent 100
(&(name=sabi)(name:.:=dbo))
```

The obfuscation function `Add-RandomExtensibleMatchFilter` should then inject an undefined matching-rule token (e.g., a random lowercase `:word:`) before the `=` of an equality filter:

```powershell
PS> '(&(name=sabi)(name=dbo))' | Add-RandomExtensibleMatchFilter -RandomNodePercent 100
(&(name:anrpml:=sabi)(name:djcbkmub:=dbo))
```

### 3.3 The additional deobfuscation techniques

As far as extracting technical specs, the deobfuscators only cover the six insertion techniques described above. However, 
when we reached this stage, it was apparent that our implementation was lacking something. 
The full original module could obfuscate using other techniques as well, and it was apparent in the authors' screenshot. 

So we started checking if we could infer other primitives from the detection rules, following a similar inversion logic 
we used with the previous functions.  

We found that the file `DetectionHelper.psm1` contained the required information to proceed:
1. Hex value encoding rule `VALUE_WITH_HEX_ENCODING_FOR_ALPHANUMERIC_CHARS` ⟶ `Add-RandomHexValue`
2. OID attribute syntax rules `DEFINED_ATTRIBUTE_OID_SYNTAX_WITH_ZEROS` / `..._WITH_OID_PREFIX` ⟶ `Add-RandomOid`
3. Presence filter rule `SENSITIVE_ATTRIBUTE_PRESENCE_FILTER` ⟶ `Add-RandomPresenceFilter`

The ruleset scores any value byte written as a `\xx` escape when the underlying character is alphanumeric (25 points each) -
because the LDAP server decodes `\62` back to `b`, so an alphanumeric written in hex is pure obfuscation. 

Below the extract from `DetectionHelper.psm1`: 

```powershell
PS C:\Users\klezvirus\Desktop\repos\Invoke-Maldaptive>> '((|(name=s\61bi)(name=\44\62o)))' | Find-Evil -Summarize | Show-EvilSummary

############################
## Full Detection Details ##
############################

Score          : 25
ID             : VALUE_WITH_HEX_ENCODING_FOR_ALPHANUMERIC_CHARS
Name           : Filter Value Contains Excessive Count (1) of Hex-Encoded Alphanumeric Character(s) (\61=>a): s\61bi => sabi
Depth          : 2
Start          : 3
Content        : (name=s\61bi)
ContentDecoded : (name=sabi)

Score          : 50
ID             : VALUE_WITH_HEX_ENCODING_FOR_ALPHANUMERIC_CHARS
Name           : Filter Value Contains Excessive Count (2) of Hex-Encoded Alphanumeric Character(s) (\44=>D, \62=>b): \44\62o => Dbo
Depth          : 2
Start          : 16
Content        : (name=\44\62o)
ContentDecoded : (name=Dbo)
```

Using another piece of information in the same file, we detected other two rules. 
These detect an attribute written as its numeric OID with prepended octet zeros (`001.00002...`, 25 pts) or with an `OID.` prefix (5 pts),  
plus a generic `DEFINED_ATTRIBUTE_ABNORMAL_SYNTAX` (20 pts). 

So, for the obfuscation counterpart, we would have to replace the attribute name with its OID, optionally padding octets with zeros and/or prepend `OID.`.

Again, these were extracted from `DetectionHelper.psm1` (even though this time we had to re-execute the PowerShell 
command a bit differently to show all the detection rules):

```powershell
PS C:\Users\klezvirus\Desktop\repos\Invoke-Maldaptive> '(   !  ((    ((!(   (|   (|name=s\61bi)   (& (&(& (&(      OiD.0001.2.840.113556.00000001.4.1=\44\62o))  )  )) )   )) ))   ))' |
>>     Find-Evil -Summarize |
>>     Select-Object TotalScore,DetectionCount,UniqueDetectionIDs,SearchFilterLength,SearchFilter |
>>     Format-Table DetectionCount,@{
>>         Label='DetectionIds'
>>         Expression={$_.UniqueDetectionIDs -join "`n"}
>>     } -Wrap

DetectionCount DetectionIds
-------------- ------------
            18 CONTEXT_WHITESPACE_EXCESSIVE_COUNT
               CONTEXT_LARGE_WHITESPACE_EXCESSIVE_COUNT
               CONTEXT_WHITESPACE_UNCOMMON_NEIGHBOR_EXCESSIVE_COUNT
               CONTEXT_FILTER_EXCESSIVE_MAX_DEPTH
               CONTEXT_FILTERLIST_BRANCH_WITH_GAPPED_BOOLEANOPERATOR
               CONTEXT_FILTERLIST_BRANCH_WITH_BOOLEANOPERATOR_CLOSING_GAPPED_BOOLEANOPERATOR
               CONTEXT_BOOLEANOPERATOR_FILTER_SCOPE_OR
               VALUE_WITH_HEX_ENCODING_FOR_ALPHANUMERIC_CHARS
               CONTEXT_BOOLEANOPERATOR_ADJACENT_REPEATING_FILTER_OR_COUNT
               CONTEXT_BOOLEANOPERATOR_ADJACENT_REPEATING_FILTERLIST_AND_COUNT
               CONTEXT_BOOLEANOPERATOR_FILTER_SCOPE_EXCESSIVE_COUNT
               CONTEXT_FILTER_EXCESSIVE_DEPTH
               DEFINED_ATTRIBUTE_ABNORMAL_SYNTAX
               DEFINED_ATTRIBUTE_OID_SYNTAX_WITH_OID_PREFIX
               DEFINED_ATTRIBUTE_OID_SYNTAX_WITH_ZEROS
               CONTEXT_BOOLEANOPERATOR_AND_MODIFYING_SINGLE_FILTER
```

The fact that wildcards are generally used for detection is nothing new, and indeed another rule flags the presence 
of a filter `(attr=*)` on a sensitive attribute (20 pts). 

```powershell
PS C:\Users\klezvirus\Desktop\repos\Invoke-Maldaptive> '(userPassword=*)' | Find-Evil | Select-Object Score,ID

Score                                  ID
-----                                  --
20.00 SENSITIVE_ATTRIBUTE_PRESENCE_FILTER
```

*The piece we built.* `Add-RandomPresenceFilter` rewrites `(a=v)` into `(&(a=*)(a=v))` - injecting the very presence filter the rule looks for:

```powershell
PS> '(userPassword=secret)' | Add-RandomPresenceFilter -RandomNodePercent 100
(&(userPassword=*)(userPassword=secret))
```

We immediately spotted that some other techniques were not in the rulebook. Among these, we noticed:
* Case randomization
* Sibling reordering 
* Tautology/contradiction decoys 

```powershell
PS> '(nAMe=sabi)'                  | Find-Evil   # case  -> (nothing)
PS> '(&(name=dbo)(name=sabi))'     | Find-Evil   # order -> (nothing)
PS> '(|(zzqq=aa)(!(zzqq=aa)))'     | Find-Evil   # decoy -> (nothing)
```



The result of this reconstruction was organized as `Substitute`, `Transform`, and `SubstituteOrder`. 

| Function                    | Menu path                  | Technique                                                                       | Logic-preservation                                                                           |
|-----------------------------|----------------------------|---------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------|
| `Add-RandomHexValue`        | `Substitute\Hex`           | `\xx` hex-encode value chars                                                    | the server decodes `\xx`; `ContentDecoded` unchanged                                         |
| `Add-RandomCase`            | `Substitute\Case`          | flip attribute/value case                                                       | attribute names are case-insensitive; values only when the matching rule is case-insensitive |
| `Add-RandomOid`             | `Substitute\OID`           | `name → 1.2.840.113556.1.4.x` (+ optional `OID.` prefix, prepended octet zeros) | OID is an equivalent identifier for the attribute                                            |
| `Add-RandomFilter`          | `Transform\FilterRandom`   | inject logically-inert decoy filters                                            | `(X ∨ ¬X) ≡ true`, `(X ∧ ¬X) ≡ false`; AND-ing true / OR-ing false is identity               |
| `Add-RandomPresenceFilter`  | `Transform\FilterPresence` | `(a=v) → (&(a=*)(a=v))`                                                         | `a=v ⟹ a=*`, so the presence conjunct is redundant                                           |
| `Add-RandomFilterListOrder` | `SubstituteOrder`          | shuffle siblings of `&`/` \| ` lists                                            | `∧`, `∨` are commutative                                                                     |

`Add-RandomFilter` uses the tautology/contradiction skeleton with a random non-matching value:

```
AND scope:  (|(<rand-attr>=<rand-val>)(!(<rand-attr>=<rand-val>)))   ; always true
OR  scope:  (&(<rand-attr>=<rand-val>)(!(<rand-attr>=<rand-val>)))   ; always false
```

`X ∨ ¬X` is true and `X ∧ ¬X` is false regardless of the value we may use, so we may also use words from a dictionary instead
of randomly generated strings, which may help the query to appear less suspicious.

## 4. Potential Detection blind spots

`Find-Evil` calls the compiled `[Maldaptive.LdapParser]::FindEvil(...)`, 
which evaluates around 82 rules and returns scored `Detection` objects; the total is a simple sum of the score of each detection. 

That design has a structural blind spot, which we measured directly. Taking a baseline filter and applying each technique at full intensity, summing `Find-Evil`:

| Technique @ 100%                     | Δ score    |
|--------------------------------------|------------|
| Case randomization                   | **+0**     |
| Sibling reorder                      | **+0**     |
| Plain OID substitution               | **+0**     |
| Redundant parentheses (small filter) | **+0**     |
| Inert decoy filters                  | **+0**     |
| Whitespace (len 1 / len 5)           | +30 / +157 |
| Wildcard insertion                   | +85        |
| OID **+ prepended zeros**            | +45        |
| Hex (few chars / all chars)          | +25 / +400 |

From the above we can easily observe that `Find-Evil` tends to be unable to detect logically-equivalent restructuring 
that stays within normal-looking syntax.  

## 5. Adding detection

At this stage, before releasing anything, we wanted to be sure to take the obfuscation techniques and write the missing detector for each. 

Detection here is the dual of obfuscation. For each obfuscation mapping `s → s'` that preserves meaning, 
detection should recognize that `s'` is an unusual encoding of some `s`. In order to do that, we worked on two core ideas:

* Normalization-divergence: We built a normalizer that would case-fold attributes, resolve OIDs to canonical names, sort commutative siblings, and strip redundant parens/presence. 
  Anything this normalizer would remove is, by definition, gratuitous - so score the divergence between the filter and its normalized form. This led to the addition of the following rules:

- `EXTENDED_DEFINED_ATTRIBUTE_OID_SYNTAX` - a defined attribute in plain numeric OID syntax (the core ruleset only scored the `+zeros` and `OID.`-prefix variants, leaving plain OID free)
- `EXTENDED_ATTRIBUTE_NONCANONICAL_CASE` - the literal attribute text matches its canonical name ignoring case but differs in case

* Decoy-density: The inert decoy `(|(X)(!(X)))` / `(&(X)(!(X)))` and the redundant presence `(&(a=*)(a=v))` are a dead giveaway that obfuscation is taking place. 
To detect the decoy we had to reduce each FilterList child to its logical root:

> Peel single-child FilterList chains, accumulating a **negation parity** ∈ {0,1} for each `!` encountered, until you reach a leaf filter; the core is `attr·op·value` and the parity is the number of negations mod 2.

If two siblings share the same root but opposite parity, you have `X` and `¬X` side by side. This can lead to a tautology in a `|` list or a contradiction in a `&` list (i.e. a decoy). This led to the addition of the following rules:

- `EXTENDED_LOGICALLY_INERT_DECOY_FILTER` - a FilterList with a same-core/opposite-parity sibling pair.
- `EXTENDED_REDUNDANT_PRESENCE_FILTER` - an AND-list containing both `(a=*)` and a concrete `(a=…)` for the same `a`.

All these were added to `LdapParser.cs`, if you'd like to check them out. As a note, we decided to add them as an Extended Ruleset, so to be able to test them while also leaving the original behavior untouched.

Measured: a filter that scores **0 on the core ruleset** scores **55 on the extended ruleset** (all four rules firing); core-only stays 0 (no regression).

## 6. Automatic recipe search

At this point, although we could handpick a recipe directly from the tables in part 2, we figured we could use the scoring function 
as a feedback to programmatically apply changes in a stealthy way. This requires us to formalize the problem as on optimization
problem.

> Before you read: this part is completely optional and I just decided to try and work on this cause I found it interesting. 
In all honesty, in this specific case, this could be completely skipped as it was obvious that many obfuscation strategies would
score 0, making the research of the "best" obfuscation recipe completely pointless.

> So when this could be useful? In real cases, you might observe detection or alert triggering at a certain score threshold.
> The automatic search would help finding just how much you can obfuscate a query keeping the overall score under that threshold.

### 6.1 Formalizing the problem

Let:

- `s₀` be the original filter,
- `P` be the set of logic-preserving obfuscation passes (each `p ∈ P` is a randomized function `filter → filter`),
- a recipe `r = (p₁, p₂, …, p_k)` be an ordered sequence drawn from `P`,
- `apply(r, s₀)` be the filter obtained by folding the passes over `s₀`,
- `Score(s)` be the total `Find-Evil` score (core, or core+extended),
- `C` be a hard score cap (default `C = Score(s₀)` - add zero detectable signal),
- `d(a, b)` be the Levenshtein edit distance.

We want the recipe whose output diverges most from the original while staying under the cap:

```
maximize    d(s₀, apply(r, s₀))
subject to  Score(apply(r, s₀)) ≤ C
over        r ∈ P*           (P* = all finite sequences over P, |r| ≤ L)
```

Because `P` contains only logic-preserving passes, every feasible point is logically equivalent to `s₀` by construction,
which makes the search safe to run on its own.

### 6.2 Objective function

Why maximizing edit distance rather than, say, length? The reason should be obvious, but if not, it's because some of the 
strongest transforms don't change length at all (i.e., case-folding, sibling reordering, etc., only rewrite in place). 
As such, length would reward only the bulk-adding passes (decoys, presence) and ignore case/order ones, which we want to exercise. 
Levenshtein distance, instead, rewards any divergence, including both in-place and bulk transforms.

We fold the constraint into a single scalar "fitness" with a penalty for infeasibility:

```
        ⎧  d(s₀, apply(r, s₀))                  if Score ≤ C   (feasible)
f(r) =  ⎨
        ⎩  −1000 − (Score − C)                  if Score > C   (infeasible, penalised by overage)
```

Maximizing `f` drives the search into the feasible region first (any feasible recipe beats any infeasible one) and then 
maximizes divergence within it. 
Edit distance is computed with the standard dynamic program (two rolling rows for O(min(m,n)) space):

```
D[i,j] = min( D[i−1,j] + 1,              # deletion
              D[i,j−1] + 1,              # insertion
              D[i−1,j−1] + [a_i ≠ b_j] ) # substitution
```

As optimization strategies, we opted for three basic algorithms that seemed fit for purpose. The only difference between 
the three is how they perform a search in the recipe space, which is a discrete, variable-length, non-convex, noisy landscape 
with several local optima.

The three strategies are:
1. Greedy Hill-Climbing - Fast but myopic
2. Simulated annealing - Good tradeoff between speed and exploration
3. Genetic Algorithms - Maximize space exploration but expensive

#### 6.2.1 Algorithm 1: Greedy hill-climbing

[Hill-climbing](https://en.wikipedia.org/wiki/Hill_climbing) maintains a single incumbent and only ever moves to a strictly better neighbor. Here a "move" is to append one more pass: from recipe `r` of length `k`, evaluate every `r ∥ p` for `p ∈ P` 
(each retried a few times because passes are randomized) and keep the appended pass that most increases distance while staying feasible. Stop when no append improves.

Greedy converges fast and is simple, but it is kind of myopic: it never removes or reorders, and it commits to locally-best appends, so it gets eventually trapped in local optima. 
The standard mitigation, as also stated in the Wikipedia reference, is making the algorithm stochastic. This is done applying random restarts to force the algorithm away from the same local maxima. 
The stochastic variant can be seen as a global search whose quality scales with the number of restarts. 

#### 6.2.2 Algorithm 2: Simulated annealing

Annealing borrows from statistical mechanics: a physical system cooled slowly enough settles into a minimum-energy state. In our case, this state is characterized by maximum-fitness. 
It maintains a single state and at each step proposes a neighbor by a small mutation (i.e, insert/delete/substitute/single-swap). Let `Δf = f(neighbour) − f(current)`. The neighbor is accepted with probability

```
P(accept) = 1                       if Δf ≥ 0          (always take improvements)
P(accept) = exp(Δf / T)             if Δf < 0          (sometimes take worse moves)
```

This is known as the Metropolis-Hastings acceptance criterion. The temperature `T` starts high and decays geometrically, `T ← α·T` (we use `α = 0.97`):

- Initially, the value of T is High → `exp(Δf/T) → 1`, so almost any move is accepted, allowing the search to explore freely and escape local optima.
- Gradually, the value of T diminishes and eventually starts tending to 0 (`exp(Δf/T) → 0` for `Δf < 0`), making the search more conservative and eventually reaching a maximum.

The schedule interpolates exploration and exploitation. With a sufficiently slow schedule, annealing converges in probability to the global optimum; in practice the geometric schedule is a pragmatic approximation. 
 
#### 6.2.3 Algorithm 3: Genetic algorithm

A GA evolves a population of recipes under selection, recombination, and mutation, exploring many regions of `P*` in parallel rather than tracking a single point.

- **Genotype** = the recipe (a variable-length list of pass names). **Phenotype** = `apply(r, s₀)`. **Fitness** = `f(r)`.
- **Selection** - tournament selection: pick `t` random individuals, keep the fittest. Larger `t` ⇒ stronger selection pressure (faster convergence, less diversity).
- **Crossover** - single-point cut-and-splice: cut parents A and B at random points and splice `A_prefix ∥ B_suffix`. This recombines useful sub-sequences ("building blocks") from two parents into a child; the **schema theorem** (Holland) is the intuition for why short, high-fitness sub-patterns proliferate across generations.
- **Mutation** - with probability `μ`, apply one random insert/delete/substitute/swap. Mutation supplies the diversity crossover alone cannot, preventing premature convergence.
- **Elitism** - copy the top `E` individuals unchanged into the next generation, so the best-so-far never regresses (a monotonicity guarantee the basic GA lacks).

Each generation: evaluate the whole population, record the best feasible individual, then build the next generation as `elites ∪ {mutate(crossover(select, select))}`. 

### 6.3 Understanding good results: Noisy fitness

To avoid having lucky draws being treated unfairly (i.e., being promoted as winners), we randomize every pass, making `f(r)`
a random variable. This means the same recipe yields different filters and scores on each evaluation.

Consider this is handled directly by the search algorithms: 
* greedy retries each candidate append a few times and keeps the best realization; 
* the GA re-evaluates every generation (so good genotypes must be robustly good to survive); 
* annealing's stochastic acceptance is itself tolerant of noise

All three of our search strategies degrade gracefully because none of them rely on a single fixed score reading.

> I rewrote this section several times. 
> In a nutshell, the same recipe can produce different obfuscated artifacts. 
> Since some transformations are applied probabilistically, one execution may simply 
> end up with fewer obfuscated elements than another, resulting in a lower score purely by chance.

### 6.4 Results

Interestingly, all three search strategies independently converged on the same set of recipes: `{OID, Presence, FilterRandom, Order, Case}`.

Nothing surprising, as each of these recipes is independently capable of producing score-0 obfuscations,
as we previously noticed.

Of course, using the new ruleset (the one we extended), these "shortcuts" won't work anymore, changing the search
results.

| Scored against    | Best score-0 obfuscation (edit distance)                                     |
|-------------------|------------------------------------------------------------------------------|
| Core ruleset      | ≈ 588 - a 60-char filter blown up ~12×, logically identical, `Find-Evil = 0` |
| Extended ruleset  | ≈ 162 - a ~72% collapse                                                      |

All three strategies independently converge on the same set of recipes `{OID, Presence, FilterRandom, Order, Case}`. 
That was obvious, as they would lead to 0.


