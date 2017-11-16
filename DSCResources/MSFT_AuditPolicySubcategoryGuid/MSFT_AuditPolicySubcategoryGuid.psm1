Import-Module -Name (Join-Path -Path ( Split-Path $PSScriptRoot -Parent ) `
                               -ChildPath 'AuditPolicyResourceHelper\AuditPolicyResourceHelper.psm1') `
                               -Force

# Localized messages for Write-Verbose statements in this resource
$script:localizedData = Get-LocalizedData -ResourceName 'MSFT_AuditPolicySubcategoryGuid'

<#
    .SYNOPSIS
        Returns the current audit flag for the given subcategory.
    .PARAMETER Id
        Specifies the subcategory to retrieve by GUID.
    .PARAMETER AuditFlag
        Specifies the audit flag to retrieve.
#>
function Get-TargetResource
{
    [CmdletBinding()]
    [OutputType([Hashtable])]
    param
    (
        [Parameter(Mandatory = $true)]
        [String]
        $Id,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Success', 'Failure')]
        [String]
        $AuditFlag
    )

    $auditPolicySubcategoryParameters = @{
        Name = $Id
        AuditFlag = $AuditFlag
        Verbose = $VerbosePreference
    }

    $auditPolicySubcategory = Get-AuditPolicySubcategory @auditPolicySubcategoryParameters

    return @{
        Id        = $auditPolicySubcategory.Name
        AuditFlag = $auditPolicySubcategory.AuditFlag
        Ensure    = $auditPolicySubcategory.Ensure
    }
}

<#
    .SYNOPSIS
        Sets the audit flag for the given subcategory.
    .PARAMETER Name
        Specifies the subcategory to set.
    .PARAMETER AuditFlag
        Specifies the audit flag to set.
    .PARAMETER Ensure
        Specifies the state of the audit flag provided. By default this is set to Present.
#>
function Set-TargetResource
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [String]
        $Id,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Success', 'Failure')]
        [String]
        $AuditFlag,

        [Parameter()]
        [ValidateSet('Present', 'Absent')]
        [String]
        $Ensure = 'Present'
    )

    $auditPolicySubcategoryParameters = @{
        Name = $Id
        AuditFlag = $AuditFlag
        Ensure = $Ensure
        Verbose = $VerbosePreference
    }

    Set-AuditPolicySubcategory @auditPolicySubcategoryParameters
}

<#
    .SYNOPSIS
        Tests the audit flag state for the given subcategory.
    .PARAMETER Name
        Specifies the subcategory to test.
    .PARAMETER AuditFlag
        Specifies the audit flag to test.
    .PARAMETER Ensure
        Specifies the state of the audit flag should be in.
#>
function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [Parameter(Mandatory = $true)]
        [String]
        $Id,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Success', 'Failure')]
        [String]
        $AuditFlag,

        [Parameter()]
        [ValidateSet('Present', 'Absent')]
        [String]
        $Ensure
    )

    $auditPolicySubcategoryParameters = @{
        Name = $Id
        AuditFlag = $AuditFlag
        Ensure = $Ensure
        Verbose = $VerbosePreference
    }
    return ( Test-AuditPolicySubcategory @auditPolicySubcategoryParameters )
}

Export-ModuleMember -Function *-TargetResource
