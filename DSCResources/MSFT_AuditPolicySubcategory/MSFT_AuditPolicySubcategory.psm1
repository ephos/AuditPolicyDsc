Import-Module -Name (Join-Path -Path ( Split-Path $PSScriptRoot -Parent ) `
                               -ChildPath 'AuditPolicyResourceHelper\AuditPolicyResourceHelper.psm1') `
                               -Force

# Localized messages for Write-Verbose statements in this resource
$script:localizedData = Get-LocalizedData -ResourceName 'MSFT_AuditPolicySubcategory'

<#
    .SYNOPSIS
        Returns the current audit flag for the given subcategory.
    .PARAMETER Name
        Specifies the subcategory to retrieve by localized friendly name.
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
        $Name,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Success', 'Failure')]
        [String]
        $AuditFlag
    )

    $auditPolicySubcategoryParameters = @{
        Name      = $Name
        AuditFlag = $AuditFlag
        Verbose   = $VerbosePreference
    }

    $auditPolicySubcategory = Get-AuditPolicySubcategory @auditPolicySubcategoryParameters

    return @{
        Name      = $auditPolicySubcategory.Name
        AuditFlag = $auditPolicySubcategory.AuditFlag
        Ensure    = $auditPolicySubcategory.Ensure
    }
}

<#
    .SYNOPSIS
        Sets the audit flag for the given subcategory.
    .PARAMETER Name
        Specifies the subcategory to set by localized friendly name.
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
        $Name,

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
        Name = $Name
        AuditFlag = $AuditFlag
        Ensure = $Ensure
        Verbose = $VerbosePreference
        ByGuid  = $false
    }

    Set-AuditPolicySubcategory @auditPolicySubcategoryParameters
}

<#
    .SYNOPSIS
        Tests the audit flag state for the given subcategory.
    .PARAMETER Name
        Specifies the subcategory to test by localized friendly name.
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
        $Name,

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
        Name = $Name
        AuditFlag = $AuditFlag
        Ensure = $Ensure
        Verbose = $VerbosePreference
        ByGuid  = $false
    }

    return ( Test-AuditPolicySubcategory @auditPolicySubcategoryParameters )
}

Export-ModuleMember -Function *-TargetResource
