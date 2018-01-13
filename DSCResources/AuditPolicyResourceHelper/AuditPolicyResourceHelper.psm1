#Requires -Version 4.0

<#
    This PS module contains functions for Desired State Configuration (DSC) AuditPolicyDsc provider.
    It enables querying, creation, removal and update of Windows advanced audit policies through
    Get, Set, and Test operations on DSC managed nodes.
#>

<#
    .SYNOPSIS
        Retrieves the localized string data based on the machine's culture.
        Falls back to en-US strings if the machine's culture is not supported.

    .PARAMETER ResourceName
        The name of the resource as it appears before '.strings.psd1' of the localized string file.
        For example:
            AuditPolicySubcategory: MSFT_AuditPolicySubcategory
            AuditPolicyOption: MSFT_AuditPolicyOption
#>
function Get-LocalizedData
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true, ParameterSetName = 'resource')]
        [ValidateNotNullOrEmpty()]
        [String]
        $ResourceName,

        [Parameter(Mandatory = $true, ParameterSetName = 'helper')]
        [ValidateNotNullOrEmpty()]
        [String]
        $HelperName
    )

    # With the helper module just update the name and path variables as if it were a resource.
    if ($PSCmdlet.ParameterSetName -eq 'helper')
    {
        $resourceDirectory = $PSScriptRoot
        $ResourceName = $HelperName
    }
    else
    {
        # Step up one additional level to build the correct path to the resource culture.
        $resourceDirectory = Join-Path -Path ( Split-Path $PSScriptRoot -Parent ) `
                                       -ChildPath $ResourceName
    }

    $localizedStringFileLocation = Join-Path -Path $resourceDirectory -ChildPath $PSUICulture

    if (-not (Test-Path -Path $localizedStringFileLocation))
    {
        # Fallback to en-US
        $localizedStringFileLocation = Join-Path -Path $resourceDirectory -ChildPath 'en-US'
    }

    Import-LocalizedData `
        -BindingVariable 'localizedData' `
        -FileName "$ResourceName.strings.psd1" `
        -BaseDirectory $localizedStringFileLocation

    return $localizedData
}

#---------------------------------------------------------------------------------------------------
# Support functions to handle auditpol subcatgories

$script:localizedData = Get-LocalizedData -ResourceName 'AuditPolicyResourceHelper'

<#
    .SYNOPSIS
        Returns the current audit flag for the given subcategory.
    .PARAMETER Name
        Specifies the subcategory to retrieve.
    .PARAMETER AuditFlag
        Specifies the audit flag to retrieve.
#>
function Get-AuditPolicySubcategory
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

    try
    {
        $currentAuditFlag = Get-AuditSubcategoryFlag -Name $Name
        Write-Verbose -Message ( $localizedData.GetAuditpolSubcategorySucceed -f $Name, $AuditFlag )
    }
    catch
    {
        Write-Verbose -Message ( $localizedData.GetAuditPolSubcategoryFailed -f $Name, $AuditFlag )
    }

    <#
        The auditType property returned from Get-AuditSubcategoryFlag can be 'NoAuditing','Success',
        'Failure', or 'SuccessandFailure'. Using the match operator will return the correct
        state if both are set.
    #>
    if ( $currentAuditFlag -match $AuditFlag )
    {
        # The current audit flag can be SuccessandFailure, so only return the specifc flag we need.
        $currentAuditFlag = $AuditFlag
        $ensure = 'Present'
    }
    else
    {
        $ensure = 'Absent'
    }

    return @{
        Name      = $Name
        AuditFlag = $currentAuditFlag
        Ensure    = $ensure
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
    .PARAMETER ByGuid
        Forces the list if Subcategories to use GUIDs only.
#>
function Set-AuditPolicySubcategory
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
        $Ensure = 'Present',

        [Parameter()]
        [Switch]
        $ByGuid
    )

    if ( -Not ( Test-ValidSubcategory -Name $Name -ByGuid:$ByGuid ) )
    {
        if ($ByGuid)
        {
            $InvalidSubcategoryMessage = $localizedData.InvalidSubcategoryGuid -f $Name
        }
        else 
        {
            $InvalidSubcategoryMessage = $localizedData.InvalidSubcategory -f $Name
        }

        Throw $InvalidSubcategoryMessage
    }
    try
    {
        Set-AuditSubcategoryFlag -Name $Name -AuditFlag $AuditFlag -Ensure $Ensure
        Write-Verbose -Message ( $localizedData.SetAuditpolSubcategorySucceed `
                        -f $Name, $AuditFlag, $Ensure )
    }
    catch
    {
        Write-Verbose -Message ( $localizedData.SetAuditpolSubcategoryFailed `
                        -f $Name, $AuditFlag, $Ensure )
    }
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
    .PARAMETER ByGuid
        Forces the list if Subcategories to use GUIDs only.
#>
function Test-AuditPolicySubcategory
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
        $Ensure,

        [Parameter()]
        [Switch]
        $ByGuid
    )

    [Boolean] $isInDesiredState = $false

    if ( -Not ( Test-ValidSubcategory -Name $Name -ByGuid:$ByGuid ) )
    {
        if ( $ByGuid )
        {
            $InvalidSubcategoryMessage = $localizedData.InvalidSubcategoryGuid -f $Name
        }
        else 
        {
            $InvalidSubcategoryMessage = $localizedData.InvalidSubcategory -f $Name
        }

        Throw $InvalidSubcategoryMessage
    }

    try
    {
        [String] $currentAuditFlag = Get-AuditSubcategoryFlag -Name $Name
        Write-Verbose -Message ( $localizedData.GetAuditpolSubcategorySucceed -f $Name, $AuditFlag )
    }
    catch
    {
        Write-Verbose -Message ( $localizedData.GetAuditPolSubcategoryFailed -f $Name, $AuditFlag )
    }

    # If the setting should be present look for a match, otherwise look for a notmatch
    if ( $Ensure -eq 'Present' )
    {
        $isInDesiredState = $currentAuditFlag -match $AuditFlag
    }
    else
    {
        $isInDesiredState = $currentAuditFlag -notmatch $AuditFlag
    }

    <#
        The audit type can be true in either a match or non-match state. If the audit type
        matches the ensure property return the setting correct message, else return the
        setting incorrect message
    #>
    if ( $isInDesiredState )
    {
        Write-Verbose -Message ( $localizedData.TestAuditpolSubcategoryCorrect `
                        -f $Name, $AuditFlag, $Ensure )
    }
    else
    {
        Write-Verbose -Message ( $localizedData.TestAuditpolSubcategoryIncorrect `
                       -f $Name, $AuditFlag, $Ensure )
    }

    $isInDesiredState
}

#---------------------------------------------------------------------------------------------------
# Support functions to handle auditpol I/O

<#
 .SYNOPSIS
    Invoke-AuditPol is a private function that wraps auditpol.exe providing a
    centralized function to manage access to and the output of auditpol.exe.
 .DESCRIPTION
    The function will accept a string to pass to auditpol.exe for execution. Any 'get' or
    'set' opertions can be passed to the central wrapper to execute. All of the
    nuances of auditpol.exe can be further broken out into specalized functions that
    call Invoke-AuditPol.

    Since the call operator is being used to run auditpol, the input is restricted to only execute
    against auditpol.exe. Any input that is an invalid flag or parameter in
    auditpol.exe will return an error to prevent abuse of the call.
    The call operator will not parse the parameters, so they are split in the function.
 .PARAMETER Command
    The action that audtipol should take on the subcommand.
 .PARAMETER SubCommand
    The subcommand to execute.
 .OUTPUTS
    The raw string output of auditpol.exe with the /r switch to return a CSV string.
 .EXAMPLE
    Invoke-AuditPol -Command 'Get' -SubCommand 'Subcategory:Logon'
#>
function Invoke-AuditPol
{
    [OutputType([Object])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateSet('Get', 'Set', 'List','Restore','Backup')]
        [String]
        $Command,

        [Parameter(Mandatory = $true)]
        [String[]]
        $SubCommand
    )

    # Localized messages for Write-Verbose statements in this resource
    $localizedData = Get-LocalizedData -HelperName 'AuditPolicyResourceHelper'
    <#
        The raw auditpol data with the /r switch is a 3 line CSV
        0 - header row
        1 - blank row
        2 - the data row we are interested in
    #>

    # set the base commands to execute
    if ( $Command -eq 'Get')
    {
        $auditpolArguments = @("/$Command","/$SubCommand","/r" )
    }
    else
    {
        # The set subcommand comes in an array of the subcategory and flag
        $auditpolArguments = @("/$Command","/$($SubCommand[0])",$SubCommand[1] )
    }

    Write-Debug -Message ( $localizedData.ExecuteAuditpolCommand -f $auditpolArguments )

    try
    {
        # Use System.Diagnostics.Process to process the auditpol command
        $process = New-Object System.Diagnostics.Process
        $process.StartInfo.Arguments = $auditpolArguments
        $process.StartInfo.CreateNoWindow = $true
        $process.StartInfo.FileName = 'auditpol.exe'
        $process.StartInfo.RedirectStandardOutput = $true
        $process.StartInfo.UseShellExecute = $false
        $null = $process.Start()

        $auditpolReturn = $process.StandardOutput.ReadToEnd()

        # auditpol does not throw exceptions, so test the results and throw if needed
        if ( $process.ExitCode -ne 0 )
        {
            throw New-Object System.ArgumentException
        }

        if ( $Command -notmatch "Restore|Backup" )
        {
            return ( ConvertFrom-Csv -InputObject $auditpolReturn )
        }
    }
    catch [System.ComponentModel.Win32Exception]
    {
        # Catch error if the auditpol command is not found on the system
        Write-Error -Message $localizedData.AuditpolNotFound
    }
    catch [System.ArgumentException]
    {
        # Catch the error thrown if the lastexitcode is not 0
        [String] $errorString = $error[0].Exception
        $errorString = $errorString + "`$LASTEXITCODE = $LASTEXITCODE;"
        $errorString = $errorString + " Command = auditpol $commandString"
        Write-Error -Message $errorString
    }
    catch
    {
        # Catch any other errors
        Write-Error -Message ( $localizedData.UnknownError -f $error[0] )
    }
}

<#
    .SYNOPSIS
        Gets the audit flag state for a specifc subcategory.
    .DESCRIPTION
        This function enforces parameters that will be passed to Invoke-Auditpol.
    .PARAMETER Name
        The name of the subcategory to get the audit flags from.
    .OUTPUTS
        A string with the flags that are set for the specificed subcategory
    .EXAMPLE
        Get-AuditSubcategoryFlag -Name 'Logon'
#>
function Get-AuditSubcategoryFlag
{
    [CmdletBinding()]
    [OutputType([String])]
    param
    (
        [Parameter(Mandatory = $true)]
        [String]
        $Name
    )
    <#
        When PowerShell cmdlets are released for individual audit policy settings a condition
        will be placed here to use native PowerShell cmdlets to set the subcategory flags.
    #>
    # get the auditpol raw csv output
    $subcategory = Invoke-AuditPol -Command 'Get' -SubCommand "Subcategory:""$Name"""

    # The subcategory flag is stored in the 'Inclusion Setting' property of the output CSV.
    return $subcategory.'Inclusion Setting'
}

<#
    .SYNOPSIS
        Sets the audit flag state for a specifc subcategory.
    .DESCRIPTION
        Calls the private function to execute a set operation on the given subcategory
    .PARAMETER Name
        The name of the audit subcategory to set
    .PARAMETER AuditFlag
        The specifc flag to set (Success|Failure)
    .PARAMETER Ensure
        The action to take on the flag
    .EXAMPLE
        Set-AuditSubcategoryFlag -Name 'Logon' -AuditFlag 'Success' -Ensure 'Present'
#>
function Set-AuditSubcategoryFlag
{
    [CmdletBinding(SupportsShouldProcess = $true)]
    param
    (
        [Parameter(Mandatory = $true)]
        [String]
        $Name,

        [Parameter(Mandatory = $true)]
        [ValidateSet( 'Success','Failure' )]
        [String]
        $AuditFlag,

        [Parameter(Mandatory = $true)]
        [String]
        $Ensure
    )
    <#
        When PowerShell cmdlets are released for individual audit policy settings a condition
        will be placed here to use native PowerShell cmdlets to set the option details.
    #>
    if ( $pscmdlet.ShouldProcess( "$Name","Set AuditFlag '$AuditFlag'" ) )
    {
        # translate $ensure=present to enable and $ensure=absent to disable
        $auditState = @{
            'Present' = 'enable'
            'Absent'  = 'disable'
        }

        # Create the line needed for auditpol to set the category flag
        if ( $AuditFlag -eq 'Success' )
        {
            [String[]] $subcommand = @( "Subcategory:""$Name""", "/success:$($auditState[$Ensure])" )
        }
        else
        {
            [String[]] $subcommand = @( "Subcategory:""$Name""", "/failure:$($auditState[$Ensure])" )
        }

        Invoke-AuditPol -Command 'Set' -subCommand $subcommand | Out-Null
    }
}

<#
    .SYNOPSIS
        Returns a hash table of valid subcategories and associated GUID.
    .DESCRIPTION
        This funciton will check if the hashtable has already been created. If the hashtable exists 
        it will simply return it. If it does not exist, it will generate it and return it.
#>
function Get-ValidSubcategoryList
{
    [OutputType([PsObject])]
    [CmdletBinding()]
    param()

    if ( $null -eq $script:validSubcategoryList )
    {
        $script:validSubcategoryList = Invoke-AuditPol -Command Get -SubCommand "category:*"
    }

    return $script:validSubcategoryList
}

<#
    .SYNOPSIS
        Verifies that the Subcategory is valid.
    .PARAMETER Name
        The name of the Subcategory to validate.
    .PARAMETER ByGuid
        A switch to lookup the subcategory by its GUID.
#>
function Test-ValidSubcategory
{
    [OutputType([Boolean])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [String]
        $Name,

        [Parameter()]
        [Switch]
        $ByGuid
    )

    if ( $ByGuid )
    {
        [string[]] $validSubcategoryList = ( Get-ValidSubcategoryList ).'Subcategory GUID'
    }
    else
    {
        [string[]] $validSubcategoryList = ( Get-ValidSubcategoryList ).Subcategory
    }
    
    if ( $validSubcategoryList -icontains "$Name" )
    {
        return $true
    }
    else
    {
        return $false
    }
}

Export-ModuleMember -Function @( 
    'Invoke-AuditPol', 'Get-LocalizedData', 'Test-ValidSubcategory',
    '*-AuditPolicySubcategory'
)
