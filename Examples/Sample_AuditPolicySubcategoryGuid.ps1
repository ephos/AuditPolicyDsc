<#
    This example will set the Logon (by GUID) Success and Failure flags on the localhost.
    To use this example, run it using PowerShell.
#>
Configuration Sample_AuditSubcategoryGuid
{
    param
    (
        [String] $NodeName = 'localhost'
    )

    Import-DscResource -ModuleName AuditPolicyDsc

    Node $NodeName
    {
        AuditPolicySubcategory LogonSuccess
        {
            Name      = '{0CCE9215-69AE-11D9-BED3-505054503030}'
            AuditFlag = 'Success'
            Ensure    = 'Absent'
        }

        AuditPolicySubcategory LogonFailure
        {
            Name      = '{0CCE9215-69AE-11D9-BED3-505054503030}'
            AuditFlag = 'Failure'
            Ensure    = 'Present'
        }
    }
}

Sample_AuditSubcategoryGuid
