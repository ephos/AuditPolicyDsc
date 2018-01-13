#requires -RunAsAdministrator

# Get the root path of the resourse
[String] $script:moduleRoot = Split-Path -Parent ( Split-Path -Parent $PSScriptRoot )

Import-Module -Name (Join-Path -Path $moduleRoot `
                               -ChildPath 'DSCResources\AuditPolicyResourceHelper\AuditPolicyResourceHelper.psm1' ) `
                               -Force
InModuleScope AuditPolicyResourceHelper {
    Describe 'Prerequisites' {

        # There are several dependencies for both Pester and AuditPolicyDsc that need to be validated.
        It "Should be running as admin" {
            # The tests need to run as admin to have access to the auditpol data
            ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
            [Security.Principal.WindowsBuiltInRole] "Administrator") | Should Be $true
        }

        It "Should find auditpol.exe in System32" {
            # If the auditpol is not located on the system, the entire module will fail
            Test-Path "$env:SystemRoot\system32\auditpol.exe" | Should Be $true
        }
    }

    Describe 'Get-AuditPolicySubcategory' {

        It 'Should return the correct hashtable properties' {
            Mock -CommandName Get-AuditSubcategoryFlag -MockWith { 'SuccessandFailure' }
            $script:getTargetResourceResult = Get-AuditPolicySubcategory -Name 'Logon' -AuditFlag 'Success'
            $script:getTargetResourceResult.Name      | Should Be 'Logon'
            $script:getTargetResourceResult.AuditFlag | Should Be 'Success'
            $script:getTargetResourceResult.Ensure    | Should Be 'Present'
        }

        It 'Should return the correct hashtable properties' {
            Mock -CommandName Get-AuditSubcategoryFlag -MockWith { 'Success' }
            $script:getTargetResourceResult = Get-AuditPolicySubcategory -Name 'Logon' -AuditFlag 'Success'
            $script:getTargetResourceResult.Name      | Should Be 'Logon'
            $script:getTargetResourceResult.AuditFlag | Should Be 'Success'
            $script:getTargetResourceResult.Ensure    | Should Be 'Present'
        }

        It 'Should return the correct hashtable properties' {
            Mock -CommandName Get-AuditSubcategoryFlag -MockWith { 'Failure' }
            $script:getTargetResourceResult = Get-AuditPolicySubcategory -Name 'Logon' -AuditFlag 'Success'
            $script:getTargetResourceResult.Name      | Should Be 'Logon'
            $script:getTargetResourceResult.AuditFlag | Should Be 'Failure'
            $script:getTargetResourceResult.Ensure    | Should Be 'Absent'
        }

        It 'Should return the correct hashtable properties' {
            Mock -CommandName Get-AuditSubcategoryFlag -MockWith { 'NoAuditing' }
            $script:getTargetResourceResult = Get-AuditPolicySubcategory -Name 'Logon' -AuditFlag 'Success'
            $script:getTargetResourceResult.Name      | Should Be 'Logon'
            $script:getTargetResourceResult.AuditFlag | Should Be 'Failure'
            $script:getTargetResourceResult.Ensure    | Should Be 'Absent'
        }
    }

    Describe 'Set-AuditPolicySubcategory' {

        It 'Should throw when invalid subcategory is provided' {
            Mock -CommandName Test-ValidSubcategory -MockWith { $false }
            {Set-AuditPolicySubcategory -Name 'Invalid' -AuditFlag 'Success' } | Should Throw
        }

        It 'Should call Set-AuditSubcategoryFlag to set the configuration' {
            Mock -CommandName Test-ValidSubcategory -MockWith { $true }
            Mock -CommandName Set-AuditSubcategoryFlag -MockWith {}
            Set-AuditPolicySubcategory -Name logon -AuditFlag Success -Ensure Present
            Assert-MockCalled -CommandName Set-AuditSubcategoryFlag -Exactly 1
        }
    }

    Describe 'Test-AuditPolicySubcategory' {

        It 'Should throw when invalid subcategory is provided' {
            Mock -CommandName Test-ValidSubcategory -MockWith { $false }
            {Test-AuditPolicySubcategory -Name 'Invalid' -AuditFlag 'Success' } | Should Throw
        }

        Context 'In Desired State by Name' {

            $tests = @(
                @{
                    AuditFlagMock = 'Success'
                    AuditFlag = 'Success'
                    Ensure = 'Present'
                },
                @{
                    AuditFlagMock = 'SuccessandFailure'
                    AuditFlag = 'Success'
                    Ensure = 'Present'
                },
                @{
                    AuditFlagMock = 'Failure'
                    AuditFlag = 'Success'
                    Ensure = 'Absent'
                },
                @{
                    AuditFlagMock = 'NoAuditing'
                    AuditFlag = 'Success'
                    Ensure = 'Absent'
                }
            )
            Mock -CommandName Test-ValidSubcategory -MockWith { $true }

            foreach ( $test in $tests )
            {
                It "Should be in desired state when Ensure $($test.AuditFlag) is $($test.Ensure) with the system set to $($test.AuditFlagMock)" {
                    Mock -CommandName Get-AuditSubcategoryFlag -MockWith { $test.AuditFlagMock }
                    Test-AuditPolicySubcategory -Name 'Logon' -AuditFlag $test.AuditFlag -Ensure $test.Ensure | Should Be $true
                }
            }
        }

        Context 'Not in Desired State by Name' {
            $tests = @(
                @{
                    AuditFlagMock = 'Failure'
                    AuditFlag = 'Success'
                    Ensure = 'Present'
                },
                @{
                    AuditFlagMock = 'NoAuditing'
                    AuditFlag = 'Success'
                    Ensure = 'Present'
                },
                @{
                    AuditFlagMock = 'Success'
                    AuditFlag = 'Success'
                    Ensure = 'Absent'
                },
                @{
                    AuditFlagMock = 'SuccessandFailure'
                    AuditFlag = 'Success'
                    Ensure = 'Absent'
                }
            )
            Mock -CommandName Test-ValidSubcategory -MockWith { $true }

            foreach ( $test in $tests )
            {
                It "Should NOT be in desired state when Ensure $($test.AuditFlag) is $($test.Ensure) with the system set to $($test.AuditFlagMock)" {
                    Mock -CommandName Get-AuditSubcategoryFlag -MockWith { $test.AuditFlagMock }
                    Test-AuditPolicySubcategory -Name 'Logon' -AuditFlag $test.AuditFlag -Ensure $test.Ensure | Should Be $false
                }
            }
        }
    }

    Describe "Invoke-Auditpol" {

        Context 'Subcategory and Option' {

            # These tests verify that an object is returned from Invoke-Auditpol
            It 'Should return an object when a single word subcategory is passed in' {
                $subcategory = Invoke-Auditpol -Command "Get" -SubCommand "Subcategory:Logoff"
                $subcategory.Subcategory         | Should Be 'Logoff'
                $subcategory.'Subcategory GUID'  | Should Be '{0CCE9216-69AE-11D9-BED3-505054503030}'
                $subcategory.'Inclusion Setting' | Should Match 'Success|Failure|No Auditing|Success and Failure'
            }

            It 'Should return an object when a multi-word subcategory is passed in' {
                $subcategory = Invoke-Auditpol -Command "Get" -SubCommand "Subcategory:""Credential Validation"""
                $subcategory.Subcategory         | Should Be 'Credential Validation'
                $subcategory.'Subcategory GUID'  | Should Be '{0CCE923F-69AE-11D9-BED3-505054503030}'
                $subcategory.'Inclusion Setting' | Should Match 'Success|Failure|No Auditing|Success and Failure'
            }

            It 'Should return an object when an option is passed in' {
                $option = Invoke-Auditpol -Command "Get" -SubCommand "option:CrashOnAuditFail"
                $option.Subcategory         | Should Be 'option:CrashOnAuditFail'
                $option.'Subcategory GUID'  | Should BeNullOrEmpty
                $option.'Inclusion Setting' | Should Match 'Disabled|Enabled'
            }
        }

        Context 'Backup' {

            $script:path = ([system.IO.Path]::GetTempFileName()).Replace('tmp','csv')

            It 'Should be able to call Invoke-Audtipol with backup and not throw' {
                {$script:auditpolBackupReturn = Invoke-AuditPol -Command 'Backup' `
                                                                -SubCommand "file:$script:path"} |
                    Should Not Throw
            }

            It 'Should not return anything when a backup is requested' {
                $script:auditpolBackupReturn | Should BeNullOrEmpty
            }

            It 'Should produce a valid CSV in a temp file when the backup switch is used' {
                (Get-Content -Path $script:path)[0] |
                    Should BeExactly "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value"
            }
        }

        Context 'Restore' {

            It 'Should be able to call Invoke-Audtipol with backup and not throw' {
                {$script:auditpolRestoreReturn = Invoke-AuditPol -Command 'Restore' `
                                                                    -SubCommand "file:$script:path"} |
                    Should Not Throw
            }

            It 'Should not return anything when a restore is requested' {
                $script:auditpolRestoreReturn | Should BeNullOrEmpty
            }
        }
    }

    Describe 'Get-AuditSubcategoryFlag' {

        $contextList = @(
            @{
                'Title'               = 'Get single word audit category success flag'
                'TestSubcategory'     = 'Logon'
                'TestSubcategoryGuid' = '{0CCE9215-69AE-11D9-BED3-505054503030}'
                'TestAuditFlag'       = 'Success'
            },
            @{
                'Title'               = 'Get single word audit category failure flag'
                'TestSubcategory'     = 'Logon'
                'TestSubcategoryGuid' = '{0CCE9215-69AE-11D9-BED3-505054503030}'
                'TestAuditFlag'       = 'Failure'
            },
            @{
                'Title'               = 'Get multi word audit category success flag'
                'TestSubcategory'     = 'Credential Validation'
                'TestSubcategoryGuid' = '{0CCE923F-69AE-11D9-BED3-505054503030}'
                'TestAuditFlag'       = 'Success'
            },
            @{
                'Title'               = 'Get multi word audit category success flag'
                'TestSubcategory'     = 'Credential Validation'
                'TestSubcategoryGuid' = '{0CCE923F-69AE-11D9-BED3-505054503030}'
                'TestAuditFlag'       = 'Failure'
            }
        )

        foreach ($context in $contextList)
        {
            Context $context.Title {

                Mock -CommandName Invoke-Auditpol -MockWith {
                    @{
                        'Machine Name'      = $env:COMPUTERNAME
                        'Policy Target'     = 'System'
                        'Subcategory'       = $context.TestSubcategory
                        'Subcategory GUID'  = $context.TestSubcategoryGuid
                        'Inclusion Setting' = $context.TestAuditFlag
                        'Exclusion Setting' = ''
                    }
                } -ParameterFilter { $Command -eq 'Get' } -Verifiable

                It 'Should not throw an exception using the name' {
                    { $script:getAuditCategoryResult = Get-AuditSubcategoryFlag -Name $context.TestSubcategory } |
                        Should Not Throw
                    Assert-VerifiableMocks
                    Assert-MockCalled -CommandName Invoke-Auditpol -Exactly 1 -Scope It
                }

                It 'Should return the correct audit flag' {
                    $script:getAuditCategoryResult | Should Be $context.TestAuditFlag
                }

                It 'Should not throw an exception using the GUID' {
                    { $script:getAuditCategoryResult = Get-AuditSubcategoryFlag -Name $context.TestSubcategoryGuid } |
                        Should Not Throw
                    Assert-VerifiableMocks
                    Assert-MockCalled -CommandName Invoke-Auditpol -Exactly 1 -Scope It 
                }

                It 'Should return the correct audit flag' {
                    $script:getAuditCategoryResult | Should Be $context.TestAuditFlag
                }
            }
        }
    }

    Describe 'Set-AuditSubcategoryFlag' {

        $contextList = @(
            @{
                'Title'               = 'Set single word audit category Success flag to Present'
                'TestSubcategory'     = 'Logon'
                'TestSubcategoryGuid' = '{0CCE9215-69AE-11D9-BED3-505054503030}'
                'TestAuditFlag'       = 'Success'
                'TestEnsure'          = 'Present'
            },
            @{
                'Title'               = 'Set single word audit category Success flag to Absent'
                'TestSubcategory'     = 'Logon'
                'TestSubcategoryGuid' = '{0CCE9215-69AE-11D9-BED3-505054503030}'
                'TestAuditFlag'       = 'Success'
                'TestEnsure'          = 'Absent'
            },
            @{
                'Title'               = 'Set multi-word audit category Success flag to Present'
                'TestSubcategory'     = 'Credential Validation'
                'TestSubcategoryGuid' = '{0CCE923F-69AE-11D9-BED3-505054503030}'
                'TestAuditFlag'       = 'Success'
                'TestEnsure'          = 'Present'
            },
            @{
                'Title'               = 'Set multi-word audit category Success flag to Absent'
                'TestSubcategory'     = 'Credential Validation'
                'TestSubcategoryGuid' = '{0CCE923F-69AE-11D9-BED3-505054503030}'
                'TestAuditFlag'       = 'Success'
                'TestEnsure'          = 'Absent'
            }
        )

        foreach ( $context in $contextList )
        {
            Context $context.Title { 

                $comamnd = @{
                    Name      = $context.TestSubcategory
                    AuditFlag = $context.TestAuditFlag
                    Ensure    = $context.TestEnsure
                }
    
                Mock -CommandName Invoke-Auditpol -MockWith { } -ParameterFilter {
                    $Command -eq 'Set' } -Verifiable
    
                It 'Should not throw when setting by Name' {
                    { Set-AuditSubcategoryFlag @comamnd } | Should Not Throw
                    Assert-VerifiableMocks
                    Assert-MockCalled -CommandName Invoke-Auditpol -Exactly 1 -Scope It
                }

                $comamnd = @{
                    Name      = $context.TestSubcategoryGuid
                    AuditFlag = $context.TestAuditFlag
                    Ensure    = $context.TestEnsure
                }

                It 'Should not throw when setting by GUID' {
                    { Set-AuditSubcategoryFlag @comamnd } | Should Not Throw
                    Assert-VerifiableMocks
                    Assert-MockCalled -CommandName Invoke-Auditpol -Exactly 1 -Scope It
                }
            }
        }
    }

    Describe 'Get-ValidSubcategoryList' {
        <# 
            Get-ValidSubcategoryList generates the list once by calling Invoke-Auditpol and sets 
            it to a script scoped varaible. If the vaiarbel is populated, Invoke-Auditpol is not
            called so this test will fail if run multiple times witout the BeforeEach block. 
        #>
        BeforeEach {
            Remove-Variable validSubcategoryList -Scope 'Script' -ErrorAction SilentlyContinue
        }

        It 'Should invoke auditpol to get the list of valid subcategory names' {
            Mock -CommandName Invoke-Auditpol -MockWith { } -ParameterFilter {
                $Command -eq 'Get' -and $SubCommand -eq "category:*" } -Verifiable

            Get-ValidSubcategoryList | Out-Null
            Assert-VerifiableMocks
            Assert-MockCalled -CommandName Invoke-Auditpol -Exactly 1 -Scope It
        }
    }

    Describe 'Test-ValidSubcategory' {
        # Test-ValidSubcategory is exported, but it calls a private function, so InModuleScope is needed.
        
        $validSubcategoryListReturn = @{
            'Subcategory' = @('logon','logoff')
            'Subcategory GUID' = @('{0CCE9215-69AE-11D9-BED3-505054503030}','{0CCE9216-69AE-11D9-BED3-505054503030}')
        }

        $contextList = @(
            @{
                'Title'  = 'Valid Name'
                'Name'   = 'logon'
                'Return' = $true
                'ByGuid' = $false
            },
            @{
                'Title'  = 'Invalid Name'
                'Name'   = 'invalid'
                'Return' = $false
                'ByGuid' = $false
            },
            @{
                'Title'  = 'Valid GUID'
                'Name'   = '{0CCE9215-69AE-11D9-BED3-505054503030}'
                'Return' = $true
                'ByGuid' = $true
            },
            @{
                'Title'  = 'Invalid GUID'
                'Name'   = '{0CCE9215-69AE-11D9-BED3-50505450ABCD}'
                'Return' = $false
                'ByGuid' = $true
            }
        )

        foreach ($context in $contextList)
        {
            Context $context.Title {

                Mock -CommandName Get-ValidSubcategoryList -MockWith {$validSubcategoryListReturn}
        
                It 'Should not throw an ex ception' {
                    { $script:testValidSubcategoryResult = Test-ValidSubcategory -Name $context.Name -ByGuid:$context.ByGuid  } |
                        Should Not Throw
                }
        
                It "Should return $($context.Return)" {
                    $script:testValidSubcategoryResult | Should Be $context.Return
                }
            }
        }
    }
}
