$script:DSCModuleName   = 'AuditPolicyDsc'
$script:DSCResourceName = 'MSFT_AuditPolicySubcategoryGuid'

#region HEADER
[String] $script:moduleRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $script:MyInvocation.MyCommand.Path))
if ( (-not (Test-Path -Path (Join-Path -Path $moduleRoot -ChildPath 'DSCResource.Tests'))) -or `
     (-not (Test-Path -Path (Join-Path -Path $moduleRoot -ChildPath 'DSCResource.Tests\TestHelper.psm1'))) )
{
    & git @('clone','https://github.com/PowerShell/DscResource.Tests.git',(Join-Path -Path $moduleRoot -ChildPath '\DSCResource.Tests\'))
}
else
{
    & git @('-C',(Join-Path -Path $moduleRoot -ChildPath '\DSCResource.Tests\'),'pull')
}
Import-Module (Join-Path -Path $moduleRoot -ChildPath 'DSCResource.Tests\TestHelper.psm1') -Force
$TestEnvironment = Initialize-TestEnvironment `
    -DSCModuleName $script:DSCModuleName `
    -DSCResourceName $script:DSCResourceName `
    -TestType Unit
#endregion

# Begin Testing
try
{
    #region Pester Tests

    InModuleScope -ModuleName $script:DSCResourceName {
        
        $id = '{0CCE9215-69AE-11D9-BED3-505054503030}'

        Describe "$($script:DSCResourceName)\Get-TargetResource" {
    
            $getTestData = @(
                @{
                    title          = "Subcategory guid submit 'Success' and return 'Success'"
                    id             = $id
                    AuditFlag      = 'Success'
                    AuditFlagState = 'Success'
                    Ensure         = 'Present'
                },
                @{
                    title          = "Subcategory guid submit 'Success' and return 'SuccessandFailure'"
                    id             = $id
                    AuditFlag      = 'Success'
                    AuditFlagState = 'SuccessandFailure'
                    Ensure         = 'Present'
                },
                @{
                    title          = "Subcategory guid submit 'Success' and return 'Failure'"
                    id             = $id
                    AuditFlag      = 'Success'
                    AuditFlagState = 'Failure'
                    Ensure         = 'Absent'
                },
                @{
                    title          = "Subcategory guid submit 'Success' and return 'NoAuditing'"
                    id             = $id
                    AuditFlag      = 'Success'
                    AuditFlagState = 'NoAuditing'
                    Ensure         = 'Absent'
                },
                @{
                    title          = "Subcategory guid submit 'Failure' and return 'Failure'"
                    id             = $id
                    AuditFlag      = 'Failure'
                    AuditFlagState = 'Failure'
                    Ensure         = 'Present'
                },
                @{
                    title          = "Subcategory guid submit 'Failure' and return 'SuccessandFailure'"
                    id             = $id
                    AuditFlag      = 'Failure'
                    AuditFlagState = 'SuccessandFailure'
                    Ensure         = 'Present'
                },
                @{
                    title          = "Subcategory guid submit 'Failure' and return 'NoAuditing'"
                    id             = $id
                    AuditFlag      = 'Failure'
                    AuditFlagState = 'NoAuditing'
                    Ensure         = 'Absent'
                },
                @{
                    title          = "Subcategory guid submit 'Failure' and return 'Success'"
                    id             = $id
                    AuditFlag      = 'Failure'
                    AuditFlagState = 'Success'
                    Ensure         = 'Absent'
                }
            )

            foreach ($test in $getTestData)
            {
                Context $test.title {
                    
                    Mock -CommandName Get-AuditPolicySubcategory -MockWith { return @{
                            Name = $test.id
                            AuditFlag = $test.AuditFlag
                            Ensure = $test.ensure
                        } 
                    } 
                    
                    $testParameters = @{
                        Id        = $test.id
                        AuditFlag = $test.AuditFlag
                    }

                    It 'Should not throw an exception' {
                        { $script:getTargetResourceResult = Get-TargetResource @testParameters } |
                            Should Not Throw
                    }
    
                    It 'Should return the correct hashtable properties' {
                        $script:getTargetResourceResult.Id        | Should Be $test.id
                        $script:getTargetResourceResult.AuditFlag | Should Be $test.AuditFlag
                        $script:getTargetResourceResult.Ensure    | Should Be $test.Ensure
                    }
    
                    It 'Should call expected Mocks' {
                        Assert-MockCalled -CommandName Get-AuditPolicySubcategory -Exactly 1 -Scope Context
                    }
                }
            }
        }
 
        Describe "$($script:DSCResourceName)\Test-TargetResource" {

            Mock -CommandName Test-ValidSubcategory -MockWith { return $true } `
                 -ModuleName AuditPolicyResourceHelper

            $testParameters = @{
                Id        = 'Invalid'
                AuditFlag = 'Success'
                Ensure    = 'Present'
            }

            Context 'Invalid subcategory' {
                Mock -CommandName Test-ValidSubcategory -MockWith { return $false } `
                -ModuleName AuditPolicyResourceHelper

                Mock -CommandName Get-AuditPolicySubcategory -MockWith { } 

                It 'Should throw an exception' {
                    { Get-TargetResource @testParameters } |
                        Should Throw
                }

                It 'Should NOT call expected Mocks' {
                    Assert-MockCalled -CommandName Get-AuditPolicySubcategory -Times 0
                }
            }

            $testTestData = @(
                @{
                    Title      = "Subcategory guid Success flag present and should be"
                    Id         = $id
                    AuditFlag  = 'Success'
                    Ensure     = 'Present'
                    ReturnFlag = $true
                },
                @{
                    Title      = "Subcategory guid Success flag present and should not be"
                    Id         = $id
                    AuditFlag  = 'Success'
                    Ensure     = 'Absent'
                    ReturnFlag = $false
                },
                @{
                    Title      = "Subcategory guid failure flag present and should be"
                    Id         = $id
                    AuditFlag  = 'Failure'
                    Ensure     = 'Present'
                    ReturnFlag = $true
                },
                @{
                    Title      = "Subcategory guid failure flag present and should not be"
                    Id         = $id
                    AuditFlag  = 'Failure'
                    Ensure     = 'Absent'
                    ReturnFlag = $false
                }
            )
            
            foreach ($test in $testTestData)
            {
                Context $test.Title {

                    Mock -CommandName Test-AuditPolicySubcategory -MockWith { return $test.ReturnFlag } `
                         -ParameterFilter {
                            $Name      -eq $test.Id -and
                            $AuditFlag -eq $test.AuditFlag -and
                            $Ensure    -eq $test.Ensure -and
                            $ByGuid    -eq $true
                         }
                    
                    $testParameters = @{
                        Id        = $test.Id
                        AuditFlag = $test.AuditFlag
                        Ensure    = $test.Ensure
                    }

                    It 'Should not throw an exception' {
                        { $script:testTargetResourceResult = Test-TargetResource @testParameters } |
                            Should Not Throw
                    }
    
                    It "Should return $($test.ReturnFlag)" {
                        $script:testTargetResourceResult | Should Be $test.ReturnFlag
                    }
    
                    It 'Should call expected Mocks with correct parameters' {
                        Assert-MockCalled -CommandName Test-AuditPolicySubcategory -Exactly 1 -Scope Context
                    }
                }
            }
        }

        Describe "$($script:DSCResourceName)\Set-TargetResource" {

            Mock -CommandName Test-ValidSubcategory -MockWith { return $true } `
                 -ModuleName AuditPolicyResourceHelper

            $setTestData = @(
                @{
                    Title     = "Set Subcategory guid success flag to present"
                    Id        = $id
                    AuditFlag = 'Success'
                    Ensure    = 'Present'
                },
                @{
                    Title     = "Set Subcategory guid success flag to absent"
                    Id        = $id
                    AuditFlag = 'Success'
                    Ensure    = 'Absent'
                },
                @{
                    Title     = "Set Subcategory guid failure flag to present"
                    Id        = $id
                    AuditFlag = 'Failure'
                    Ensure    = 'Present'
                },
                @{
                    Title     = "Set Subcategory guid failure flag to absent"
                    Id        = $id
                    AuditFlag = 'Failure'
                    Ensure    = 'Absent'
                }
            )

            foreach ($test in $setTestData)
            {
                Context $test.Title {
                    
                    $testParameters = @{
                        Id        = $test.Id
                        AuditFlag = $test.AuditFlag
                        Ensure    = $test.Ensure
                    }

                    Mock -CommandName Set-AuditPolicySubcategory -MockWith { } -ParameterFilter {
                        $Name -eq $test.id -and
                        $AuditFlag -eq $test.AuditFlag -and
                        $Ensure -eq $test.Ensure
                    }
    
                    It 'Should not throw an exception' {
                        { Set-TargetResource @testParameters } | Should Not Throw
                    }
    
                    It 'Should call expected Mocks with correct parameters' {
                        Assert-MockCalled -CommandName Set-AuditPolicySubcategory -Exactly 1 -Scope Context
                    }
                }
            }
        }
    }
    #endregion
}
finally
{
    #region FOOTER
    Restore-TestEnvironment -TestEnvironment $TestEnvironment
    #endregion
}
