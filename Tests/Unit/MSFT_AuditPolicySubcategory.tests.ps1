
$Global:DSCModuleName      = 'AuditPolicyDsc'
$Global:DSCResourceName    = 'MSFT_AuditPolicySubcategory'

#region HEADER
[String] $moduleRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $Script:MyInvocation.MyCommand.Path))
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
    -DSCModuleName $Global:DSCModuleName `
    -DSCResourceName $Global:DSCResourceName `
    -TestType Unit 
#endregion

# Begin Testing
try
{
    #region Pester Tests

    # The InModuleScope command allows you to perform white-box unit testing on the internal
    # (non-exported) code of a Script Module.
    InModuleScope $Global:DSCResourceName {

        #region Pester Test Initialization
        # the audit option to use in the tests
        $Subcategory   = 'Credential Validation'
        $AuditFlag     = 'Failure'
        $MockAuditFlags = 'Success','Failure','SuccessandFailure','NoAuditing'
        $AuditFlagSwap = @{'Failure'='Success';'Success'='Failure'}
        #endregion


        #region Function Get-TargetResource
        Describe "$($Global:DSCResourceName)\Get-TargetResource" {
            
            Context "Return object " {
                
                # mock call to the helper module to isolate Get-TargetResource
                Mock Get-AuditCategory { return @{'Name'=$Subcategory;'AuditFlag'=$AuditFlag} } -ModuleName MSFT_AuditPolicySubcategory

                $Get = Get-TargetResource -Subcategory $Subcategory -AuditFlag $AuditFlag

                    It " is a hashtable that has the following keys:" {
                        $isHashtable = $Get.GetType().Name -eq 'hashtable'

                        $isHashtable | Should Be $true
                    }
            
                    It "  Subcategory" {
                        $ContainsSubcategoryKey = $Get.ContainsKey('Subcategory') 
                
                        $ContainsSubcategoryKey | Should Be $true
                    }

                    It "  AuditFlag" {
                        $ContainsAuditFlagKey = $Get.ContainsKey('AuditFlag') 
                
                        $ContainsAuditFlagKey | Should Be $true
                    }

                    It "  Ensure" {
                        $ContainsEnsureKey = $Get.ContainsKey('Ensure') 
                
                        $ContainsEnsureKey| Should Be $true
                    }
            }

            Context "Submit '$AuditFlag' and return '$AuditFlag'" {

                # mock call to the helper module to isolate Get-TargetResource
                Mock Get-AuditCategory { return $AuditFlag } -ModuleName MSFT_AuditPolicySubcategory

                $Get = Get-TargetResource -Subcategory $Subcategory -AuditFlag $AuditFlag

                It " 'Subcategory' = '$Subcategory'" {
                    $RetrievedSubcategory =  $Get.Subcategory 
                
                    $RetrievedSubcategory | Should Be $Subcategory
                }
                    
                It " 'AuditFlag' = '$AuditFlag'" {
                    $RetrievedAuditFlag = $Get.AuditFlag 
                
                    $RetrievedAuditFlag | Should Match $AuditFlag
                }

                It " 'Ensure' = 'Present'" {
                    $RetrievedEnsure = $Get.Ensure 
                
                    $RetrievedEnsure | Should Be 'Present'
                }
            }

            Context "Submit '$AuditFlag' and return '$($AuditFlagSwap[$AuditFlag])'" {
            
                # mock call to the helper module to isolate Get-TargetResource
                Mock Get-AuditCategory { return $AuditFlagSwap[$AuditFlag] } -ModuleName MSFT_AuditPolicySubcategory

                $Get = Get-TargetResource -Subcategory $Subcategory -AuditFlag $AuditFlag

                It " 'Subcategory' = '$Subcategory'" {
                    $RetrievedSubcategory =  $Get.Subcategory 
                
                    $RetrievedSubcategory | Should Be $Subcategory
                }
                    
                It " 'AuditFlag' != '$AuditFlag'" {
                    $RetrievedAuditFlag = $Get.AuditFlag 
                
                    $RetrievedAuditFlag | Should Not Match $AuditFlag
                }

                It " 'Ensure' = 'Absent'" {
                    $RetrievedEnsure = $Get.Ensure 
                
                    $RetrievedEnsure | Should Be 'Absent'
                }
            }

            Context "Submit '$AuditFlag' and return 'NoAuditing'" {

                Mock Get-AuditCategory { return 'NoAuditing' } -ModuleName MSFT_AuditPolicySubcategory

                $Get = Get-TargetResource -Subcategory $Subcategory -AuditFlag $AuditFlag
            
                It " 'Subcategory' = '$Subcategory'" {
                    $RetrievedSubcategory =  $Get.Subcategory 
                
                    $RetrievedSubcategory | Should Be $Subcategory
                }

                It " 'AuditFlag' != '$AuditFlag'" {
                    $RetrievedAuditFlag = $Get.AuditFlag 
                
                    $RetrievedAuditFlag | Should Not Match $AuditFlag
                }


                It " 'Ensure' = 'Absent'" {
                    $RetrievedEnsure = $Get.Ensure 
                
                    $RetrievedEnsure | Should Be 'Absent'
                }

            }

            Context "Submit '$AuditFlag' and return 'SuccessandFailure'" {

                Mock Get-AuditCategory { return 'SuccessandFailure' } -ModuleName MSFT_AuditPolicySubcategory

                $Get = Get-TargetResource -Subcategory $Subcategory -AuditFlag $AuditFlag
            
                It " 'Subcategory' = '$Subcategory'" {
                    $RetrievedSubcategory =  $Get.Subcategory 
                
                    $RetrievedSubcategory | Should Be $Subcategory
                }

                It " 'AuditFlag' = '$AuditFlag'" {
                    $RetrievedAuditFlag = $Get.AuditFlag 
                
                    $RetrievedAuditFlag | Should Be $AuditFlag
                }

                It " 'Ensure' = 'Present'" {
                    $RetrievedEnsure = $Get.Ensure 
                
                    $RetrievedEnsure | Should Be 'Present'
                }
            }
        }
        #endregion

        #region Function Test-TargetResource
        Describe "$($Global:DSCResourceName)\Test-TargetResource" {

            # mock call to the helper module to isolate Get-TargetResource
            Mock Get-AuditCategory { return $AuditFlag } -ModuleName MSFT_AuditPolicySubcategory
            
            $testResult = Test-TargetResource -Subcategory $Subcategory -AuditFlag $AuditFlag -Ensure "Present"
    
            It "Returns an Object of type Boolean" {
                
                $isBool = $testResult.GetType().Name -eq 'Boolean'
                $isBool | Should Be $true
            }

            It " that is True when the Audit flag is Present and should be Present" {
                
                $testResult | Should Be $true
            }

            It " and False when the Audit flag is Absent and should be Present" {
                
                $testResult = Test-TargetResource -Subcategory $Subcategory -AuditFlag $AuditFlag -Ensure "Absent"
                $testResult | Should Be $false
            }
        }
        #endregion

        #region Function Set-TargetResource
        Describe "$($Global:DSCResourceName)\Set-TargetResource" {
            
            Mock Set-AuditCategory { return }

            Context 'Return object' {
                $set = Set-TargetResource -Subcategory $Subcategory -AuditFlag $AuditFlag

                It 'is Empty' {
                    $set | Should BeNullOrEmpty
                }
            }

            Context 'Mandatory parameters' {
                
                It 'AuditFlag is mandatory ' {
                    {
                        Set-TargetResource -Subcategory $Subcategory -AuditFlag
                    } | Should Throw
                }

                It 'Subcategory is mandatory ' {
                    {
                        Set-TargetResource -Subcategory  -AuditFlag $AuditFlag
                    } | Should Throw
                }
            }

            Context "Validate support function" {
                
                $functionName = 'Set-AuditCategory'
                $Function = Get-Command $functionName

                It " Found function $functionName" {
                    $FunctionName = $Function.Name
        
                    $FunctionName | Should Be $functionName
                }

                It " Found parameter 'Subcategory'" {
                    $Subcategory = $Function.Parameters['Subcategory'].name
        
                    $Subcategory | Should Be 'Subcategory'
                }
            }
        }
        #endregion

        #region Helper Cmdlets
        Describe 'Private function Get-AuditCategory'  {
            
            $command = Get-Command Get-AuditCategory
            $parameter = 'SubCategory'
                
            It "Should Exist" {

                $command | Should Be $command 
            }

            It 'With output type set to "String"' {

                $command.OutputType | Should Be 'System.String'
            }

            It "Has a parameter '$parameter'" {

                $command.Parameters[$parameter].Name | Should Be $parameter
            }

            It 'Of type "String"' {

                $command.Parameters[$parameter].ParameterType | Should Be 'String'
            }


                Context 'Get-AuditCategory with Mock Invoke-Auditpol ' {

                    [string] $subCategory = 'Logon'
                    [string] $auditFlag   = 'Success'
                    # the return format is ComputerName,System,Subcategory,GUID,AuditFlags
                    [string] $returnString = "$env:ComputerName,system,$subCategory,[GUID],$auditFlag"

                    Mock Invoke-Auditpol { return $returnString } -ModuleName Helper

                    $AuditCategory = Get-AuditCategory -SubCategory $subCategory 

                    It "The return object is a String" {

                        $AuditCategory.GetType() | Should Be 'String'
                    }

                    It "with the value '$auditFlag'" {

                        $AuditCategory | Should BeExactly $auditFlag
                    }
            }
        }

        Describe 'Private function Set-AuditCategory' {

            $command = Get-Command Set-AuditCategory
            $parameter = 'SubCategory'
                
            It "Should Exist" {

                $command | Should Be $command 
            }

            It "With no output" {

                $command.OutputType | Should BeNullOrEmpty
            }

            It "Has a parameter '$parameter'" {

                $command.Parameters[$parameter].Name | Should Be $parameter
            }

            It 'Of type "String"' {

                $command.Parameters[$parameter].ParameterType | Should Be 'String'
            }

            Context 'Set-AuditCategory with Mock Invoke-Auditpol' {
                
                    Mock Invoke-Auditpol { } -ModuleName Helper
                    
                    $comamnd = @{
                        SubCategory = "Logon"
                        AuditFlag = "Success"
                        Ensure = "Present"
                    }

                    It 'Should not throw an error' {

                        { $AuditCategory = Set-AuditCategory @comamnd } | Should Not Throw 
                    }

                    It "Should not return a value"  {

                        $AuditCategory | Should BeNullOrEmpty
                    }
            }
        }
        #endregion
    }
    #endregion
}
finally
{
    #region FOOTER
    Restore-TestEnvironment -TestEnvironment $TestEnvironment
    #endregion
}
