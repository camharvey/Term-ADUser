function Term-ADUser {
    [CmdletBinding(SupportsShouldProcess=$True)]
    param(
        [Parameter(Mandatory=$True,
                   ValueFromPipeline=$True,
                   ValueFromPipelineByPropertyName=$True)]
        [string[]]$username #Empty brackets in string makes it an array
        
        )
    BEGIN {
        Import-Module ActiveDirectory
        Add-Type -AssemblyName System.Web
    
    }
    PROCESS {
        foreach ($user in $username) {
            if ($pscmdlet.ShouldProcess($user)) {
                $Query = Get-ADUser -LDAPFilter "(samAccountName=$user)"
                if ($Query -eq $null)
                { 
                    Write-Warning "User '$user' does not exist"
                }
                else
                { 
                    Write-Verbose "User '$user' exists"
                    #Moving $user to Active but Gone OU"
                    $Query | Move-ADObject -TargetPath "OU=Active but Gone,OU=Users,OU=SecureLink,DC=sl,DC=lan"
                    #Resetting password to a randomly generated password
                    $NewPass = [system.web.security.membership]::GeneratePassword(16,1) | ConvertTo-SecureString -AsPlainText -Force
                    Set-ADAccountPassword -Identity $Query -NewPassword $NewPass -Reset
                    #Set Primary AD Group to Domain Users & Revoke Badge Access
                    Set-ADUser -Replace @{primaryGroupID="513"; gtecFacilityCode=555; gtecAccessCard=55555; gtecAccessPin=55555}
                    #Remove AD Group Memberships of $user
                    Get-ADUser $Query -Properties MemberOf | ForEach-Object {
                        $_.MemberOf | Remove-ADGroupMember -Members $_.DistinguishedName -Confirm 
                    }
                    #Disable AD Account for $user
                    Disable-ADAccount -Identity $Query
                    #Move $user to "Disable Accounts" OU
                    $Query | Move-ADObject -TargetPath "OU=Disabled Accounts,OU=Users,OU=SecureLink,DC=sl,DC=lan"
                }
            }
        }
    }
    END {} 
}