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
                #Running valid user checks before proceeding with actions
                $Query = Get-ADUser -LDAPFilter "(samAccountName=$user)"
                if ($Query -eq $null) #Catches if $user does not exist in AD
                { 
                    Write-Warning "User '$user' does not exist"
                }
                 elseif ($Query.DistinguishedName.Split("=")[2].split(",")[0] -ne "Corporate Accounts" ) #Catches $user not in Corporate Accounts OU
                {
                    Write-Warning "User '$user' is not in the Corporate Accounts OU"
                }
                elseif ($Query.Enabled -eq $false) #Catches $user if they're already disabled 
                {
                    Write-Warning "User '$user' is already disabled"
                }
                else #Runs termination tasks if $user passes above checks
                { 
                    Write-Verbose "User '$user' exists"
                    #Moving $user to Active but Gone OU"
                    Get-ADUser -Identity $user | Move-ADObject -TargetPath "OU=Active but Gone,OU=Users,OU=SecureLink,DC=sl,DC=lan"
                    #Resetting password to a randomly generated password
                    $NewPass = [system.web.security.membership]::GeneratePassword(16,1) | ConvertTo-SecureString -AsPlainText -Force
                    Set-ADAccountPassword -Identity $user -NewPassword $NewPass -Reset
                    #Set Primary AD Group to Domain Users & Revoke Badge Access
                    Set-ADUser -Identity $user -Replace @{primaryGroupID="513"; gtecFacilityCode=555; gtecAccessCard=55555; gtecAccessPin=55555}
                    #Remove AD Group Memberships of $user
                    Get-ADUser $user -Properties MemberOf | ForEach-Object {
                        $_.MemberOf | Remove-ADGroupMember -Members $_.DistinguishedName -Confirm 
                    }
                    #Disable AD Account for $user
                    Disable-ADAccount -Identity $user
                    #Move $user to "Disable Accounts" OU
                    Get-ADUser -Identity $user | Move-ADObject -TargetPath "OU=Disabled Accounts,OU=Users,OU=SecureLink,DC=sl,DC=lan"
                }
            }
        }
    }
    END {} 
}