#Remove any DVD from client
$drv = (psdrive | where{$_.Free -eq 0})
if($drv.free -eq "0" -and $_.name -ne "C")
    {
    Write-Host "Eject DVD and try again" -BackgroundColor Red
    Break
    }
 
#Confirm for elevated admin
    if (-not([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
    {
    Write-Host "An elevated administrator account is required to run this script." -BackgroundColor Red
    Break
    }
else
{
        start-transcript -path c:\SecureClient\output\psActions.log -Append -Force
        
        
        $ok = $null
        $choice = $null
        do {
            cls
            write-host ""
            write-host "A - User"
            write-host "B - UnQuoted Paths"
            write-host "C - WriteableFiles, WriteableFolders, WriteableRegistry "
            write-host "D - Bitlocker"
            write-host "E - Firewall"
            write-host "F - Applocker"
            write-host "G - DeviceGuard"
            write-host "H - SCM"
            Write-Host "I - Disable Windows Script Host"
            Write-host "J - Disable Legacy Network Protocols" 
            Write-host "K - Authentication inc Secure LSA" 
            write-host ""
            write-host "R - Rollback and disable security enforcing features"
            write-host ""
            write-host "Choose which security actions to execute, abcdefg...."
            write-host "Press Ctrl + C to exit"
            $choice = read-host
            write-host ""
        
            $ok = $choice -match '^[a,b,c,d,e,f,g,h,i,j,k,r,y,z]+$'
        
            if (-not $ok) {write-host "Oops something has gone wrong with your selection.  "}
            } until ($ok) 

<#

Inset Named Functions here to call on
Inset Named Functions here to call on
Inset Named Functions here to call on
Inset Named Functions here to call on
Inset Named Functions here to call on
Inset Named Functions here to call on
Inset Named Functions here to call on

#>


    $choiceZ = $choice + "z"
    foreach ($letter in $choiceZ.ToCharArray())
    {
    <#
    .Synopsis
   
    .DESCRIPTION
        
    .VERSION
    210617.01 - Created
    #>
        if ($letter -match "a"){User}
        if ($letter -match "b"){UnQuoted}
        if ($letter -match "c"){WriteableFolders}
        if ($letter -match "c"){WriteableFiles}
        if ($letter -match "c"){WriteableRegistry}
        if ($letter -match "d"){Bitlocker}
        if ($letter -match "e"){Firewall}
        if ($letter -match "f"){Applocker}
        if ($letter -match "g"){DeviceGuard}
        if ($letter -match "h"){SCM}
        if ($letter -match "i"){WSH}
        if ($letter -match "j"){LegacyNetwork}
        if ($letter -match "k"){Authentication}
        if ($letter -match "r"){RollBack}  
        if ($letter -match "z"){FinalActions}      
        Vulnfix
        
    }
}
