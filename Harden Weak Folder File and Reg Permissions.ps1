    Function WriteablFiles
    {
    <#
    .Synopsis

    Validates files in the system folders don't allow Users, Authenticated Users or Everyone 'Write' and 'Execute', resets to 'Read' and 'Execute'

    Further information on these attacks can be found @ https://www.tenaka.net/unquotedpaths
   
    .DESCRIPTION
   
    .EXAMPLE

    .VERSION
    210617.01 - Created
    #> 

    $SecureClient = "C:\SecureClient"
    $OutFunc = "WriteableFiles"  

    $tpSec10 = Test-Path "C:\SecureClient\output\$OutFunc\"
    if ($tpSec10 -eq $false)
    {
    New-Item -Path "C:\SecureClient\output\$OutFunc\" -ItemType Directory -Force
    }

    $lpath = "C:\SecureClient\output\$OutFunc\" + "$OutFunc.log"

    #Folder\Directory Permissions
    $inherNone = [System.Security.AccessControl.InheritanceFlags]::None
    $propNone = [System.Security.AccessControl.PropagationFlags]::None
    $inherCnIn = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit
    $propInOn = [System.Security.AccessControl.PropagationFlags]::InheritOnly
    $inherObIn = [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $propNoPr = [System.Security.AccessControl.PropagationFlags]::NoPropagateInherit

    $hfiles =  Get-ChildItem C:\  | where {$_.Name -eq "PerfLogs" -or ` 
    $_.Name -eq "Program Files" -or `
    $_.Name -eq "Program Files (x86)" }# -or `
       # $_.Name -eq "Windows"}

    $filehash = @()
    foreach ($hfile in $hfiles.fullname)
        {
            $subfl = Get-ChildItem -Path $hfile -force -Recurse -Include *.exe, *.dll
            $filehash+=$subfl
            $filehash 
        }
    foreach ($cfile in $filehash.fullname)
        {
        $cfileAcl = Get-Acl $cfile -ErrorAction SilentlyContinue
        if ($cfileAcl | where {$_.accesstostring -like "*Users Allow  Write*" -or $_.accesstostring -like "*Users Allow  Modify*" -or $_.accesstostring -like "*Users Allow  FullControl*"})
            {
                $cfile | Out-File $lpath -Append
                Write-Host $cfile -ForegroundColor green
                $aclInh = get-acl $cfile
                $aclInh.SetAccessRuleProtection($false,$true)
                Set-Acl $cfile $aclInh
                $getAcl = Get-Acl $cfile
                $cfileacc = New-Object System.Security.AccessControl.FileSystemAccessRule("Users","READ","None","None","Allow")
                $getAcl.SetAccessRule($cfileacc)
                Set-Acl $cfile $getAcl
            }
            if ($cfileAcl | where {$_.accesstostring -like "*Everyone Allow  Write*" -or $_.accesstostring -like "*Everyone Allow  Modify*" -or $_.accesstostring -like "*Everyone Allow  FullControl*"})
            {
                $cfile | Out-File $lpath -Append
                Write-Host $cfile -ForegroundColor green
                $aclInh = get-acl $cfile
                $aclInh.SetAccessRuleProtection($false,$true)
                Set-Acl $cfile $aclInh
                $getAcl = Get-Acl $cfile
                $cfileacc = New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone","READ","None","None","Allow")
                $getAcl.SetAccessRule($cfileacc)
                Set-Acl $cfile $getAcl
            }
            if ($cfileAcl | where {$_.accesstostring -like "*Authenticated Users Allow  Write*" -or $_.accesstostring -like "*Authenticated Users Allow  Modify*" -or $_.accesstostring -like "*Authenticated Users Allow  FullControl*"})
            {
                $cfile | Out-File $lpath -Append
                Write-Host $cfile -ForegroundColor green
                $aclInh = get-acl $cfile
                $aclInh.SetAccessRuleProtection($false,$true)
                Set-Acl $cfile $aclInh
                $getAcl = Get-Acl $cfile
                $cfileacc = New-Object System.Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\Authenticated Users","READ","None","None","Allow")
                $getAcl.SetAccessRule($cfileacc)
                Set-Acl $cfile $getAcl
            }
        }
    }

    Function WriteableRegistry
    {
     <#
    .Synopsis
    Validates that Registry paths to Services and Software do not allow Users, Authenticates Users or Everyone modifies keys to update the settings and repoint to malware.

    Further information on these attacks can be found @ https://www.tenaka.net/unquotedpaths

   
    .DESCRIPTION
   
    .EXAMPLE

    .VERSION
    210617.01 - Created
    #>
    $SecureClient = "C:\SecureClient"
    $OutFunc = "WriteableReg"  

    $tpSec10 = Test-Path "C:\SecureClient\output\$OutFunc\"
    if ($tpSec10 -eq $false)
    {
        New-Item -Path "C:\SecureClient\output\$OutFunc\" -ItemType Directory -Force
    }

    $lpath = "C:\SecureClient\output\$OutFunc\" + "$OutFunc.log"

    $inherObIn = [System.Security.AccessControl.InheritanceFlags]::"ObjectInherit"

    #Registry Permissions
    $HKLMSvc = 'HKLM:\SYSTEM\CurrentControlSet\Services'
    $HKLMSoft = 'HKLM:\Software'
    $HKLMCheck = $HKLMSoft,$HKLMSvc

    Foreach ($key in $HKLMCheck) 
        {
            #Get a list of key names and make a variable
            cd hklm:
            $SvcPath = Get-childItem $key -Recurse -Depth 1 | where {$_.Name -notlike "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\*"}
            #Update HKEY_Local.... to HKLM:
            $RegList = $SvcPath.name.replace("HKEY_LOCAL_MACHINE","HKLM:")
            Foreach ($regPath in $RegList)
        {
    $acl = Get-Acl $regPath
    $acc = $acl.AccessToString
    Write-Output  $regPath
    foreach ($ac in $acc)
    {
    if ($ac | Select-String -SimpleMatch "BUILTIN\Users Allow  FullControl")
        {
            $regPath | Out-File $lpath -Append
            Write-Host $regPath -ForegroundColor red
            $getAcl = Get-Acl $regPath
            $RegAcc = New-Object System.Security.AccessControl.RegistryAccessRule("Users","READKEY","$inherObIn","none","Allow")
            $getAcl.SetAccessRule($RegAcc)
            Set-Acl $regPath $getAcl
        } 

    if ($ac | Select-String -SimpleMatch "NT AUTHORITY\Authenticated Users Allow  FullControl")
        {
            $regPath | Out-File $lpath -Append
            Write-Host $regPath -ForegroundColor yellow
            $getAcl = Get-Acl $regPath
            $RegAcc = New-Object System.Security.AccessControl.RegistryAccessRule("Authenticated Users","READKEY","$inherObIn","none","Allow")
            $getAcl.SetAccessRule($RegAcc)
            Set-Acl $regPath $getAcl
        }
    if ($ac | Select-String -SimpleMatch "Everyone Allow  FullControl")
         {
            $regPath | Out-File $lpath -Append
            Write-Host $regPath -ForegroundColor cyan
            $getAcl = Get-Acl $regPath
            $RegAcc = New-Object System.Security.AccessControl.RegistryAccessRule("Everyone","READKEY","$inherObIn","none","Allow")
            $getAcl.SetAccessRule($RegAcc)
            Set-Acl $regPath $getAcl
        }
    }
    }
    }
    cd C:\
    }
 
     Function WriteableFolders
    {   
    <#
    .Synopsis
   
    Validates any folder that is not created by default does not allow Users, Authenticated Users or Everyone 'Write' and 'Execute', resets to 'Read' and 'Execute'
   
    Further information on these attacks can be found @ https://www.tenaka.net/unquotedpaths
   
    .DESCRIPTION
   
    .EXAMPLE

    .VERSION
    210617.01 - Created
    #>
    $SecureClient = "C:\SecureClient"
    $OutFunc = "WriteableFolders"  

    $tpSec10 = Test-Path "C:\SecureClient\output\$OutFunc\"
    if ($tpSec10 -eq $false)
    {
        New-Item -Path "C:\SecureClient\output\$OutFunc\" -ItemType Directory -Force
    }

    $lpath = "C:\SecureClient\output\$OutFunc\" + "$OutFunc.log"

    #Removes Users\Auth Users Root Modify
    & icacls.exe c:\ /remove:g "Authenticated Users"

    #Folder\Directory Permissions
    $inherNone = [System.Security.AccessControl.InheritanceFlags]::None
    $propNone = [System.Security.AccessControl.PropagationFlags]::None
    $inherCnIn = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit
    $propInOn = [System.Security.AccessControl.PropagationFlags]::InheritOnly
    $inherObIn = [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $propNoPr = [System.Security.AccessControl.PropagationFlags]::NoPropagateInherit

    #Additional Folders off the root of C: that is not system

    $hfolders =  Get-ChildItem c:\  | where {$_.Name -ne "PerfLogs" -and ` 
    $_.Name -ne "Program Files" -and `
    $_.Name -ne "Program Files (x86)" -and `
    $_.Name -ne "Users" -and `
    $_.Name -ne "Windows"}

    $foldhash = @()
    foreach ($hfold in $hfolders.fullname)
        {
            $subfl = Get-ChildItem -Path $hfold -Directory -Recurse -Force
            $foldhash+=$hfolders
            $foldhash+=$subfl
        }
    foreach ($cfold in $foldhash.fullname)
    {
    $cfoldAcl = Get-Acl $cfold -ErrorAction SilentlyContinue

    if ($cfoldAcl | where {$_.accesstostring -like "*Users Allow  Write*" -or $_.accesstostring -like "*Users Allow  Modify*" -or $_.accesstostring -like "*Users Allow  FullControl*"})
        {
            $cfold | Out-File $lpath -Append
            Write-Host $cfold -ForegroundColor green
            $aclInh = get-acl $cfold
            $aclInh.SetAccessRuleProtection($false,$false)
            Set-Acl $cfold $aclInh
            $getAcl = Get-Acl $cfold
            $cfileacc = New-Object System.Security.AccessControl.FileSystemAccessRule("Users","ReadAndExecute","$inherCnIn ,$inherObIn","None","Allow")
            $getAcl.SetAccessRule($cfileacc)
            #$getAcl.removeAccessRuleAll($cfileacc)
            Set-Acl $cfold $getAcl
        }
     if ($cfoldAcl | where {$_.accesstostring -like "*Everyone Allow  Write*" -or $_.accesstostring -like "*Everyone Allow  Modify*" -or $_.accesstostring -like "*Everyone Allow  FullControl*"})
        {
            $cfold | Out-File $lpath -Append
            Write-Host $cfold -ForegroundColor cyan
            $aclInh = get-acl $cfold
            $aclInh.SetAccessRuleProtection($false,$false)
            Set-Acl $cfold $aclInh
            $getAcl = Get-Acl $cfold
            $cfileacc = New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone","ReadAndExecute","$inherCnIn ,$inherObIn","None","Allow")
            $getAcl.SetAccessRule($cfileacc)
            #$getAcl.removeAccessRuleAll($cfileacc)
            Set-Acl $cfold $getAcl
        }
     if ($cfoldAcl | where {$_.accesstostring -like "*Authenticated Users Allow  Write*" -or $_.accesstostring -like "*Authenticated Users Allow  Modify*" -or $_.accesstostring -like "*Authenticated Users Allow  FullControl*"})
        {
            $cfold | Out-File $lpath -Append
            Write-Host $cfold -ForegroundColor yellow
            $aclInh = get-acl $cfold
            $aclInh.SetAccessRuleProtection($false,$false)
            Set-Acl $cfold $aclInh
            $getAcl = Get-Acl $cfold
            $cfileacc = New-Object System.Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\Authenticated Users","ReadAndExecute","$inherCnIn ,$inherObIn","None","Allow")
            $getAcl.SetAccessRule($cfileacc)
            #$getAcl.removeAccessRuleAll($cfileacc)
            Set-Acl $cfold $getAcl
        }   
    }
  

    <#
    .Synopsis
   
    .DESCRIPTION
   
    .EXAMPLE

    .VERSION
    210617.01 - Created
    #> 
    $hfolders =  Get-ChildItem C:\  | where {$_.Name -eq "PerfLogs" -or ` 
    $_.Name -eq "Program Files" -or `
    $_.Name -eq "Program Files (x86)"} # -or `
    #$_.Name -eq "Windows"}
    $foldhash = @()
    foreach ($hfold in $hfolders.fullname)
        {
            $subfl = Get-ChildItem -Path $hfold -Directory -Recurse -Force
            $foldhash+=$subfl
        }
    foreach ($cfold in $foldhash.fullname)
        {
            $cfoldAcl = Get-Acl $cfold -ErrorAction SilentlyContinue
            if ($cfoldAcl | where {$_.accesstostring -like "*Users Allow  Write*" -or $_.accesstostring -like "*Users Allow  Modify*" -or $_.accesstostring -like "*Users Allow  FullControl*"})
            {
                $cfold | Out-File $lpath -Append
                Write-Host $cfold -ForegroundColor green
                $aclInh = get-acl $cfold
                $aclInh.SetAccessRuleProtection($false,$false)
                Set-Acl $cfold $aclInh
                $getAcl = Get-Acl $cfold
                $cfileacc = New-Object System.Security.AccessControl.FileSystemAccessRule("Users","ReadAndExecute","$inherCnIn ,$inherObIn","None","Allow")
                #$getAcl.SetAccessRule($cfileacc)
                $getAcl.removeAccessRuleAll($cfileacc)
                Set-Acl $cfold $getAcl
            }
         if ($cfoldAcl | where {$_.accesstostring -like "*Everyone Allow  Write*" -or $_.accesstostring -like "*Everyone Allow  Modify*" -or $_.accesstostring -like "*Everyone Allow  FullControl*"})
            {
                $cfold | Out-File $lpath -Append
                Write-Host $cfold -ForegroundColor cyan
                $aclInh = get-acl $cfold
                $aclInh.SetAccessRuleProtection($false,$false)
                Set-Acl $cfold $aclInh
                $getAcl = Get-Acl $cfold
                $cfileacc = New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone","ReadAndExecute","$inherCnIn ,$inherObIn","None","Allow")
                $getAcl.SetAccessRule($cfileacc)
                #$getAcl.removeAccessRuleAll($cfileacc)
                Set-Acl $cfold $getAcl
            }
            if ($cfoldAcl | where {$_.accesstostring -like "*Authenticated Users Allow  Write*" -or $_.accesstostring -like "*Authenticated Users Allow  Modify*" -or $_.accesstostring -like "*Authenticated Users Allow  FullControl*"})
            {
                $cfold | Out-File $lpath -Append
                Write-Host $cfold -ForegroundColor yellow
                $aclInh = get-acl $cfold
                $aclInh.SetAccessRuleProtection($false,$false)
                Set-Acl $cfold $aclInh
                $getAcl = Get-Acl $cfold
                $cfileacc = New-Object System.Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\Authenticated Users","ReadAndExecute","$inherCnIn ,$inherObIn","None","Allow")
                $getAcl.SetAccessRule($cfileacc)
                #$getAcl.removeAccessRuleAll($cfileacc)
                Set-Acl $cfold $getAcl
            }
        }
    } 
    
    WriteableRegistry
    WriteableFolders
    WriteablFiles
    
