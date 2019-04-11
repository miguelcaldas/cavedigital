configuration ConfigureDCVM {
    param (
        [Parameter(Mandatory)] [String]$DomainFQDN,
        [Parameter(Mandatory)] [System.Management.Automation.PSCredential]$Admincreds,
        [Parameter(Mandatory)] [System.Management.Automation.PSCredential]$AdfsSvcCreds,
        [Parameter(Mandatory)] [String]$PrivateIP
    )

    Import-DscResource -ModuleName xActiveDirectory, NetworkingDsc, xPSDesiredStateConfiguration, xPendingReboot, xDnsServer
    [String] $DomainNetbiosName = (Get-NetBIOSName -DomainFQDN $DomainFQDN)
    [System.Management.Automation.PSCredential] $DomainCredsNetbios = New-Object System.Management.Automation.PSCredential ("${DomainNetbiosName}\$($Admincreds.UserName)", $Admincreds.Password)
    [System.Management.Automation.PSCredential] $AdfsSvcCredsQualified = New-Object System.Management.Automation.PSCredential ("${DomainNetbiosName}\$($AdfsSvcCreds.UserName)", $AdfsSvcCreds.Password)
    $Interface = Get-NetAdapter| Where-Object Name -Like "Ethernet*"| Select-Object -First 1
    $InterfaceAlias = $($Interface.Name)
    $ComputerName = Get-Content env:computername
    [Int] $RetryCount = 20
    [Int] $RetryIntervalSec = 30
    [String] $SPTrustedSitesName = "SPSites"
    [String] $ADFSSiteName = "ADFS"
    [String] $AppDomainFQDN = (Get-AppDomain -DomainFQDN $DomainFQDN -Suffix "Apps")
    [String] $AppDomainIntranetFQDN = (Get-AppDomain -DomainFQDN $DomainFQDN -Suffix "Apps-Intranet")

    Node localhost {
        LocalConfigurationManager {
            ConfigurationMode = 'ApplyOnly'
            RebootNodeIfNeeded = $true
        }

        WindowsFeature ADDS {Name = "AD-Domain-Services"; Ensure = "Present"}
        WindowsFeature DNS {Name = "DNS"; Ensure = "Present"}
        WindowsFeature DnsTools {Name = "RSAT-DNS-Server"; Ensure = "Present"}

        DnsServerAddress DnsServerAddress {
            Address        = '127.0.0.1' 
            InterfaceAlias = $InterfaceAlias
            AddressFamily  = 'IPv4'
            DependsOn = "[WindowsFeature]DNS"
        }

        xADDomain FirstDS {
            DomainName = $DomainFQDN
            DomainAdministratorCredential = $DomainCredsNetbios
            SafemodeAdministratorPassword = $DomainCredsNetbios
            DatabasePath = "C:\NTDS"
            LogPath = "C:\NTDS"
            SysvolPath = "C:\SYSVOL"
            DependsOn = "[DnsServerAddress]DnsServerAddress"
        }

        xPendingReboot Reboot1 {
            Name = "RebootServer"
            DependsOn = "[xADDomain]FirstDS"
        }

        xDnsServerPrimaryZone CreateAppsDnsZone {
            Name = $AppDomainFQDN
            Ensure = 'Present'
            DependsOn = "[xPendingReboot]Reboot1"
        }

        xDnsServerPrimaryZone CreateAppsIntranetDnsZone {
            Name = $AppDomainIntranetFQDN
            Ensure= 'Present'
            DependsOn = "[xDnsServerPrimaryZone]CreateAppsDnsZone"
        }

        #**********************************************************
        # Misc: Set email of AD domain admin and add remote AD tools
        #**********************************************************
        xADUser SetEmailOfDomainAdmin {
            DomainAdministratorCredential = $DomainCredsNetbios
            DomainName = $DomainFQDN
            UserName = $Admincreds.UserName
            Password = $Admincreds
            EmailAddress = $Admincreds.UserName + "@" + $DomainFQDN
            PasswordAuthentication = 'Negotiate'
            Ensure = "Present"
            PasswordNeverExpires = $true
            DependsOn = "[xPendingReboot]Reboot1"
        }

        WindowsFeature AddADFeature {Name = "RSAT-ADDS-Tools"; Ensure = "Present"; DependsOn = "[xPendingReboot]Reboot1"}
    }
}

function Get-NetBIOSName {
    [OutputType([string])]
    param (
        [string]$DomainFQDN
    )

    if ($DomainFQDN.Contains('.')) {
        $length=$DomainFQDN.IndexOf('.')
        if ( $length -ge 16) {
            $length=15
        }
        return $DomainFQDN.Substring(0,$length)
    }
    else {
        if ($DomainFQDN.Length -gt 15) {
            return $DomainFQDN.Substring(0,15)
        }
        else {
            return $DomainFQDN
        }
    }
}

function Get-AppDomain {
    [OutputType([string])]
    param(
        [string]$DomainFQDN,
        [string]$Suffix
    )

    $appDomain = [String]::Empty
    if ($DomainFQDN.Contains('.')) {
        $domainParts = $DomainFQDN.Split('.')
        $appDomain = $domainParts[0]
        $appDomain += "$Suffix."
        $appDomain += $domainParts[1]
    }
    return $appDomain
}
