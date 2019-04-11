configuration ConfigureSPVM {
    param (
        [Parameter(Mandatory)] [String]$DNSServer,
        [Parameter(Mandatory)] [String]$DomainFQDN,
        [Parameter(Mandatory)] [String]$DCName,
        [Parameter(Mandatory)] [String]$SQLName,
        [Parameter(Mandatory)] [String]$SQLAlias,
        [Parameter(Mandatory)] [String]$SharePointVersion,
        [Parameter(Mandatory)] [System.Management.Automation.PSCredential]$DomainAdminCreds,
        [Parameter(Mandatory)] [System.Management.Automation.PSCredential]$SPSetupCreds,
        [Parameter(Mandatory)] [System.Management.Automation.PSCredential]$SPFarmCreds,
        [Parameter(Mandatory)] [System.Management.Automation.PSCredential]$SPSvcCreds,
        [Parameter(Mandatory)] [System.Management.Automation.PSCredential]$SPAppPoolCreds,
        [Parameter(Mandatory)] [System.Management.Automation.PSCredential]$SPPassphraseCreds,
        [Parameter(Mandatory)] [System.Management.Automation.PSCredential]$SPSuperUserCreds,
        [Parameter(Mandatory)] [System.Management.Automation.PSCredential]$SPSuperReaderCreds
    )

    Import-DscResource -ModuleName ComputerManagementDsc, StorageDsc, NetworkingDsc, xActiveDirectory, xCredSSP, xWebAdministration, SharePointDsc, xPSDesiredStateConfiguration, xDnsServer, SqlServerDsc, xPendingReboot

    [String] $DomainNetbiosName = (Get-NetBIOSName -DomainFQDN $DomainFQDN)
    $Interface = Get-NetAdapter| Where-Object Name -Like "Ethernet*"| Select-Object -First 1
    $InterfaceAlias = $($Interface.Name)
    [System.Management.Automation.PSCredential] $DomainAdminCredsQualified = New-Object System.Management.Automation.PSCredential ("${DomainNetbiosName}\$($DomainAdminCreds.UserName)", $DomainAdminCreds.Password)
    [System.Management.Automation.PSCredential] $SPSetupCredsQualified = New-Object System.Management.Automation.PSCredential ("${DomainNetbiosName}\$($SPSetupCreds.UserName)", $SPSetupCreds.Password)
    [System.Management.Automation.PSCredential] $SPFarmCredsQualified = New-Object System.Management.Automation.PSCredential ("${DomainNetbiosName}\$($SPFarmCreds.UserName)", $SPFarmCreds.Password)
    [System.Management.Automation.PSCredential] $SPSvcCredsQualified = New-Object System.Management.Automation.PSCredential ("${DomainNetbiosName}\$($SPSvcCreds.UserName)", $SPSvcCreds.Password)
    [System.Management.Automation.PSCredential] $SPAppPoolCredsQualified = New-Object System.Management.Automation.PSCredential ("${DomainNetbiosName}\$($SPAppPoolCreds.UserName)", $SPAppPoolCreds.Password)
    [String] $SPDBPrefix = "SPDSC_"
    [String] $SPTrustedSitesName = "SPSites"
    [Int] $RetryCount = 30
    [Int] $RetryIntervalSec = 30
    [String] $ComputerName = Get-Content env:computername
    [String] $ServiceAppPoolName = "SharePoint Service Applications"
    [String] $UpaServiceName = "User Profile Service Application"
    [String] $AppDomainFQDN = (Get-AppDomain -DomainFQDN $DomainFQDN -Suffix "Apps")
    [String] $AppDomainIntranetFQDN = (Get-AppDomain -DomainFQDN $DomainFQDN -Suffix "Apps-Intranet")
    [String] $SetupPath = "C:\Setup"
    [String] $DCSetupPath = "\\$DCName\C$\Setup"
    [String] $MySiteHostAlias = "OhMy"
    [String] $HNSC1Alias = "HNSC1"

    Node localhost {
        LocalConfigurationManager {
            ConfigurationMode = 'ApplyOnly'
            RebootNodeIfNeeded = $true
        }

        WindowsFeature ADTools {Name = "RSAT-AD-Tools"; Ensure = "Present"}
        WindowsFeature ADPS {Name = "RSAT-AD-PowerShell"; Ensure = "Present"}
        WindowsFeature DnsTools {Name = "RSAT-DNS-Server"; Ensure = "Present"}

        DnsServerAddress DnsServerAddress {
            Address = $DNSServer
            InterfaceAlias = $InterfaceAlias
            AddressFamily = 'IPv4'
            DependsOn ="[WindowsFeature]ADPS"
        }

        xCredSSP CredSSPServer {
		    Ensure = "Present"
			Role = "Server"
			DependsOn = "[DnsServerAddress]DnsServerAddress"
		}
        xCredSSP CredSSPClient {
		    Ensure = "Present"
			Role = "Client"
			DelegateComputers = "*.$DomainFQDN", "localhost"
			DependsOn = "[xCredSSP]CredSSPServer"
		}

        xWaitForADDomain DscForestWait {
            DomainName = $DomainFQDN
            RetryCount = $RetryCount
            RetryIntervalSec = $RetryIntervalSec
            DomainUserCredential = $DomainAdminCredsQualified
            DependsOn = "[xCredSSP]CredSSPClient"
        }

        Computer DomainJoin {
            Name = $ComputerName
            DomainName = $DomainFQDN
            Credential = $DomainAdminCredsQualified
            DependsOn = "[xWaitForADDomain]DscForestWait"
        }

        xScript CreateWSManSPNsIfNeeded {
            SetScript = {
                # A few times, deployment failed because of this error:
                # "The WinRM client cannot process the request. A computer policy does not allow the delegation of the user credentials to the target computer because the computer is not trusted."
                # The root cause was that SPNs WSMAN/SP and WSMAN/sp.contoso.local were missing in computer account contoso\SP
                # Those SPNs are created by WSMan when it (re)starts
                # Restarting service causes an error, so creates SPNs manually instead
                # Restart-Service winrm

                # Create SPNs WSMAN/SP and WSMAN/sp.contoso.local
                $domainFQDN = $using:DomainFQDN
                $computerName = $using:ComputerName
                Write-Verbose -Message "Adding SPNs 'WSMAN/$computerName' and 'WSMAN/$computerName.$domainFQDN' to computer '$computerName'"
                setspn.exe -S "WSMAN/$computerName" "$computerName"
                setspn.exe -S "WSMAN/$computerName.$domainFQDN" "$computerName"
            }
            GetScript = { }
            TestScript = {
                $computerName = $using:ComputerName
                $samAccountName = "$computerName$"
                if ((Get-ADComputer -Filter {(SamAccountName -eq $samAccountName)} -Property serviceprincipalname | Select-Object serviceprincipalname | Where-Object {$_.ServicePrincipalName -like "WSMAN/$computerName"}) -ne $null) {
                    # SPN is present
                    return $true
                }
                else {
                    # SPN is missing and must be created
                    return $false
                }
            }
            DependsOn = "[Computer]DomainJoin"
        }

        Registry DisableLoopBackCheck {
            Key = "HKLM:\System\CurrentControlSet\Control\Lsa"
            ValueName = "DisableLoopbackCheck"
            ValueData = "1"
            ValueType = "Dword"
            Ensure = "Present"
            DependsOn ="[Computer]DomainJoin"
        }

        xDnsRecord AddTrustedSiteDNS {
            Name = $SPTrustedSitesName
            Zone = $DomainFQDN
            DnsServer = $DCName
            Target = "$ComputerName.$DomainFQDN"
            Type = "CName"
            Ensure = "Present"
            PsDscRunAsCredential = $DomainAdminCredsQualified
            DependsOn = "[Computer]DomainJoin"
        }

        xDnsRecord AddMySiteHostDNS {
            Name = $MySiteHostAlias
            Zone = $DomainFQDN
            DnsServer = $DCName
            Target = "$ComputerName.$DomainFQDN"
            Type = "CName"
            Ensure = "Present"
            PsDscRunAsCredential = $DomainAdminCredsQualified
            DependsOn = "[Computer]DomainJoin"
        }

        xDnsRecord AddHNSC1DNS {
            Name = $HNSC1Alias
            Zone = $DomainFQDN
            DnsServer = $DCName
            Target = "$ComputerName.$DomainFQDN"
            Type = "CName"
            Ensure = "Present"
            PsDscRunAsCredential = $DomainAdminCredsQualified
            DependsOn = "[Computer]DomainJoin"
        }

        xWebAppPool RemoveDotNet2Pool {Name = ".NET v2.0"; Ensure = "Absent"; DependsOn = "[Computer]DomainJoin"}
        xWebAppPool RemoveDotNet2ClassicPool {Name = ".NET v2.0 Classic"; Ensure = "Absent"; DependsOn = "[Computer]DomainJoin"}
        xWebAppPool RemoveDotNet45Pool {Name = ".NET v4.5"; Ensure = "Absent"; DependsOn = "[Computer]DomainJoin"}
        xWebAppPool RemoveDotNet45ClassicPool {Name = ".NET v4.5 Classic"; Ensure = "Absent"; DependsOn = "[Computer]DomainJoin"}
        xWebAppPool RemoveClassicDotNetPool {Name = "Classic .NET AppPool"; Ensure = "Absent"; DependsOn = "[Computer]DomainJoin"}
        xWebAppPool RemoveDefaultAppPool {Name = "DefaultAppPool"; Ensure = "Absent"; DependsOn = "[Computer]DomainJoin"}
        xWebSite RemoveDefaultWebSite {Name = "Default Web Site"; Ensure = "Absent"; PhysicalPath = "C:\inetpub\wwwroot"; DependsOn = "[Computer]DomainJoin"}

        xADUser CreateSPSetupAccount {
            DomainName = $DomainFQDN
            UserName = $SPSetupCreds.UserName
            Password = $SPSetupCreds
            PasswordNeverExpires = $true
            Ensure = "Present"
            DomainAdministratorCredential = $DomainAdminCredsQualified
            DependsOn = "[Computer]DomainJoin"
        }        

        xADUser CreateSPFarmAccount {
            DomainName = $DomainFQDN
            UserName = $SPFarmCreds.UserName
            Password = $SPFarmCreds
            PasswordNeverExpires = $true
            Ensure = "Present"
            DomainAdministratorCredential = $DomainAdminCredsQualified
            DependsOn = "[Computer]DomainJoin"
        }

        Group AddSPSetupAccountToAdminGroup {
            GroupName = "Administrators"
            Ensure = "Present"
            MembersToInclude = @("$($SPSetupCredsQualified.UserName)")
            Credential = $DomainAdminCredsQualified
            PsDscRunAsCredential = $DomainAdminCredsQualified
            DependsOn = "[xADUser]CreateSPSetupAccount", "[xADUser]CreateSPFarmAccount"
        }

        xADUser CreateSPSvcAccount {
            DomainName = $DomainFQDN
            UserName = $SPSvcCreds.UserName
            Password = $SPSvcCreds
            PasswordNeverExpires = $true
            Ensure = "Present"
            DomainAdministratorCredential = $DomainAdminCredsQualified
            DependsOn = "[Computer]DomainJoin"
        }

        xADUser CreateSPAppPoolAccount {
            DomainName = $DomainFQDN
            UserName = $SPAppPoolCreds.UserName
            Password = $SPAppPoolCreds
            PasswordNeverExpires = $true
            Ensure = "Present"
            DomainAdministratorCredential = $DomainAdminCredsQualified
            DependsOn = "[Computer]DomainJoin"
        }

        xADUser CreateSPSuperUserAccount {
            DomainName = $DomainFQDN
            UserName = $SPSuperUserCreds.UserName
            Password = $SPSuperUserCreds
            PasswordNeverExpires = $true
            Ensure = "Present"
            DomainAdministratorCredential = $DomainAdminCredsQualified
            DependsOn = "[Computer]DomainJoin"
        }

        xADUser CreateSPSuperReaderAccount {
            DomainName = $DomainFQDN
            UserName = $SPSuperReaderCreds.UserName
            Password = $SPSuperReaderCreds
            PasswordNeverExpires = $true
            Ensure = "Present"
            DomainAdministratorCredential = $DomainAdminCredsQualified
            DependsOn = "[Computer]DomainJoin"
        }

        File AccountsProvisioned {
            DestinationPath = "C:\Logs\DSC0.txt"
            Contents = "AccountsProvisioned"
            Type = 'File'
            Force = $true
            PsDscRunAsCredential = $SPSetupCredential
            DependsOn = "[Group]AddSPSetupAccountToAdminGroup", "[xADUser]CreateSPFarmAccount", "[xADUser]CreateSPSvcAccount", "[xADUser]CreateSPAppPoolAccount", "[xADUser]CreateSPSuperUserAccount", "[xADUser]CreateSPSuperReaderAccount"
        }

        SqlAlias AddSqlAlias {
            Ensure = "Present"
            Name = $SQLAlias
            ServerName = $SQLName
            Protocol = "TCP"
            TcpPort = 1433
            PsDscRunAsCredential = $DomainAdminCredsQualified
            DependsOn = "[File]AccountsProvisioned"
        }

        xScript WaitForSQL {
            SetScript = {
                $retrySleep = $using:RetryIntervalSec
                $server = $using:SQLAlias
                $db="master"
                $retry = $true
                while ($retry) {
                    $sqlConnection = New-Object System.Data.SqlClient.SqlConnection "Data Source=$server;Initial Catalog=$db;Integrated Security=True;Enlist=False;Connect Timeout=3"
                    try {
                        $sqlConnection.Open()
                        Write-Verbose "Connection to SQL Server $server succeeded"
                        $sqlConnection.Close()
                        $retry = $false
                    }
                    catch {
                        Write-Verbose "SQL connection to $server failed, retry in $retrySleep secs..."
                        Start-Sleep -s $retrySleep
                    }
                }
            }
            GetScript = { }
            TestScript = {return $false}
            PsDscRunAsCredential = $DomainAdminCredsQualified
            DependsOn = "[SqlAlias]AddSqlAlias"
        }

        SPFarm CreateSPFarm {
            DatabaseServer = $SQLAlias
            FarmConfigDatabaseName = $SPDBPrefix + "Config"
            Passphrase = $SPPassphraseCreds
            FarmAccount = $SPFarmCredsQualified
            PsDscRunAsCredential = $SPSetupCredsQualified
            AdminContentDatabaseName = $SPDBPrefix + "AdminContent"
            CentralAdministrationPort = 5000
            # If RunCentralAdmin is false and configdb does not exist, SPFarm checks during 30 mins if configdb got created and joins the farm
            RunCentralAdmin = $true
            IsSingleInstance = "Yes"
            Ensure = "Present"
            DependsOn = "[xScript]WaitForSQL"
        }

        File Step1 {
            DestinationPath = "C:\Logs\DSC1.txt"
            Contents = "SPFarm CreateSPFarm"
            Type = 'File'
            Force = $true
            PsDscRunAsCredential = $SPSetupCredential
            DependsOn = "[SPFarm]CreateSPFarm"
        }

        xScript RestartSPTimer {
            SetScript = {
                # Restarting SPTimerV4 service before deploying solution makes deployment a lot more reliable
                Restart-Service SPTimerV4
            }
            GetScript = { }
            TestScript = {return $false}
            PsDscRunAsCredential = $DomainAdminCredsQualified
            DependsOn = "[SPFarm]CreateSPFarm"
        }

        SPManagedAccount CreateSPSvcManagedAccount {
            AccountName = $SPSvcCredsQualified.UserName
            Account = $SPSvcCredsQualified
            PsDscRunAsCredential = $SPSetupCredsQualified
            DependsOn = "[SPFarm]CreateSPFarm"
        }

        SPManagedAccount CreateSPAppPoolManagedAccount {
            AccountName = $SPAppPoolCredsQualified.UserName
            Account = $SPAppPoolCredsQualified
            PsDscRunAsCredential = $SPSetupCredsQualified
            DependsOn = "[SPFarm]CreateSPFarm"
        }

        SPDiagnosticLoggingSettings ApplyDiagnosticLogSettings {
            LogPath = "C:\ULS"
            LogSpaceInGB = 20
            IsSingleInstance = "Yes"
            PsDscRunAsCredential = $SPSetupCredsQualified
            DependsOn = "[SPFarm]CreateSPFarm"
        }

        SPStateServiceApp StateServiceApp {
            Name = "State Service Application"
            DatabaseName = $SPDBPrefix + "StateService"
            PsDscRunAsCredential = $SPSetupCredsQualified
            DependsOn = "[SPFarm]CreateSPFarm"
        }

        SPDistributedCacheService EnableDistributedCache {
            Name = "AppFabricCachingService"
            CacheSizeInMB = 2000
            CreateFirewallRules = $true
            ServiceAccount = $SPSvcCredsQualified.UserName
            PsDscRunAsCredential = $SPSetupCredsQualified
            Ensure = "Present"
            DependsOn = "[SPFarm]CreateSPFarm"
        }

        SPServiceAppPool MainServiceAppPool {
            Name = $ServiceAppPoolName
            ServiceAccount = $SPSvcCredsQualified.UserName
            PsDscRunAsCredential = $SPSetupCredsQualified
            DependsOn = "[SPFarm]CreateSPFarm"
        }

        SPServiceInstance UPAServiceInstance {
            Name = "User Profile Service"
            Ensure = "Present"
            PsDscRunAsCredential = $SPSetupCredsQualified
            DependsOn = "[SPFarm]CreateSPFarm"
        }

        SPServiceInstance StartSubscriptionSettingsServiceInstance {
            Name = "Microsoft SharePoint Foundation Subscription Settings Service"
            Ensure = "Present"
            PsDscRunAsCredential = $SPSetupCredsQualified
            DependsOn = "[SPFarm]CreateSPFarm"
        }

        SPServiceInstance StartAppManagementServiceInstance {
            Name = "App Management Service"
            Ensure = "Present"
            PsDscRunAsCredential = $SPSetupCredsQualified
            DependsOn = "[SPFarm]CreateSPFarm"
        }

        SPWebApplication MainWebApp {
            Name = "SharePoint - 80"
            ApplicationPool = "SharePoint - 80"
            ApplicationPoolAccount = $SPAppPoolCredsQualified.UserName
            AllowAnonymous = $false
            DatabaseName = $SPDBPrefix + "Content_80"
            WebAppUrl = "http://$SPTrustedSitesName/"
            Port = 80
            Ensure = "Present"
            PsDscRunAsCredential = $SPSetupCredsQualified
            DependsOn = "[SPFarm]CreateSPFarm"
        }

        File Step2 {
            DestinationPath = "C:\Logs\DSC2.txt"
            Contents = "SPWebApplication MainWebApp"
            Type = 'File'
            Force = $true
            PsDscRunAsCredential = $SPSetupCredential
            DependsOn = "[SPWebApplication]MainWebApp"
        }

        SPWebAppAuthentication ConfigureWebAppAuthentication {
            WebAppUrl = "http://$SPTrustedSitesName/"
            Default = @(
                MSFT_SPWebAppAuthenticationMode {
                    AuthenticationMethod = "NTLM"
                }
            )
<#
            Intranet = @(
                MSFT_SPWebAppAuthenticationMode {
                    AuthenticationMethod = "Federated"
                    AuthenticationProvider = $DomainFQDN
                }
            )
#>
            PsDscRunAsCredential = $SPSetupCredsQualified
            DependsOn = "[SPWebApplication]MainWebApp"
        }

        File Step3 {
            DestinationPath = "C:\Logs\DSC3.txt"
            Contents = "SPWebAppAuthentication ConfigureWebAppAuthentication"
            Type = 'File'
            Force = $true
            PsDscRunAsCredential = $SPSetupCredential
            DependsOn = "[SPWebAppAuthentication]ConfigureWebAppAuthentication"
        }

        SPCacheAccounts SetCacheAccounts {
            WebAppUrl = "http://$SPTrustedSitesName/"
            SuperUserAlias = "$DomainNetbiosName\$($SPSuperUserCreds.UserName)"
            SuperReaderAlias = "$DomainNetbiosName\$($SPSuperReaderCreds.UserName)"
            PsDscRunAsCredential = $SPSetupCredsQualified
            DependsOn = "[SPWebApplication]MainWebApp"
        }

        File Step4 {
            DestinationPath = "C:\Logs\DSC4.txt"
            Contents = "SPCacheAccounts SetCacheAccounts"
            Type = 'File'
            Force = $true
            PsDscRunAsCredential = $SPSetupCredential
            DependsOn = "[SPCacheAccounts]SetCacheAccounts"
        }

        SPSite RootTeamSite {
            Url = "http://$SPTrustedSitesName/"
            OwnerAlias           = "i:0#.w|$DomainNetbiosName\$($DomainAdminCreds.UserName)"
#            SecondaryOwnerAlias  = "i:05.t|$DomainFQDN|$($DomainAdminCreds.UserName)@$DomainFQDN"
            Name = "Team site"
            Template = "STS#0"
            PsDscRunAsCredential = $SPSetupCredsQualified
            DependsOn = "[SPWebApplication]MainWebApp"
        }

        File Step5 {
            DestinationPath = "C:\Logs\DSC5.txt"
            Contents = "SPSite RootTeamSite"
            Type = 'File'
            Force = $true
            PsDscRunAsCredential = $SPSetupCredential
            DependsOn = "[SPSite]RootTeamSite"
        }

        SPSite MySiteHost {
            Url = "http://$MySiteHostAlias/"
            HostHeaderWebApplication = "http://$SPTrustedSitesName/"
            OwnerAlias = "i:0#.w|$DomainNetbiosName\$($DomainAdminCreds.UserName)"
#            SecondaryOwnerAlias      = "i:05.t|$DomainFQDN|$($DomainAdminCreds.UserName)@$DomainFQDN"
            Name = "MySite host"
            Template = "SPSMSITEHOST#0"
            PsDscRunAsCredential = $SPSetupCredsQualified
            DependsOn = "[SPWebApplication]MainWebApp"
        }

        File Step6 {
            DestinationPath = "C:\Logs\DSC6.txt"
            Contents = "SPSite MySiteHost"
            Type = 'File'
            Force = $true
            PsDscRunAsCredential = $SPSetupCredential
            DependsOn = "[SPSite]MySiteHost"
        }

<#
        SPSiteUrl MySiteHostIntranetUrl {
            Url = "http://$MySiteHostAlias/"
            Intranet = "https://$MySiteHostAlias.$DomainFQDN"
            PsDscRunAsCredential = $SPSetupCredsQualified
            DependsOn = "[SPSite]MySiteHost"
        }
#>

        SPManagedPath MySiteManagedPath {
            WebAppUrl = "http://$SPTrustedSitesName/"
            RelativeUrl = "personal"
            Explicit = $false
            HostHeader = $true
            PsDscRunAsCredential = $SPSetupCredsQualified
            DependsOn = "[SPSite]MySiteHost"
        }

        File Step7 {
            DestinationPath = "C:\Logs\DSC7.txt"
            Contents = "SPManagedPath MySiteManagedPath"
            Type = 'File'
            Force = $true
            PsDscRunAsCredential = $SPSetupCredential
            DependsOn = "[SPManagedPath]MySiteManagedPath"
        }

        SPUserProfileServiceApp UserProfileServiceApp {
            Name = $UpaServiceName
            ApplicationPool = $ServiceAppPoolName
            MySiteHostLocation = "http://$MySiteHostAlias/"
            ProfileDBName = $SPDBPrefix + "UPA_Profiles"
            SocialDBName = $SPDBPrefix + "UPA_Social"
            SyncDBName = $SPDBPrefix + "UPA_Sync"
            EnableNetBIOS = $false
            PsDscRunAsCredential = $SPSetupCredsQualified
            DependsOn = "[SPServiceAppPool]MainServiceAppPool", "[SPServiceInstance]UPAServiceInstance", "[SPSite]MySiteHost"
        }

        File Step8 {
            DestinationPath = "C:\Logs\DSC8.txt"
            Contents = "SPUserProfileServiceApp UserProfileServiceApp"
            Type = 'File'
            Force = $true
            PsDscRunAsCredential = $SPSetupCredential
            DependsOn = "[SPUserProfileServiceApp]UserProfileServiceApp"
        }

        SPSite DevSite {
            Url = "http://$SPTrustedSitesName/sites/dev"
            OwnerAlias = "i:0#.w|$DomainNetbiosName\$($DomainAdminCreds.UserName)"
#            SecondaryOwnerAlias  = "i:05.t|$DomainFQDN|$($DomainAdminCreds.UserName)@$DomainFQDN"
            Name = "Developer site"
            Template = "DEV#0"
            PsDscRunAsCredential = $SPSetupCredsQualified
            DependsOn = "[SPWebApplication]MainWebApp"
        }

        File Step9 {
            DestinationPath = "C:\Logs\DSC9.txt"
            Contents = "SPSite DevSite"
            Type = 'File'
            Force = $true
            PsDscRunAsCredential = $SPSetupCredential
            DependsOn = "[SPSite]DevSite"
        }

        SPSite CreateHNSC1 {
            Url = "http://$HNSC1Alias/"
            HostHeaderWebApplication = "http://$SPTrustedSitesName/"
            OwnerAlias = "i:0#.w|$DomainNetbiosName\$($DomainAdminCreds.UserName)"
#            SecondaryOwnerAlias      = "i:05.t|$DomainFQDN|$($DomainAdminCreds.UserName)@$DomainFQDN"
            Name = "$HNSC1Alias site"
            Template = "STS#0"
            PsDscRunAsCredential = $SPSetupCredsQualified
            DependsOn = "[SPWebApplication]MainWebApp"
        }

        File Step10 {
            DestinationPath = "C:\Logs\DSC10.txt"
            Contents = "SPSite CreateHNSC1"
            Type = 'File'
            Force = $true
            PsDscRunAsCredential = $SPSetupCredential
            DependsOn = "[SPSite]CreateHNSC1"
        }

<#
        SPSiteUrl HNSC1IntranetUrl {
            Url = "http://$HNSC1Alias/"
            Intranet = "https://$HNSC1Alias.$DomainFQDN"
            PsDscRunAsCredential = $SPSetupCredsQualified
            DependsOn = "[SPSite]CreateHNSC1"
        }
#>

<#
		xScript CreateDefaultGroupsInTeamSites
        {
            SetScript = {
                $argumentList = @(@{"sitesToUpdate" = @("http://$using:SPTrustedSitesName", "http://$using:SPTrustedSitesName/sites/team");
                                    "owner1" = "i:0#.w|$using:DomainNetbiosName\$($using:DomainAdminCreds.UserName)";
                                    "owner2" = "i:05.t|$using:DomainFQDN|$($using:DomainAdminCreds.UserName)@$using:DomainFQDN"})
                Invoke-SPDscCommand -Arguments @argumentList -ScriptBlock {
                    # Create members/visitors/owners groups in team sites
                    $params = $args[0]
                    #$sitesToUpdate = Get-SPSite
                    $sitesToUpdate = $params.sitesToUpdate
                    $owner1 = $params.owner1
                    $owner2 = $params.owner2

                    foreach ($siteUrl in $sitesToUpdate) {
                        $spsite = Get-SPSite $siteUrl
                        $spsite| fl *| Out-File $SetupPath\test.txt
                        Write-Verbose -Message "site $($spsite.Title) has template $($spsite.RootWeb.WebTemplate)"
                        if ($spsite.RootWeb.WebTemplate -like "STS") {
                            Write-Verbose -Message "Updating site $siteUrl with $owner1 and $($spsite.Url)"
                            $spsite.RootWeb.CreateDefaultAssociatedGroups($owner1, $owner2, $spsite.RootWeb.Title);
                            $spsite.RootWeb.Update();
                        }
                    }
                }
            }
            GetScript = {return @{ "Result" = "false"}}
            TestScript = {return $false}
            PsDscRunAsCredential = $DomainAdminCredsQualified
            DependsOn = "[SPSite]RootTeamSite", "[SPSite]TeamSite"
        }
#>

        # Grant spsvc full control to UPA to allow newsfeeds to work properly
        SPServiceAppSecurity UserProfileServiceSecurity {
            ServiceAppName = $UpaServiceName
            SecurityType = "SharingPermissions"
            MembersToInclude =  @(
                MSFT_SPServiceAppSecurityEntry {
                    Username = $SPSvcCredsQualified.UserName
                    AccessLevels = @("Full Control")
                }
		    )
            PsDscRunAsCredential = $SPSetupCredsQualified
            DependsOn = "[SPUserProfileServiceApp]UserProfileServiceApp"
        }

        File Step11 {
            DestinationPath = "C:\Logs\DSC11.txt"
            Contents = "SPServiceAppSecurity UserProfileServiceSecurity"
            Type = 'File'
            Force = $true
            PsDscRunAsCredential = $SPSetupCredential
            DependsOn = "[SPServiceAppSecurity]UserProfileServiceSecurity"
        }

        SPSubscriptionSettingsServiceApp CreateSubscriptionSettingsServiceApp {
            Name = "Subscription Settings Service Application"
            ApplicationPool = $ServiceAppPoolName
            DatabaseName = "$($SPDBPrefix)SubscriptionSettings"
            InstallAccount = $DomainAdminCredsQualified
            DependsOn = "[SPServiceAppPool]MainServiceAppPool", "[SPServiceInstance]StartSubscriptionSettingsServiceInstance"
        }

        File Step12 {
            DestinationPath = "C:\Logs\DSC12.txt"
            Contents = "SPSubscriptionSettingsServiceApp CreateSubscriptionSettingsServiceApp"
            Type = 'File'
            Force = $true
            PsDscRunAsCredential = $SPSetupCredential
            DependsOn = "[SPSubscriptionSettingsServiceApp]CreateSubscriptionSettingsServiceApp"
        }

        SPAppManagementServiceApp CreateAppManagementServiceApp {
            Name = "App Management Service Application"
            ApplicationPool = $ServiceAppPoolName
            DatabaseName = "$($SPDBPrefix)AppManagement"
            InstallAccount = $DomainAdminCredsQualified
            DependsOn = "[SPServiceAppPool]MainServiceAppPool", "[SPServiceInstance]StartAppManagementServiceInstance"
        }

        File Step13 {
            DestinationPath = "C:\Logs\DSC13.txt"
            Contents = "SPAppManagementServiceApp CreateAppManagementServiceApp"
            Type = 'File'
            Force = $true
            PsDscRunAsCredential = $SPSetupCredential
            DependsOn = "[SPAppManagementServiceApp]CreateAppManagementServiceApp"
        }

        SPSite TeamSite {
            Url = "http://$SPTrustedSitesName/sites/team"
            OwnerAlias = "i:0#.w|$DomainNetbiosName\$($DomainAdminCreds.UserName)"
#            SecondaryOwnerAlias  = "i:05.t|$DomainFQDN|$($DomainAdminCreds.UserName)@$DomainFQDN"
            Name = "Team site"
            Template = "STS#0"
            PsDscRunAsCredential = $SPSetupCredsQualified
            DependsOn = "[SPWebApplication]MainWebApp"
        }

        File Step14 {
            DestinationPath = "C:\Logs\DSC14.txt"
            Contents = "SPSite TeamSite"
            Type = 'File'
            Force = $true
            PsDscRunAsCredential = $SPSetupCredential
            DependsOn = "[SPSite]TeamSite"
        }

        xDnsRecord AddAddinDNSWildcard {
            Name = "*"
            Zone = $AppDomainFQDN
            Target = "$ComputerName.$DomainFQDN"
            Type = "CName"
            DnsServer = "$DCName.$DomainFQDN"
            Ensure = "Present"
            PsDscRunAsCredential = $DomainAdminCredsQualified
            DependsOn = "[SPFarm]CreateSPFarm"
        }

        xDnsRecord AddAddinDNSWildcardInIntranetZone {
            Name = "*"
            Zone = $AppDomainIntranetFQDN
            Target = "$ComputerName.$DomainFQDN"
            Type = "CName"
            DnsServer = "$DCName.$DomainFQDN"
            Ensure = "Present"
            PsDscRunAsCredential = $DomainAdminCredsQualified
            DependsOn = "[SPFarm]CreateSPFarm"
        }

        SPAppDomain ConfigureLocalFarmAppUrls {
            AppDomain = $AppDomainFQDN
            Prefix = "addin"
            PsDscRunAsCredential = $SPSetupCredsQualified
            DependsOn = "[SPSubscriptionSettingsServiceApp]CreateSubscriptionSettingsServiceApp", "[SPAppManagementServiceApp]CreateAppManagementServiceApp"
        }

        File Step15 {
            DestinationPath = "C:\Logs\DSC15.txt"
            Contents = "SPAppDomain ConfigureLocalFarmAppUrls"
            Type = 'File'
            Force = $true
            PsDscRunAsCredential = $SPSetupCredential
            DependsOn = "[SPAppDomain]ConfigureLocalFarmAppUrls"
        }

        SPSite AppCatalog {
            Url = "http://$SPTrustedSitesName/sites/AppCatalog"
            OwnerAlias = "i:0#.w|$DomainNetbiosName\$($DomainAdminCreds.UserName)"
#            SecondaryOwnerAlias = "i:05.t|$DomainFQDN|$($DomainAdminCreds.UserName)@$DomainFQDN"
            Name = "AppCatalog"
            Template = "APPCATALOG#0"
            PsDscRunAsCredential = $SPSetupCredsQualified
            DependsOn = "[SPWebApplication]MainWebApp"
        }

        File Step16 {
            DestinationPath = "C:\Logs\DSC16.txt"
            Contents = "SPSite AppCatalog"
            Type = 'File'
            Force = $true
            PsDscRunAsCredential = $SPSetupCredential
            DependsOn = "[SPSite]AppCatalog"
        }

        Script ConfigureAppDomains {
            SetScript = {
                $argumentList = @(@{"webAppUrl" = "http://$using:SPTrustedSitesName";
                                    "AppDomainFQDN" = "$using:AppDomainFQDN";
                                    "AppDomainIntranetFQDN" = "$using:AppDomainIntranetFQDN"})
                Invoke-SPDscCommand -Arguments @argumentList -ScriptBlock {
                    $params = $args[0]

                    # Configure app domains in zones of the web application
                    $webAppUrl = $params.webAppUrl
                    $appDomainDefaultZone = $params.AppDomainFQDN
                    $appDomainIntranetZone = $params.AppDomainIntranetFQDN

                    $defaultZoneConfig = Get-SPWebApplicationAppDomain -WebApplication $webAppUrl -Zone Default
                    if($defaultZoneConfig -eq $null) {
                        New-SPWebApplicationAppDomain -WebApplication $webAppUrl -Zone Default -AppDomain $appDomainDefaultZone -ErrorAction SilentlyContinue
                    }
                    elseif ($defaultZoneConfig.AppDomain -notlike $appDomainDefaultZone) {
                        $defaultZoneConfig| Remove-SPWebApplicationAppDomain -Confirm:$false
                        New-SPWebApplicationAppDomain -WebApplication $webAppUrl -Zone Default -AppDomain $appDomainDefaultZone -ErrorAction SilentlyContinue
                    }

                    $IntranetZoneConfig = Get-SPWebApplicationAppDomain -WebApplication $webAppUrl -Zone Intranet
                    if($IntranetZoneConfig -eq $null) {
                        New-SPWebApplicationAppDomain -WebApplication $webAppUrl -Zone Intranet -SecureSocketsLayer -AppDomain $appDomainIntranetZone -ErrorAction SilentlyContinue
                    }
                    elseif ($IntranetZoneConfig.AppDomain -notlike $appDomainIntranetZone) {
                        $IntranetZoneConfig| Remove-SPWebApplicationAppDomain -Confirm:$false
                        New-SPWebApplicationAppDomain -WebApplication $webAppUrl -Zone Intranet -SecureSocketsLayer -AppDomain $appDomainIntranetZone -ErrorAction SilentlyContinue
                    }

                    # Configure app catalog
                    # Deactivated because it throws "Access is denied. (Exception from HRESULT: 0x80070005 (E_ACCESSDENIED))"
                    #Update-SPAppCatalogConfiguration -Site "$webAppUrl/sites/AppCatalog" -Confirm:$false
                }
            }
            GetScript            = {return @{"Result" = "false"}}
            TestScript           = {return $false}
            PsDscRunAsCredential = $DomainAdminCredsQualified
            DependsOn = "[SPAppDomain]ConfigureLocalFarmAppUrls"
        }

        File Step17 {
            DestinationPath = "C:\Logs\DSC17.txt"
            Contents = "Script ConfigureAppDomains"
            Type = 'File'
            Force = $true
            PsDscRunAsCredential = $SPSetupCredential
            DependsOn = "[Script]ConfigureAppDomains"
        }

        SPAppCatalog MainAppCatalog {
            SiteUrl = "http://$SPTrustedSitesName/sites/AppCatalog"
            PsDscRunAsCredential = $DomainAdminCredsQualified
            DependsOn = "[SPSite]AppCatalog"
        }

        File Step18 {
            DestinationPath = "C:\Logs\DSC18.txt"
            Contents = "SPAppCatalog MainAppCatalog"
            Type = 'File'
            Force = $true
            PsDscRunAsCredential = $SPSetupCredential
            DependsOn = "[SPAppCatalog]MainAppCatalog"
        }

        # DSC resource File throws an access denied when accessing a remote location, so use xScript instead
        xScript CreateDSCCompletionFile {
            SetScript = {
                $SetupPath = $using:DCSetupPath
                $ComputerName = $using:ComputerName
                $DestinationPath = "$SetupPath\SPDSCFinished.txt"
                $Contents = "DSC Configuration on $ComputerName finished successfully."
                # Do not overwrite and do not throw an exception if file already exists
                New-Item $DestinationPath -Type file -Value $Contents -ErrorAction SilentlyContinue
            }
            GetScript = { }
            TestScript = {return $false}
            PsDscRunAsCredential = $DomainAdminCredsQualified
            DependsOn = "[Script]ConfigureAppDomains"
        }
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
    param (
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
