import argparse
import random
import re
import string
import sys

obfuscated_strings = []
known_cmdlets = ["Add-Computer","Add-Content","Add-EtwTraceProvider","Add-History","Add-JobTrigger","Add-KdsRootKey","Add-LocalGroupMember","Add-Member","Add-MpPreference","Add-NetEventProvider","Add-NetEventVFPProvider","Add-NetEventVmSwitch","Add-OdbcDsn","Add-PSSnapin","Add-PhysicalDisk","Add-Printer","Add-PrinterDriver","Add-PrinterPort","Add-StorageFaultDomain","Add-Type","Add-VpnConnection","Add-VpnConnectionRoute","Add-WindowsCapability","Add-WindowsDriver","Add-WindowsImage","Add-WindowsPackage","Clear-Content","Clear-Disk","Clear-DnsClientCache","Clear-EventLog","Clear-History","Clear-Host","Clear-Item","Clear-ItemProperty","Clear-Recyclebin","Clear-Tpm","Clear-Variable","Close-SmbOpenFile","Close-SmbSession","Compare-Object","Complete-BitsTransfer","Complete-Transaction","Compress-Archive","Connect-PSSession","Convert-Path","Convert-String","ConvertFrom-SecureString","ConvertFrom-String","ConvertFrom-StringData","ConvertTo-Csv","ConvertTo-Html","ConvertTo-Json","ConvertTo-SecureString","ConvertTo-Xml","Copy-BcdEntry","Copy-Item","Copy-ItemProperty","Copy-NetFirewallRule","Copy-NetIPsecRule","Debug-FileShare","Debug-Process","Debug-Runspace","Disable-DscDebug","Disable-JobTrigger","Disable-LocalUser","Disable-MMAgent","Disable-NetAdapter","Disable-NetAdapterBinding","Disable-NetFirewallRule","Disable-OdbcPerfCounter","Disable-PSBreakpoint","Disable-PSRemoting","Disable-PSTrace","Disable-PnpDevice","Disable-RunspaceDebug","Disable-ScheduledJob","Disable-ScheduledTask","Enable-ComputerRestore","Enable-DscDebug","Enable-JobTrigger","Enable-LocalUser","Enable-MMAgent","Enable-NetAdapter","Enable-PSRemoting","Enable-PSSessionConfiguration","Enable-ScheduledJob","Enable-ScheduledTask","Enable-SmbDelegation","Enable-StorageBusDisk","Enter-PSHostProcess","Enter-PSSession","Exit-PSHostProcess","Exit-PSSession","Expand-Archive","Export-Alias","Export-Certificate","Export-Clixml","Export-Console","Export-Counter","Export-Csv","Export-FormatData","Export-ModuleMember","Export-ODataEndpointProxy","Export-PSSession","Export-PfxCertificate","Export-ScheduledTask","Export-StartLayout","Export-Trace","Export-WindowsDriver","Export-WindowsImage","Find-Command","Find-DscResource","Find-Module","Find-NetIPsecRule","Find-NetRoute","Find-Package","Find-PackageProvider","Find-RoleCapability","Find-Script","Flush-Volume","ForEach-Object","Format-Custom","Format-Hex","Format-List","Format-Table","Format-Volume","Format-Wide","Get-Acl","Get-Alias","Get-BitsTransfer","Get-Certificate","Get-ChildItem","Get-CimClass","Get-CimInstance","Get-CimSession","Get-Clipboard","Get-CmsMessage","Get-Command","Get-ComputerInfo","Get-Content","Get-Counter","Get-Credential","Get-Culture","Get-Date","Get-Disk","Get-DiskImage","Get-DiskSNV","Get-DnsClient","Get-DnsClientCache","Get-DscConfiguration","Get-DscResource","Get-Dtc","Get-DtcDefault","Get-DtcLog","Get-DtcTransaction","Get-EtwTraceProvider","Get-EtwTraceSession","Get-Event","Get-EventLog","Get-EventSubscriber","Get-ExecutionPolicy","Get-FileHash","Get-FileShare","Get-FileStorageTier","Get-FormatData","Get-Help","Get-History","Get-Host","Get-HotFix","Get-InitiatorId","Get-IscsiConnection","Get-IscsiSession","Get-IscsiTarget","Get-IscsiTargetPortal","Get-IseSnippet","Get-Item","Get-ItemProperty","Get-Job","Get-JobTrigger","Get-Language","Get-LapsAADPassword","Get-LapsADPassword","Get-LapsDiagnostics","Get-LocalGroup","Get-LocalGroupMember","Get-LocalUser","Get-Location","Get-LogProperties","Get-MMAgent","Get-MaskingSet","Get-Member","Get-Module","Get-MpComputerStatus","Get-MpPreference","Get-MpThreat","Get-MpThreatCatalog","Get-NetFirewallProfile","Get-NetIPAddress","Get-NetIPConfiguration","Get-NetIPHttpsConfiguration","Get-NetIPHttpsState","Get-NetIPInterface","Get-NetNat","Get-NetNatGlobal","Get-NetNatSession","Get-NetPrefixPolicy","Get-NetView","Get-PSBreakpoint","Get-PSCallStack","Get-PSDrive","Get-PSHostProcessInfo","Get-PSProvider","Get-PSRepository","Get-PSSession","Get-Package","Get-PackageProvider","Get-PackageSource","Get-Partition","Get-PartitionSupportedSize","Get-PfxCertificate","Get-PfxData","Get-PhysicalDisk","Get-PhysicalExtent","Get-PrintConfiguration","Get-PrintJob","Get-Printer","Get-PrinterDriver","Get-PrinterPort","Get-PrinterProperty","Get-Process","Get-ProcessMitigation","Get-Random","Get-ResiliencySetting","Get-Runspace","Get-RunspaceDebug","Get-ScheduledJob","Get-ScheduledTask","Get-ScheduledTaskInfo","Get-SecureBootPolicy","Get-SecureBootUEFI","Get-Service","Get-SmbConnection","Get-SmbDelegation","Get-SmbGlobalMapping","Get-SmbMapping","Get-SmbOpenFile","Get-SmbSession","Get-SmbShare","Get-SmbShareAccess","Get-SmbWitnessClient","Get-StartApps","Get-StorageBusBinding","Get-StorageBusCache","Get-StorageBusDisk","Get-StorageHistory","Get-StorageJob","Get-StorageNode","Get-StoragePool","Get-StorageProvider","Get-StorageSubSystem","Get-StorageTier","Get-SystemLanguage","Get-TargetPort","Get-TargetPortal","Get-TestDriveItem","Get-TimeZone","Get-TlsCipherSuite","Get-TlsEccCurve","Get-Tpm","Get-TraceSource","Get-Transaction","Get-TypeData","Get-UICulture","Get-Unique","Get-Variable","Get-Verb","Get-VirtualDisk","Get-Volume","Get-VpnConnection","Get-WIMBootEntry","Get-WSManCredSSP","Get-WSManInstance","Get-WdacBidTrace","Get-WinEvent","Get-WinSystemLocale","Get-WindowsDriver","Get-WindowsEdition","Get-WindowsImage","Get-WindowsImageContent","Get-WindowsPackage","Get-WindowsUpdateLog","Get-WinhttpProxy","Get-WmiObject","Group-Object","Hide-VirtualDisk","Import-Alias","Import-BcdStore","Import-BinaryMiLog","Import-Certificate","Import-Clixml","Import-Counter","Import-Csv","Import-IseSnippet","Import-LocalizedData","Import-Module","Import-PSSession","Import-StartLayout","Import-TpmOwnerAuth","Import-WinhttpProxy","Initialize-Disk","Initialize-Tpm","Initialize-Volume","Install-Dtc","Install-Language","Install-Module","Install-Package","Install-PackageProvider","Install-Script","Invoke-Command","Invoke-CommandInDesktopPackage","Invoke-DscResource","Invoke-Expression","Invoke-History","Invoke-Item","Invoke-Pester","Invoke-RestMethod","Invoke-WSManAction","Invoke-WebRequest","Invoke-WmiMethod","Join-Path","Limit-EventLog","Lock-BitLocker","Measure-Command","Measure-Object","Mount-DiskImage","Mount-WindowsImage","Move-Item","Move-ItemProperty","Move-SmbClient","New-Alias","New-AutologgerConfig","New-BcdEntry","New-BcdStore","New-CimInstance","New-CimSession","New-CimSessionOption","New-DscChecksum","New-EapConfiguration","New-EtwTraceSession","New-Event","New-EventLog","New-FileCatalog","New-FileShare","New-Fixture","New-Guid","New-Item","New-ItemProperty","New-JobTrigger","New-LocalGroup","New-LocalUser","New-MaskingSet","New-Module","New-Object","New-PSDrive","New-PSRoleCapabilityFile","New-PSSession","New-PSSessionOption","New-PSTransportOption","New-PSWorkflowSession","New-Partition","New-PesterOption","New-PmemDedicatedMemory","New-PmemDisk","New-ProvisioningRepro","New-ScheduledJobOption","New-ScheduledTask","New-ScheduledTaskAction","New-ScriptFileInfo","New-SelfSignedCertificate","New-Service","New-SmbGlobalMapping","New-SmbMapping","New-SmbShare","New-StorageBusBinding","New-StorageTier","New-TemporaryFile","New-TimeSpan","New-Variable","New-VirtualDisk","New-VirtualDiskClone","New-Volume","New-WebServiceProxy","New-WinEvent","New-WindowsImage","Open-NetGPO","Out-Default","Out-File","Out-Host","Out-Null","Out-Printer","Out-String","Pop-Location","Protect-CmsMessage","Publish-Module","Publish-Script","Push-Location","Read-Host","Register-PSRepository","Register-PackageSource","Register-ScheduledJob","Register-ScheduledTask","Register-WmiEvent","Remove-BcdEntry","Remove-Computer","Remove-EtwTraceProvider","Remove-EtwTraceSession","Remove-Event","Remove-EventLog","Remove-FileShare","Remove-InitiatorId","Remove-IscsiTargetPortal","Remove-Item","Remove-ItemProperty","Remove-Job","Remove-JobTrigger","Remove-LocalGroup","Remove-LocalGroupMember","Remove-LocalUser","Remove-MaskingSet","Remove-Module","Remove-MpPreference","Remove-MpThreat","Remove-NetFirewallRule","Remove-NetIPAddress","Remove-NetIPsecRule","Remove-NetNat","Remove-NetworkSwitchVlan","Remove-OdbcDsn","Remove-PSDrive","Remove-PSSession","Remove-PSSnapin","Remove-Partition","Remove-PhysicalDisk","Remove-PmemDisk","Remove-PrintJob","Remove-Printer","Remove-PrinterDriver","Remove-PrinterPort","Remove-SMBComponent","Remove-SmbMapping","Remove-SmbShare","Remove-StorageFileServer","Remove-StoragePool","Remove-StorageTier","Remove-TypeData","Remove-Variable","Remove-VirtualDisk","Remove-WSManInstance","Remove-WindowsDriver","Remove-WindowsImage","Remove-WindowsPackage","Remove-WmiObject","Rename-Computer","Rename-Item","Rename-ItemProperty","Rename-LocalGroup","Rename-LocalUser","Rename-MaskingSet","Rename-NetAdapter","Rename-Printer","Repair-FileIntegrity","Repair-VirtualDisk","Repair-Volume","Reset-LapsPassword","Reset-PhysicalDisk","Reset-WinhttpProxy","Resize-Partition","Resize-StorageTier","Resize-VirtualDisk","Restart-Computer","Restart-NetAdapter","Restart-PcsvDevice","Restart-PrintJob","Restart-Service","Restore-Computer","Resume-BitLocker","Resume-BitsTransfer","Resume-Job","Resume-PrintJob","Resume-Service","Resume-StorageBusDisk","Save-EtwTraceSession","Save-Help","Save-Module","Save-NetGPO","Save-Package","Save-Script","Save-SoftwareInventory","Save-WindowsImage","Select-Object","Select-String","Select-Xml","Send-EtwTraceSession","Send-MailMessage","Set-Acl","Set-Alias","Set-BitsTransfer","Set-CimInstance","Set-Clipboard","Set-Content","Set-Culture","Set-DODownloadMode","Set-Date","Set-Disk","Set-DnsClient","Set-EtwTraceProvider","Set-EtwTraceSession","Set-ExecutionPolicy","Set-FileIntegrity","Set-FileShare","Set-FileStorageTier","Set-Item","Set-ItemProperty","Set-JobTrigger","Set-KdsConfiguration","Set-LapsADAuditing","Set-LocalGroup","Set-LocalUser","Set-Location","Set-LogProperties","Set-MMAgent","Set-MpPreference","Set-NetUDPSetting","Set-OdbcDriver","Set-OdbcDsn","Set-PSBreakpoint","Set-PSDebug","Set-PSReadLineOption","Set-PSRepository","Set-PackageSource","Set-Partition","Set-PhysicalDisk","Set-PreferredLanguage","Set-PrintConfiguration","Set-Printer","Set-PrinterProperty","Set-ProcessMitigation","Set-ResiliencySetting","Set-ScheduledJob","Set-ScheduledJobOption","Set-Service","Set-SmbPathAcl","Set-SmbShare","Set-StorageBusProfile","Set-StorageFileServer","Set-StoragePool","Set-StorageProvider","Set-StorageSetting","Set-StorageSubSystem","Set-StorageTier","Set-StrictMode","Set-SystemLanguage","Set-TestInconclusive","Set-TimeZone","Set-TpmOwnerAuth","Set-TraceSource","Set-Variable","Set-VirtualDisk","Set-Volume","Set-WindowsProductKey","Set-WinhttpProxy","Set-WmiInstance","Show-Command","Show-EventLog","Show-NetFirewallRule","Show-NetIPsecRule","Show-StorageHistory","Show-VirtualDisk","Sort-Object","Split-Path","Start-AppBackgroundTask","Start-AutologgerConfig","Start-BitsTransfer","Start-DscConfiguration","Start-Dtc","Start-EtwTraceSession","Start-Job","Start-MpRollback","Start-MpScan","Start-MpWDOScan","Start-NetEventSession","Start-OSUninstall","Start-PcsvDevice","Start-Process","Start-ScheduledTask","Start-Service","Start-Sleep","Start-Trace","Start-Transaction","Start-Transcript","Stop-Computer","Stop-DscConfiguration","Stop-Dtc","Stop-EtwTraceSession","Stop-Job","Stop-NetEventSession","Stop-PcsvDevice","Stop-Process","Stop-ScheduledTask","Stop-Service","Stop-StorageDiagnosticLog","Stop-StorageJob","Stop-Trace","Stop-Transcript","Suspend-BitLocker","Suspend-BitsTransfer","Suspend-Job","Suspend-PrintJob","Suspend-Service","Suspend-StorageBusDisk","Switch-Certificate","Sync-NetIPsecRule","Tee-Object","Test-Certificate","Test-ComputerSecureChannel","Test-Connection","Test-DscConfiguration","Test-Dtc","Test-FileCatalog","Test-KdsRootKey","Test-ModuleManifest","Test-NetConnection","Test-Path","Test-ScriptFileInfo","Test-WSMan","Trace-Command","Update-IscsiTarget","Update-LapsADSchema","Update-List","Update-Module","Update-MpSignature","Update-TypeData","Use-Transaction","Wait-Debugger","Wait-Event","Wait-Job","Wait-Process","Where-Object","Write-Debug","Write-Error","Write-EventLog","Write-FileSystemCache","Write-Host","Write-Information","Write-Output","Write-PrinterNfcTag","Write-Progress","Write-Verbose","Write-VolumeCache","Write-Warning","IEX"]
special_vars = ["$true", "$false", "$null", "$error", "$this", "$input"]
known_namespace_classes = ["System.IO.StreamWriter", "System.Net.Sockets.TcpClient"]
special_characters = "?<>',?[]}{=-)(*&^%$#`~{}"
no_backticks = "0abefnrtuxv"

safe_mode = False
all_mode = False
verbose = False
case_obfs = False


def ascii_art():
    print("OFFSHELL\n")
    print("by @uixss v0.2\n")


def parse_args():
    parser = argparse.ArgumentParser(description="OFFSHELL | Offensive tool to obfuscate powershell payloads")
    parser.add_argument("-f", "--file", required=True, help="source Powershell script to obfuscate")
    parser.add_argument("-o", "--output", required=True, help="store obfuscated script in a file")
    parser.add_argument("-a", "--all", action="store_true", help="use all obfuscation techniques")
    parser.add_argument("-s", "--safe", action="store_true", help="enable safe obfuscation mode")
    parser.add_argument("--vars", action="store_true", help="enable variable obfuscation")
    parser.add_argument("--funcs", action="store_true", help="enable functions obfuscation")
    parser.add_argument("--cmdlets", action="store_true", help="enable cmdlets obfuscation")
    parser.add_argument("--namespaces", action="store_true", help="enable namespace classes obfuscation")
    parser.add_argument("--backticks", action="store_true", help="enable backticks obfuscation")
    parser.add_argument("--case", action="store_true", help="enable uppercase/lowercase obfuscation")
    parser.add_argument("--pipes", action="store_true", help="enable pipes and pipelines obfuscation")
    parser.add_argument("--comments", action="store_true", help="remove and obfuscate comments")
    parser.add_argument("--indentation", action="store_true", help="add random indentation")
    parser.add_argument("--ips", action="store_true", help="obfuscate IP addresses by converting them to hex format")
    parser.add_argument("-v", "--verbose", action="store_true", help="enable verbose")
    return parser.parse_args()


def random_string(length=8):
    return ''.join(random.choices(string.ascii_letters, k=length))


def obfuscate_word_case(word):
    return ''.join(char.upper() if random.choice([True, False]) else char.lower() for char in word)


def add_backticks_to_word(word):
    obfuscated = ""
    for char in word:
        if char not in special_characters and char not in no_backticks:
            obfuscated += "`" + char if random.choice([True, False]) else char
        else:
            obfuscated += char
    return obfuscated if "`" in obfuscated else "`" + obfuscated


def obfuscate_variables(content):
    if verbose:
        print("[*] Obfuscating variables...")
    variables = set(re.findall(r"\$[\w|_]+", content))

    replacements = {}
    for var in variables:
        if var.lower() not in map(str.lower, special_vars):
            replacements[var] = f"${random_string(10)}"

    if verbose:
        print(f"Reemplazos generados: {replacements}")

    for var, new_var in replacements.items():
        content = re.sub(rf"\b{re.escape(var)}\b", new_var, content)

    return content

def obfuscate_functions(content):
    if verbose:
        print("[*] Obfuscating functions...")
    functions = set(re.findall(r"function\s+([\w|\_|\-]+)\s*\{", content, re.IGNORECASE))
    for func in sorted(functions, key=len, reverse=True):
        new_func = random_string(12)
        content = re.sub(rf"\b{re.escape(func)}\b", new_func, content)
    return content


def obfuscate_cmdlets(content):
    if verbose:
        print("[*] Obfuscating cmdlets...")
    for cmdlet in known_cmdlets:
        if cmdlet.lower() in content.lower():
            content = re.sub(rf"\b{re.escape(cmdlet)}\b", add_backticks_to_word(obfuscate_word_case(cmdlet)), content, flags=re.IGNORECASE)
    return content


def obfuscate_namespaces(content):
    if verbose:
        print("[*] Obfuscating namespace classes...")
    for namespace in known_namespace_classes:
        if namespace.lower() in content.lower():
            obfuscated = "$(" + "".join(f"[char]({ord(c)}+{random.randint(1, 100)}-{random.randint(1, 100)})+" for c in namespace).strip("+") + ")"
            content = re.sub(rf"\b{re.escape(namespace)}\b", obfuscated, content, flags=re.IGNORECASE)
    return content


def obfuscate_comments(content):
    if verbose:
        print("[*] Removing comments...")
    content = re.sub(r"<#.*?#>", "", content, flags=re.DOTALL)
    content = re.sub(r"#.*", "", content)
    return content


def obfuscate_pipes(content):
    if verbose:
        print("[*] Obfuscating pipes...")
    return re.sub(r"\|", "|%{$_}|", content)


def obfuscate_indentation(content):
    if verbose:
        print("[*] Adding random indentation...")
    return "\n".join(" " * random.randint(0, 8) + line for line in content.splitlines())


def obfuscate_ips(content):
    if verbose:
        print("[*] Obfuscating IP addresses...")
    ip_pattern = r"((?:[0-9]{1,3}\.){3}[0-9]{1,3})"
    return re.sub(ip_pattern, lambda match: "0x" + "".join(f"{int(octet):02x}" for octet in match.group(0).split(".")), content)


def main():
    args = parse_args()
    global verbose, safe_mode, all_mode, case_obfs
    verbose = args.verbose
    safe_mode = args.safe
    all_mode = args.all
    case_obfs = args.case

    ascii_art()

    try:
        with open(args.file, "r", encoding="utf-8") as f:
            content = f.read()
    except Exception as e:
        print(f"[!] Error reading file {args.file}: {e}")
        sys.exit(1)

    if safe_mode or all_mode or any([args.vars, args.funcs, args.cmdlets, args.namespaces, args.backticks, args.pipes, args.comments, args.indentation, args.ips]):
        if safe_mode or args.comments:
            content = obfuscate_comments(content)
        if args.vars or all_mode:
            content = obfuscate_variables(content)
        if args.funcs or all_mode:
            content = obfuscate_functions(content)
        if args.cmdlets or all_mode:
            content = obfuscate_cmdlets(content)
        if args.namespaces or all_mode:
            content = obfuscate_namespaces(content)
        if args.backticks or all_mode:
            content = re.sub(r"\b\w+\b", lambda word: add_backticks_to_word(word.group()), content)
        if args.pipes or all_mode:
            content = obfuscate_pipes(content)
        if args.indentation or all_mode:
            content = obfuscate_indentation(content)
        if args.ips or all_mode:
            content = obfuscate_ips(content)
    else:
        print("[!] No obfuscation techniques specified.")
        sys.exit(1)

    try:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(content)
    except Exception as e:
        print(f"[!] Error writing to file {args.output}: {e}")
        sys.exit(1)

    print(f"[+] Obfuscated script written to {args.output}")


if __name__ == "__main__":
    main()
