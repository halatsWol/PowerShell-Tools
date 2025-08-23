function Get-Shortcut {
	<#
	.SYNOPSIS
	Get information about a shortcut file.

	.DESCRIPTION
	prints information about a shortcut file.

	.PARAMETER path
	The path to the shortcut file.

	.EXAMPLE
	Get-Shortcut -path 'C:\Users\Public\Desktop\Notepad.lnk'

	.NOTES
    This script is provided as-is and is not supported by Microsoft. Use it at your own risk.
    WinRM must be enabled and configured on the remote computer for this script to work. Using IP addresses may require additional configuration.
    Using this script may require administrative privileges on the remote computer.
    In a Domain, powershell can be executed locally as the user wich has the necessary permissions on the remote computer.

	WARNING:
    NEVER CHANGE SYSTEM SETTINGS OR DELETE FILES WITHOUT PERMISSION OR AUTHORIZATION.
    NEVER CHANGE SYSTEM SETTINGS OR DELETE FILES WITHOUT UNDERSTANDING THE CONSEQUENCES.
    NEVER RUN SCRIPTS FROM UNTRUSTED SOURCES WITHOUT REVIEWING AND UNDERSTANDING THE CODE.
    DO NOT USE THIS SCRIPT ON PRODUCTION SYSTEMS WITHOUT PROPER TESTING. IT MAY CAUSE DATA LOSS OR SYSTEM INSTABILITY.


    Author: Wolfram Halatschek
    E-Mail: halatschek.wolfram@gmail.com
    Date: 2024-10-06

	#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true, ValueFromPipeline=$true)]
		[string]$path
	)

	$obj = New-Object -ComObject WScript.Shell
	# Check if Path is a single file or a folder
	if (Test-Path -Path $Path -PathType Leaf) {
		# If it's a single file
		$shortcutFiles = Get-ChildItem $Path -Filter *.lnk
	} elseif (Test-Path -Path $Path -PathType Container) {
		# If it's a folder, search for .lnk files recursively
		$shortcutFiles = Get-ChildItem $Path -Filter *.lnk -Recurse
	} else {
		Write-Error "The specified path '$Path' does not exist."
		return
	}

	$shortcutFiles | ForEach-Object {
		try{
			if ($_ -is [string]) {
				$_ = Get-ChildItem $_ -Filter *.lnk
			}
			if ($_) {
				$link = $obj.CreateShortcut($_.FullName)

				$info = @{}
				$info.Hotkey = $link.Hotkey
				$info.TargetPath = $link.TargetPath
				$info.LinkPath = $link.FullName
				$info.Arguments = $link.Arguments
				$info.Target = try { Split-Path $info.TargetPath -Leaf } catch { 'n/a' }
				$info.Link = try { Split-Path $info.LinkPath -Leaf } catch { 'n/a' }
				$info.WindowStyle = $link.WindowStyle
				$info.IconLocation = $link.IconLocation
				$info.WorkingDirectory = $link.WorkingDirectory

				New-Object PSObject -Property $info
			}
		} catch {
			Write-Error "Failed to retrieve information for the shortcut: $_"
		}
	}
}

function Set-Shortcut {
	<#
	.SYNOPSIS
	Create or modify a shortcut file.

	.DESCRIPTION
	Create or modify a shortcut file.

	.PARAMETER LinkPath
	Destination Path of the Shortcut

	.PARAMETER Hotkey
	Hotkey of the Shortcut

	.PARAMETER IconLocation
	Icon Location of the Shortcut, if not set, the target icon is used (value ',1')

	.PARAMETER Arguments
	Arguments of the Shortcut

	.PARAMETER TargetPath
	Target Path of the Shortcut

	.PARAMETER WorkingDirectory
	Working-Directory / 'Start In'-Directory of the Shortcut, If not set, the target directory is used
	If WorkingDirectory needs to be empty, please set it to an empty string


	.EXAMPLE
	Set-Shortcut -LinkPath 'C:\Users\Public\Desktop\Notepad.lnk' -Hotkey 'Ctrl+Alt+N' -IconLocation 'C:\Windows\System32\notepad.exe,0' -Arguments 'C:\Windows\System32\notepad.exe' -TargetPath 'C:\Windows\System32\notepad.exe' -WorkingDirectory 'C:\Windows\System32'

    .LINK
    https://github.com/halatsWol/PowerShell-Tools

    .LINK
	https://kMarflow.com/

	.NOTES
    This script is provided as-is and is not supported by Microsoft. Use it at your own risk.
    WinRM must be enabled and configured on the remote computer for this script to work. Using IP addresses may require additional configuration.
    Using this script may require administrative privileges on the remote computer.
    In a Domain, powershell can be executed locally as the user wich has the necessary permissions on the remote computer.

	WARNING:
    NEVER CHANGE SYSTEM SETTINGS OR DELETE FILES WITHOUT PERMISSION OR AUTHORIZATION.
    NEVER CHANGE SYSTEM SETTINGS OR DELETE FILES WITHOUT UNDERSTANDING THE CONSEQUENCES.
    NEVER RUN SCRIPTS FROM UNTRUSTED SOURCES WITHOUT REVIEWING AND UNDERSTANDING THE CODE.
    DO NOT USE THIS SCRIPT ON PRODUCTION SYSTEMS WITHOUT PROPER TESTING. IT MAY CAUSE DATA LOSS OR SYSTEM INSTABILITY.


    Author: Wolfram Halatschek
    E-Mail: halatschek.wolfram@gmail.com
    Date: 2024-10-06

	#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true, ValueFromPipeline=$true)]
		[string]$LinkPath,

		[Parameter(Mandatory=$false)]
		[string]$Hotkey,

		[Parameter(Mandatory=$false)]
		[string]$IconLocation,

		[Parameter(Mandatory=$false)]
		[string]$Arguments,

		[Parameter(Mandatory=$true)]
		[string]$TargetPath,

		[Parameter(Mandatory=$false)]
		[string]$WorkingDirectory
	)



	if(-not $IconLocation){
		$IconLocation = ',0'
	}
	# if WorkingDirectory is not set, use the target directory
	if (-not $PSCmdlet.MyInvocation.BoundParameters.ContainsKey('WorkingDirectory')) {
		$WorkingDirectory = (Get-Item $TargetPath).DirectoryName
	}


	$shell = New-Object -ComObject WScript.Shell
	$link = $shell.CreateShortcut($LinkPath)
	$PSCmdlet.MyInvocation.BoundParameters.GetEnumerator() |
	Where-Object { $_.key -ne 'LinkPath' } |
	ForEach-Object { $link.$($_.key) = $_.value }
	$link.Save()

}

Export-ModuleMember -Function Get-Shortcut,Set-Shortcut
