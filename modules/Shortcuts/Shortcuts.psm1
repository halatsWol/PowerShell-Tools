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
		Author: Wolfram Halatschek
		E-Mail: halatschek.wolfram@gmail.com
		Date: 2024-10-04
	#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true, ValueFromPipeline=$true)]
		[string]$path
	)

	$obj = New-Object -ComObject WScript.Shell
	$pathUser = [System.Environment]::GetFolderPath('StartMenu')
	$pathCommon = $obj.SpecialFolders.Item('AllUsersStartMenu')
	$path = Get-ChildItem $pathUser, $pathCommon -Filter *.lnk -Recurse
	$path = Get-ChildItem $path -Filter *.lnk

	$path | ForEach-Object {
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
	#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true, ValueFromPipeline=$true)]
		[string]$LinkPath,

		[Patameter(Mandatory=$false)]
		[string]$Hotkey,

		[Patameter(Mandatory=$false)]
		[string]$IconLocation,

		[Patameter(Mandatory=$false)]
		[string]$Arguments,

		[Patameter(Mandatory=$true)]
		[string]$TargetPath,

		[Patameter(Mandatory=$false)]
		[string]$WorkingDirectory
	)



	if(-not $IconLocation){
		$IconLocation = ',1'
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

Export-ModuleMember -Function Set-Shortcut, Get-Shortcut