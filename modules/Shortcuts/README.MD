# Shortcuts PowerShell Module

## Overview

The `Shortcuts` PowerShell module provides functions to manage Windows shortcut (`.lnk`) files. It allows users to retrieve detailed information about existing shortcuts and create or modify shortcuts with specific parameters such as target path, hotkey, icon location, and working directory. This module is useful for automating the management of shortcut files in both user and system environments.

## Functionality

### `Get-Shortcut`

Retrieves information about a specified shortcut file, including its target path, arguments, icon, working directory, and hotkey. This function allows for exploration of existing shortcuts on the system.

#### Parameters

- **`-Path`** (Mandatory): The path to the shortcut file or folder containing shortcut files. Can be piped into the function.

#### Example

```PowerShell
# Get information about a specific shortcut
Get-Shortcut -Path 'C:\Users\Public\Desktop\Notepad.lnk'

# Get information about all shortcuts within a folder
Get-Shortcut -Path 'C:\Users\Public\Desktop'
```

### `Set-Shortcut`

Creates or modifies a shortcut file with specified parameters such as the target application, arguments, hotkey, icon, and working directory. It provides flexibility to customize the shortcut settings according to user preferences.


#### Parameters

- **`LinkPath`** (Mandatory): The destination path where the shortcut will be created or modified.
- **`TargetPath`** (Mandatory): The target path the shortcut will point to.
- **`Hotkey`** (Optional): The hotkey for the shortcut.
- **`IconLocation`** (Optional): The icon location for the shortcut. Defaults to the target's icon if not specified.
- **`Arguments`** (Optional): Command-line arguments to pass to the target application.
- **`WorkingDirectory`** (Optional): The working directory for the shortcut. If not specified, the directory of the target path is used.

#### Example

```PowerShell
# Create or modify a shortcut with a custom target, icon, and hotkey
Set-Shortcut -LinkPath 'C:\Users\Public\Desktop\Notepad.lnk' -TargetPath 'C:\Windows\System32\notepad.exe' -Hotkey 'Ctrl+Alt+N' -IconLocation 'C:\Icons\Notepad.ico'

# Create a shortcut with default settings for icon and working directory
Set-Shortcut -LinkPath 'C:\Users\Public\Desktop\MyShortcut.lnk' -TargetPath 'C:\Program Files\MyApp\MyApp.exe'

```

## Requirements

- The PowerShell module uses the Windows Script Host COM object (WScript.Shell) to manage shortcut files, so it is compatible only with Windows systems.
- Administrative privileges are not required to use this module unless shortcuts in protected directories are being modified.


## Notes

- This script is provided as-is and is not supported by Microsoft.
- Test thoroughly before using on production systems as improper use may cause data loss or system instability.
- Ensure you understand the consequences before making system changes or deleting files.

## Author

- **Author**: Wolfram Halatschek
- **Contact**: halatschek.wolfram@gmail.com
- **Date**: October 0, 2024

## Warnings

- **ALWAYS REVIEW AND UNDERSTAND THE CODE BEFORE EXECUTING.**
- **NEVER MAKE SYSTEM CHANGES WITHOUT AUTHORIZATION.**
- **DO NOT USE THIS SCRIPT ON PRODUCTION SYSTEMS WITHOUT PROPER TESTING.**
