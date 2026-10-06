# PowerShell-Tools

Welcome to the **PowerShell-Tools** repository! This repository is dedicated to providing a collection of PowerShell scripts and modules designed to make IT tasks easier, more efficient, and more automated.

## Table of Contents

- [PowerShell-Tools](#powershell-tools)
	- [Table of Contents](#table-of-contents)
	- [Introduction](#introduction)
	- [Features](#features)
	- [Modules and Scripts](#modules-and-scripts)
		- [Modules](#modules)
			- [`Repair-System`](#repair-system)
			- [`Shortcuts`](#shortcuts)
			- [`TempDataCleanup`](#tempdatacleanup)
			- [`CredentialHandler`](#credentialhandler)
		- [Scripts](#scripts)
			- [`AutoDeskCleanRemove.ps1`](#autodeskcleanremoveps1)
			- [`bulkUninstall.ps1`](#bulkuninstallps1)
			- [`removeUserProfile.ps1`](#removeuserprofileps1)
		- [Upcoming Tools](#upcoming-tools)
	- [Installation](#installation)
		- [Installation of Modules](#installation-of-modules)
		- [Running a Script](#running-a-script)
	- [Releasing the Module Suite](#releasing-the-module-suite)
		- [Version Placeholders](#version-placeholders)


## Introduction

The **PowerShell-Tools** repository is a comprehensive tool-kit for IT professionals. Whether you're managing systems, automating tasks, or performing routine maintenance, these PowerShell scripts and modules are designed to help streamline your workflow.

Even though it currently looks a bit empty, more will come...

## Features

- **Ease of Use:** Simple, user-friendly scripts that can be easily integrated into your existing processes.
- **Automation:** Automate repetitive tasks to save time and reduce the chance of human error.
- **Modularity:** Each script or module is designed to be as self-contained as possible, allowing for easy use and customization.
- **Documentation:** Each script and module comes with detailed documentation, including usage examples.
In-Depth documentation and usage help can be retrieved from the README file in each module-directory and from within PowerShell using the get-help CmdLet:
	```PowerShell
	Get-Help <Module-Name>
	```

## Modules and Scripts

### Modules
#### [`Repair-System`](./modules/Repair-System)

The [Repair-System](./modules/Repair-System) module is a tool that allows you to perform system repair operations on remote computers.


#### [`Shortcuts`](./modules/Shortcuts)

The [Shortcuts](./modules/Shortcuts) module is a tool to print Shortcut-Properties and Create Shortcuts.


#### [`TempDataCleanup`](./modules/TempDataCleanup)

The [TempDataCleanup](./modules/TempDataCleanup) module is a tool to clean up Temporary Data from a System.

#### [`CredentialHandler`](./modules/CredentialHandler)

The [CredentialHandler](./modules/CredentialHandler) module is a tool to prompt for credentials within the prompt (workaround for a PowerShell 5.1 Bug with `Get-Credential`)

### Scripts
#### [`AutoDeskCleanRemove.ps1`](./scripts/AutoDeskCleanRemove.ps1)

The [AutoDeskCleanRemove.ps1](./scripts/AutoDeskCleanRemove.ps1) Script automates Autodesk's official clean uninstall procedure (2022 and newer) unattended. It uninstalls every Autodesk bundle silently through ODIS, then every Autodesk MSI product still installed, runs the Autodesk removers, deletes the Autodesk folders, user data and registry keys (backed up as `.reg` first), and uninstalls the Autodesk Genuine Service last. Before it starts, it shows an estimated duration based on the installed size. What is locked while Windows runs is finished by a one-shot task at the next boot. The exit code reflects the verified end state: `0` clean, `3010` restart required, `10` a forced Windows Installer cleanup was needed (restart required), `1` something is left. Not tested with Fusion 360.

#### [`bulkUninstall.ps1`](./scripts/bulkUninstall.ps1)

The [bulkUninstall.ps1](./scripts/bulkUninstall.ps1) Script can be used to uninstall multiple programs of a vendor.

 :bangbang: ``Use at own risk... uninstalling Software in the wrong order might damage other Software Components``


#### [`removeUserProfile.ps1`](./scripts/removeUserProfile.ps1)

The [removeUserProfile.ps1](./scripts/removeUserProfile.ps1) Script is a tool to remove one or more Windows User Profiles. It backs up the profile's registry keys, mapped network drives and printer connections first, then renames the profile folder to `<User>-<Date>.old` or, with `-Delete`, deletes the profile permanently. Anything locked is finished automatically during a restart.

Profile deletion through `Win32_UserProfile` and its safety checks are based on a profile cleanup script by [Dumpweed-Git](https://github.com/dumpweed-git).



### Upcoming Tools

More scripts and modules will be added to this repository over time. Stay tuned for tools that will assist with:

- Microsoft Office Removal
- And more...

## Installation
### Installation of Modules

To install and use modules from this repository simply run the [installer](https://github.com/halatsWol/PowerShell-Tools/releases)


### Running a Script

To run any script from the repository, navigate to the directory containing the script and execute it in PowerShell:

```PowerShell
.\script-name.ps1
```

If Script-execution is blocked (common in Enterprise-Environments) please run first

```PowerShell
Set-ExecutionPolicy Bypass
```

and confirm with 'Y'

## Releasing the Module Suite

The modules are released together as one suite. Pushing a version tag (e.g. `v1.8.0`) runs the [release workflow](./.github/workflows/release.yml), which builds both installers and creates a draft GitHub release. The tag is the suite version; each module keeps its own version in `ModuleVersion` of its `.psd1`.

### Version Placeholders

[`make/Pre-Install.nfo`](./make/Pre-Install.nfo) (shown by the installer) and [`make/releasenote.md`](./make/releasenote.md) (the release body) are templates. Never type a version number into them; use these placeholders instead:

| Placeholder | Renders as |
|---|---|
| `{{Tag}}` | The suite version, i.e. the release tag (`dev` for local builds without a tag) |
| `{{Version:<Module>}}` | `ModuleVersion` from that module's `.psd1`, without a leading `v` (e.g. `{{Version:TempDataCleanup}}` → `1.8`). `<Module>` is the `.psd1` name, e.g. `RepairSystem`, not the folder name `Repair-System` |
| `{{ModuleList}}` | One line per module under `modules/`, alphabetical. In `.md` files: `- [Name](<link to the module folder at the tag>) (vX.Y)`, otherwise `- Name (vX.Y)`. Must be alone on its line; any indentation before it is repeated on every line |

[`make/Build-ReleaseInfo.ps1`](./make/Build-ReleaseInfo.ps1) fills them in and writes the result to `make/build/` (not tracked by git); the templates themselves are never changed. Both installer scripts (`make/*.iss`) run it automatically when they are compiled, and the release workflow runs it before reading the release note. An unknown placeholder or module name stops the build.

To check the rendered output locally:

```PowerShell
.\make\Build-ReleaseInfo.ps1 -Tag v1.8.0
```
