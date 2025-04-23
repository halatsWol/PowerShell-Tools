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
		- [Scripts](#scripts)
			- [`bulkUninstall.ps1`](#bulkuninstallps1)
			- [`removeUserProfile.ps1`](#removeuserprofileps1)
		- [Upcoming Tools](#upcoming-tools)
	- [Installation](#installation)
		- [Installation of Modules](#installation-of-modules)
		- [Temporary Import of Modules](#temporary-import-of-modules)
	- [Usage](#usage)
		- [Running a Script](#running-a-script)


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

### Scripts
#### [`bulkUninstall.ps1`](./scripts/bulkUninstall.ps1)

The [bulkUninstall.ps1](./scripts/bulkUninstall.ps1) Script can be used to uninstall multiple programs of a vendor.

 :bangbang: ``Use at own risk... uninstalling Software in the wrong order might damage other Software Components``


#### [`removeUserProfile.ps1`](./scripts/removeUserProfile.ps1)

The [removeUserProfile.ps1](./scripts/removeUserProfile.ps1) Script is a tool to remove a Windows User Profile.

 :bangbang: ``Module not fully tested yet! Do only use on your own risk!``


### Upcoming Tools

More scripts and modules will be added to this repository over time. Stay tuned for tools that will assist with:

- System monitoring
- Network diagnostics
- And more...

## Installation
### Installation of Modules

To install and use modules from this repository simply run the [installer](https://github.com/halatsWol/PowerShell-Tools/releases) or via following steps:

1. Download the repository to your local machine:

2. unzip the directory and open the modules folder:

3. run as Administrator the ```install.cmd```-file within the Modules-Folder




4. Restart any PowerShell session to use the functions of the module. For further information and help please visit the readme of the module

### Temporary Import of Modules

Alternatively, modules can also be used temporarily.

1. Follow Step 1. & 2. in [Installation of Modules](#installation-of-modules) enter directly in the specific Module Directory
2. copy the Path from the Explorer Address-Bar
3. Open Windows PowerShell as Administrator and enter:
	```PowerShell
	cd <copied-Path>
	```
4. import module so it can be used
	```PowerShell
	Import-Module .\<Module-Name>
	```

## Usage

### Running a Script

To run any script from the repository, navigate to the directory containing the script and execute it in PowerShell:

```PowerShell
.\script-name.ps1
```