# PowerShell-Tools

Welcome to the **PowerShell-Tools** repository! This repository is dedicated to providing a collection of PowerShell scripts and modules designed to make IT tasks easier, more efficient, and more automated.

## Table of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Modules and Scripts](#modules-and-scripts)
  - [Repair-System](#repair-system)
  - [Additional Tools](#additional-tools)
- [Installation](#installation)
- [Usage](#usage)
  - [Running a Script](#running-a-script)


## Introduction

The **PowerShell-Tools** repository is a comprehensive toolkit for IT professionals. Whether you're managing systems, automating tasks, or performing routine maintenance, these PowerShell scripts and modules are designed to help streamline your workflow.

Eventhough it currently looks a bit empty, more will come...

## Features

- **Ease of Use:** Simple, user-friendly scripts that can be easily integrated into your existing processes.
- **Automation:** Automate repetitive tasks to save time and reduce the chance of human error.
- **Modularity:** Each script or module is designed to be as self-contained as possible, allowing for easy use and customization.
- **Documentation:** Each script and module comes with detailed documentation, including usage examples.

## Modules and Scripts

### [Repair-System](./modules/Repair-System)

The [`Repair-System`](./modules/Repair-System) module is a tool that allows you to perform system repair operations on remote computers.


### Additional Tools

More scripts and modules will be added to this repository over time. Stay tuned for tools that will assist with:

- System monitoring
- Network diagnostics
- And more...

## Installation
### Installation of Modules

To install and use the scripts and modules from this repository:

1. Download the repository to your local machine:

2. unzip the directory and open the modules folder:

3. Copy the desired module-Folder into on of the PowerShell-Module-Directories:


	* %userprofile%\Documents\WindowsPowerShell\Modules
	* %ProgramFiles%\WindowsPowerShell\Modules
	* %ProgramFiles(x86)%\WindowsPowerShell\Modules
	* %WinDir%\system32\WindowsPowerShell\v1.0\Modules


4. Run restart any Powershell session to use the module. For further help please visit the readme of the module

## Usage

### Running a Script

To run any script from the repository, navigate to the directory containing the script and execute it in PowerShell:

```powershell
.\script-name.ps1
```