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
  - [Importing a Module](#importing-a-module)
- [Contributing](#contributing)
- [License](#license)

## Introduction

The **PowerShell-Tools** repository is a comprehensive toolkit for IT professionals. Whether you're managing systems, automating tasks, or performing routine maintenance, these PowerShell scripts and modules are designed to help streamline your workflow.

## Features

- **Ease of Use:** Simple, user-friendly scripts that can be easily integrated into your existing processes.
- **Automation:** Automate repetitive tasks to save time and reduce the chance of human error.
- **Modularity:** Each script or module is designed to be as self-contained as possible, allowing for easy use and customization.
- **Documentation:** Each script and module comes with detailed documentation, including usage examples.

## Modules and Scripts

### Repair-System

The `Repair-System` module is a key tool within this repository. It allows you to perform system repair operations on remote computers using a combination of SFC and DISM commands. This module can check the availability of remote machines, execute repair commands, and handle logging and file transfers.

**Key Features:**
- Run `sfc /scannow` and DISM commands on remote computers.
- Optionally run only the SFC command.
- Quiet mode for logging without console output.
- Automatic log file collection and transfer to the local machine.

### Additional Tools

More scripts and modules will be added to this repository over time. Stay tuned for tools that will assist with:

- System monitoring
- Automated patch management
- Network diagnostics
- User account management
- And more...

## Installation

To install and use the scripts and modules from this repository:

1. Clone the repository to your local machine:

    ```bash
    git clone https://github.com/yourusername/PowerShell-Tools.git
    ```

2. Navigate to the repository directory:

    ```bash
    cd PowerShell-Tools
    ```

3. Import the desired module into your PowerShell session:

    ```powershell
    Import-Module .\Repair-System.psm1
    ```

## Usage

### Running a Script

To run any script from the repository, navigate to the directory containing the script and execute it in PowerShell:

```powershell
.\script-name.ps1
