# iss-cw

![Python Version](https://img.shields.io/badge/Python-3.x-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

Cryptosystem simulation for a healthcare provider service, St. John's Clinic.

## Description

A Python simulation of various APIs that use cryptographic implementations to meet a healthcare provider's security requirements.

> Note that this is not a simulation of the system. Rather, a simulation of independent APIs to demonstrate cryptography. It would be linked together in a real-time system.

## Features

### Authentication

- Authentication supporting username/password credentials
- Simulation of third-party SSO (Single Sign-on)
- Role Based Access Control (RBAC) with role permissions to allow need-based data access
- Simulation of two-factor authentication (2FA) for login and registration

### Data protection

- AES-256 encryption to secure sensitive data-at-rest
- RSA encryption for secure data transmission
- Alignment with healthcare data protection regulations

### Key management

- Random cryptographic key generation 
- Simulation of HSM (Hardware Security Module) key store
- Simulation of key retrieval from HSM key store
- RSA key refresh upon every login
- AES key expiry and rotation

### Record management

- Storing of records based on permissions and roles
- Retrieving of records based on permissions and roles
- Encrypted sensitive data

### Workflow simulation

- Modular design segregated into organised folders
- Python tests for each major user journey workflow reflecting real clinical operations

## Installation

### Prerequisites

#### Python version

Ensure that your Python environment is at minimum Python 3.6 or higher.

> NOTE: Older versions may work but Python 3.6+ is recommended

You can install a version of Python 3.x from their official website suitable for your system OS [here](https://www.python.org/downloads/).

#### `git` CLI

To clone this repository and the general use of GitHub version control tools and systems, the `git` CLI is required.

You can install a version of `git` from their official website suitable for your system OS [here](https://git-scm.com/downloads).

### Clone this repository

Clone the project repository from GitHub.

```bash
git clone https://github.com/iArcanic/iss-cw
```

### Set up virtual Python environment [optional]

Optionally, set up a virtual Python `3.x` environment to isolate project dependencies from system-wide dependencies.

First install Python virtual environment.

```bash
pip3 install virtualenv
```

Create a new virtual environment. Replace `<virtual-environment-name>` with the actual name you want to give the virtual environment.

```bash
python3 -m venv <virtual-environment-name>
source <virtual-environment-name>/bin/activate
```

### Install required Python libraries and packages

Navigate to the repository root folder (i.e. `iss.cw`) and install the required Python packages.

```bash
pip3 install -r requirements.txt
```

If you are optionally using a Python virtual environment, check if the packages from `requirements.txt` have been installed.

```bash
pip3 list
```

If you run the same command outside your Python virtual environment (or before it has been activated), you will see discrepancies in the install Python libraries. This not only verifies that the required packages have been installed, but helps to differentiate whether you are within your Python virtual environment.  

## Usage

All user journey workflows to demonstrate the cryptographic simulation are implemented as Python test cases, within the [`tests`](https://github.com/iArcanic/iss-cw/tree/main/tests) folder.

All the tests use Python's `pytest` library engine.

### Set environment variable

Before running the tests, ensure that the `PYTHONPATH` environment variable includes the path to the project. This ensures that the Python interpreter can find the project modules.

Replace `/path/to/project` with the actual path to your project directory.

```bash
export PYTHONPATH=/path/to/project:$PYTHONPATH
```

## Assumptions

### Simulation scope

- Certain aspects like physical hardware, secure deployment environments, and network infrastructure are out of scope and are assumed to be secure already.
- Only workflows involving cryptographic protocols and access controls are focussed on.

### Data

- Sample data within the [`data`](https://github.com/iArcanic/iss-cw/tree/main/data) folder.
- No real production data that is reflective of a real-time system is used.
- Data in a real-time system may use an SQL relational database, but this simulation uses simple JSON objects.

### External dependencies

- HSMs (Hardware Security Module), PKIs (Public Key Infrastructure) are simulated as simple JSON objects.
- Third party SSO (Single Sign-On) key repositories and certification authorities not simulated.

### Compliance requirements

- Simulation attempts to provide compliance with GDPR, CCPA, and PSD2.
- Final compliance responsibility ultimately lies with healthcare provider

### Authentication

- Advance enterprise IAM (Identity Access Management) not implemented in simulation.
- Only simple username and password based authentication suffices for simulation.
- More advanced hardware based authentication controls, like biometric, facial, or hardware based is up to the company to consider.

### Roles

- Users are granted roles by an admin manually beforehand.
- User roles assumed, like doctor, nurse, and so on based on common healthcare provider norms.
- Only core attributes simulated - advanced RBAC left for actual enterprise integration.

### Cryptographic algorithms

- Basic implementation of industry standard encryption algorithms simulated to a basic level.
- Additional platform specific encryption algorithms not implemented.

### Key management

- Only essential stages in the key management lifecycle able to be simulated – generation, storage, usage, and rotation.
- Actual HSM synchronisation protocols not considered.

### Exception handling

- Core exception handling done but extensive error flows not implemented.

### Concurrency

- Only one test case workflow is run at a time.
- Parallel processing capabilities of different workflows not considered.

### Performance

- Code optimisation not achieved to full capabilities.
- Large scale data, user and cryptographic operation performance testing not done.
