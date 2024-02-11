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

```bash
python3 -m venv venv
source venv/bin/activate
```

### Install required Python libraries and packages

Navigate to the repository root folder (i.e. `iss.cw`) and install the required Python packages.

```bash
pip3 install -r requirements.txt
```

## Usage

All user journey workflows to demonstrate the cryptographic simulation are implemented as Python test cases, within the [`tests`](https://github.com/iArcanic/iss-cw/tree/main/tests) folder.

All the tests use Python's `pytest` library engine.

## Assumptions