# iss-cw

![Python Version](https://img.shields.io/badge/Python-3.x-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

A cryptographic simulation for a healthcare provider service, St. John's Clinic.

## 1 Description

A Python simulation of various APIs that use cryptographic implementations to meet a healthcare provider's security requirements.

> NOTE: This is not a simulation of the system. Rather, a simulation of independent APIs to demonstrate cryptography. It would be linked together in a real-time system.

## 2 Features

### 2.1 Authentication

- Authentication supporting username/password credentials
- Simulation of third-party SSO (Single Sign-on) login
- Simulation of two-factor authentication (2FA) for login and registration

### 2.2 Data protection

- AES-256 encryption to secure sensitive data at rest
- RSA encryption for secure data transmission
- Role Based Access Control (RBAC) with role permissions to allow need-based data access

### 2.3 Key management

- Random cryptographic key generation
- Simulation of HSM (Hardware Security Module) key store
- Simulation of key retrieval from HSM key store
- RSA key refreshes upon every login
- AES key expiry and rotation

### 2.4 Record management

- Storing of records based on permissions and roles
- Retrieving records based on permissions and roles
- Encrypted sensitive data
- Grant individual record access to specific users

### 2.5 Workflow simulation

- Modular design segregated into organised folders
- Python tests for each major user journey workflow reflecting real-time clinical operations

## 3 Installation

### 3.1 Prerequisites

#### 3.1.1 Python version

Ensure that your Python environment is at minimum Python 3.6 or higher.

> NOTE: Older versions may work but Python 3.6+ is recommended

You can install a version of Python 3.x from their official website suitable for your system OS [here](https://www.python.org/downloads/).

### 3.2 Clone this repository

Clone the project repository from GitHub.

```bash
git clone https://github.com/iArcanic/iss-cw
```

> NOTE: If you already have the files available locally already and/or are not using `git`, please skip to [3.3](#33-install-required-python-libraries-and-packages).

### 3.3 Install required Python libraries and packages

Navigate to the repository root folder (i.e. `iss.cw`) and install the required Python packages.

```bash
pip3 install -r requirements.txt
```

## 4 Usage

All user journey workflows to demonstrate the cryptographic simulation are implemented as Python test cases, within the [`tests`](https://github.com/iArcanic/iss-cw/tree/main/tests) folder.

All the tests use Python's `pytest` library engine.

### 4.1 Set environment variable

Before running the tests, ensure that the `PYTHONPATH` environment variable includes the path to the project. This ensures that the Python interpreter can find the project modules.

Replace `/path/to/project` with the actual path to your project directory.

```bash
export PYTHONPATH=/path/to/project:$PYTHONPATH
```

> NOTE: Ensure that you restart your terminal console session for the environment variable to take effect.

### 4.2 Run the Python workflow test cases

Ensure that your current directory is the [`iss-cw`](https://github.com/iArcanic/iss-cw/tree/main) project root.

Navigate into the [`tests`](https://github.com/iArcanic/iss-cw/tree/main/tests) folder.

```bash
cd tests
```

List all current workflow test cases.

```bash
ls
```

To run a specific workflow test case. Replace `<name-of-python-workflow-test-case>` with the actual name of the test you want to run.

```bash
pytest -s <name-of-python-workflow-test-case>
```

To run all available workflow test cases.

```bash
pytest -s *.py
```

> NOTE: In the case of any error like so:
>
> ```bash
> E   ModuleNotFoundError: No module named 'src'
> ```
>
> Please re-run the path environment variable command from [4.1](#41-set-environment-variable):
>
> ```bash
> export PYTHONPATH=/path/to/project:$PYTHONPATH
> ```

## 5 Assumptions

### 5.1 Simulation scope

- Certain aspects like physical hardware, secure deployment environments, and network infrastructure are out of scope and are assumed to be secure already.
- Only workflows involving cryptographic protocols and access controls are focussed on.
- A simple command line interface with appropriate annotations via `print()` statements is implemented – no advanced GUI.

### 5.2 Data

- Sample data within the [`data`](https://github.com/iArcanic/iss-cw/tree/main/data) folder.
- No real production data that is reflective of a real-time system is used.
- Data in a real-time system may use an SQL relational database, but this simulation uses simple JSON objects.

### 5.3 External dependencies

- HSMs (Hardware Security Module), and PKIs (Public Key Infrastructure) are simulated as simple JSON objects.
- Third-party key repositories and certification authorities are not simulated.

### 5.4 Compliance requirements

- Simulation attempts to provide compliance with GDPR, CCPA, and PSD2.
- Final compliance responsibility ultimately lies with the healthcare provider

### 5.5 Authentication

- Advanced enterprise IAM (Identity Access Management) not implemented in simulation.
- Only simple username and password-based authentication suffices for simulation.
- More advanced hardware-based authentication controls, like biometric or facial are up to the company to consider.

### 5.6 Roles

- All JSON "databases" are stored in the healthcare provider's cloud service, MediCloud.
- Users are granted roles by an admin manually beforehand.
- User roles assumed, like doctor, nurse, and so on based on common healthcare provider norms.
- Only core attributes simulated - advanced RBAC left for actual enterprise integration.

### 5.7 Cryptographic algorithms

- Basic implementation of industry-standard encryption algorithms simulated to a basic level.
- Additional platform-specific encryption algorithms are not implemented.

### 5.8 Key management

- Only essential stages in the key management lifecycle are able to be simulated – generation, storage, usage, and rotation.
- Actual HSM synchronisation protocols are not considered.

### 5.9 Exception handling

- Core exception handling is done but extensive error flows are not implemented.

### 5.10 Concurrency

- Only one test case workflow is run at a time.
- Parallel processing capabilities of different workflows are not considered.

### 5.11 Performance

- Code optimisation not achieved to full capabilities.
- Large-scale data, user and cryptographic operation performance testing not done.
