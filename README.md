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

## Usage

### 1. Clone this repository

```bash
git clone https://github.com/iArcanic/iss-cw
```

### 2. Install required Python libraries and packages

## Assumptions