---
title: "ISS-CW3 Report"
author: "2242090"
bibliography: docs/report/references.bib
toc: true
toc-title: Table of Contents
toc-depth: 4
geometry: "left=1.25cm, right=1.25cm, top=1.25cm, bottom=1.25cm"
csl: docs/report/harvard-imperial-college-london.csl
---

# 1 Introduction

This report provides a comprehensive narrative description of the proposed cryptographic simulation for the healthcare provider, St. John's Clinic. The design has been implemented in such a way that it addresses the key security gaps within the clinic's data protection requirements, in order to align with compliance standards, and provide robust safeguarding mechanisms to secure sensitive data, that is, patient personal information, medical prescriptions, financial transactions, research data, and so on.

A current analysis of the cybersecurity practices which St. John's Clinic need to implement for security enhancement falls into the following areas of:

- Authentication
- Key management (and its relevant key lifecycle stages)
- Role based access control
- Cryptographic encryption algorithms
- Secure data transmission

# 2 System description

For reference, please see [Appendix 5.1](#51-sequence-diagram) for the sequence diagram.

## 2.1 Authentication

A robust authentication framework means that only authorised users are allowed to interact with the system. It therefore regulates access to protected sensitive data and clinic services which should otherwise be inaccessible to unauthorised entities.

### 2.1.1 User registration

Under the assumption that any new users need to be registered securely with the system, a register function has been takes this into consideration. Since this is a simulation, the patient details this function processes are not that substantial to the overall functionality of the system, so only the following have been taken into account:

```python
def register_user(username, password, phone_number)
```

A `username` will help be a front-end unique identifier for users. A `password`, obviously, the user provides their custom password which will have the necessary hashing functions applied upon it. The `phone_number` parameter is just more placeholder registration data to fill out the JSON database entry.

To ensure that the username is unique, it reads the contents of the `USER_DB` JSON file and checks whether the chosen username exists or not – reflective of the actual clinic's system.

```python
users_data = data_read_return_empty_if_not_found(USER_DB)

if username in users_data:
    print(f"register.register_user -> Username '{username}' already exists. "
        f"Please choose a different username.")
    return
```

Since we want the authentication framework to be secure, a simulation of two factor authentication is implemented. The two functions that are called in the code below, `generate_2fa_code()` and `send_2fa_code()`, are simple functions that mimic the process. One generates the code and the other "sends" that code to the user's phone. In this case, there is no "sending", so a simple on-screen message is returned. The user then needs to simply repeat this code to the program console and depending upon the code verification, the function flow continues.

```python
two_factor_code = generate_2fa_code()
send_2fa_code(phone_number, two_factor_code)
entered_code = input("Enter the 2FA code: ")

if entered_code == two_factor_code:
    print("register.register_user -> 2FA verification successful.")
else:
    print("register.register_user -> 2FA verification failed. Registration aborted.")
    return
```

Preparation to store the data in the database takes place here. First using the `uuid` library allows the generation of a UUID 4, and this is converted to a string format. A salt is generated for the hashing of the password using the `bcrypt` library. Note that using `.encode('utf-8')` allows for the password to be converted to bytes first.

```python
user_id = str(uuid.uuid4())
salt = bcrypt.gensalt()
hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
```

Finally, a new JSON object is created first as a Python dictionary. Note that the `hashed_password` and `salt` all have `.decode('utf-8')`, to allow them to be converted from bytes to strings. This is called JSON serialisation, since JSON does not support the storage of pure bytes.

Using another abstract function. `data_store()`, that I created to simplify file writing, this new JSON object is written to the JSON database file.

```python
new_user = {
    'user_id': user_id,
    'username': username,
    'hashed_password': hashed_password.decode('utf-8'),
    'salt': salt.decode('utf-8'),
    'phone_number': phone_number
}

users_data[username] = new_user
data_store(USER_DB, users_data)
```

For more detail on the full code implementation see [Appendix 5.3.1.1](#5311-registerpy).

### 2.1.2 User login

The user, with their newly created account via the `register()` function, can now use that to login into the system and access the relevant data. The only credentials that they require for this is their `username` and `password` as such. These are passed as parameters to the function.

```python
def login_user(username, password)
```

Based on the given parameters to the function, `login()` then checks if the username exists, and if not, appropriately terminates the program flow.

```python
if username not in users_data:
    print("login.login_user -> Username not found. Please register first.")
    return
```

Using the username and the JSON document, it attempts to get all of the user's data. This data is then used for further processing.

```python
user_data = users_data[username]
stored_password_hash = user_data['hashed_password']
salt = user_data['salt']
phone_number = user_data.get('phone_number', None)
```

Since the function is hashed, the `bcrypt` Python library's `.checkpw` function compares the bytes of the entered user's password against the stored hash in the JSON database. Only then will the post processing actions take place if the function returns true based on the hash.

```python
if bcrypt.checkpw(entered_password.encode('utf-8'), stored_password_hash.encode('utf-8'))
```

Since two factor authentication was proposed for a secure authentication framework, a simulation of sending the one time password code is "sent" to the user's mobile device. If the verification passes, then the an RSA key under the user's ID is generated and stored (see [2.2.1](#221-key-generation) and [2.2.2](#222-key-storage)) in the RSA HSM (Hardware Security Module). The `user_id` and `public_key` public key object is returned from the function for any post login actions.

```python
two_factor_code = generate_2fa_code()
send_2fa_code(phone_number, two_factor_code)
entered_code = input("Enter the 2FA code: ")

if entered_code == two_factor_code:
    print("login.login_user -> Login successful.")
    public_key = refresh_rsa_key(user_data["user_id"])
    return user_data['user_id'], public_key
```

For more detail on the full code implementation, see [Appendix 5.3.1.2](#5312-loginpy).

### 2.1.3 Single Sign-on (SSO)

For SSO, since homegrown SSO within the organisation was implemented, i.e, authentication with username and password, this SSO accounts for external authentication. Since this is the case, the below function os a simulation of this – only requiring a `username`. The backend identity management will be the responsibility of the third party company performing the authentication and returning the result of it.

```python
def single_sign_on(username)
```

The program flow is terminated if the username isn't found in the user database of the third party company.

```python
if username not in third_party_data:
    raise ValueError(f"sso.single_sign_on -> Username {username} not found. "
                    f"Please register with the third party provider first.")
```

The program flow continues if the above is not the case, and using the data content from the JSON file, it then makes a new user entry. The important here is to note that this JSON object has less fields than the regular authentication framework – this is the third party company's responsibility to implement and provide their own identity authentication or any other relevant user details. The important additional field, `third_party_status`, is important to note, as it helps to differentiate between a homegrown (i.e. internal within the company) SSO and an external SSO (i.e. external, such as Google or Facebook login).

```python
third_party_data = third_party_data[username]

if third_party_data:
    new_user = {
        'user_id': str(uuid.uuid4()),
        'username': username,
        'third_party_status': True
    }
```

Finally, this entry is written to the healthcare provider's normal user database.

```python
users_data[username] = new_user
data_store(USER_DB, users_data)
```

For more detail on the full code implementation, see [Appendix 5.3.1.3](#5313-ssopy).

## 2.2 Key management

For the chosen encryption algorithms, cryptographic keys serve need to have a well-defined key lifecycle, ensuring the security and integrity of these keys at every stage. Each phase of the lifecycle prevents unauthorised access, data collection or loss, with the aim of maintaining the confidentiality and integrity of these keys.

Since two different encryption algorithms, i.e. RSA and AES, are used, the key lifecycle stages are explained for each where applicable and implemented, but may have different characteristics.

### 2.2.1 Key generation

#### 2.2.2.1 AES

For AES, the key generation process is very simple. Using the Python built-in OS library, the `urandom` function generates a random binary string of 32 bytes (i.e. 256 bits). Since this uses random logic, it is safe to say that this is cryptographically secure.

```python
def generate_aes_key():
    key = os.urandom(32)
    return key
```

For more detail on the full code implementation see [Appendix 5.3.2.1.1](#53211-key_genpy).

#### 2.2.2.2 RSA

For RSA, there is a dedicated library for all RSA encryption functions. Using the `rsa.generate_private_key` method, a new RSA private key is generated with the parameters enclosed within the brackets. `public_exponent` specifies the public exponent value used in the RSA algorithm. The value of `65537` is the default for most RSA keys. `key_size`, as the name suggests, is the size of the key in bits, so a value of `2048` is a standard size providing a adequate balance between both security and performance. Finally the `backend` parameter is set to `default_backend()`, which is the backend provided by the library to perform the generation process. A `public_key` can also be derived from the generated private key.

```python
def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key
```

For more detail on the full code implementation see [5.3.2.2](#5322-rsa_key_managerpy).

### 2.2.2 Key storage

### 2.2.3 Key retrieval

### 2.2.4 Key expiry rotation

## 2.3 Data transmission

## 2.4 Record management

## 2.5 Workflow simulation

# 3 Addressing requirements

## 3.1 Cryptographic algorithms and protocols

## 3.2 Compliance and standards

# 4 Assumptions taken

# 5 Appendices

## 5.1 Sequence diagram

![Sequence diagram pt. 1](images/sequence-diagram-1.png)
![Sequence diagram pt. 2](images/sequence-diagram-2.png)

## 5.2 GitHub repository

Link to GitHub repository, containing full code and installation documentation.

[iss-cw3 GitHub repository](https://github.com/iArcanic/iss-cw)

## 5.3 Implementation source code

### 5.3.1 Authentication

#### 5.3.1.1 `register.py`

```python
import uuid

import bcrypt

from src.authentication.two_fa import generate_2fa_code, send_2fa_code
from src.data_manager import *

# User database simulation
USER_DB = "data/user_db.json"


def register_user(username, password, phone_number):
    users_data = data_read_return_empty_if_not_found(USER_DB)

    # Check if the username already exists in the database
    if username in users_data:
        print(f"register.register_user -> Username '{username}' already exists. "
            f"Please choose a different username.")
        return

    # Generate a 2FA code
    two_factor_code = generate_2fa_code()

    # Simulate sending the 2FA code to the user
    send_2fa_code(phone_number, two_factor_code)

    # Prompt the user to enter the received 2FA code
    entered_code = input("Enter the 2FA code: ")

    # Check if the entered code matches the generated 2FA code
    if entered_code == two_factor_code:
        print("register.register_user -> 2FA verification successful.")
    else:
        print("register.register_user -> 2FA verification failed. Registration aborted.")
        return

    # Generate a unique user_id using UUID
    user_id = str(uuid.uuid4())

    # Generate a random salt
    salt = bcrypt.gensalt()

    # Combine the password with the salt and hash it
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)

    # Create a new user entry
    new_user = {
        'user_id': user_id,
        'username': username,
        'hashed_password': hashed_password.decode('utf-8'),  # Convert bytes to string for JSON serialization
        'salt': salt.decode('utf-8'),  # Convert bytes to string for JSON serialization
        'phone_number': phone_number
    }

    # Add the new user to the database
    users_data[username] = new_user

    # Save the updated database to the file
    data_store(USER_DB, users_data)

    print(f"register.register_user -> User '{username}' registered successfully. "
          f"Login with your new account to continue.")
```

#### 5.3.1.2 `login.py`

```python
import bcrypt

from src.authentication.two_fa import generate_2fa_code, send_2fa_code
from src.data_manager import *
from src.key_management.rsa_key_manager import *

# User database simulation
USER_DB = "data/user_db.json"


def login_user(username, password):
    users_data = data_read(USER_DB)

    # Check if the username exists in the database
    if username not in users_data:
        print("login.login_user -> Username not found. Please register first.")
        return

    if username in users_data and "third_party_status" in users_data[username]:
        print("login.login_user -> Please use SSO to login.")
        return

    user_data = users_data[username]
    stored_password_hash = user_data['hashed_password']
    salt = user_data['salt']
    phone_number = user_data.get('phone_number', None)

    # Get the user's password
    if password is None:
        entered_password = input("Enter your password: ")
    else:
        entered_password = password

    # Verify the entered password
    if bcrypt.checkpw(entered_password.encode('utf-8'), stored_password_hash.encode('utf-8')):
        # If the password is correct, proceed with 2FA verification
        two_factor_code = generate_2fa_code()
        send_2fa_code(phone_number, two_factor_code)

        entered_code = input("Enter the 2FA code: ")

        if entered_code == two_factor_code:
            print("login.login_user -> Login successful.")
            # Every time the user logins the RSA key is regenerated
            # Used for transferring data across multiple clinic services
            public_key = refresh_rsa_key(user_data["user_id"])
            return user_data['user_id'], public_key
        else:
            print("login.login_user -> 2FA verification failed. Login aborted.")
    else:
        print("login.login_user -> Incorrect password. Login aborted.")
```

### 5.3.1.3 `sso.py`

```python
import uuid

from src.data_manager import *

# Third party provider database simulation
THIRD_PARTY_DB = "data/third_party_db.json"

# User database simulation
USER_DB = "data/user_db.json"


def single_sign_on(username):
    # Read all user entries from the third party provider database
    third_party_data = data_read(THIRD_PARTY_DB)

    # Read all user entries from the Users database
    users_data = data_read_return_empty_if_not_found(USER_DB)

    if username not in third_party_data:
        raise ValueError(f"sso.single_sign_on -> Username {username} not found. "
                        f"Please register with the third party provider first.")

    # Get the correct user entry
    third_party_data = third_party_data[username]

    if third_party_data:
        # Make a new entry
        new_user = {
            'user_id': str(uuid.uuid4()),
            'username': username,
            'third_party_status': True
        }

        # Make a new entry in the Users database
        users_data[username] = new_user

        # Add the new SSO user to the database
        data_store(USER_DB, users_data)

        # Third party identity provider would do their own authentication logic here
        print("sso.single_sign_on -> Third party authentication successful "
                "Authentication logic by the third party provider.")
    else:
        # Terminate on unsuccessful SSO login
        print("sso.single_sign_on -> Third party authentication failed. SSO login aborted.")
```

### 5.3.2 Key management

#### 5.3.2.1 AES key functions

##### 5.3.2.1.1 `key_gen.py`

```python
import os


def generate_aes_key():
    key = os.urandom(32)
    return key
```

#### 5.3.2.2 `rsa_key_manager.py`

```python
import json

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa


def replace_or_insert_key_from_file(user_id, new_key, file_path="data/rsa_hsm.json"):
    try:
        with open(file_path, 'r') as file:
            json_data = json.load(file)
    except FileNotFoundError:
        json_data = {"rsa_keys": []}

    for entry in json_data["rsa_keys"]:
        # Get the correct user entry
        if entry["user_id"] == user_id:
            # Store the new RSA key in JSON object in RSA HSM
            entry["key"] = new_key
            break
    else:
        # If user_id not found, insert a new entry
        json_data["rsa_keys"].append({"user_id": user_id, "key": new_key})

    # Write to RSA HSM
    with open(file_path, 'w') as file:
        json.dump(json_data, file, indent=2)


# Convert private key bytes into PEM format to be stored in JSON
def pem_convert_private_key(key):
    # Get RSA private key bytes
    pem_format = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    # Convert bytes into string
    return pem_format.decode('utf-8')


# Convert public key bytes into PEM format to be stored in JSON
def pem_convert_public_key(key):
    # Get RSA public key bytes
    pem_format = key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    # Convert bytes into string
    return pem_format.decode('utf-8')


# Refresh RSA public and private keys when the user logins in PEM format
def refresh_rsa_key(user_id):
    # Generate new RSA key pair
    private_key, public_key = generate_key_pair()

    # Convert RSA private key into PEM format
    private_key_pem = pem_convert_private_key(private_key)

    # Store new RSA private key into RSA HSM under the given user_id
    replace_or_insert_key_from_file(user_id, private_key_pem)

    return pem_convert_public_key(public_key)


# Generate an RSA public and private key pair
def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


# Encrypt with RSA public key
def rsa_encrypt(data, public_key_pem):
    public_key = load_public_key_from_pem_string(public_key_pem)
    ciphertext = public_key.encrypt(
        # Data as hex
        data.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext


def rsa_decrypt(ciphertext, private_key_pem):
    private_key = load_private_key_from_pem_string(private_key_pem)
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # Convert from bytes to string
    return plaintext.decode("utf-8")


# Convert RSA private key from string to key object
def load_private_key_from_pem_string(pem_string):
    private_key = serialization.load_pem_private_key(
        # Convert to bytes
        pem_string.encode(),
        password=None,
        backend=default_backend()
    )
    return private_key


# Convert RSA public key from string to key object
def load_public_key_from_pem_string(pem_string):
    public_key = serialization.load_pem_public_key(
        # Convert to bytes
        pem_string.encode(),
        backend=default_backend()
    )
    return public_key
```

# 6 References
