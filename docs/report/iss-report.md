---
title: "ISS-CW3 Report"
author: "Preetham Ananthkumar 2242090"
bibliography: docs/report/references.bib
toc: true
toc-title: Table of Contents
toc-depth: 5
geometry: "left=1.25cm, right=1.25cm, top=1.25cm, bottom=1.25cm"
csl: docs/report/harvard-imperial-college-london.csl
---

---

# 1 Introduction

This report provides a comprehensive description of the proposed cryptographic simulation for the healthcare provider, St. John's Clinic. The design has been implemented in such a way that it addresses the key security gaps within the clinic's data protection requirements, in order to align with compliance standards, and provide robust safeguarding mechanisms to secure sensitive data.

A current analysis of the cybersecurity practices which St. John's Clinic need to implement for security enhancement falls into the following areas of:

- Authentication
- Key management (and its relevant key lifecycle stages)
- Role based access control
- Cryptographic encryption algorithms
- Secure data transmission

# 2 System description

As this is a simulation, a lot of assumptions have been made. These are documented in [Appendix 4.1](#41-simulation-assumptions). A read of this is highly encouraged, as it will provide insight and understanding around the following implementation.

For the full source code implementation for each of the following sections, please also refer to [Appendix 4.3](#43-implementation-source-code).

## 2.1 Authentication

### 2.1.1 User registration

New users must securely register with the system. The following function facilitates this process.

- **`username`**: a unique identifier for users on the front-end.
- **`password`**: custom password provided by the user.
- **`phone_number`**: placeholder registration data.

```python
def register_user(username, password, phone_number)
```

User registration is initiated upon successful verification of provided details, with appropriate error messages returned in case of validation issues.

```python
users_data = data_read_return_empty_if_not_found(USER_DB)

if username in users_data:
    print(f"register.register_user -> Username '{username}' already exists. "
            f"Please choose a different username.")
    return
```

Registration also performs two factor authentication, the below code generates a 2FA code, sends it to the provided phone number (simulated by displaying it on the console), prompts the user to enter the code, and verifies it against the generated code. This ensures an additional layer of security during user registration.

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

Upon successful registration, the user's details, including a cryptographic salt, a unique user ID and a securely hashed password using the Python `bcrypt` library, are stored in the database for increased security.

```python
user_id = str(uuid.uuid4())
salt = bcrypt.gensalt()
hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
```

User details are stored in the database as a JSON document.

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

### 2.1.2 User login

The user, with their newly created account, can now login into the system and access the relevant data. The following function takes that into consideration.

- **`username`**: chosen user's username provided during registration.
- **`password`**: user's custom password provided during registration.

```python
def login_user(username, password)
```

Appropriate validation checks are performed, and error messages are returned if necessary.

```python
if username not in users_data:
    print("login.login_user -> Username not found. Please register first.")
    return
```

All the data relating to the user from the database by getting the correct JSON document is captured.

```python
user_data = users_data[username]
stored_password_hash = user_data['hashed_password']
salt = user_data['salt']
phone_number = user_data.get('phone_number', None)
```

Using the Python `bcrypt` library, the entered password's is first hashed. This is compared against the stored hash in the database to confirm that the passwords indeed match.

```python
if bcrypt.checkpw(
    entered_password.encode('utf-8'),
    stored_password_hash.encode('utf-8'))
```

Two factor authentication is called again to provide an additional layer of security for the login process as well. If the generated code matches the user's inputted code, then an RSA public key is generated for data transmission purposes later on (see [2.4](#24-data-transmission)).

```python
two_factor_code = generate_2fa_code()
send_2fa_code(phone_number, two_factor_code)

entered_code = input("Enter the 2FA code: ")

if entered_code == two_factor_code:
    print("login.login_user -> Login successful.")
    public_key = refresh_rsa_key(user_data["user_id"])
    return user_data['user_id'], public_key
```

### 2.1.3 Single Sign-on (SSO)

[2.1.2](#212-user-login) considered homegrown SSO, i.e. a username and password based authentication within the system. The SSO here accounts for external identity authentication, where a third party will be responsible for performing the authentication and returning the result of it.

- **`username`**: unique identifier of the third party SSO system.

```python
def single_sign_on(username)
```

Validation checks are performed, returning appropriate error messages where necessary.

```python
if username not in third_party_data:
    raise ValueError(f"sso.single_sign_on -> Username {username} not found. "
                    f"Please register with the third party provider first.")
```

The user's data from the third party's database is retrieved to check whether the user is registered with the third party. If so, a new JSON document, specifically for external SSO, is created.

```python
third_party_data = third_party_data[username]

if third_party_data:
    new_user = {
        'user_id': str(uuid.uuid4()),
        'username': username,
        'third_party_status': True
    }
```

This is then stored within the healthcare provider's user database.

```python
users_data[username] = new_user
data_store(USER_DB, users_data)
```

## 2.2 Key management

### 2.2.1 Key generation

#### 2.2.1.1 AES

The following function generates a random AES key for symmetric encryption and decryption. With `os.urandom(32)`, the key is 32 bytes (256 bits) in length, allowing for a good balance between both security and performance.

```python
def generate_aes_key():
    key = os.urandom(32)
    return key
```

#### 2.2.1.2 RSA

Using the `rsa.generate_private_key()` method, a new RSA private key is generated with the parameters enclosed within the brackets. `public_exponent` has the value of `65537`, which is the default for most RSA keys. `key_size` is the size of the key in bits, so a value of `2048` is a standard size providing a reasonable balance between both security and performance. Finally the `backend` parameter is set to `default_backend()`, which is the backend provided by the library. A `public_key` can also be derived from the generated private key.

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

**NOTE**: for more detail on the full code implementation see [4.3.2.2](#4322-rsa_key_managerpy).

### 2.2.2 Key storage

#### 2.2.2.1 AES

To store the AES symmetric key, it needs to be stored under the corresponding user. This ensures a unique key for each user and can be accessed system-wide by the multiple clinic services, so that it can be consistent.

```python
def store_aes_key(user_id, key)
```

Using a simple `try` `catch` block, a file open operation is attempted in order to capture all the existing keys from the file. If not found, then it defaults the `json_data` variable to an empty JSON collection.

```python
try:
    with open(HSM_DB, 'r') as file:
        json_data = json.load(file)
except FileNotFoundError:
    json_data = {"aes_keys": []}
```

By iterating through the `aes_keys` JSON collection, if the `user_id` passed in parameter matches the `for` loop's index, it makes an entry for the key, but as a hex object using `.hex()`. This is because the key is passed in as raw bytes, and cannot be stored in the JSON file unless serialised. It then stores this.

```python
for entry in json_data["aes_keys"]:
    if entry["user_id"] == user_id:
        entry["key"] = key.hex()
        break
    else:
        json_data["aes_keys"].append({"user_id": user_id, "key": key.hex()})

with open(HSM_DB, 'w') as file:
    json.dump(json_data, file, indent=2)
```

**NOTE**: for more detail on the full code implementation see [4.3.2.1.2](#43212-key_storepy).

#### 2.2.2.2 RSA

The function that takes care of storing the RSA keys is the same as in [2.2.2.1](#2221-aes). This function below, `replace_or_insert_key_from_file()` takes in the `user_id` of the user which the key is stored under, `new_key` being the new RSA generated key from the previous `generate_key_pair()` function, and the `file_path` to the RSA HSM.

```python
def replace_or_insert_key_from_file(user_id, new_key, file_path="data/rsa_hsm.json")
```

The logic of this function is exactly similar to the AES key store function.

However, one thing to note, is that since the `generate_key_pair()` function returns a the RSA public and private keys in a usable format, i.e. in bytes, it cannot be stored into JSON unless serialised. But in this instance, the RSA keys do not have a callable `.hex()` function so the Python RSA cryptographic library has its own specialised serialisation functions for this. Instead of bytes, it is converted into a PEM string format. The two functions below take this into account and perform the conversion.

Firstly for the RSA private key, using the `.private_bytes()` function, it takes a couple of arguments. The `encoding` parameter explicitly states that a PEM encoder should be used for a PEM output. The `format` parameter specifies the format for the private key, which in this case is `PKCS8` – which is the widely used standard. Finally the `encryption_algorithm` parameter states that there should be no encryption applied to the RSA private key when converted to PEM since the simulated HSM is assumed to automatically encrypt the keys anyway (see [Appendix 4.1.4](#414-external-dependencies)). At the end, it decodes the `pem_format` variable from bytes to string so that it can be stored in JSON.

```python
def pem_convert_private_key(key):
    pem_format = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return pem_format.decode('utf-8')
```

The same applies when converting the RSA public key to a PEM format, but this time using the `.private_bytes()` method.

```python
def pem_convert_public_key(key):
    pem_format = key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem_format.decode('utf-8')
```

**NOTE**: for more detail on the full code implementation see [4.3.2.2](#4322-rsa_key_managerpy).

### 2.2.3 Key retrieval

#### 2.2.3.1 AES

The stored AES keys need to be retrieved for any symmetric encryption processes for the relevant user. This allows for the same key to be used across all the various clinic systems.

This function will accept a `user_id` parameter to return the key for the given user.

```python
def retrieve_key(user_id)
```

For this, a simple file read takes place, iterating through the JSON file via a `for` loop. `key_entries` uses a `data_read()` utility function to capture all the data from the JSON file. By looping through, it checks for the matching `user_id` and then returns the key in a usable format, i.e. converting it from the stored hex into its original bytes form.

```python
key_entries = data_read(HSM_DB)

for entry in key_entries["aes_keys"]:
    if entry["user_id"] == user_id:
        return bytes.fromhex(entry["key"])
```

**NOTE**: for more detail on the full code implementation see [4.3.2.1.3](#43213-key_retrievepy).

#### 2.2.3.2 RSA

Although there is no explicit function in the `rsa_manager.py` file for key retrieval, wherever required, a simple JSON file read was sufficient enough to obtain the key, and the logic is exactly the same as in [2.2.3.1](#2231-aes).

The main issue is the conversion between the PEM string into a usable RSA key format from the JSON serialisation. The following two function address this.

Below, this function takes in the RSA private key's `pem_string` as a parameter and utilises the cryptographic library's `.load_pem_private_key()` method to load the private key object. The `pem_string` is converted into bytes via `.encode()` since the function expects data in binary form, allowing any non-textual characters or special formatting within the PEM data to be preserved accurately. `password` being set to `None` means that there is no password protection applied, which is consistent with the fact that no encryption algorithm was applied in the initial PEM conversion.

```python
def load_private_key_from_pem_string(pem_string):
    private_key = serialization.load_pem_private_key(
        pem_string.encode(),
        password=None,
        backend=default_backend()
    )
    return private_key
```

The counterpart function, for the RSA public key, is more or less the same, except the method being used is `.load_pem_public_key()`.

```python
def load_public_key_from_pem_string(pem_string):
    public_key = serialization.load_pem_public_key(
        pem_string.encode(),
        backend=default_backend()
    )
    return public_key
```

**NOTE**: For more detail on the full code implementation see [4.3.2.2](#4322-rsa_key_managerpy).

### 2.2.4 Key expiry rotation

#### 2.2.4.1 AES

The AES keys stored in the HSM need to be rotated and expired periodically in order to be cryptographically secure. In the event the HSM is breached and access to the AES key is gained, since the key has been rotated, the data still cannot be decrypted regardless.

This function needs to know the correct `user_id` in order to find the AES key of the user to expire.

```python
def expire_aes_key(user_id)
```

By using the previous `retrieve_key()` function in [2.2.3.1](#2231-aes), it gets the user's current AES key, and labels in a variable called `old_aes_key`, since the key will expire soon. Now using the `generate_aes_key()` function from [2.2.1.1](#2211-aes), a new AES key is generated that will replace the previous one.

```python
old_aes_key = retrieve_key(user_id)
new_aes_key = generate_aes_key()
```

By looping through a JSON file containing data used by the various clinical systems, i.e. records (see [2.3](#23-record-management)), the `if` statement helps to determine the right record based on the `user_id`. By getting the data from the `data` field of the JSON object, the `old_aes_key` is used to decrypt and replace the contents of the field with its original plaintext form using the `aes_data_decrypt()` function (see [2.3.2](#232-decryption)).

```python
for record in records_data["records"]:
    if record["owner_id"] == user_id:
        record["data"] = aes_data_decrypt(old_aes_key, record["data"])
```

Now that the data is in its plaintext form, the `new_aes_key` can be used to encrypt the plaintext into a new cipher text form using the `aes_encrypt()` function (see [2.3.1](#231-encryption)). Note that using the `.encode()` method, the plaintext has to be converted into bytes. However, a problem arises in that raw bytes cannot be stored in JSON file so serialisation is required. Finally, the `data` attribute of the `record` JSON object is overwritten with the new cipher text.

```python
if record["owner_id"] == user_id:
    # ...previous code

    ciphertext = aes_encrypt(new_aes_key, record["data"].encode())
    serialized_ciphertext = base64.b64encode(ciphertext).decode()
    record["data"] = serialized_ciphertext
```

**NOTE**: for more detail on the full code implementation, see [4.3.2.1.4](#43214-key_expirepy).

#### 2.2.4.2 RSA

For RSA, there is no explicit key expiry implemented. This is because each time the user logins, both their RSA public and private keys are dynamically re-generated so no key rotation is required.

## 2.3 Record management

In this system, data is organised into records, which serve as the fundamental units of information storage. Users from the various clinical services interacting with the system, have the capability to both create new records and store them within the system's database, as well as retrieve existing records as needed. These records are structured as JSON objects.

### 2.3.1 Encryption

For data at rest, AES symmetric encryption has been used, and the following function performs this operation. Parameters include `key`, being the user's generated AES key, and the plaintext `data` to encrypt.

```python
def aes_encrypt(key, data)
```

Simple exception handling is implemented, checking whether the AES key length is 32. This also gives assurance that the AES key is only generated by the `generate_aes_key()` within the crypto system and no external keys are being used – the key cannot be manipulated or corrupted by malicious actors. If data is encrypted with an invalid key, the cipher text is corrupted and cannot be recovered to its original state, so therefore this prevents the malformed cipher text from propagating throughout the different clinical systems.

```python
if len(key) != 32:
    raise ValueError("AES key must be 32 bytes long for AES-256")
```

A new initialisation vector is created using the `os` Python library to create a random to create a random binary string of 16 bytes (or 128 bits). An initialisation vector ensures cryptographic randomness and true variance in the different cipher texts generated.

```python
iv = os.urandom(16)
```

Here, a new cryptographic cipher is created, which is an object that can perform the encryption process. The `algorithms.AES(key)` parameter means that this encryption should use AES symmetric encryption with the given `key`. `modes.CFB(iv)` ensures that it uses CFB (Cipher Feedback) mode of operation for block ciphers using the initialisation vector. Finally, the `backend` is the library's default.

```python
cipher = Cipher(
    algorithms.AES(key),
    modes.CFB(iv),
    backend=default_backend())
```

A new encryptor is created from the cipher object. This will perform the necessary encryption for the given `data`.

```python
encryptor = cipher.encryptor()
```

To create the cipher text, the `encryptor` will take the plain text input of `data` and returns the corresponding cipher text with the chosen encryption settings from the `cipher` variable. The `encryptor.finalize()` method finalises the process, ensuring that any remaining data within the internal buffer of the `encryptor` is included within the cipher text output.

```python
ciphertext = encryptor.update(data) + encryptor.finalize()
```

The final cipher text is returned as a concatenation of the initialisation vector and the newly generated cipher text. This will be required in the decryption process (see [2.3.2](#232-decryption)).

```python
return iv + ciphertext
```

**NOTE**: for more detail on the full code implementation, see [4.3.3.1](#4331-encryptionpy).

### 2.3.2 Decryption

The relevant AES decryption operation has to be performed to convert the cipher text output to its original readable plain text input. This function again, takes the same arguments as `aes_encrypt()`.

```python
def aes_data_decrypt(aes_key, data)
```

As the `data` parameter will take the value of serialised cipher text from the JSON object, it needs to be unserialised in the same way, and that is again by decoding via Base64.

```python
ciphertext = base64.b64decode(data)
```

Since in `aes_encrypt()` the final cipher text was a combination of the initialisation vector and the cipher text components (see [2.3.1](#231-encryption)), using string splicing, the cipher text is appropriately split up in half, of length 16 characters – the size of the initialisation vector and the actual cipher text are both 16 (see [2.3.1](#231-encryption)).

```python
iv = ciphertext[:16]
actual_ciphertext = ciphertext[16:]
```

Again, as explained in [2.3.1](#231-encryption), the `aes_key` is checked to see if it is of the correct length to ensure that malformed data does not traverse the system.

```python
if len(aes_key) != 32:
    raise ValueError("AES key must be 32 bytes long for AES-256")
```

Like before in [2.3.1](#231-encryption), a cipher object must be formed again using the exact same parameters and values.

```python
cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
```

This time however, a `decryptor` is made since the required operation is decryption. This via the `.decryptor()` method of the cipher object.

```python
decryptor = cipher.decryptor()
```

Using this `decryptor` and the decryption configuration from the `cipher` variable, the decryption process is performed in the exact same way as the encryption process, but with the `actual_ciphertext` spliced component of the passed in cipher text.

```python
decrypted_data = decryptor.update(actual_ciphertext) + decryptor.finalize()
```

Finally, as the `decryptor` returns the plain text in bytes, using `decode()`, it converts this back into a string, so that it can be read.

```python
return decrypted_data.decode()
```

**NOTE**: for more detail on the full code implementation, see [4.3.3.2](#4332-decryptionpy).

### 2.3.3 Role Based Access Control (RBAC)

The Role Based Access Control (RBAC), is a method of access control where users are granted certain privileges or access to specific system properties based on the permissions they have. Access decisions are solely dependent on the user's permissions rather than the actual identity of the users themselves. This approach allows for easier access management since permissions can be quickly assigned or revoked by administrators.

The RBAC for this simulation has been implemented as a Python wrapper function or decorator. This allows for additional functionality and flexibility. The decisioning for this implementation is that the RBAC needs to be called each time a user attempts to perform a record operation (see [2.3.4](#234-store-records) and [2.3.5](#235-retrieve-records)) – they are only able to do so if they have the necessary permissions.

A wrapper function is defined like so. The `role_check_decorator()` takes in a `func` parameter, meaning it takes in another whole function as a parameter. The inner `wrapper()` function either modifies or extends the behavior of the function is is called upon, taking in `owner_id` (owner of the record), `*args` and `**kwargs` to accept any number of extra positional arguments.

```python
def role_check_decorator(func):
    def wrapper(owner_id, *args, **kwargs):
```

To start the role access logic, first, the owner of the record or rather, whichever user is attempting to perform a record operation should be first checked to see if they exist and have roles allocated to them. If this is the case, then store all the available user roles into a variable.

```python
if owner_id in user_roles_data:
    user_roles = user_roles_data[owner_id]["roles"]
else:
    print(f"role_check.role_check_decorator -> User with ID {owner_id} not found in user roles data.")
```

By looping through the user roles database, it first checks if the role actually exists. If so, then get the `permission` parameter with `kwargs.get()` from the wrapped function. As the permissions in the role permissions database are stored in capital letters, the `.upper()` ensures that it is in the same case regardless of the parameter value.

```python
if owner_id in user_roles_data:
    # ...previous code

    for role in user_roles:
        if role in role_permissions_data:
            permission_name = kwargs.get("permission", "").upper()
        else:
            print(f"role_check.role_check_decorator -> Role {role} not found in role permissions data.")
```

The function then checks whether the claimed permission passed to the original function is indeed within the permissions of that specific role. If so then control is passed back to the original function and the program flow resumes as normal – the user does have the necessary role. However, if this isn't the case, then a special `PermissionError` can be raised, terminating the execution – the user does not have the necessary roles.

```python
if role in role_permissions_data:
    # ...previous code

    if permission_name in role_permissions_data[role]["permissions"]:
        return func(owner_id, *args, **kwargs)
    else:
        raise PermissionError(
                            f"role_check.role_check_decorator -> User with ID {owner_id} "
                            f"does not have required permissions for this operation.")
```

**NOTE**: for more detail on the full code implementation, see [4.3.3.3](#4333-role_checkpy).

### 2.3.4 Store records

To simulate users being able to interact with the various clinic's services and systems, being able to write and/or edit data is an important operation to implement. The function below is annotated with the `role_check_decorator` (see [2.3.3](#233-role-based-access-control-rbac)), so the user's role is checked each time they attempt to execute this function. `owner_id` is the ID of the user writing the record (the record owner), `data` being the actual data to be stored, `metadata` is any additional data passed in as a dictionary, `permission` which is the user's permission, `decrypted_data` for the data received from the RSA data transmission (see [2.4](#24-data-transmission)), and finally `individual_access` if the user wants the record to be retrieved by specific users only (see [2.5.1](#2351-individual-access-record-retrieval)) – defaulted to `None` initially.

```python
@role_check_decorator
def record_store(owner_id, data, meta_data, permission, decrypted_data, individual_access=None):
```

First, the AES key assigned to the user is retrieved, by passing in the `owner_id` as the parameter for the `aes_encrypt()` method. `json_data` is the JSON file dump of the decrypted data from the RSA data transmission (see [2.4](#24-data-transmission)). `ciphertext` being the encrypted form of the plaintext, which needs to be serialised to be suitable for JSON storage.

```python
key = retrieve_key(owner_id)
json_data = json.dumps(decrypted_data, indent=2)
ciphertext = aes_encrypt(key, json_data.encode())
serialized_ciphertext = base64.b64encode(ciphertext).decode()
```

All the components of the JSON object are brought together via a dictionary mapping. Using the `uuid` Python library a random unique identifier is generated. This JSON object will be stored in the `"records"` JSON collection.

```python
record_id = str(uuid.uuid4())

json_data["records"].append(
    {
        "record_id": record_id,
        "owner_id": owner_id,
        "data": serialized_ciphertext,
        "meta_data": meta_data,
        "individual_access": individual_access
    })
```

**NOTE**: for more detail on the full code implementation, see [4.3.3.4](#4334-record_storepy).

### 2.3.5 Retrieve records

To simulate data being read across the multiple clinic's services, the counterpart function of `record_store` is implemented. Again, like with `record_store`, this function is annotated with the wrapper `role_check_decorator()` since the RBAC has to be called to check user permissions if this operation is attempted. A record is retrieved based on the `owner_id`, the `patient_id` present within the `metadata` field of the record's JSON object, as well as the user's permission that the `role_check_decorator` uses.

```python
@role_check_decorator
def record_retrieve(owner_id, patient_id, permission)
```

An empty list is initialised at the start of the function, which will be an array of all the found records. At the end of the function, this will be returned to the user.

```python
records_list = []
```

The correct `aes_key` of the user (or record owner) is required for decryption purposes, using `retrieve_key()`.

```python
aes_key = retrieve_key(owner_id)
```

Iterating through the records database, the corresponding record needs to be found, based on the `owner_id` and `patient_id` fields of the record JSON object – if they match with the values of the given arguments.

```python
for record in records_data["records"]:
    if record["owner_id"] == owner_id and record["meta_data"]["patient_id"] == patient_id:
```

Using the `data` field of the record JSON object, the decryption process is performed using `aes_decrypt`, with the user's AES key and the encrypted cipher text. This is then appended to the `records_list` mentioned earlier in this section and returned to the user.

```python
# ...previous code
    record["data"] = aes_data_decrypt(aes_key, record["data"])
    records_list.append(record)

return records_list
```

**NOTE**: for more detail on the full code implementation, see [4.3.3.5](#4335-record_retrievepy).

#### 2.3.5.1 Individual access record retrieval

Another additional requirement, especially for third party data being stored in the company, is the ability for owners to delegate access to specific users of the clinic, since it is their intellectual property after all.

An additional function was required, so therefore, the `record_retrieve_by_id()` function allows the user to read a record based on its ID, and the `user_id` being the ID of the user trying to access this record. Note that the `role_check_decorator()` has not be wrapped around this function since the logic here is different the regular role check.

```python
def record_retrieve_by_id(record_id, user_id)
```

To get all matching records, this line filters a list of records based on the condition that the `lambda` enforced, where `x` takes each element of the list and checks to see whether the `"record_id"` attribute of the JSON object matches the parameter `record_id`. The `[0]` is to access the first element in the `"records"` JSON collection.

```python
record = list(filter(lambda x: x["record_id"] == record_id, records_data["records"]))[0]
```

The `if` statement here checks to see whether the ID of the user is in the `"individual_access"` collection of the matching record JSON object, i.e. if the user calling this function has been given access for that record. If not, then a `PermissionError` is raised.

```python
if user_id in record["individual_access"]:
    # next code...
else:
    raise PermissionError(
        f"record_retrieve.record_retrieve_by_id -> User with ID {user_id} "
        f"does not have required permissions for this operation."
    )
```

Within the `if` statement block, the same logic (see [2.3.5](#235-retrieve-records)) to decrypt the stored cipher text in the JSON object is implemented. The decrypted record is returned to the user at the end.

```python
# ...previous code

aes_key = retrieve_key(record["owner_id"])
record["data"] = aes_data_decrypt(aes_key, record["data"])
return record
```

**NOTE**: for more detail on the full code implementation, see [4.3.3.5](#4335-record_retrievepy).

## 2.4 Data transmission

Data needs to be stored and read across the various systems in the clinic. During the transmission, this data needs to remain secure and unreadable, so even if an unauthorised third party has access to the data, it is presented to them in an unreadable format. The algorithm of choice for this is RSA asymmetric key encryption.

### 2.4.1 Encryption

The function below implements RSA encryption, using Python's RSA cryptographic library. It takes in the `data` to take to output as cipher text and the PEM string of the user's RSA public key that they have been assigned with.

```python
def rsa_encrypt(data, public_key_pem)
```

Since the public key is passed in as a PEM format, the previous `load_public_key_from_pem_string()` function (see [2.2.3.2](#2232-rsa)) takes the PEM string and converts into a usable RSA public key object.

```python
public_key = load_public_key_from_pem_string(public_key_pem)
```

By using the `.encrypt()` method of the `public_key` object, the `data` can be RSA encrypted. First, the plaintext data is converted into bytes via `.encode()`, since this is the format the function accepts. With `padding.OAEP`, a padding scheme needs to be specified, where `mgf=padding.MGF1(algorithm=hashes.SHA256())` is the Mask Generation Function used, in this case with the SHA256 algorithm. The `label` parameter can be used for any additional labels to be included within the padding, but this is not required here, so it has been set to `None` (or `null`).

```python
ciphertext = public_key.encrypt(
        data.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

return ciphertext
```

**NOTE**: for more detail on the full code implementation, see [4.3.2.2](#4322-rsa_key_managerpy).

### 2.4.2 Decryption

The RSA decryption process has also been implemented as a wrapper.

Firstly, starting with the `rsa_decrypt()` function, it uses the user's private key and the `.decrypt()` method of the `private_key`. At the end, the `plaintext` is decoded back to a string to be readable.

```python
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
    return plaintext.decode("utf-8")
```

This wrapper function takes in a function as a parameter. The inner function additionally accepts the record owner's ID as well as the `data`, which is the cipher text in this case.

```python
def rsa_decrypt_data_decorator(func):
    def wrapper(owner_id, data, *args, **kwargs):
```

All the data from the RSA HSM is looped through to find the correct record based on the `user_id`. From this record, the PEM format of the RSA private key is obtained.

```python
rsa_hsm_data = data_read("data/rsa_hsm.json")
    for key_info in rsa_hsm_data["rsa_keys"]:
        if key_info["user_id"] == owner_id:
            private_key_pem = key_info["key"]
```

It then decrypts the transmission data via `rsa_decrypt()` by passing in the cipher text (through `data`) and the PEM of the RSA private key (that is converted into a usable key format).

```python
decrypted_data = rsa_decrypt(data, private_key_pem)
```

At the end, the original function's arguments are returned back, by passing the new values that the parameters take.

```python
return func(
    owner_id=owner_id,
    data=data,
    meta_data=kwargs.get("meta_data"),
    permission=kwargs.get("permission"),
    decrypted_data=decrypted_data,
    individual_access=kwargs.get("individual_access")
)
```

**NOTE**: for more detail on the full code implementation, see [4.3.4.1](#4341-decrypt_datapy).

# 3 Addressing requirements

## 3.1 Cryptographic algorithms and protocols

### 3.1.1 AES

AES symmetric key encryption has been chosen to be used for the data at rest, i.e. the data in MediCloud or data that is not in transit in general.

Highly efficient and computationally fast – ideal for encrypting and decrypting data of large volumes without causing a significant impact on performance. This is obviously dependent on the clinic's hardware, but even despite that, AES can optimally use the resources its been allocated. It is thus suitable for a healthcare provider since they will have a lot of data traversing between the different clinical services at multiple times and quickly too. The same key is used for both encryption and decryption operations, simplifying key management processes and ensuring efficient, quick data access throughout the system.

Key size is sufficiently large enough that prevents brute force attacks, so sensitive data at rest remains confidential and protected from unauthorised access. AES is an industry standard, and has remained to be for many years due to extensive security analysis by cryptographers, so it is a trusted framework that can be reliably used.

### 3.1.2 RSA

RSA asymmetric encryption has been chosen for encrypting data that is in transit, that being the data that is propagated around the various systems of the clinic.

Since data transmission can potentially occur over unsecured networks, it is important that confidentiality is ensured at all times. As seen in [2.1.2](#212-user-login), the public key is not secured at all and widely distributed to the simulated client side but the private key isn't. This ensures that data encrypted with the public key can only be decrypted with the corresponding user's private key, so sensitive data is protected.

Although not implemented, the clinic would highly benefit from the use of a PKI (Public Key Infrastructure) to manage multiple public keys efficiently. If the clinic does grow in size in its user base or external partners, then this algorithm ensures scalability.

## 3.2 Compliance and standards

The proposed cryptographic solution needs to comply with relevant data protection regulations. These include:

- **General Data Protection Regulation (GDPR)**: European Union (EU) regulation for the processing of personal data of users within the EU region and the European Economic Area (EEA) [@wolford].
- **California Consumer Privacy Act (CCPA)**: A Californian law granting specific rights to individuals with a Californian citizenship, and regards their personal information with appropriate choices to either access, delete, or opt-out of their data being sold [@genesis].
- **Payment Services Directive 2 (PSD2)**: Another EU regulation covering payment services and providers within the same EEA region, with the aim of enhancing security within financial operations [@ukfinance].

### 3.2.1 Data encryption

By encrypting data at both rest and transit (see [3.1.1](#311-aes) and [3.1.2](#312-rsa)) at both stationary (rest) and in transit reaffirms the "security by design" principle highlighted in GDPR and CCPA. The encryption protocols, along with storing that data, meet requirements such as Article 32 of GDPR [@intersoftconsulting1] and Section 1798.100 of CCPA [@casetext1].

### 3.2.2 Key management

Albeit simulated, the use of secure key management practices such as a Hardware Security Module (HSM) for robust key storage is vital for maintaining the integrity and confidentiality of keys. Stages such as key rotation can help in mitigating the associated risks of any compromised keys [@warner2022].

### 3.2.3 Access control

The implementation of the role-based access control system (RBAC) alongside the encryption provided via AES and RSA further strengthens data protection by only allowing access to certain individuals based on their roles and permissions. The reason for this is to adhere to the principle of data "minimisation" outlined in Article 5 of GDPR [@intersoftconsulting2] and Section 1798.110 of CCPA [@casetext2]. By only allowing the most minimal privileges for the user, this allows users to still perform their jobs and functionality whilst also preventing unauthorised data access or any leaks.

# 4 Appendices

## 4.1 Simulation assumptions

### 4.1.1 System definition

**NOTE**: This implementation is **NOT** intended to be defined as a "system" or "cryptosystem" of any kind. Rather, each module or function is treated as a separate API (that implements the cryptographic logic). It would ultimately be the responsibility of the developer to combine these APIs and form a coherent "system" of both a back-end and front-end, and facilitate the appropriate communication between them.

### 4.1.2 Simulation scope

- Certain aspects like physical hardware, secure deployment environments, and network infrastructure are out of scope and are assumed to be secure already.
- Only workflows involving cryptographic protocols and access controls are focussed on.
- A simple command line interface with appropriate annotations via `print()` statements is implemented – no advanced GUI.

### 4.1.3 Data

- Sample data within the [`data`](https://github.com/iArcanic/iss-cw/tree/main/data) folder.
- No real production data that is reflective of a real-time system is used.
- Data in a real-time system may use an SQL relational database, but this simulation uses simple JSON objects.

### 4.1.4 External dependencies

- HSMs (Hardware Security Module), and PKIs (Public Key Infrastructure) are simulated as simple JSON objects.
- Third-party key repositories and certification authorities are not simulated.

### 4.1.5 Compliance requirements

- Simulation attempts to provide compliance with GDPR, CCPA, and PSD2.
- Final compliance responsibility ultimately lies with the healthcare provider

### 4.1.6 Authentication

- Advanced enterprise IAM (Identity Access Management) not implemented in simulation.
- Only simple username and password-based authentication suffices for simulation.
- More advanced hardware-based authentication controls, like biometric or facial are up to the company to consider.

### 4.1.7 Roles

- All JSON "databases" are stored in the healthcare provider's cloud service, MediCloud.
- Users are granted roles by an admin manually beforehand.
- User roles assumed, like doctor, nurse, and so on based on common healthcare provider norms.
- Only core attributes simulated - advanced RBAC left for actual enterprise integration.

### 4.1.8 Cryptographic algorithms

- Basic implementation of industry-standard encryption algorithms simulated to a basic level.
- Additional platform-specific encryption algorithms are not implemented.

### 4.1.9 Key management

- Only essential stages in the key management lifecycle are able to be simulated – generation, storage, usage, and rotation.
- Actual HSM synchronisation protocols are not considered.

### 4.1.10 Exception handling

- Core exception handling is done but extensive error flows are not implemented.

### 4.1.11 Concurrency

- Only one test case workflow is run at a time.
- Parallel processing capabilities of different workflows are not considered.

### 4.1.12 Performance

- Code optimisation not achieved to full capabilities.
- Large-scale data, user and cryptographic operation performance testing not done.

## 4.2 GitHub repository

Link to GitHub repository, containing full code and installation documentation:

> [https://github.com/iArcanic/iss-cw](https://github.com/iArcanic/iss-cw)

## 4.3 Implementation source code

### 4.3.1 Authentication

#### 4.3.1.1 [`register.py`](https://github.com/iArcanic/iss-cw/blob/main/src/authentication/register.py)

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

#### 4.3.1.2 [`login.py`](https://github.com/iArcanic/iss-cw/blob/main/src/authentication/login.py)

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

### 4.3.1.3 [`sso.py`](https://github.com/iArcanic/iss-cw/blob/main/src/authentication/sso.py)

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

### 4.3.2 Key management

#### 4.3.2.1 AES key functions

##### 4.3.2.1.1 [`key_gen.py`](https://github.com/iArcanic/iss-cw/blob/main/src/key_management/key_gen.py)

```python
import os


def generate_aes_key():
    key = os.urandom(32)
    return key
```

##### 4.3.2.1.2 [`key_store.py`](https://github.com/iArcanic/iss-cw/blob/main/src/key_management/key_store.py)

```python
import base64

from src.decryption import aes_data_decrypt
from src.encryption import aes_encrypt
from src.key_management.key_gen import generate_aes_key
from src.key_management.key_retrieve import *

# Hardware Security Module (HSM) for AES keys simulation
HSM_DB = "data/hsm.json"

# Records database simulation
RECORDS_DB = "data/records_db.json"


def store_aes_key(user_id, key):
    try:
        with open(HSM_DB, 'r') as file:
            # Read all key entries from HSM
            json_data = json.load(file)
    except FileNotFoundError:
        # If file is not found then make an empty aes_keys JSON collection
        json_data = {"aes_keys": []}

    for entry in json_data["aes_keys"]:
        if entry["user_id"] == user_id:
            # Store AES key as hex in database
            entry["key"] = key.hex()
            break
        else:
            # If user_id not found, insert a new entry using the given AES key
            json_data["aes_keys"].append({"user_id": user_id, "key": key.hex()})

    with open(HSM_DB, 'w') as file:
        json.dump(json_data, file, indent=2)
```

##### 4.3.2.1.3 [`key_retrieve.py`](https://github.com/iArcanic/iss-cw/blob/main/src/key_management/key_retrieve.py)

```python
from src.data_manager import *

# Hardware Security Module (HSM) for AES keys simulation
HSM_DB = "data/hsm.json"


def retrieve_key(user_id):
    # Read all key entries from HSM
    key_entries = data_read(HSM_DB)

    for entry in key_entries["aes_keys"]:
        # Get the correct record
        if entry["user_id"] == user_id:
            # Return AES key from hex into a usable format
            return bytes.fromhex(entry["key"])

    print(f"key_retrieve.retrieve_key -> Key for user {user_id} not found in {HSM_DB}!")
    return None
```

##### 4.3.2.1.4 `key_expire.py`

> NOTE: The `expire_aes_key` function is implemented within the [`key_store.py`](https://github.com/iArcanic/iss-cw/blob/main/src/key_management/key_store.py) (see [4.3.2.1.2](#43212-key_storepy)) rather than in its own separate file. For clarity and understanding purposes, it has been presented in here as its own distinct file.

```python
import base64

from src.decryption import aes_data_decrypt
from src.encryption import aes_encrypt
from src.key_management.key_gen import generate_aes_key
from src.key_management.key_retrieve import *

# Hardware Security Module (HSM) for AES keys simulation
HSM_DB = "data/hsm.json"

# Records database simulation
RECORDS_DB = "data/records_db.json"

# This has to be highly transactional.
# For any failures, old key should be rolled back, including data encryption and decryption
def expire_aes_key(user_id):

    # Read all record entries from Records database
    records_data = data_read(RECORDS_DB)

    # Get AES old key
    old_aes_key = retrieve_key(user_id)

    # Make a new AES key
    new_aes_key = generate_aes_key()

    # Store new key under the given user_id
    store_aes_key(user_id, new_aes_key)

    for record in records_data["records"]:
        # Get the correct record
        if record["owner_id"] == user_id:
            # Decrypt the data of that record with the old AES key
            record["data"] = aes_data_decrypt(old_aes_key, record["data"])

            # Encrypt the data of that record with the new key
            ciphertext = aes_encrypt(new_aes_key, record["data"].encode())

            # Serialise the ciphertext so it can be stored as JSON
            serialized_ciphertext = base64.b64encode(ciphertext).decode()

            # Overwrite the data of that record with the new serialised ciphertext
            record["data"] = serialized_ciphertext

    # Write to Records database
    data_store(RECORDS_DB, records_data)
```

#### 4.3.2.2 [`rsa_key_manager.py`](https://github.com/iArcanic/iss-cw/blob/main/src/key_management/rsa_key_manager.py)

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

### 4.3.3 Record management

#### 4.3.3.1 [`encryption.py`](https://github.com/iArcanic/iss-cw/blob/main/src/encryption.py)

```python
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# AES data encryption operation
def aes_encrypt(key, data):
    # Check whether the AES key is of the required length
    if len(key) != 32:
        raise ValueError("AES key must be 32 bytes long for AES-256")

    # Create a new initialisation vector of 16 characters
    iv = os.urandom(16)

    # Create a new cipher with the AES key and initialisation vector
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())

    # Make a new encrypter with that cipher to encrypt the data
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()

    # Concatenate the IV and ciphertext to form the final ciphertext
    return iv + ciphertext
```

#### 4.3.3.2 [`decryption.py`](https://github.com/iArcanic/iss-cw/blob/main/src/decryption.py)

```python
import base64

from src.encryption import *


# AES data decryption operation
def aes_data_decrypt(aes_key, data):
    # Base64 decode the encrypted data
    ciphertext = base64.b64decode(data)
    print(f"record_store.record_store -> Encrypted data at rest {ciphertext}")

    # Splice the initialisation vector from the cipher text
    iv = ciphertext[:16]

    # Splice the actual encrypted data content from the ciphertext
    actual_ciphertext = ciphertext[16:]

    # Check whether the AES key is of the required length
    if len(aes_key) != 32:
        raise ValueError("AES key must be 32 bytes long for AES-256")

    # Create a new AES cipher using the AES key and IV
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())

    # Make a new decrypter with that cipher to decrypt the data
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(actual_ciphertext) + decryptor.finalize()

    # Decode the plaintext to string from bytes
    plaintext = decrypted_data
    return plaintext.decode()
```

#### 4.3.3.3 [`role_check.py`](https://github.com/iArcanic/iss-cw/blob/main/src/role_check.py)

```python
import json

# User roles database simulation
USER_ROLES_DB = "data/user_roles_db.json"

# Role permissions database simulation
ROLE_PERMISSIONS_DB = "data/role_permissions_db.json"


def role_check_decorator(func):
    def wrapper(owner_id, *args, **kwargs):
        try:
            with open(USER_ROLES_DB, 'r') as user_roles_file:
                # Get all the users with their relevant allocated roles
                user_roles_data = json.load(user_roles_file)

            with open(ROLE_PERMISSIONS_DB, 'r') as role_permissions_file:
                # Get all permissions
                role_permissions_data = json.load(role_permissions_file)

        except FileNotFoundError:
            print(f"role_check.role_check_decorator -> {USER_ROLES_DB} database or {ROLE_PERMISSIONS_DB} database not "
                  f"found.")
            return

        if owner_id in user_roles_data:
            # Get all the roles which the user has been granted
            user_roles = user_roles_data[owner_id]["roles"]

            for role in user_roles:
                # Check if the role exists
                if role in role_permissions_data:
                    # Check if the function's name corresponds to a permission
                    permission_name = kwargs.get("permission", "").upper()
                    # Get the correct permission from permissions database
                    if permission_name in role_permissions_data[role]["permissions"]:
                        # Return to the original function
                        return func(owner_id, *args, **kwargs)
                    else:
                        # Terminate the program if the user does not have the relevant role
                        raise PermissionError(
                            f"role_check.role_check_decorator -> User with ID {owner_id} "
                            f"does not have required permissions for this operation.")
                else:
                    # Terminate the program if the role is not found
                    print(f"role_check.role_check_decorator -> Role {role} not found in role permissions data.")
        else:
            # Terminate the program if the user is not found
            print(f"role_check.role_check_decorator -> User with ID {owner_id} not found in user roles data.")

    return wrapper
```

#### 4.3.3.4 [`record_store.py`](https://github.com/iArcanic/iss-cw/blob/main/src/record_management/record_store.py)

```python
import base64
import uuid

from src.decrypt_data import *
from src.encryption import *
from src.key_management.key_retrieve import retrieve_key
from src.role_check import *

# Records database simulation
RECORDS_DB = "data/records_db.json"


# Decorators executed each time function is run
@rsa_decrypt_data_decorator
@role_check_decorator
# Store a record based on record owner_id, data, meta-data, permission of user performing this operation,
# decrypted data from RSA data transmission, and individual access rights
def record_store(owner_id, data, meta_data, permission, decrypted_data, individual_access=None):
    # If individual_access parameter is not passed when function is called
    if individual_access is None:
        # Create empty collection to be stored in the JSON object
        individual_access = []
    print(f"record_store.record_store -> Data received encrypted: {data}")

    # Get AES key record owner
    key = retrieve_key(owner_id)

    # Decrypt data from data transmission
    json_data = json.dumps(decrypted_data, indent=2)

    # Encrypt the JSON-formatted data at rest
    ciphertext = aes_encrypt(key, json_data.encode())

    # Convert the ciphertext to a JSON-serializable format (Base64-encoded string)
    serialized_ciphertext = base64.b64encode(ciphertext).decode()

    try:
        with open(RECORDS_DB, 'r') as file:
            # Read all record entries from Records database
            json_data = json.load(file)
    except FileNotFoundError:
        # If file is not found then make an empty records JSON collection
        json_data = {"records": []}

    try:
        with open(RECORDS_DB, 'w') as file:

            # Make UUID dynamically for each new record
            record_id = str(uuid.uuid4())

            # Add to records JSON collection
            json_data["records"].append(
                {"record_id": record_id, "owner_id": owner_id, "data": serialized_ciphertext,
                 "meta_data": meta_data, "individual_access": individual_access})

            # Write to the Records database
            json.dump(json_data, file, indent=2)

            return record_id

    except FileNotFoundError:
        print(f"record_store.record_store -> {RECORDS_DB} not found.")
```

#### 4.3.3.5 [`record_retrieve.py`](https://github.com/iArcanic/iss-cw/blob/main/src/record_management/record_retrieve.py)

```python
from src.decryption import aes_data_decrypt
from src.key_management.key_retrieve import *
from src.role_check import *

# Records database simulation
RECORDS_DB = "data/records_db.json"


# Decorator executed each time function is run
@role_check_decorator
# Get all records based on record owner_id, patient_id, and the permission of user performing this operation
def record_retrieve(owner_id, patient_id, permission):
    # List to capture all found records
    records_list = []

    # Get all record entries
    records_data = data_read(RECORDS_DB)

    # Get relevant AES key based on record owner_id
    aes_key = retrieve_key(owner_id)

    for record in records_data["records"]:
        # Get the correct record based on the record owner_id and patient_id
        if record["owner_id"] == owner_id and record["meta_data"]["patient_id"] == patient_id:

            # Use AES key to perform AES decryption on data
            # Overwrite encrypted data with the decrypted plaintext
            record["data"] = aes_data_decrypt(aes_key, record["data"])

            # Add all found and modified records to list
            records_list.append(record)

    return records_list


# Retrieve record by record_id
def record_retrieve_by_id(record_id, user_id):
    # Get all record entries
    records_data = data_read(RECORDS_DB)

    # Filter records by record_id
    record = list(filter(lambda x: x["record_id"] == record_id, records_data["records"]))[0]

    # Get record that has individual access for given user_id
    if user_id in record["individual_access"]:
        # Get record owner's AES key
        aes_key = retrieve_key(record["owner_id"])

        # Use AES key to perform AES decryption on data
        # Overwrite encrypted data with the decrypted plaintext
        record["data"] = aes_data_decrypt(aes_key, record["data"])

        return record
    else:
        # Raise error if the wrong user tried to access the record
        raise PermissionError(
            f"record_retrieve.record_retrieve_by_id -> User with ID {user_id} "
            f"does not have required permissions for this operation."
        )
```

### 4.3.4 Data transmission

#### 4.3.4.1 [`decrypt_data.py`](https://github.com/iArcanic/iss-cw/blob/main/src/decrypt_data.py)

```python
from src.data_manager import *
from src.key_management.rsa_key_manager import *


# Decorator function RSA decrypt data
def rsa_decrypt_data_decorator(func):
    def wrapper(owner_id, data, *args, **kwargs):

        # Get all RSA private key entries from RSA HSM
        rsa_hsm_data = data_read("data/rsa_hsm.json")

        for key_info in rsa_hsm_data["rsa_keys"]:
            # Get correct RSA private key entry for record owner
            if key_info["user_id"] == owner_id:
                # Get RSA private key PEM string
                private_key_pem = key_info["key"]

                # Use RSA private key PEM string to perform RSA decryption on data
                decrypted_data = rsa_decrypt(data, private_key_pem)

                # Return to the original function''s arguments
                return func(
                    owner_id=owner_id,
                    data=data,
                    meta_data=kwargs.get("meta_data"),
                    permission=kwargs.get("permission"),
                    decrypted_data=decrypted_data,
                    individual_access=kwargs.get("individual_access")
                )

    return wrapper
```

# 5 References
