# data_manager.py

import json

# General utility functions for JSON file operations


# Store data into JSON
def data_store(db, json_data):
    try:
        with open(db, "w") as file:
            json.dump(json_data, file, indent=2)
    except FileNotFoundError:
        print(f"data_manager.data_store -> Database {db} not found.")
        return


# Read data from JSON
def data_read(db):
    try:
        with open(db, "r") as file:
            return json.load(file)
    except FileNotFoundError:
        print(f"data_manager.data_read -> Database {db} not found.")
        return


# Read data from JSON, but return an empty JSON if not found
def data_read_return_empty_if_not_found(db):
    try:
        with open(db, "r") as file:
            return json.load(file)
    except FileNotFoundError:
        print(f"data_manager.data_read_return_empty_if_not_found -> Database {db} not found.")
        return {}
