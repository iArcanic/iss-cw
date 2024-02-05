# data_manager.py

import json


def data_store(db, json_data):
    try:
        with open(db, "w") as file:
            json.dump(json_data, file, indent=2)
    except FileNotFoundError:
        print(f"Database {db} not found.")
        return


def data_read(db):
    try:
        with open(db, "r") as file:
            return json.load(file)
    except FileNotFoundError:
        print(f"Database {db} not found.")
        return


def data_read_return_empty_if_not_found(db):
    try:
        with open(db, "r") as file:
            return json.load(file)
    except FileNotFoundError:
        print(f"Database {db} not found.")
        return {}
