# Initialises the database and populates the user table with 10 test users
# Contains functions to access and query the database for use in server.py

import sqlite3
from hashlib import sha256


def access_database(dbfile, query, *par):
    """Query the local database provided. Takes any number of query input parameters"""

    connect = sqlite3.connect(dbfile)
    cursor = connect.cursor()
    if par == ():
        cursor.execute(query)
    else:
        cursor.execute(query, par)
    connect.commit()
    connect.close()


def access_database_with_result(dbfile, query, *par):
    """Query the local database provided and return the results.
    Takes any number of query input parameters"""

    connect = sqlite3.connect(dbfile)
    cursor = connect.cursor()
    if par == ():
        rows = cursor.execute(query).fetchall()
    else:
        rows = cursor.execute(query, par).fetchall()
    connect.commit()
    connect.close()
    return rows


def hash_password(password):
    """return a hashed password from a password input using the hashlib module"""
    h_pass = sha256()
    password = bytes(password, 'utf-8')
    h_pass.update(password)
    hashed_password = h_pass.hexdigest()

    return hashed_password


# empty tables if they already exist
access_database("trafficdb.db", "DROP TABLE IF EXISTS users")
access_database("trafficdb.db", "DROP TABLE IF EXISTS sessions")
access_database("trafficdb.db", "DROP TABLE IF EXISTS traffic_data")

# create tables
access_database("trafficdb.db",
                """CREATE TABLE users (username VARCHAR, password VARCHAR)"""
                )

access_database("trafficdb.db",
                """CREATE TABLE sessions
                (session_id VARCHAR primary key, username VARCHAR,
                start_time text, end_time text)"""
                )

access_database("trafficdb.db",
                """CREATE TABLE traffic_data
                (location VARCHAR, type VARCHAR, occupancy tinyint, rec_time text,
                username VARCHAR, session_id VARCHAR, undo_flag tinyint)"""
                )

# hard code users
for i in range(10):
    username = 'test' + str(i+1)
    pass_clear = 'password' + str(i+1)

    # hash passwords for security
    access_database("trafficdb.db",
                    """INSERT INTO users (username, password) VALUES (?,?)""",
                    username, hash_password(pass_clear)
                    )
