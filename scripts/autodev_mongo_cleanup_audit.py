"""Read-only, secret-free evidence that retired AutoDev local Mongo objects are absent.

Run only in the target Railway project network. No data/user writes.
"""
import os
import sys
from pymongo import MongoClient

uri = os.getenv("AUTODEV_MONGO_AUDIT_URI", "")
if not uri:
    print("AUTODEV_MONGO_AUDIT=BLOCKED:MISSING_URI", flush=True)
    sys.exit(2)

try:
    with MongoClient(uri, serverSelectionTimeoutMS=7000, connectTimeoutMS=5000,
                     socketTimeoutMS=7000, retryWrites=False) as client:
        client.admin.command("ping")
        users = client.admin.command({"usersInfo": {"forAllDBs": True}})["users"]
        retired_users = [
            (entry.get("db"), entry.get("user"))
            for entry in users
            if isinstance(entry.get("user"), str)
            and entry["user"].startswith("autodev_local_")
        ]
        for dbname, username in retired_users:
            matched = next(u for u in users if u.get("db") == dbname and u.get("user") == username)
            role_names = sorted(str(r.get("role", "")) for r in matched.get("roles", []) if isinstance(r, dict))
            print("AUTODEV_RETIRED_USER=" + str(dbname) + "/" + str(username), flush=True)
            print("AUTODEV_RETIRED_USER_ROLES=" + ",".join(role_names), flush=True)
        retired_collections = []
        for dbname in client.list_database_names():
            if "autodev_local_devices" in client[dbname].list_collection_names():
                retired_collections.append(dbname)
        print("AUTODEV_MONGO_AUDIT_CONNECTED=PASS", flush=True)
        print("AUTODEV_MONGO_RETIRED_USER_COUNT=" + str(len(retired_users)), flush=True)
        print("AUTODEV_MONGO_RETIRED_COLLECTION_COUNT=" + str(len(retired_collections)), flush=True)
        if retired_users or retired_collections:
            print("AUTODEV_MONGO_CLEANUP=FAIL:RETIRED_OBJECTS_PRESENT", flush=True)
            sys.exit(1)
        print("AUTODEV_MONGO_CLEANUP=PASS", flush=True)
except Exception as error:
    print("AUTODEV_MONGO_AUDIT=BLOCKED:" + type(error).__name__, flush=True)
    sys.exit(2)
