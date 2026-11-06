from database.db import test_connection as check_mongodb_connection


def test_mongodb_connection():
    assert check_mongodb_connection() is True