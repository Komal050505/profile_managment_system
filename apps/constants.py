"""

This module is for constants which contains DATA Base related DATA

"""
# DATABASE RECORD
USERS = ['kmakala', 'dinesh', 'kmahesh', 'Kumar Makala']
ADMINS = ['komal']

DATA = {
    "records": [
        {"mobile": 914234234245, "name": "kmakala", "company": "KXN",
         "employee_id": "EMP001", "password": "kumar@2929", "isadmin": False},
        {"mobile": 915421215452, "name": "Komal", "company": "APPLE",
         "employee_id": "EMP002", "password": "komal@0529", "isadmin": True},
        {"mobile": 913020022100, "name": "dinesh", "company": "MICROSOFT",
         "employee_id": "EMP003", "password": "mahesh@123", "isadmin": False},
        {"mobile": 910000000000, "name": "kmahesh", "company": "WIPRO",
         "employee_id": "EMP004", "password": "rajesh@54", "isadmin": False},
        {"mobile": 914111111111, "name": "Suresh", "company": "MIND TREE",
         "employee_id": "EMP005", "password": "suresh@4575", "isadmin": False}
    ],
    "users": USERS,
    "admins": ADMINS
}

AVAILABLE_RECORDS = [item["mobile"] for item in DATA["records"]]

# FILTERS TO BE APPLIED
VALID_COUNTRY_LIST = ["91", "45", "67", "56"]
EXCLUDED_NUMBERS = [9898989898, 9999999999, 8888888888]
VALID_EMPLOYEE_IDS = ["EMP001", "EMP002", "EMP003", "EMP004", "EMP005"]

EMAILS = []

LOG_SWITCH = True
