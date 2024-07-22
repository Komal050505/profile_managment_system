from apps.constants import *
from logging_activity.logging_utils import *
import re

"""
This module contains utilities which are repeated in the actual program. Programmers can use these in their code.
"""


def is_valid_name(name):
    """
        This function checks whether the name is valid or not.
        :param name: str
        :return: bool
        """
    log_info(f"is valid name function entered")
    try:
        if not name:
            log_debug(f"Name {name} or not")
            return False
        if not name.isalpha():
            log_debug(f"Name {name} has alphabets or not")
            return False
        log_info(f"Valid name {name} So True")
        return True
    except Exception as error:
        return error


# MOBILE VALIDATION

def is_valid_mobile(mobile):
    """
    This function checks whether the mobile number is valid or not.
    :param mobile: str or int
    :return: bool
    """
    log_info("------is valid mobile function entered------")
    try:
        # Convert integer to string if necessary
        if isinstance(mobile, int):
            mobile = str(mobile)  # Convert integer to string

        log_debug(f"Validating mobile number: {mobile}")

        # Ensure mobile number is a string
        if not isinstance(mobile, str):
            raise ValueError(f"Invalid mobile number type - {type(mobile)}. Expected a string.")

        # Check if mobile number contains only digits
        if not mobile.isdigit():
            raise ValueError("Mobile number should contain digits only.")

        # Check if mobile number length is between 10 and 12 digits
        if len(mobile) < 10 or len(mobile) > 12:
            raise ValueError("Mobile number must be between 10 and 12 digits.")

        log_debug(f"Mobile number {mobile} is valid")
        return True
    except ValueError as e:
        log_error(f"Error in is_valid_mobile function: {e}")
        return False
    finally:
        log_info("------is valid mobile function ended------")


def is_excluded(mobile_num):
    """
    This function checks whether the mobile number is in the exemptions mobile number list.
    :param mobile_num: int
    :return: bool
    """
    log_info(f" ------is excluded function entered------\n")

    if not isinstance(mobile_num, int):
        log_error(f"Invalid type for mobile_num: {type(mobile_num)}. Expected type is int.")
        raise ValueError(f"Invalid type for mobile_num: {type(mobile_num)}. Expected type is int.")

    if mobile_num in EXCLUDED_NUMBERS:
        log_debug(f"mobile_num {mobile_num} is in EXCLUDED_NUMBERS {EXCLUDED_NUMBERS}. Verification successful.")
        return True
    log_warning(f"mobile_num {mobile_num} is not in {EXCLUDED_NUMBERS}.")
    return False


def is_valid_country(converted_str):
    """
    This function checks whether the mobile number matches the given country code or not.
    :param converted_str: str
    :return: bool
    """
    log_info(f" ------is valid country function entered------\n")
    if converted_str[:2] in VALID_COUNTRY_LIST:
        log_debug(f"converted_str {converted_str} is in VALID_COUNTRY_LIST {VALID_COUNTRY_LIST}")
        return True
    else:
        log_error(f"Invalid country code - {converted_str[:2]} which is not in {VALID_COUNTRY_LIST}")
        raise ValueError(f"Invalid country code - {converted_str[:2]}. Valid country codes are {VALID_COUNTRY_LIST}")


def is_mobile_length_valid(converted_str):
    """
    This function checks whether the mobile number length matches the desired length or not.
    :param converted_str: str
    :return: bool
    """
    log_info(f" ------is mobile length valid function entered------\n")
    if len(converted_str) == 12:
        log_debug(f"converted_str {converted_str} is of valid length (12 digits)")
        log_info("------is mobile length valid function ended------")
        return True
    else:
        log_error(f"Invalid mobile length - {converted_str}, should be length of 12")
        raise ValueError(f"Invalid mobile number length {len(converted_str)}. Valid length is {converted_str}")


def is_valid_type(mobile):
    """
    This function checks whether the type and format of the mobile number are valid.
    :param mobile: str or int
    :return: bool
    """
    log_info("------is valid type function entered------")
    try:
        # Convert integer to string if necessary
        if isinstance(mobile, int):
            mobile = str(mobile)  # Convert integer to string

        log_debug(f"Validating mobile number: {mobile}")

        # Ensure mobile number is a string
        if not isinstance(mobile, str):
            raise ValueError(f"Invalid mobile number type - {type(mobile)}. Expected a string.")

        # Check if mobile number contains only digits
        if not mobile.isdigit():
            raise ValueError("Mobile number should contain digits only.")

        # Check if mobile number length is between 10 and 12 digits
        if len(mobile) < 10 or len(mobile) > 12:
            raise ValueError("Mobile number must be between 10 and 12 digits.")

        log_debug(f"Mobile number {mobile} is valid")
        return True
    except ValueError as e:
        log_error(f"Error in is_valid_type function: {e}")
        return False
    finally:
        log_info("------is valid type function ended------")


def is_valid_record(RAW_DATA, record):
    """
    This function checks whether the record is valid or not.
    :param RAW_DATA: dict
    :param record: list of dict
    :return: bool
    """
    log_info(f" ------is  valid record function entered------\n")

    if not isinstance(RAW_DATA, dict):
        log_error(f"Invalid data structure - {RAW_DATA}, should be a dict")
        raise ValueError(f"Invalid input DATA {RAW_DATA}")

    if not isinstance(record, dict):
        log_error(f"Invalid data structure - {record}, should be a dict")
        raise ValueError(f"Record should be a dictionary, got {type(record)} instead.")

    if "mobile" not in record:
        log_error(f"Missing 'mobile' key in record: {record}")
        raise ValueError(f"Missing 'mobile' key in record: {record}")

    log_debug(f"Record {record} is valid")
    return True


def is_valid_employee_id(employee_id):
    """
    This function checks whether the employee ID is valid or not.
    :param employee_id: str
    :return: bool
    """
    log_info(f" ------is valid employee ID function entered------\n")
    if isinstance(employee_id, str) and employee_id.startswith("EMP") and len(employee_id) == 6:
        log_debug(f"Employee ID {employee_id} is valid.")
        return True
    else:
        log_warning(f"Invalid employee ID format: {employee_id}")
        return False


def send_email(recipients, message):
    """
    Sends an email to the given recipients.
    :param recipients: list of str
    :param message: str
    :return: None
    """
    log_info(f"Sending email to {recipients} with message: {message}")

    log_debug("Email sent successfully.")


def is_valid_email(email):
    # Define the regex pattern for a valid email
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None
