
from email_setup.email_config import *

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText




def send_email(too_email, subject, body):
    """
    This function is used to send emails whenever there are changes in CRUD operations
    :param too_email: list of email addresses needed to be sent
    :param subject: The subject of the email
    :param body: The message which user needs to be notified
    :return: None
    """
    if too_email is None:
        too_email = []

    msg = MIMEMultipart()
    msg['From'] = SENDER_EMAIL
    msg['To'] = ", ".join(too_email)
    msg['Subject'] = subject

    msg.attach(MIMEText(body, 'plain'))

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()
        server.login(SENDER_EMAIL, PASSWORD)
        server.sendmail(SENDER_EMAIL, too_email, msg.as_string())


def new_record_email_content(name, record):
    email_subject = f"Admin '{name}' added a new record"
    email_body = f"""
    Admin '{name}' has added a new record:
    Name: {record.get('name', 'N/A')}
    Mobile: {record.get('mobile', 'N/A')}
    Company: {record.get('company', 'N/A')}
    Employee ID: {record.get('employee_id', 'N/A')}
    """
    return email_subject, email_body


def get_single_record_email_content(name, record):
    email_subject = f" '{name}' is checking his own  single record"
    email_body = f"""
     '{name}' is checking his own record using single user record:
    Name: {record.get('name', 'N/A')}
    Mobile: {record.get('mobile', 'N/A')}
    Company: {record.get('company', 'N/A')}
    Employee ID: {record.get('employee_id', 'N/A')}
    """
    return email_subject, email_body
