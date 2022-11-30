from crypt import methods
import flask
import yaml
from werkzeug.middleware.proxy_fix import ProxyFix

from ldap3.core.exceptions import LDAPInsufficientAccessRightsResult
from ldap import ADObjects
import os

import subprocess
from subprocess import Popen, PIPE
import logging
import smtplib
import datetime
from email.mime.text import MIMEText

logging.basicConfig()
LOGGER = logging.getLogger("werkzeug")
LOGGER.setLevel(logging.DEBUG)




# Configure flask app and apply fix for running under a rev-proxy
app = flask.Flask("NSLS2 Login Lockout Email API")
app.wsgi_app = ProxyFix(app.wsgi_app, x_prefix=1)

def get_email_from_username(username):

    ret_msg = ""

    with ADObjects(
        "dc2.bnl.gov",
        authenticate=False,
        username=username,
        ca_certs_file="/etc/pki/ca-trust/source/anchors/bnlroot.crt",
        group_search="dc=bnl,dc=gov",
        user_search="ou=cam - users,ou=cam,dc=bnl,dc=gov",
    ) as ad:

        # Get the beamline group
        user = None

        if username is not None:
            user = ad.get_user_by_samaccountname(username)
            if len(user) == 0:
                raise RuntimeError(f"Unable to find user {username}, please check.")

            if len(user) != 1:
                raise RuntimeError(
                    f"Login (Username) {username} is not unique. Please check."
                )

            user = user[0]

        else:
            raise RuntimeError(f"Failed to validate group manager service account!")

        print(user['mail'])

    return user['mail'] 


def compose_email(username, hostname):

    target_email = get_email_from_username(username)
    subject_line = f'Account lockout for user {username} on host {hostname}'
    message_body = f'User {username} has had too many account authentication failures on host {hostname}\n\nTIMESTAMP: {datetime.datetime.now()}'

    return target_email, subject_line, message_body


@app.route("/")
def hello():
    return "Hello NSLS2 Account Lockout Email Notification API"


@app.route("/lockout", methods=["POST"])
def process_lockout_event():
    
    lockout_user = flask.request.json.get('username')
    host = flask.request.json.get('hostname')
    print(f"Detected lockout for user {lockout_user} on host {host}...")

    send_to, subject_line, message_body = compose_email(lockout_user, host)

    msg = MIMEText(message_body)
    msg['Subject'] = subject_line
    msg['From'] = 'do-not-reply@bnl.gov'
    msg['To'] = send_to
    
    with smtplib.SMTP('smtpgw.bnl.gov', 587) as mail_server:
        mail_server.sendmail('do-not-reply@bnl.gov', send_to, msg.as_string())
        ret = f'Sent "{subject_line}" message to "{send_to}"'
        print(ret)
    return ret
    

if __name__ == "__main__":

    app.run()
