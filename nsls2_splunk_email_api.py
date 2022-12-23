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
import jinja2

logging.basicConfig()
LOGGER = logging.getLogger("werkzeug")
LOGGER.setLevel(logging.DEBUG)


# Indicates list of directories to search for jinja based email templates
template_search_path = [ '/etc/nsls2_splunk_email_api', './templates']

# YML configuration file that maps POST codes to the template to use
config_search_path = ['/etc/nsls2_splunk_email_api', '~/.config', '.']


# Configure flask app and apply fix for running under a rev-proxy
app = flask.Flask("NSLS2 Splunk Event Email API")
app.wsgi_app = ProxyFix(app.wsgi_app, x_prefix=1)


def get_email_from_username(username):
    """Retrieve user email from username from post request
    """

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


def compose_email(post_route, jinja_var_dict):

    config_file = None
    for dir in config_search_path:
        if os.path.exists(os.path.join(dir, 'nsls2_splunk_email_api.yml')):
            config_file = os.path.join(dir, 'nsls2_splunk_email_api.yml')
            break
    if config_file is None:
        raise RuntimeError(f"Failed to detect valid config file in search path!")
    with open(config_file, 'r') as cfp:
        config = yaml.load(cfp)

    if post_route not in config:
        raise RuntimeError(f"Could not find templates for route: {post_route} in config file: {config_file}!")

    subject_line_template = 'base-subject.j2'
    if 'subject' in config[post_route]:
        subject_line_template = config[post_route]['subject']
    
    message_body_template = config[post_route]['body']

    subject_template_path = None
    body_template_path = None
    for dir in template_search_path:
        print(f'Searching for {subject_line_template} in dir: {os.path.abspath(dir)}')
        if os.path.exists(os.path.join(dir, subject_line_template)):
            subject_template_path = os.path.join(dir, subject_line_template)
            break
  
    for dir in template_search_path:
        print(f'Searching for {message_body_template} in dir: {os.path.abspath(dir)}')
        if os.path.exists(os.path.join(dir, message_body_template)):
            body_template_path = os.path.join(dir, message_body_template)
            break

    if subject_template_path is None or body_template_path is None:
        raise RuntimeError(f"Could not find the jinja template for either the body or subject lines")

    with open(subject_template_path, 'r') as stfp:
        subject_template = jinja2.Template(stfp.read())

    with open(body_template_path, 'r') as btfp:
        body_template = jinja2.Template(btfp.read())

    return subject_template.render(**jinja_var_dict), body_template.render(**jinja_var_dict)


@app.route("/")
def hello():
    return "Hello NSLS2 SPLUNK Event Notification Email API"


@app.route("/lockout", methods=["POST"])
def process_lockout_event():
    post_route = 'lockout'

    lockout_user = flask.request.json.get('nsls2_locked_out_user')
    host = flask.request.json.get('nsls2_host')
    print(f"Detected lockout for user {lockout_user} on host {host}...")

    try:
        send_to = get_email_from_username(lockout_user)
    except RuntimeError as e:
        ret = f'Failed to get email from username: {str(e)}'
        print(ret)
        return ret
    
    jinja_var_dict = {'nsls2_locked_out_user': lockout_user, 'nsls2_host': host, 'timestamp': str(datetime.datetime.now()) }
    try:
        subject_line, message_body = compose_email(post_route, jinja_var_dict)
    except RuntimeError as e:
        ret = f'Failed to compose email: {str(e)}'
        print(ret)
        return ret

    msg = MIMEText(message_body)
    msg['Subject'] = subject_line
    msg['From'] = 'do-not-reply@bnl.gov'
    msg['To'] = send_to
    
    with smtplib.SMTP('smtpgw.bnl.gov') as mail_server:
        mail_server.sendmail('do-not-reply@bnl.gov', send_to, msg.as_string())
        ret = f'Sent "{subject_line}" message to "{send_to}"'
        print(ret)
    return ret
    

if __name__ == "__main__":

    app.run()
