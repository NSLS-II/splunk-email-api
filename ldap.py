import ssl
import os
from enum import IntEnum
import datetime
from getpass import getpass
from ldap3 import (Server, Connection, Tls, NTLM,
                   SASL, GSSAPI, SUBTREE)
from ldap3.core.exceptions import (LDAPAuthMethodNotSupportedResult,
                                   LDAPPackageUnavailableError,
                                   LDAPInvalidCredentialsResult)

from ldap3.extend.microsoft.addMembersToGroups \
    import ad_add_members_to_groups

from ldap3.extend.microsoft.removeMembersFromGroups \
    import ad_remove_members_from_groups


mdci = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)


def get_ad_time(adtime):
    if type(adtime) == datetime.datetime:
        return adtime

    else:
        microseconds = int(adtime) / 10
        seconds, microseconds = divmod(microseconds, 1e6)
        days, seconds = divmod(seconds, 86400)
        a = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
        b = datetime.timedelta(days, seconds, microseconds)
        return a + b


class ADUserAccountControl(IntEnum):
    ADS_UF_SCRIPT = 0x00000001
    ADS_UF_ACCOUNTDISABLE = 0x00000002
    ADS_UF_HOMEDIR_REQUIRED = 0x00000008
    ADS_UF_LOCKOUT = 0x00000010
    ADS_UF_PASSWD_NOTREQD = 0x00000020
    ADS_UF_PASSWD_CANT_CHANGE = 0x00000040
    ADS_UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED = 0x00000080
    ADS_UF_TEMP_DUPLICATE_ACCOUNT = 0x00000100
    ADS_UF_NORMAL_ACCOUNT = 0x00000200
    ADS_UF_INTERDOMAIN_TRUST_ACCOUNT = 0x00000800
    ADS_UF_WORKSTATION_TRUST_ACCOUNT = 0x00001000
    ADS_UF_SERVER_TRUST_ACCOUNT = 0x00002000
    ADS_UF_DONT_EXPIRE_PASSWD = 0x00010000
    ADS_UF_MNS_LOGON_ACCOUNT = 0x00020000
    ADS_UF_SMARTCARD_REQUIRED = 0x00040000
    ADS_UF_TRUSTED_FOR_DELEGATION = 0x00080000
    ADS_UF_NOT_DELEGATED = 0x00100000
    ADS_UF_USE_DES_KEY_ONLY = 0x00200000
    ADS_UF_DONT_REQUIRE_PREAUTH = 0x00400000
    ADS_UF_PASSWORD_EXPIRED = 0x00800000
    ADS_UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION = 0x01000000


class ADObjects(object):
    _GROUP_ATTRIBUTES = ['sAMAccountName', 'distinguishedName',
                         'member', 'memberOf']
    _USER_ATTRIBUTES = ['sAMAccountName', 'distinguishedName',
                        'displayName', 'employeeID', 'mail',
                        'description', 'userPrincipalName',
                        'pwdLastSet', 'userAccountControl',
                        'lockoutTime', 'memberOf']
    _LOCKOUT_TIME = datetime.timedelta(minutes=15)

    def __init__(self, server,
                 group_search=None,
                 user_search=None,
                 authenticate=False,
                 username=None,
                 ca_certs_file=None):

        tls_conf = Tls(
            ca_certs_file=ca_certs_file,
            validate=ssl.CERT_REQUIRED,
            version=ssl.PROTOCOL_TLSv1_2
        )

        self.server = Server(server, use_ssl=True, tls=tls_conf)
        self.authenticate = authenticate
        self.username = username
        self.user_prefix = 'BNL\\'
        self._group_search = group_search
        self._user_search = user_search

    def __enter__(self):
        if self.authenticate:
            _auth = False

            if self.username is None:
                # We have no username and GSSAPI, try
                # GSSAPI (Kerberos) first
                self.connection = Connection(self.server,
                                             authentication=SASL,
                                             sasl_mechanism=GSSAPI,
                                             auto_bind=False,
                                             raise_exceptions=True)
                try:
                    self.connection.bind()
                except LDAPAuthMethodNotSupportedResult:
                    _auth = False
                except LDAPPackageUnavailableError:
                    _auth = False
                else:
                    _auth = True

            if _auth is not True:
                # NTLM (Password Authentication)
                password = None
                if 'GRPMGR_PASSWD' in os.environ:
                    password = os.environ['GRPMGR_PASSWD']
                
                if password is None:
                    raise RuntimeError('Group Manager Service account password not found!')
                #if self.username is None:
                #    self.username = input("\nUsername : ")

                #password = getpass("Password : ")

                self.connection = Connection(
                    self.server, user=self.user_prefix + self.username,
                    password=password, authentication=NTLM,
                    auto_bind=True, raise_exceptions=True)
                try:
                    self.connection.bind()
                except LDAPInvalidCredentialsResult:
                    _auth = False
                else:
                    _auth = True

            if _auth:
                whoami = self.connection.extend.standard.who_am_i()
                print('\nAuthenticated as : {}'.format(str(whoami)))
            else:
                raise RuntimeError("Unable to autheticate to server. "
                                   " Please check credentials") from None
        else:
            # Anonymous connection to LDAP server
            self.connection = Connection(self.server,
                                         auto_bind=True,
                                         raise_exceptions=False)

        return self

    def __exit__(self, type, value, traceback):
        self.connection.unbind()

    def _get_group(self, search_filter):
        self.connection.search(
            search_base=self._group_search,
            search_scope=SUBTREE,
            attributes=self._GROUP_ATTRIBUTES,
            search_filter=search_filter
        )

        # Make a dict of returned values

        rtn = list()
        for entry in self.connection.entries:
            rtn.append({key: entry[key].value
                        for key in self._GROUP_ATTRIBUTES})

        return rtn

    def _calc_user_fields(self, entry):
        """Calculate fields based on LDAP properties"""
        out = dict()

        if 'pwdLastSet' in entry and 'userAccountControl' in entry:
            pwd_last_set = get_ad_time(entry.pwdLastSet.value)

            user_account_control = int(entry.userAccountControl.value)
            pwd_exp = bool(user_account_control &
                           ADUserAccountControl.ADS_UF_DONT_EXPIRE_PASSWD)

            if not pwd_exp and pwd_last_set == mdci:
                out['set_passwd'] = True
            else:
                out['set_passwd'] = False

        if 'lockoutTime' in entry:
            lockout_time = entry.lockoutTime.value
            if lockout_time is None:
                lockout_time = mdci
            else:
                lockout_time = get_ad_time(lockout_time)

            if lockout_time != mdci:
                now = datetime.datetime.now(datetime.timezone.utc)
                delta_t = now - lockout_time
                if delta_t <= self._LOCKOUT_TIME:
                    out['was_locked'] = False
                    out['locked'] = True
                    out['lock_time'] = self._LOCKOUT_TIME - delta_t
                else:
                    out['locked'] = False
                    out['was_locked'] = True
            else:
                out['locked'] = False
                out['was_locked'] = False

        return out

    def _get_user(self, search_filter):
        self.connection.search(
            search_base=self._user_search,
            search_scope=SUBTREE,
            attributes=self._USER_ATTRIBUTES,
            search_filter=search_filter
        )

        # Make a dict of returned values

        rtn = list()
        for entry in self.connection.entries:
            uf = self._calc_user_fields(entry)
            user = {key: entry[key].value
                    for key in self._USER_ATTRIBUTES}
            rtn.append({**user, **uf})

        return rtn

    def get_user_by_id(self, id):
        return self._get_user('(employeeID={})'.format(id))

    def get_user_by_samaccountname(self, id):
        return self._get_user('(sAMAccountName={})'.format(id))

    def get_user_by_dn(self, id):
        return self._get_user('(distinguishedname={})'.format(id))

    def get_user_by_surname_and_givenname(self,
                                          surname, givenname,
                                          user_type):
        if user_type is None:
            user_type = '*'
        if surname is None:
            surname = '*'
        if givenname is None:
            givenname = '*'

        filter = '(&(sn={})(givenName={})(description={}))'.format(
            surname, givenname, user_type)

        return self._get_user(filter)

    def get_user_by_surname_and_givenname_dict(
            self, surname, givenname, user_type):
        users = self.get_user_by_surname_and_givenname(
            surname, givenname, user_type
        )
        d = {u['userPrincipalName']: u for u in users}
        return d

    def get_group_by_samaccountname(self, id):
        return self._get_group('(sAMAccountName={})'.format(id))


    def get_group_members(self, group_name):
        group = self.get_group_by_samaccountname(group_name)
        if len(group) > 1:
            raise RuntimeError(f"Group name '{group_name}' is not unique. "
                               f"Found groups: {group}")
        elif len(group) == 0:
            raise RuntimeError(f"Group name '{group_name}' is empty.")

        group = group[0]

        ldap_filter = "(&(objectCategory=person)(objectClass=user)"
        ldap_filter += "(memberOf:1.2.840.113556.1.4.1941:="
        ldap_filter += "{}))".format(group['distinguishedName'])

        self.connection.search(
            search_base=self._group_search,
            search_scope=SUBTREE,
            attributes=self._USER_ATTRIBUTES,
            search_filter=ldap_filter
        )

        rtn = list()
        for entry in self.connection.entries:
            uf = self._calc_user_fields(entry)
            user = {key: entry[key].value
                    for key in self._USER_ATTRIBUTES}
            rtn.append({**user, **uf})

        return rtn


    def get_group_members_dict(self, groupname):
        members = self.get_group_members(groupname)
        d = {m['userPrincipalName']: m for m in members}
        return d

    def get_group_members_samacccounts(self, groupname):
        members = self.get_group_members(groupname)
        l = [m['sAMAccountName'] for m in members]
        return l

    def add_user_to_group_by_dn(self, group_name, username):
        ad_add_members_to_groups(self.connection, username, group_name,
                                 fix=True, raise_error=True)

    def remove_user_from_group_by_dn(self, group_name, username):
        ad_remove_members_from_groups(self.connection, username, group_name,
                                      fix=True, raise_error=True)
