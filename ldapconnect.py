# ldapconnect.py
# Handles directly talking to the LDAP server
# including binding, authentication and so on

import ldap, ldapurl, ldap.sasl
from logging import *


_ldap_conn = None



def ldap_connect(dn = None, pwd = None, host = None):
	#    '''Connects to LDAP. The connection is cached.
	#
	#    If uid is not None, it is taken as the user to connect as,
	#    otherwise it chooses the current user. If password is None, it
	#    will attempt to connect first without a password and if that fails
	#    it will try to read a password from the terminal
	#    '''
	#    global _ldap_conn
	#    if uid is None and pwd is None and _ldap_conn is not None:
	#        return _ldap_conn
	#    if uid is None:
	#        dn = ldap_myself()
	#    else:
	#        dn = ldap_byuid(uid)	

	#    l = _ldap_conn
	#    l.simple_bind_s(dn, pwd)
	#    return l
        global _ldap_conn
        if _ldap_conn is None:
                if dn is None:
                        _ldap_conn = ldap.initialize("ldapi:///")
                        _ldap_conn.sasl_interactive_bind_s("", ldap.sasl.external())
                else:
                        if host is None: host = "127.0.0.1"
                        _ldap_conn = ldap.initialize(str(ldapurl.LDAPUrl(host)))
                        _ldap_conn.simple_bind_s(dn, pwd)
        return _ldap_conn
    


def search(base, scope, filter, attrlist=None):
    if filter is None:
        filter = "(objectClass=*)"
    ldebug("Searching in %s for %s" % (base,filter))
    l = ldap_connect()
    return l.search_s(base, scope, filter, attrlist)

def add(dn, modlist):
    l = ldap_connect()
    l.add_s(dn, modlist)

def delete(dn):
    l = ldap_connect()
    l.delete_s(dn)

def modify(dn, modlist):
    ldebug("Modifying %s" % dn)
    l = ldap_connect()
    l.modify_s(dn, modlist)

def modrdn(dn, newrdn):
    ldebug("Renaming %s" % dn)
    l = ldap_connect()
    l.rename_s(dn, newrdn)

def passwd(dn, oldpw, newpw):
    ldebug("Changing password for %s" % dn)
    l = ldap_connect()
    l.passwd_s(dn, oldpw, newpw)
