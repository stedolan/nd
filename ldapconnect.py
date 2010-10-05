# ldapconnect.py
# Handles directly talking to the LDAP server
# including binding, authentication and so on

import pwd as mod_pwd, os, getpass
import ldap, ldapurl, ldap.sasl
from ldaplogging import *


uidfmt = "uid=%s,ou=User,dc=netsoc,dc=tcd,dc=ie"

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
    if dn is None:
	# if no DN is specified, we try ldapi first
	try:
	    l = ldap.initialize("ldapi:///")
	    l.sasl_interactive_bind_s("", ldap.sasl.external())
	except:
	    # then try the host called "ldap"
	    l = ldap.initialize("ldap://ldap")
	    uid = mod_pwd.getpwuid(os.getuid())[0]
	    passwd = getpass.getpass()
	    l.simple_bind_s(uidfmt % uid, passwd)
    else:
	if host is None: host = "127.0.0.1"
	l = ldap.initialize(str(ldapurl.LDAPUrl(host)))
	l.simple_bind_s(dn, pwd)
    _ldap_conn = l
    return l

def with_ldap_connection(f):
    def func(*args, **kwargs):
	global _ldap_conn
	if _ldap_conn is None:
	    ldap_connect()
	try:
	    return f(_ldap_conn, *args, **kwargs)
	except ldap.SERVER_DOWN:
	    ldap_connect()
	    return f(_ldap_conn, *args, **kwargs)
    func.__name__ = f.__name__
    func.__doc__ = f.__doc__
    return func



@with_ldap_connection
def search(l, base, scope, filter, attrlist=None):
    if filter is None:
        filter = "(objectClass=*)"
    ldebug("Searching in %s for %s" % (base,filter))
    return l.search_s(base, scope, filter, attrlist)

@with_ldap_connection
def add(l, dn, modlist):
    ldebug("Adding %s" % modlist)
    l.add_s(dn, modlist)

@with_ldap_connection
def delete(l, dn):
    l.delete_s(dn)

@with_ldap_connection
def modify(l, dn, modlist):
    ldebug("Modifying %s: %s" % (dn,modlist))
    l.modify_s(dn, modlist)

@with_ldap_connection
def modrdn(l, dn, newrdn):
    ldebug("Renaming %s" % dn)
    l.rename_s(dn, newrdn)

@with_ldap_connection
def passwd(l, dn, oldpw, newpw):
    ldebug("Changing password for %s" % dn)
    l.passwd_s(dn, oldpw, newpw)

@with_ldap_connection
def whoami(l):
    return l.whoami_s()
