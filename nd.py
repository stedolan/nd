import time
import posix
import re
import pwd
import grp
import getpass
import ldap
import ldapurl
import random
import time

valid_username = re.compile("^[a-z_][a-z0-9_-]*$")
root_DN = "cn=root,dc=netsoc,dc=tcd,dc=ie"


def current_session():
    '''Current session of Netsoc, e.g. "2008-2009"

    The next session starts at the beginning of August, to give us a
    month or two to fix things. FIXME: should it?
    '''
    year, month = time.gmtime()[0:2]
    if month >= 8:
        year += 1
    return "%4d-%4d" % (year-1, year)


def ldap_myself():
    '''Returns the LDAP DN of the current user'''
    return ldap_byuid(posix.getuid())


def ldap_byuid(uid):
    '''Returns the LDAP DN of the given user.

    e.g. for user mu, returns uid=mu,ou=users,dc=netsoc,dc=tcd,dc=ie
    Just because this function returns a DN does not mean that DN exists.
    Can take a DN, a username, or a numeric UID as an argument.
    '''
    if isinstance(uid,str) and uid.endswith("dc=netsoc,dc=tcd,dc=ie"):
        #already a DN
        return uid
    # This uses getpwuid to do a UID->name lookup, rather than LDAP
    # This is because we mightn't have a LDAP connection at this point
    # because to connect to LDAP you need to know your DN
    try:
        uid = int(uid)
        if uid < 0:
            raise ValueError("Invalid UID")
        try:
            uid = pwd.getpwuid(uid)[0]
        except KeyError:
            pass
        uid = str(uid)
    except ValueError:
        uid = str(uid).strip()
        if not valid_username.match(uid):
            raise ValueError("Invalid UID")

    if uid == 0 or uid == "root":
        return root_DN
    else:
        return "uid=%s,ou=users,dc=netsoc,dc=tcd,dc=ie" % uid

def _ldap_get_num(dn):
    l = ldap_connect()
    return int(l.search_s(dn, ldap.SCOPE_BASE, attrlist=['serialNumber'])[0][1]['serialNumber'][0])

def _ldap_set_num(dn, old, new):
    l = ldap_connect()
    l.modify_s(dn, [
        (ldap.MOD_DELETE, 'serialNumber', str(old)),
        (ldap.MOD_ADD, 'serialNumber', str(new))])

def _ldap_alloc_inc(dn, inc):
    for attempt in range(3):
        currid = _ldap_get_num(dn)
        try:
            _ldap_set_num(dn, currid, currid+inc)
        except ldap.NO_SUCH_ATTRIBUTE, e:
            time.sleep(random.random() * 0.1)
            continue
        return currid
    raise e


def ldap_alloc_uid():
    return _ldap_alloc_inc('cn=next-uid,dc=netsoc,dc=tcd,dc=ie', +1)
def ldap_alloc_gid():
   return _ldap_alloc_inc('cn=next-gid,dc=netsoc,dc=tcd,dc=ie', -1)

def ldap_bygid(gid):
    '''Returns the LDAP DN of the given group.

    e.g. for group webteam, this returns cn=webteam,ou=groups,dc=netsoc,dc=tcd,dc=ie.
    Can take a DN, a group name, or a numeric GID. Returns a (possibly non-existant) DN.'''
    if isinstance(gid, str) and gid.endswith("dc=netsoc,dc=tcd,dc=ie"):
        return gid
    try:
        gid = int(gid)
        try:
            gid = grp.getgrgid(gid)[0]
        except KeyError:
            pass
        gid = str(gid)
    except ValueError:
        gid = str(gid).strip()
        if not valid_username.match(gid):
            raise ValueError("Invalid GID")
    return "cn=%s,ou=groups,dc=netsoc,dc=tcd,dc=ie" % gid

_ldap_conn = None

def ldap_connect(uid = None, pwd = None):
    '''Connects to LDAP. The connection is cached.

    If uid is not None, it is taken as the user to connect as,
    otherwise it chooses the current user. If password is None, it
    will attempt to connect first without a password and if that fails
    it will try to read a password from the terminal
    '''
    global _ldap_conn
    if uid is None and pwd is None and _ldap_conn is not None:
        return _ldap_conn
    if uid is None:
        dn = ldap_myself()
    else:
        dn = ldap_byuid(uid)
    _ldap_conn = ldap.initialize(str(ldapurl.LDAPUrl(hostport="127.0.0.1")))
    l = _ldap_conn
    l.simple_bind_s(dn, pwd)
    return l


class LDAPObject(object):
    base_dn = 'dc=netsoc,dc=tcd,dc=ie'
    def __init__(self, dn, attrs_desired=None, **searchq):
        self.dn = dn
        self.attrs = None
        self.attrs_desired = attrs_desired
        self.searchq = None

    def _ensure_attrs(self):
        if self.attrs is None:
            l = ldap_connect()
            self.attrs = l.search_s(self.dn, ldap.SCOPE_BASE, attrlist=self.attrs_desired)[0][1]
    def __iter__(self):
        self._ensure_attrs()
        if self.attrs_desired:
            return iter(self.attrs_desired)
        else:
            return iter(self.attrs)
    def __getattr__(self, name):
        self._ensure_attrs()
        if name in self.attrs and len(self.attrs[name]) == 1:
            return self.attrs[name]
        else:
            raise KeyError("No or multiple values for %s" % name)
    def get_all(self, name):
        self._ensure_attrs()
        return self.attrs.get(name) or []
    def set(self, name, val):
        self._ensure_attrs()
        l = ldap_connect()
        if l.modify_s(self.dn, [(ldap.MOD_REPLACE, name, val)])[0] != ldap.RES_MODIFY:
            raise Exception("Couldn't modify value")
    def __getitem__(self, name):
        self._ensure_attrs()
        return self.attrs.get(name)

    @classmethod
    def create(cls, dn, **kw):
        l = ldap_connect()
        modlist = []
        for attr in kw:
            val = kw[attr]
            if type(val) != list: val=[val]
            for v in val:
                modlist.append((attr, str(v)))
        print modlist
        l.add_s(dn, modlist)

    def __repr__(self):
        return '<' + type(self).__name__ + " " + self.dn + '>'

    @classmethod
    def cust_search(cls, **searchq):
        l = ldap_connect()
        msgid = l.search(base=cls.base_dn, scope=ldap.SCOPE_SUBTREE, **searchq)
        while 1:
            (code, results) = l.result(msgid, 0)
            for (dn,attrs) in results:
                u = cls(dn)
                u.attrs = attrs
                yield u
            if code == ldap.RES_SEARCH_RESULT:
                break

    @classmethod
    def by_attrs(cls, **attrs):
        return cls.cust_search(filterstr='(&' +
            "".join('(' + k.replace("_","-") + '=*' + v + '*)' for k,v in attrs.items()) + ')')
    @classmethod
    def all_objs(cls, **attrs):
        return cls.by_attrs()


class User(LDAPObject):
    base_dn = 'ou=users,dc=netsoc,dc=tcd,dc=ie'
    def __init__(self, uid, **kw):
        LDAPObject.__init__(self, ldap_byuid(uid), **kw)
    @classmethod
    def everyone(cls):
        return cls.all_objs()
    @classmethod
    def all_members(cls):
        return cls.by_attrs(tcdnetsoc_membership_year=current_session())
    @classmethod
    def with_account(cls):
        return cls.cust_search(filterstr='(&(objectClass=tcdnetsoc-person)(objectClass=posixAccount))')
    @classmethod
    def without_account(cls):
        return cls.cust_search(filterstr='(!(objectClass=posixAccount))')
    @classmethod
    def create(cls, dn, **kw):
        if 'uid' not in kw:
            kw['uid'] = dn
        if 'objectClass' not in kw:
            kw['objectClass'] = []
        if 'tcdnetsoc-person' not in kw['objectClass']:
            kw['objectClass'].append('tcdnetsoc-person')

        LDAPObject.create(ldap_byuid(dn), **kw)

class Group(LDAPObject):
    base_dn = 'ou=groups,dc=netsoc,dc=tcd,dc=ie'
    def __init__(self, gid, **kw):
        LDAPObject.__init__(self, ldap_bygid(gid), **kw)
    def members(self):
        l = ldap_connect()
        memberlist = l.search_s(base=self.dn, scope=ldap.SCOPE_BASE, attrlist=['member'])[0][1]['member']
        for u in memberlist:
            yield User(u)
    @classmethod
    def posix_groups(cls):
        return cls.by_attrs(objectClass='posixGroup')
    @classmethod
    def create(cls, dn, **kw):
        if 'cn' not in kw:
            kw['cn'] = dn
        if 'objectClass' not in kw:
            kw['objectClass'] = []
        if 'tcdnetsoc-group' not in kw['objectClass']:
            kw['objectClass'].append('tcdnetsoc-group')
        LDAPObject.create(ldap_bygid(dn), **kw)

    
class Service(Group):
    base_dn = 'ou=services,ou=groups,dc=netsoc,dc=tcd,dc=ie'

class SourceProject(Group):
    base_dn = 'ou=sourceprojects,ou=groups,dc=netsoc,dc=tcd,dc=ie'
    
class UserGroup(Group):
    base_dn = 'ou=usergroups,ou=groups,dc=netsoc,dc=tcd,dc=ie'


class Host(LDAPObject):
    base_dn = 'ou=hosts,dc=netsoc,dc=tcd,dc=ie'
    
