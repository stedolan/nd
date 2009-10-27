# to be renamed...

from ldapobject import *
import pwd, grp, posix, os, stat, time
import re

def current_session():
    '''Current session of Netsoc, e.g. "2008-2009"

    The next session starts at the beginning of August, to give us a
    month or two to fix things. FIXME: should it?
    '''
    year, month = time.gmtime()[0:2]
    if month >= 8:
        year += 1
    return "%4d-%4d" % (year-1, year)


def read_small_file(file):
    '''Read a small file (e.g. ~/.plan), carefully'''
    try:
        f = open(file, "r")
        # make sure it's actually a file, not a pipe or somesuch
        st = os.fstat(f.fileno())
        if stat.S_ISREG(st[stat.ST_MODE]):
            # fixed upper limit in case someone creates a huge ~/.plan
            return f.read(1024)
        else:
            return None
    except:
        # if it doesn't exist, or it's somewhere invalid, etc., then
        # don't let the exception propagate
        return None


class NDObject(LDAPObject):
    base_dn='dc=netsoc,dc=tcd,dc=ie'

class User(NDObject):
    '''A member of Netsoc, past or present. Every member corresponds to a User, even the ones
    without active shell accounts. If a shell account exists for a user (even if it is disabled)
    user.has_account() will return True. For those users who have an account, their gidNumber
    refers to their PersonalGroup (see below)'''
    rdn_attr = 'uid'

    valid_username = re.compile("^[a-z_][a-z0-9_-]*$")
    root_DN = "cn=root,dc=netsoc,dc=tcd,dc=ie"

    def __init__(self, uid=None, obj_dn=None):
        if uid == "root":
            NDObject.__init__(self, obj_dn = root_DN)
        else:
            NDObject.__init__(self, uid, obj_dn = obj_dn)

    @property
    def project(self):
        """Read a user's ~/.project file"""
        return read_small_file(self.homeDirectory + "/.project")
    @property
    def plan(self):
        """Read a user's ~/.plan file"""
        return read_small_file(self.homeDirectory + "/.plan")

    def has_account(self):
        return 'posixAccount' in self.objectClass

    def destroy(self):
        if self.has_account() and os.access(self.homeDirectory, os.F_OK):
            raise Exception("Cannot destroy user %s since home directory still exists" % self)
        NDObject.destroy(self)

    def get_personal_group(self):
        if self.has_account():
            return PersonalGroup(self.uid)
        else:
            return None

    def info(self):
        name = self.cn
        isCurrentMember = current_session() in self.tcdnetsoc_membership_year
        hasShellAcct = 'posixAccount' in self.objectClass
        groups = list(self.memberOf)
        membershipYears = self.tcdnetsoc_membership_year
        username = self.uid
        def has(priv):
            if self in Group(priv):
                return priv
            else:
                return "no " + priv
        info = "User #%s: %s (%s), %s\n" % (self.uidNumber, username, name, "current member" if isCurrentMember else "not current member")
        if hasShellAcct:
            info += "has shell account, "+has('webspace')+", "+has('filestorage')+"\n"
            info += "in groups: " + ", ".join(g.cn for g in self.memberOf) + "\n"
        else:
            info += "no shell account\n"
        info += "Member of netsoc in " + ", ".join(self.tcdnetsoc_membership_year) + "\n"
        return info

    def __repr__(self):
        return "<User %s (%s)>" % (self.uid, self.cn)


    @staticmethod
    def myself():
        return User(pwd.getpwuid(posix.getuid())[0])

    def check(self):
        assert 'tcdnetsoc-person' in self.objectClass
        if self.has_account():
            assert self.gidNumber == self.uidNumber
            assert 'posixAccount' in self.objectClass
            assert self.get_personal_group() is not None

class Group(NDObject):
    '''A group of users. Groups may contain any number of users, including zero'''
    rdn_attr = 'cn'

    # Allow "user in group" and "for user in group" as shorthands for
    # "user in group.member" and "for user in group.member"
    def __contains__(self, obj):
        return obj in self.member
    def __iter__(self):
        return iter(self.member)

class PersonalGroup(Group):
    '''A PersonalGroup is a group with the same name as a user having only that user
    as a member. Its GID is the UID of the user and its name is the username of the user'''
    rdn_attr = 'cn'
        
    def get_user(self):
        return User(self.cn)

         
    def check(self):
        assert 'tcdnetsoc-group' in self.objectClass
        user = self.get_user()
        assert user.gidNumber == self.gidNumber
        assert len(self.member) == 1
        assert user in self



class IDNumber(NDObject):
    """Allocator for new ID numbers such as UID and GID.
    The next ID is stored in the allocator object, and when a new one is requested
    the field is atomically incremented and the old value is returned"""
    rdn_attr = 'cn'
    def _setnum(self, old, new):
        # Minor hack: we use _raw_modattrs to ensure atomicity
        # Without it, there's a race condition
        self._raw_modattrs([
            (ldap.MOD_DELETE, 'serialNumber', str(old)),
            (ldap.MOD_ADD, 'serialNumber', str(new))])
        
    def alloc(self):
        # try to atomically allocate a new number (UID, GID, etc)
        # attempt it 3 times in case it fails because someone else
        # is also allocating numbers
        for attempt in range(3):
            currid = self.serialNumber
            try:
                self._setnum(currid, currid+1)
            except ldap.NO_SUCH_ATTRIBUTE, e:
                time.sleep(random.random() * 0.1)
                continue
            return currid
        raise e

    def check(self):
        assert 'tcdnetsoc-idnum' in self.objectClass


UIDAllocator = IDNumber('next-uid')
GIDAllocator = IDNumber('next-gid')


Attribute('objectClass', [str])
Attribute('serialNumber', int)
Attribute('tcdnetsoc_membership_year', [str])
Attribute('uid', str, match_exact)
Attribute('uidNumber', int)
Attribute('gidNumber', int)
Attribute('homeDirectory', str)
Attribute('cn', str)
Attribute('member', [User])
Attribute('memberOf', [Group], backlink='member')


