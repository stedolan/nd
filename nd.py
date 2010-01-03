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
    def can_bind(self):
        return self.get_attribute("userPassword") is not None

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


    def get_full_name(self):
        gecos = self.get_attribute("gecos")
        if gecos is None: return None
        if "," in gecos: return gecos.split(",")[0]
        return gecos

    def has_account(self):
        return 'posixAccount' in self.objectClass and self.can_bind()


    def destroy(self):
        if self.has_account() and os.access(self.homeDirectory, os.F_OK):
            raise Exception("Cannot destroy user %s since home directory still exists" % self)
        NDObject.destroy(self)

    def get_personal_group(self):
        if self.has_account():
            return PersonalGroup(self.uid)
        else:
            return None

    def passwd(self, old, new):
        self._raw_passwd(old, new)

    def has_priv(self, name):
        return self in Privilege(name)
    
    @staticmethod
    def with_priv(self, name):
        return Privilege(name).member

    def info(self):
        name = self.cn
        isCurrentMember = current_session() in self.tcdnetsoc_membership_year
        hasShellAcct = 'posixAccount' in self.objectClass
        canBind = self.can_bind()
        groups = list(self.memberOf)
        membershipYears = self.tcdnetsoc_membership_year
        username = self.uid
        def has(priv):
            if self.has_priv(priv):
                return priv
            else:
                return "no " + priv
        info = "User #%s: %s (%s), %s\n" % (self.uidNumber, username, name, "current member" if isCurrentMember else "not current member")
        if canBind:
            if hasShellAcct:
                info += "has shell account, "+has('webspace')+", "+has('filestorage')+"\n"
                info += "in groups: " + ", ".join(g.cn for g in self.memberOf) + "\n"
            else:
                info += "no shell account\n"
        else:
            info += "Disabled account\n"
        info += "Member of netsoc in " + ", ".join(self.tcdnetsoc_membership_year) + "\n"
        return info

    def __repr__(self):
        return "<User %s (%s)>" % (self.uid, self.cn)


    @staticmethod
    def myself():
        return User(pwd.getpwuid(posix.getuid())[0])



    disabled_shells = ['renew','bold','expired','dead']
    disabled_shells_base = "/usr/local/special_shells/"
    first_login_shell = "/usr/local/special_shells/accept_AUP"
    homedir_pattern = "/home/%s"
    default_login_shell = "/bin/bash"
    states = ['active','disabled','renew','bold','expired','dead']

    def _has_disabled_shell(self):
        sh = self.get_attribute("loginShell")
        return sh is not None and sh != User.first_login_shell and sh.startswith(User.disabled_shells_base)

    def get_state(self):
        if self.has_account():
            disabled_shell = self._has_disabled_shell()
            if self.has_priv("shell"):
                if disabled_shell:
                    lerr(repr(self) + " is active, but has shell " + self.loginShell)
                return "active"
            else:
                if not disabled_shell:
                    lerr(repr(self) + " is disabled, but has shell " + self.loginShell)
                    return "bold" # abitrary default, this shouldn't happen
                else:
                    return sh[len(User.disabled_shells_base):]
        else:
            return "disabled"

    def set_state(self, newst):
        assert newst in User.states
        st = self.get_state()
        if st == newst:
            return
        if newst == "disabled":
            self.objectClass -= "posixAccount"
            # FIXME: remove other privileges as well??
            if self.has_priv("shell"):
                Privilege("shell").member -= self
            del self.userPassword
            return

        if st == "disabled":
            if self._has_disabled_shell():
                prevstate = self.loginShell[len(User.disabled_shells_base):]
                if newst != prevstate:
                    raise Exception("Trying to change state of %s from disabled to %s, although account was %s" % (self, newst, prevstate))
                
            assert not self.has_priv("shell")
            if not PersonalGroup(self.uid).exists():
                PersonalGroup.create(cn=self.uid,
                                     objectClass=["tcdnetsoc-group"],
                                     gidNumber=self.uidNumber,
                                     member=[self])
            self.gidNumber = self.uidNumber
            self.homeDirectory = User.homedir_pattern % self.uid
            self.objectClass += "posixAccount"
            Privilege("shell").member += self

        sh = self.get_attribute("loginShell")
        if newst == "active":
            if sh is None:
                newsh = User.first_login_shell
            else:
                newsh = User.default_login_shell
        else:
            newsh = User.disabled_shells_base + newst

        self.loginShell = newsh

    def get_correct_state(self):
        # Does this person automatically get a shell?
        noexpire = self.has_priv("noexpire")

        # Can this person sign up even if they've left college?
        alwaysrenewable = self.has_priv("alwaysrenewable")

        # Is this person a current TCD student/staff member?
        current_tcd = True # FIXME

        # Has this person paid the membership fee this year?
        current_member = current_session() in self.tcdnetsoc_membership_year

        entitled_to_renew = noexpire or alwaysrenewable or current_tcd
        entitled_to_shell = noexpire or (current_member and current_tcd)
        
        st = self.get_state()
        if st in ["active", "renew", "expired"]:
            if entitled_to_shell:
                s = "active"
            else:
                if entitled_to_renew:
                    s = "renew"
                else:
                    s = "expired"
        elif st == "disabled":
            if not self._has_disabled_shell():
                s = "active"
            else:
                s = "disabled"
        elif st == "bold":
            s = "bold"
        elif st == "dead":
            s = "dead"
        return s

    def check(self):
        assert 'tcdnetsoc-person' in self.objectClass
        st = self.get_state()
        if st == "disabled":
            assert not self.has_account()
            assert not self.has_priv("shell")
            assert self.get_attribute('userPassword') is None
        else:
            assert self.has_account()
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
        assert user.exists()
        assert user.gidNumber == self.gidNumber
        assert len(self.member) == 1
        assert user in self

class Privilege(Group):
    '''Groups controlling access to specific services, for instance webspace or
    filestorage'''
    rdn_attr = 'cn'
    def check(self):
        assert 'tcdnetsoc-privilege' in self.objectClass


class Service(NDObject):
    rdn_attr = 'cn'
    def get_password(self):
        return self.get_attribute("userPassword")
    

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
Attribute('tcdnetsoc_ISS_username', str)
Attribute('loginShell', str)
Attribute('sn', str)
Attribute('uid', str, match_exact)
Attribute('uidNumber', int)
Attribute('gidNumber', int)
Attribute('homeDirectory', str)
Attribute('cn', str)
Attribute('userPassword', str)
Attribute('mail', str)
Attribute('tcdnetsoc_admin_comment', [str])
Attribute('member', [User])
Attribute('memberOf', [Group], backlink='member')
Attribute('tcdnetsoc_service_granted', [Service])
Attribute('tcdnetsoc_granted_by_privilege', [Privilege], backlink='tcdnetsoc_service_granted')

