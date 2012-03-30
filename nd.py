# to be renamed...

from ldapobject import *
import pwd, grp, posix, os, stat, time
import re
from sendmail import *

try:
    import accountrequests
    can_request_accounts = True
except Exception:
    can_request_accounts = False

def current_session():
    '''Current session of Netsoc, e.g. "2008-2009"

    The next session starts at the beginning of August, to give us a
    month or two to fix things. FIXME: should it?
    '''
#    year, month = time.gmtime()[0:2]
#    if month >= 10:
#        year += 1
#    return "%4d-%4d" % (year-1, year)
    return Setting("current_session").tcdnetsoc_value.first()


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

def _get_samba_domain_sid():
    return LDAPObject(obj_dn='sambaDomainName=NETSOC,dc=netsoc,dc=tcd,dc=ie').sambaSID

def generate_password():
    '''Generate a random password via pwgen'''
    import subprocess
    stdout, stderr = subprocess.Popen(["pwgen", "-nc"],stdout=subprocess.PIPE).communicate()
    return stdout.strip()



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
    default_objectclass = ['tcdnetsoc-person']
    default_search_attrs = ['cn','uid']

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

    def is_current_member(self):
        return current_session() in self.tcdnetsoc_membership_year

    def gen_samba_sid(self):
        assert self.has_account()
        return "%s-%s" % (_get_samba_domain_sid(), self.uidNumber * 2 + 1000)

    @staticmethod
    def bad_usernames():
        return Setting('bad_usernames').tcdnetsoc_value

    @staticmethod
    def username_is_valid(name):
        '''Test whether a potential username is valid. If the username
        is already taken, this function will return True.

        Valid usernames must match the valid_username_regex setting
        (i.e. be short and of sensible characters), and must not 
        be one of the bad_usernames (e.g. root)'''
        regex = Setting("valid_username_regex").tcdnetsoc_value.first()
        return \
            re.match("^" + regex + "$", name) is not None \
            and \
            name not in User.bad_usernames()
            
        
    @staticmethod
    def forbid_username(name):
        '''Prevent new members from signing up with the given username'''

        if User(name).exists():
       	    raise Exception('username "%s" is already taken' % name)

        User.bad_usernames().add(name)
    
    @staticmethod
    def unforbid_username(name):
        if name in User.bad_usernames():
            User.bad_usernames().remove(name)


    def destroy(self):
        # also destroy group
        g = self.get_personal_group()
        if g and g.exists():
            self.get_personal_group().destroy()
        NDObject.destroy(self)

    def reset_mysql_pw(self, pw=None):
        '''Change the MySQL password for a user. When the password is changed,
        the database is automatically created'''
        if pw is None:
            pw = self.get_attribute('tcdnetsoc_mysql_pw')
        if pw is None:
            pw = generate_password()
        # when this field changes, the update_ldap_mysql script will notice
        # and update mysql accordingly
        self.tcdnetsoc_mysql_pw = pw

    def get_personal_group(self):
        return PersonalGroup(self.uid)

    def mark_member(self):
        if not self.is_current_member():
            self.tcdnetsoc_membership_year += current_session()

    def sendmail(self, msg, **kw):
        ''' Email the given message to this User '''
        sendmail(msg, {"To": '"%s" <%s>' % (self.cn, self.mail)}, **kw)

    def send_new_account_email(self):
        '''Sends either the "You've Renewed, Netsoc Still Works" email, or the
        "Please Finish Signing Up and Get And Account" email.

        Requires that the user is a current member, see mark_member.

        Users who already have shell accounts are assumed to be renewing'''
        assert self.is_current_member()
        assert can_request_accounts
        
        st = self.get_state()
        assert st in ["newmember","shell"]
        if st == "newmember":
            # create a url and send it to them
            url = accountrequests.make_signup_url(self)
            print "Sending account_creation email for %r to %s" % (self,self.mail)
            sendmail("account_creation", to=self.mail, url=url)
        else:
            # just send an email
            print "Sending account_renewed email for %r to %s" % (self,self.mail)
            sendmail("account_renewed", to=self.mail, username=self.uid)

    def comment(self, msg):
        self.tcdnetsoc_admin_comment += '%s: %s' % (time.asctime(), msg)

    def merge_into(self, other):
        assert self.get_state() == 'newmember'
        assert other.get_state() in ['shell','renew','bold','expired','dead']
        assert self.is_current_member()
        assert not other.is_current_member()
        issusername = self.get_attribute("tcdnetsoc_ISS_username") or other.get_attribute("tcdnetsoc_ISS_username")
        if other.get_attribute("tcdnetsoc_ISS_username") is not None:
            assert other.tcdnetsoc_ISS_username == issusername
        else:
            other.tcdnetsoc_ISS_username = issusername
        if self.cn != other.cn:
            lwarn("Names %s and %s don't match when renewing account %s" % (self.cn, other.cn, other.uid))
            other.comment("Renewed by account with non-matching name %s" % self.cn)
        if self.mail != other.mail:
            lwarn("Emails %s and %s don't match when renewing account %s"% (self.mail, other.mail, other.uid))
            other.comment("Renewed by account with non-matching mail %s" % self.mail)
        
        self.tcdnetsoc_membership_year -= current_session()
        other.tcdnetsoc_membership_year += current_session()
        self.destroy()

    def passwd(self, new, old=None):
        '''Change the password of a user from "old" to "new". If the old password
        is not known, "old" can be omitted but changing the password then requires
        admin permissions.
        
        See also generate_password.'''

        # We need to do a Password Modify Extended Operation to get Samba passswords
        # to update properly and to get secure hashing of the password. This requires
        # the old password. So, if we don't have it, we temporarily reset the password
        # via directly mungling userPassword, and then to a proper modify exop.
        if old is None:
            self.userPassword = new
            self._raw_passwd(new, new)
        else:
            self._raw_passwd(new, old)

    def reset_password(self):
        if not self.has_account():
            raise Exception("User account is disabled, password cannot be reset")
        pw = generate_password()
        self.passwd(pw)
        addr = self.get_attribute("mail")
        if addr is None:
            lwarn("No mail address recorded for user %s (%s), can't send password reset message" % 
                  (self.get_attribute("uid"), self.get_attribute("cn")))
        else:
            sendmail("password_reset", to=addr, username=self.uid, password=pw)

    def has_access(self, service):
        return service.has_access(self)

    def has_priv(self, name):
        return self in Privilege(name)
    
    def grant_priv(self, name):
        self.memberOf += Privilege(name)

    def revoke_priv(self, name):
        self.memberOf -= Privilege(name)

    def on_council(self):
        return self in Group('council')
    
    @staticmethod
    def with_priv(name):
        '''Return all Users holding the given Privilege'''
        return Privilege(name).member

    def info(self):
        name = self.cn
        isCurrentMember = self.is_current_member()
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
                info += "has shell account, "+has('webspace')+"\n"
                info += "in groups: " + ", ".join(g.cn for g in self.memberOf) + "\n"
            else:
                info += "no shell account\n"
        else:
            info += "Disabled account\n"
        info += "Member of netsoc in " + ", ".join(self.tcdnetsoc_membership_year) + "\n"
        return info

    def __repr__(self):
        if self.exists():
            return "<User %s (%s)>" % (self.uid, self.cn)
        else:
            return "<no such user>"


    @staticmethod
    def myself():
        return User(pwd.getpwuid(posix.getuid())[0])



    first_login_shell = "/usr/local/special_shells/accept_AUP"
    homedir_pattern = "/home/%s"
    default_login_shell = "/bin/bash"

    # These are the states for users with accounts
    # In theory, there is also a state "archived", when the posixAccount objectclass is removed from the
    # user and their home directories are archived
    states = ['shell','renew','bold','expired','dead','archived','newmember']

    def get_state(self):
        if self.has_account():
            for state in User.states:
                if state != "archived" and self in Privilege(state):
                    return state
            assert 0 # should be impossible to get here
        else:
            if self.get_attribute("tcdnetsoc_saved_password") == "***newmember***":
                return "newmember"
            else:
                return "archived"


    def set_state(self, newst, newpasswd = None):
        assert newst in User.states
        st = self.get_state()
        if st == newst:
            return
        if st == "newmember" and newst not in ["archived","shell","newmember"]:
            raise Exception("User doesn't have an account, so it can't be set to %s" % newst)

        if (st, newst) == ("archived","newmember"):
            self.tcdnetsoc_saved_password = "***newmember***"
        elif newst == "newmember":
            raise Exception("that makes no sense")
        elif newst == "archived":
#            self.objectClass -= "posixAccount"
#            # FIXME: remove other privileges as well??
#            if self.has_priv("shell"):
#                Privilege("shell").member -= self
#            del self.userPassword
#            return
            raise Exception("archiving accounts not yet implemented")

        elif st == "archived":
            raise Exception("un-archiving accounts not yet implemented")
#            if self._has_disabled_shell():
#                prevstate = self.loginShell[len(User.disabled_shells_base):]
#                if newst != prevstate:
#                    raise Exception("Trying to change state of %s from disabled to %s, although account was %s" % (self, newst, prevstate))
#                
#            assert not self.has_priv("shell")
#            if not PersonalGroup(self.uid).exists():
#                PersonalGroup.create(cn=self.uid,
#                                     objectClass=["tcdnetsoc-group"],
#                                     gidNumber=self.uidNumber,
#                                     member=[self])
#            self.gidNumber = self.uidNumber
#            self.homeDirectory = User.homedir_pattern % self.uid
#            self.objectClass += "posixAccount"
#            Privilege("shell").member += self
        else:
            if st == "newmember":
                del self.tcdnetsoc_saved_password
            else:
                Privilege(st).member -= self
            Privilege(newst).member += self
            if newst == "shell":
                # ensure GID is set
                if self.get_attribute('gidNumber') == None:
                    self.gidNumber = self.uidNumber
                
                # ensure homedir is set
                if self.get_attribute('homeDirectory') is None:
                    self.homeDirectory = '/home/' + self.uid

                # ensure group exists
                self.create_personal_group()

                self.objectClass += 'posixAccount'

                # (re-)enable Samba
                if st == 'newmember':
                    self.setup_samba_account()
                else:
                    self.objectClass += 'sambaSamAccount'

                # restore old password (if any)
                if newpasswd is not None:
                    self.passwd(newpasswd)
                elif self.get_attribute("tcdnetsoc_saved_password") is not None:
                    self.userPassword = self.tcdnetsoc_saved_password
                else:
                    pwd = generate_password()
                    lwarn("Setting password for %s to %s" % ( self.uid, pwd))
                    self.passwd(pwd)

                # set shell if necessary
                if self.get_attribute("loginShell") is None or "special_shell" in self.loginShell or \
                        st in ["bold","dead"]: # get AUP-violating users to re-accept AUP
                    self.loginShell = User.first_login_shell

                # expired and newmember users get webspace
                # renew users didn't lose it
                # and bold/dead users don't get it without admin intervention
                if st in ["expired", "newmember"]:
                    self.memberOf += Privilege("webspace")

                self.reset_mysql_pw()
                
                # FIXME quotas
            else:
                # can't be a new member if the account is being set to [rewew,expired,bold,dead]
                # since you need to have had an account for those things to happen
                assert st != "newmember"
                # removing shell, save old password
                if self.can_bind():
                    self.tcdnetsoc_saved_password = self.userPassword
                    del self.userPassword

                # possibly remove privileges
                if newst in ["bold","dead"]:
                    for g in list(self.memberOf):
                        if isinstance(g, Privilege) and g.cn != newst:
                            self.memberOf -= g
                
                # remove samba access
                if 'sambaSamAccount' in self.objectClass:
                    self.objectClass -= 'sambaSamAccount'

    def get_correct_state(self):
        # Does this person automatically get a shell?
        noexpire = self.has_priv("noexpire")

        # Can this person sign up even if they've left college?
        alwaysrenewable = self.has_priv("alwaysrenewable")

        # Is this person a current TCD student/staff member?
        current_tcd = True # FIXME

        # Has this person paid the membership fee this year?
        current_member = self.is_current_member()

        entitled_to_renew = noexpire or alwaysrenewable or current_tcd
        entitled_to_shell = noexpire or (current_member and current_tcd)
        
        st = self.get_state()
        if st in ["shell", "renew", "expired"]:
            if entitled_to_shell:
                s = "shell"
            else:
                if entitled_to_renew:
                    s = "renew"
                else:
                    s = "expired"
        elif st == "newmember":
            # new members' accounts stay as they are until they set up a real account
            s = "newmember"
        elif st == "archived":
            # archived accounts stay archived
            s = "archived"
        elif st == "bold":
            # bold accounts only get re-enabled with admin intervention
            s = "bold"
        elif st == "dead":
            # dead accounts only get re-enabled (or more likely, archived) with admin intervention
            s = "dead"
        return s

    def check(self):
        assert 'tcdnetsoc-person' in self.objectClass

        stategroups = [Privilege(x) for x in User.states if x not in ["archived","newmember"]]
        currentstategroups = [g for g in stategroups if self in g]

        st = self.get_state()
        if st in ["archived","newmember"]:
            assert not self.has_account()
            assert not self.can_bind()
            assert len(currentstategroups) == 0
        else:
            assert self.has_account()
            if st == "shell":
                assert self.can_bind()
                assert 'sambaSamAccount' in self.objectClass
            assert len(currentstategroups) == 1 and currentstategroups[0].cn == st

            assert self.gidNumber == self.uidNumber
            assert self.get_personal_group().exists()


            assert self.sambaSID == self.gen_samba_sid()
            assert self.get_personal_group().sambaSID == self.sambaPrimaryGroupSID

    @classmethod
    def create(cls, **attrs):
        '''Create a new user. Users are always created in the "active" state, i.e.
        they have a shell, webspace, etc. Requires that a username (uid), full name
        (cn) and email address (mail) be chosen, all other attributes will be given
        correct defaults.

        If a password is not specified (userPassword), a random one will be 
        generated.

        If a uidNumber is not specified, a new one will be allocated. If a gidNumber
        is specified, it must match the uidNumber and it will be taken to mean that
        the group has already been created.

        For users who are College students, a tcdnetsoc_ISS_username should be 
        specified.

        By default, newly-created accounts will be marked as members for the curent
        year. If this is not desired, specify "tcdnetsoc_membership_year=[]".

        Disk quotas are set to the default for each filesystem, they can be changed
        via User.quota.

        TLDR: User.create(uid="foo",
                          cn="Foo Barbaz",
                          mail="foo@barbaz.com",
                          tcdnetsoc_ISS_username="foob")'''
        for a in ['cn','mail']:
            if a not in attrs:
                raise Exception("Users must have a '%s'" % a)

        if 'uidNumber' not in attrs:
            attrs['uidNumber'] = UIDAllocator.alloc()

        if 'uid' not in attrs or attrs['uid'] == "":
            attrs['uid'] = "user%d" % attrs['uidNumber']

        if 'tcdnetsoc_membership_year' not in attrs:
            attrs['tcdnetsoc_membership_year'] = [current_session()]
        if User(attrs['uid']).exists():
            raise Exception("Uid %s is taken" % attrs['uid'])
        if not User.username_is_valid(attrs['uid']):
            raise Exception("Invalid username %s" % attrs['uid'])

        attrs['tcdnetsoc_saved_password'] = '***newmember***'
        u = super(User,cls).create(**attrs)

        return u

    def create_personal_group(self):
        '''Create the personal group for this user, a group containing only them.
        Used as the default group for their files.

        (You should never need to call this directly)'''

        if self.get_attribute('gidNumber') is None:
            self.gidNumber = self.uidNumber
        if self.get_personal_group().exists():
            return # no need to create it
        g = PersonalGroup.create(cn = self.uid,
                                 member = [self],
                                 gidNumber = self.gidNumber)
        g.sambaSID = g.gen_samba_sid()
        g.sambaGroupType = 2
        g.objectClass += 'sambaGroupMapping'
    
    def setup_samba_account(self):
        '''Set up a Samba account for this user (samba cannot use standard Posix account
        info for reasons best known to the "designers" of the SMB protocol).

        Note: the password must be changed, even to the same value, after this is called.

        (You should never need to call this directly)'''
        assert 'posixAccount' in self.objectClass
        if self.get_attribute('sambaSID') is None:
            self.sambaSID = self.gen_samba_sid()
        if self.get_attribute('sambaPrimaryGroupSID') is None:
            self.sambaPrimaryGroupSID = self.get_personal_group().gen_samba_sid()
        if 'sambaSamAccount' not in self.objectClass:
            self.objectClass += 'sambaSamAccount'
        

    def addshell(self, **attrs):
        if self.get_attribute('gidNumber') is None:
            mkgrp = True
            self.gidNumber = self.uidNumber
        if self.get_attribute('homeDirectory') is None:
            self.homeDirectory = '/home/' + self.uid

        if mkgrp:
            self.create_personal_group()


        if 'loginShell' not in attrs or "special_shell" in attrs['loginShell']:
            attrs['loginShell'] = User.first_login_shell


        self.objectClass += 'posixAccount'
        
        self.setup_samba_account()


        if 'userPassword' in attrs:
            password = attrs['userPassword']
            del attrs['userPassword']
        else:
            password = generate_password()

        print "Password for %s set to %s" % (self.uid, password)
        self.passwd(password)

                            

        u.memberOf += Privilege("shell")
        u.memberOf += Privilege("webspace")
        for fs, q in User.default_quotas.iteritems():
            u.quota(fs).set(q)

        u.reset_mysql_pw()

        return u

    # Disk quotas
    class fs:
        home = "cuberoot.netsoc.tcd.ie:/srv/userhome"
        webspace = "cuberoot.netsoc.tcd.ie:/srv/userweb"
    default_quotas = {
        fs.home: "4G",
        fs.webspace: "1G"
        }

    def quota(self, fs):
        return User.Quota(self, fs)

    class Quota:
        def __init__(self, user, fs):
            self.user = user
            self.fs = fs

        _sizes = {'T': 1024 ** 4, 'G': 1024 ** 3, 'M': 1024 ** 2, 'K': 1024}
        # bytes <-> human-readable size conversions
        @staticmethod
        def parse_size(sz):
            if sz == "unlimited": return 0
            sz = str(sz)
            m=1
            for s in User.Quota._sizes:
                if sz.endswith(s):
                    m = User.Quota._sizes[s]
                    sz = sz[0:-1]
                    break
            return int(float(sz) * m)
        @staticmethod
        def write_size(sz):
            if sz == 0: return "unlimited"
            sz = float(sz)
            suffix = ""
            for name,s in reversed(sorted(User.Quota._sizes.iteritems(), key=lambda (a,b):b)):
                if sz > 0.9 * s:
                    suffix = name
                    sz /= float(s)
                    break
            return "%.1f%s" % (sz, name)
            
        def _get_quota(self):
            for i in self.user.tcdnetsoc_diskquota:
                if i.startswith(self.fs + ":"):
                    return [int(x) for x in i.split(":")[2:6]]
            return None, None, None, None
        def _set_quota(self, l):
            for i in self.user.tcdnetsoc_diskquota:
                if i.startswith(self.fs + ":"):
                    self.user.tcdnetsoc_diskquota -= i
            self.user.tcdnetsoc_diskquota += ":".join([self.fs] + [str(x) for x in l])
        def _get_usage(self):
            for i in self.user.tcdnetsoc_diskusage:
                if i.startswith(self.fs + ":"):
                    return [int(x) for x in i.split(":")[2:]]
            return None, None, None, None, None, None

        def set(self, sz, extra_size=10, bytes_per_inode=10*1024, inode_extra_size=10):
            sz = self.parse_size(sz)
            szlimit = sz / 1024  # max size in 1k blocks
            inodelimit = float(sz) / float(bytes_per_inode) # inode limit
            self._set_quota([
                szlimit, # size in 1k blocks
                int(float(szlimit) * (1 + 0.01 * extra_size)), # hardlimit
                int(inodelimit), # max no. of inodes
                int(inodelimit * (1 + 0.01 * inode_extra_size)) # inode hardlimit
                ])

        def __repr__(self):
            blocksoft, blockhard, inodesoft, inodehard = self._get_quota()
            blockused, xblocksoft, xblockhard, inodeused, xinodesoft, xinodehard = self._get_usage()
            if blocksoft is None:
                return "no quota set"
            if blockused is None:
                return "%s [no usage data]" % self.write_size(blocksoft*1024)
            s = "%s of %s (%d%%)" % (
                self.write_size(blockused*1024 if blockused > 0 else "0"),
                self.write_size(blocksoft*1024),
                100.0 * blockused / blocksoft)
            if xblocksoft != blocksoft or xinodesoft != inodesoft or \
               xblockhard != blockhard or xinodehard != inodehard:
                s += " [with changes not yet applied]"
            return s
            
                    


class Group(NDObject):
    '''A group of users. Groups may contain any number of users, including zero'''
    rdn_attr = 'cn'
    default_objectclass = ['tcdnetsoc-group']

    # Allow "user in group" and "for user in group" as shorthands for
    # "user in group.member" and "for user in group.member"
    def __contains__(self, obj):
        return obj in self.member
    def __iter__(self):
        return iter(self.member)

    def gen_samba_sid(self):
        return "%s-%s" % (_get_samba_domain_sid(), self.gidNumber * 2 + 1001)


    def check(self):
        if 'sambaGroupMapping' in self.objectClass:
            assert self.sambaGroupType == 2
            assert self.sambaSID == self.gen_samba_sid()

    @classmethod
    def create(cls, **attrs):
        if 'gidNumber' not in attrs:
            attrs['gidNumber'] = GIDAllocator.alloc()
        return super(Group, cls).create(**attrs)


class PersonalGroup(Group):
    '''A PersonalGroup is a group with the same name as a user having only that user
    as a member. Its GID is the UID of the user and its name is the username of the user'''
    rdn_attr = 'cn'
    default_objectclass = ['tcdnetsoc-group']
        
    def get_user(self):
        return User(self.cn)

         
    def check(self):
        assert 'tcdnetsoc-group' in self.objectClass
        user = self.get_user()
        assert user.exists()
        assert user.gidNumber == self.gidNumber
        assert len(self.member) == 1
        assert user in self
        assert 'sambaGroupMapping' in self.objectClass
        

class Privilege(Group):
    '''Groups controlling access to specific services, for instance webspace or
    filestorage'''
    rdn_attr = 'cn'
    default_objectclass = ['tcdnetsoc-privilege']
    def check(self):
        assert 'tcdnetsoc-privilege' in self.objectClass


class Service(NDObject):
    rdn_attr = 'cn'
    default_objectclass = ['tcdnetsoc-service']
    def get_password(self):
        return self.get_attribute("userPassword")

    def has_access(self, user):
        return len(list(Privilege.search(SearchFilter.all(tcdnetsoc_service_granted=self,
                                                          member=user)))) != 0
    @classmethod
    def create(cls, **attrs):
        if 'userPassword' not in attrs:
            attrs['userPassword'] = generate_password()
        o = super(Service,cls).create(**attrs)
        print "Generated password '%s' for %s" % (attrs['userPassword'], o.cn)
        return o
        
    

class IDNumber(NDObject):
    """Allocator for new ID numbers such as UID and GID.
    The next ID is stored in the allocator object, and when a new one is requested
    the field is atomically incremented and the old value is returned"""
    rdn_attr = 'cn'
    default_objectclass = ['tcdnetsoc-idnum']
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


class Setting(NDObject):
    """Arbitrary configuration-style key-value setting, stored in LDAP to be accessible from all Netsoc machines"""
    rdn_attr = 'cn'
    default_objectclass = ['tcdnetsoc-setting']
    def _setnum(self, old, new):
        # Minor hack: we use _raw_modattrs to ensure atomicity
        # Without it, there's a race condition
        self._raw_modattrs([
            (ldap.MOD_DELETE, 'tcdnetsoc-value', str(old)),
            (ldap.MOD_ADD, 'tcdnetsoc-value', str(new))])
        
    def alloc(self):
        # try to atomically allocate a new number (UID, GID, etc)
        # attempt it 3 times in case it fails because someone else
        # is also allocating numbers
        for attempt in range(3):
            currid = int(self.tcdnetsoc_value.first())
            try:
                self._setnum(currid, currid+1)
            except ldap.NO_SUCH_ATTRIBUTE, e:
                time.sleep(random.random() * 0.1)
                continue
            return currid
        raise e

    def check(self):
        assert 'tcdnetsoc-setting' in self.objectClass



Attribute('objectClass', [str])
Attribute('serialNumber', int)
Attribute('tcdnetsoc_membership_year', [str])
Attribute('tcdnetsoc_ISS_username', str)
Attribute('loginShell', str)
Attribute('uid', str, match_like)
Attribute('uidNumber', int)
Attribute('gidNumber', int)
Attribute('homeDirectory', str)
Attribute('cn', str, match_like)
Attribute('userPassword', str)
Attribute('mail', str)
Attribute('tcdnetsoc_admin_comment', [str])
Attribute('member', [User])
Attribute('memberOf', [Group], backlink='member')
Attribute('tcdnetsoc_service_granted', [Service])
Attribute('tcdnetsoc_granted_by_privilege', [Privilege], backlink='tcdnetsoc_service_granted')
Attribute('tcdnetsoc_diskquota', [str])
Attribute('tcdnetsoc_diskusage', [str])
Attribute('tcdnetsoc_value', [str])
Attribute('sambaSID', str)
Attribute('sambaPrimaryGroupSID', str)
Attribute('sambaGroupType', int)
Attribute('tcdnetsoc_mysql_pw', str)
Attribute('tcdnetsoc_saved_password', str)
