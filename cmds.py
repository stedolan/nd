# Command line interface to Netsoc Directory

import os
import sys
from nd import *


objtypes = {'user':User, 'group':Group }


def help(*args):
    '''Information about commands'''
    def shorthelp(f):
        return f.__doc__.split("\n")[0]
    def longhelp(f):
        return f.__doc__
    if args:
        cmd = getfunc(args[0])
        if not cmd:
            err("Unknown command %s" % args[0])
        else:
            print longhelp(cmd)
    else:
        print "Available commands:"
        for i in cmdfuncs:
            print i.__name__ + ": " + shorthelp(i)
        print "\nUse help <command> for information about a specific command"


def myself(*args):
    '''Viewing or modifying your own user account

    The myself command is equivalent to "user <current user>", see help user for details'''
    return user(str(os.getuid()), *args)

def search(*args):
    '''Search for particular users, groups, etc.'''
    try:
        type = objtypes[args[0]]
    except:
        err()

    args = args[1:]
    if len(args) == 1:
        filter = SearchFilter.any(uid=args[0], cn=args[0])
    else:
        if len(args) % 2 != 0:
            err("search called with an odd number of parameters")
        #FIXME: validate special chars??

        keys = args[::2]
        values = args[1::2]
        filters = []
        for i in range(len(keys)):
            if keys[i] == "ldap":
                filters.append(SearchFilter.from_raw_filter(values[i]))
            else:
                filters.append(SearchFilter.attr_match(keys[i], values[i]))
        filter = SearchFilter.all(*filters)
    for i in type.search(filter):
        print i


def searchuser(*args):
    '''Searching for users, groups or hosts

    Usage:
      searchuser <type> <property> <value> [<property> <value>...]: Search by any property
        <type> is user, group or host
        If multiple properties are specified, all are matched.
        The property "memberOf" specifies that the user must be in the specified group.
        The property "ldap" specifies an arbitrary LDAP search filter
        Examples:
          search user cn stephen memberOf council
             - Finds users whose full names contain "Stephen" and are in the "council" group
          search user tcd-ISS-username sdolan
             - Finds the user whose College username is "sdolan"
          search group member mu
             - Finds groups containing user "mu"
    '''
    try:
        type = objtypes[args[0]]
    except:
        err("Invalid type (try 'user', 'group' or 'host')")
    

def query(objspec, type, args):
    if len(args) == 0:
        obj = type(objspec)
        print obj.info()
    else:
        cmd = args[0]
        if cmd == 'get':
            obj = type(objspec)
            for attr, value in obj.get_all_attribute_pairs():
                print attr + ": " + value
        elif cmd == 'set':
            obj = type(objspec)
            obj.set_attribute(args[1], args[2])
        else:
            err("Unknown command %s" % cmd)



def user(*args): #FIXME: group modification ops, user creation/deletion, whitespace in vals
    '''Creating, deleting, viewing and modifying user accounts

    Usage:
      user <uid> get: Prints out all information about a user
      user <uid> get <property>: Gets a property (full name, email address, etc.) of a user
      user <uid> set <property> <value>: Sets a property
      user <uid> set <property>: Sets a property from stdin.
         e.g. user someone set jpegPhoto < somePhoto.jpg

      You might not have permission to perform some of these operations.
      <uid> above is a username, a UID number, or an LDAP DN for a user.
      <property> is one of the available user properties, interesting ones include:
         cn: name
         jpegPhoto: a photograph
         tcdnetsoc-ISS-username: College username
         mail: email address
          and various others

    To list all the user accounts, see "group list"
    '''
    if not args:
        err()
    uid = args[0]
    query(uid, User, args[1:])
    
def group(*args):
    '''Creating, deleting, viewing and modifying groups
    Usage:
      group <gid> list: Lists the users in a given group'''
    pass

def host(*args):
    '''Creating, deleting, viewing and modifying machine accounts'''
    pass



cmdfuncs = [myself, user, group, host, help, search]

def getfunc(name):
    for f in cmdfuncs:
        if f.__name__ == name:
            return f
    return None

def run_command(args):
    if not args:
        help()
    else:
#        ldap_connect('cn=root,dc=netsoc,dc=tcd,dc=ie','foo')
        func = getfunc(args.pop(0))
        if not func:
            help()
        else:
#            try:
                func(*args)
#            except Exception, e:
#                help(func.__name__)
#                raise e

def err_on(cond):
    if cond:
        err()

def err(message="Invalid command syntax"):
    sys.stderr.write("Error: %s\n" % message)
    raise Exception(message)
def warn(message):
    sys.stderr.write("Warning: %s\n" % message)

if __name__=='__main__':
    run_command(sys.argv[1:])
