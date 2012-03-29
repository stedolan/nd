import gdbm, socket, time, md5, os, sys, pwd

run_as_server = (__name__ == '__main__')
if run_as_server:
    sys.path += ["/usr/local/nd"]

import sendmail

########### Networking

server_socket = None
def accept_network_conn():
    global server_socket
    c, addr = server_socket.accept()
    c.settimeout(1)
    return c, addr

if run_as_server:
    server_socket = socket.socket()
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("0.0.0.0", 900))
    server_socket.listen(5)


########### LDAP connection

import nd



def check_ldap():
    # If we lose the connection to LDAP, we're going to have to restart
    # since we dropped privileges and can't rebind as root
    # If running as a server, the server will be restarted
    def fail():
        if run_as_server:
            print "Not bound to LDAP as root, shutting down server"
            sys.exit()
        else:
            raise Exception("Not bound to LDAP as root")
    try:
        if nd.whoami() != 'dn:cn=root,dc=netsoc,dc=tcd,dc=ie':
            # ldap is bound as the wrong user
            fail()
    except Exception, e:
        # ldap is down
        fail()

check_ldap()
if run_as_server:
    # drop privileges now that we have the socket and the ldap connection
    os.setuid(pwd.getpwnam("daemon")[2])
    check_ldap()


########### Request marshalling/unmarshalling (both network & storage)

def parse_request(s):
    xs = s.split("\0")
    code = xs[0]
    del xs[0]
    if len(xs) % 2 != 0:
        raise Exception("badly formatted request")
    args = {}
    for i in range(0, len(xs), 2):
        args[xs[i]] = xs[i+1]
    return code, args

def unparse_request(code, args):
    def mkstr(x):
        if type(x) == unicode:
            return x.encode("utf8")
        else:
            return str(x)
    l = [(str(k), mkstr(v)) for k, v in args.items()]
    l.sort()
    # flatten
    l = [x for pair in l for x in pair]
    return code + "\0" + "\0".join(l)


########### Request database access

request_db_filename = os.path.abspath(os.path.dirname(__file__)) + "/reqs.db"

def db_lookup_code(code):
    db = gdbm.open(request_db_filename, "r")
    try:
        p = db[code]
    except KeyError:
        p = None
    db.close()
    if p is None:
        raise Exception("invalid code")
    else:
        return parse_request(p)[1]

def db_write(code, args):
    db = gdbm.open(request_db_filename, "cs", 0600)
    db[code] = unparse_request(code, args)
    db.close()

def create_key(op, **args):
    if type(op) != str:
        op = op.__name__
    assert op in operations
    args['operation'] = op
    code = "".join(["%02x" % ord(x) for x in open("/dev/urandom").read(16)])
    db_write(code, args)
    return code

def all_codes():
    db = gdbm.open(request_db_filename, "r")
    k = db.firstkey()
    l = []
    while k != None:
        l.append(parse_request(db[k]))
        k = db.nextkey(k)
    db.close()
    return l

def dump_codes():
    l = all_codes()
    usedcodes = [x for x in l if '*used' in x[1]]
    unusedcodes = [x for x in l if '*used' not in x[1]]
    def fmtreq((code, args)):
        return "%s: %s" % (code, ", ".join("%s=%r" % x for x in args.items()))
    print "Used codes:"
    for i in usedcodes:
        print fmtreq(i)
    print
    print "Unused codes:"
    for i in unusedcodes:
        print fmtreq(i)

########### Hashcodes for frontend

def create_mac(data):
    hash = lambda x: md5.md5(x).hexdigest()
    return hash("Although your world wonders me, " + hash("olololololololol" + data)) + "/" + data

def verify_mac(mac):
    if "/" not in mac: return None
    h, _, data = mac.partition("/")
    if create_mac(data) != mac:
        return None
    return data

########### Making privileged URLs to send out to users

def make_signup_url(user):
    assert type(user) == nd.User
    if user.get_state() != "newmember":
        raise Exception("%r is not a newly-created account, won't make signup URL" % user)
    print "Generating single-use code for userid %d to change their account state" % user.uidNumber
    k = create_key(setup_account, uidnumber = user.uidNumber)
    u = create_mac(str(user.uidNumber))
    return "https://signup.netsoc.tcd.ie/signup.php?code=%s&userid=%s" % (k,u)


########### Authorization logic (checking request received over network against stored parameters)

def check(condition, message):
    '''asserts with a message to be passed back to the user'''
    if not condition:
        raise Exception(message)

operations = {}

def run_request(code, args):
    props = db_lookup_code(code)
    check("*used" not in props, "This code has already been used")

    print props, args
        
    for p in props:
        if p in args:
            check(args[p] == props[p], "Code not authorized for %s = %r" % (p, args[p]))
        else:
            args[p] = props[p]

    if "*expiry" in props:
        pass # FIXME
    
    if "operation" not in args or args["operation"] not in operations:
        raise Exception("Unknown operation")
    
    opname = args["operation"]
    logmsg = args.get("log")
    op = operations[opname]
    del args["operation"]
    if "log" in args:
        del args["log"]

    check_ldap()
    op(**args)

    args["operation"] = opname
    if logmsg:
        args["log"] = logmsg
    args["*used"] = time.asctime()
    db_write(code, args)

def define_operation(fn):
    operations[fn.__name__] = fn
    return fn

########### Actual operations that can be performed

@define_operation
def change_password(username, password, **kw):
    print "pw of %s -> %s" % (username, password)

@define_operation
def setup_account(uidnumber, username, name, issusername, password):
    userlist = nd.User.search(uidNumber = uidnumber)
    check(len(userlist) == 1, "Could not find matching account")
    user = userlist[0]
    check(user.get_state() == "newmember", "User account already set up. To renew an account instead, contact support@netsoc.tcd.ie.")
    check(nd.User.username_is_valid(username), "Invalid username")
    check(len(name) > 2 and " " in name, "Please enter your full name")
    check(len(issusername) > 2, "Please enter your College username")
    check(len(password) >= 6, "Please enter at least an 6-character password")
    user.uid = username
    user.cn = name
    user.tcdnetsoc_ISS_username = issusername
    user.set_state("shell", password)
    try:
        sendmail.sendmail("account_setup", to=user.mail)
    except Exception, e:
        # if mail-sending fails we don't care that much
        print e


########### Main loop


def run_server():
    if not run_as_server:
        raise Exception("Not running as a service")
    print "server starting"
    while 1:
        addr = None
        args = {}
        try:
            c, addr = accept_network_conn()
            s = c.recv(4096)
            code, args = parse_request(s)
            ret = run_request(code, args)
            c.send("Success")
            c.close()
        except Exception,e:
            print str(e), " from ", str(addr), ", msg:", repr((code,args))
            try:
                c.sendall(str(e))
                c.close()
            except Exception,e:
                print "error sending error code " + str(e)


if run_as_server:
    run_server()
