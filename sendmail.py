# Python interface to /usr/lib/sendmail

import email, email.parser, subprocess, os.path

default_from_address = "support@netsoc.tcd.ie"
default_template_location = os.path.abspath(os.path.dirname(__file__)) + "/messages"

def sendmail(template_file, dict=None, **kwargs):
    if dict is None: dict = {}
    dict.update(kwargs)
    if template_file[0] != "/": 
        try:
            txtmsg = open(default_template_location + "/" + template_file, "r").read()
        except Exception, e:
            txtmsg = open(template_file, "r").read()
    else:
        txtmsg = open(template_file, "r").read()
    try:
        txtmsg = txtmsg % dict
    except KeyError, e:
        raise Exception("Required field %s must be included for this template" % e)

    msg = email.parser.Parser().parsestr(txtmsg)

    if 'From' not in msg:
        if 'From' in dict:
            msg['From'] = dict['From']
        else:
            msg['From'] = default_from_address
    if 'To' not in msg and 'To' in dict:
        msg['To'] = dict['To']
    if 'Subject not in msg' and 'Subject' in dict:
        msg['Subject'] = dict['Subject']
    
    for h in ['From','To','Subject']:
        if h not in msg: raise Exception("Mail message sending failed, must contain %s header" % h)

    if 'DRY_RUN' in dict:
        print "Sending:"
        print msg
        print ""
    else:
        print "Sending mail from %s to %s" % (msg['From'],msg['To'])
        sendmail = subprocess.Popen(["/usr/lib/sendmail","-f",msg['From']], stdin=subprocess.PIPE)
        sendmail.communicate(msg.as_string())


