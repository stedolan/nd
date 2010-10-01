# Python interface to /usr/lib/sendmail

import email, email.parser, subprocess, os.path

default_from_address = "support@netsoc.tcd.ie"
default_template_location = os.path.abspath(os.path.dirname(__file__)) + "/messages"

def sendmail(template_file, dict=None, **kwargs):
    if dict is None: dict = {}
    dict.update(kwargs)
    if template_file[0] != "/": template_file = default_template_location + "/" + template_file
    txtmsg = open(template_file, "r").read()
    try:
        txtmsg = txtmsg % dict
    except KeyError, e:
        raise Exception("Required field %s must be included for this template" % e)
    msg = email.parser.Parser().parsestr(txtmsg)
    if 'From' not in msg: msg['From'] = default_from_address
    
    for h in ['From','To','Subject']:
        if h not in msg: raise Exception("Mail message sending failed, must contain %s header") % h

    sendmail = subprocess.Popen(["/usr/lib/sendmail","-f",msg['From']], stdin=subprocess.PIPE)
    sendmail.communicate(msg.as_string())


