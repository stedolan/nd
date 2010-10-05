# ldapobject.py
# the framework for mapping between LDAP entries and Python objects

import ldap, ldap.dn, ldapurl, ldap.filter
from ldaplogging import *
import ldapconnect as lc


# The mapping model is as follows:
# Nodes in the LDAP tree with children are mapped to classes
#
# Nodes in the LDAP tree without children are mapped to objects
#
# If a node in LDAP is a child of another node, then the child
#   is a subclass (if it's a class) or an object (if it's an
#   object) of the parent node.
#
# LDAP nodes are identified by Distinguished Names (DNs), which
# show a path down from the top of the tree. Since the LDAP tree
# is mapped to the inheritance heirarchy, the DN of an object
# will show it's class, that class's parent, and so on.
# For instance, an object called "mu" of type PersonalGroup,
# where PersonalGroup subclasses Group, will have a DN starting
# with "cn=mu,ou=PersonalGroup,ou=Group,..."



# DNs are represented internally by tuples of pairs of attribute
# and value, for example:
# (('uid','mu'),('ou','User'),('dc','netsoc'),('dc','tcd'),('dc','ie'))
# These two functions convert between tuple syntax and string syntax
def dn_to_tuple(dn):
    dnparts = [x.partition("=") for x in ldap.dn.explode_dn(dn)]
    return tuple((x[0],x[2]) for x in dnparts)
def tuple_to_dn(t):
    return ",".join("%s=%s" % (ldap.dn.escape_dn_chars(attr),
                               ldap.dn.escape_dn_chars(val))
                    for (attr,val) in t)

def whoami():
    return lc.whoami()


class LDAPClass(type):
    '''Classes which are mapped to LDAP. LDAPClass is used as a metaclass for
    LDAP-mapped classes. So, a class User might subclass LDAPObject and would
    be an instance of LDAPClass. This metaclass defines operations which can
    be performed on LDAP *classes*, such as creation (not only must Python
    constructors run, but LDAP operations must be performed), searching
    (searching for all users is a static method of User which is defined in
    LDAPClass), and so on.'''
    _classmap = {}
    def __init__(cls, name, bases, dict):
        '''The constructor. Since this is a metaclass, this method is called when
        new *classes* are created, such as during subclassing. This method ensures
        single-inheritance and keeps track of the tree of subclasses and where
        they fit into the LDAP tree'''
        if len(bases) != 1:
            raise TypeError("LDAP-mapped classes only support single-inheritance")
        super(LDAPClass,cls).__init__(name,bases,dict)
        # skip this for LDAPObject
        if bases[0] is not object:
            # rebuild DN -> class mapping
            LDAPClass._classmap = {}
            LDAPObject._update_class_tree(())
    def _update_class_tree(cls, dnsuffix):
        if cls is LDAPObject:
            assert(len(dnsuffix) == 0)
            dn = ()
        elif 'base_dn' in cls.__dict__ and cls.base_dn is not None:
            dn = dn_to_tuple(cls.base_dn)
            # dn must end with dnsuffix
            if len(dnsuffix) > 0 and not dn[-len(dnsuffix):] == dnsuffix:
                raise TypeError("Invalid DN %s for class %s (must be under %s)" % (dn, cls.__name__, dnsuffix))
        else:
            # classes are mapped to organizationalUnits
            dn = (("ou", cls.__name__),) + dnsuffix
        cmap = LDAPClass._classmap
        if dn in cmap:
            raise TypeError("Duplicate classes (%s and %s) for DN %s" % (cls.__name__, cmap[dn], dn))
        ldebug("rebuilding classmap: %s has base dn %s" % (cls.__name__, dn))
        cmap[dn] = cls
        for subclass in cls.__subclasses__():
            subclass._update_class_tree(dn)
        cls.cls_dn_tuple = dn
        cls.cls_dn_str = tuple_to_dn(dn)

    @staticmethod
    def classmap_as_graphviz():
        cmap = LDAPClass._classmap
        parent = {}
        name = {}
        maxid = 1
        id = {}
        for dn in cmap:
            if dn == (): continue
            for i in range(1,len(dn)):
                if dn[i:] in cmap:
                    parent[dn] = dn[i:]
                    name[dn] = tuple_to_dn(dn[0:i])
                    id[dn] = maxid
                    maxid += 1
                    break
            else:
                name[dn] = tuple_to_dn(dn)
                id[dn] = maxid
                maxid += 1
        retdata = []
        p = retdata.append
        p("digraph {")
        for dn in cmap:
            if dn != ():
                p('n%d [label="%s",shape=box]' % (id[dn], name[dn]))
        for dn in cmap:
            if dn in parent:
                p("n%d -> n%d" % (id[parent[dn]], id[dn]))
        p("}")
        return "\n".join(retdata)

       
    @staticmethod
    def get_class_by_dn(dn_str):
        '''Given a DN in string form, determine the class of the object with that DN'''
        dn = dn_to_tuple(dn_str)
        # we check all suffixes of the dn
        while len(dn) > 0:
            if dn in LDAPClass._classmap:
                return LDAPClass._classmap[dn]
            dn = dn[1:]
        raise TypeError("No class found for DN %s" % dn_str)

    @staticmethod
    def get_object_by_dn(dn_str):
        '''Given a DN in string form, return the Python object referring to it'''
        # we get the class and call the constructor, passing the DN
        return LDAPClass.get_class_by_dn(dn_str)(obj_dn = dn_str)

    def check_all(cls):
        '''Perform consistency checks. Each LDAP class may define a method check().
        When this method is run, all of the check() methods appropriate to each object
        in the tree are run. If any "assert"s fail, a detailed error message is given'''
        try:
            lc.search(cls.cls_dn_str, ldap.SCOPE_BASE, None, [])
        except Exception,e:
            lerr("LDAP object of class %s does not exist: %s" % (cls, e))
        try:
            for obj in cls.all_objs():
                # Call *all* the check methods, not just the most recently-defined
                for c in type(obj).mro():
                    method = c.__dict__.get("check")
                    if method:
                        try:
                            method(obj)
                        except Exception, e:
                            lerr("%s check of object %s failed: %s"%(c, obj, e))
                            if isinstance(e, AssertionError):
                                try:
                                    import traceback
                                    (file,line,meth,src) =  traceback.extract_tb(sys.exc_info()[2])[-1]
                                    lerr("    %s:%d: %s failed" % (file, line, src))
                                except Exception, e:
                                    pass
        except Exception, e:
            lerr("Can't iterate over objects of class %s: %s" % (cls, e))


    def all_objs(cls):
        '''Return all instances of this class (or subclasses) stored in the LDAP tree'''
        return cls.search(SearchFilter.match_everything())

    def __len__(cls):
        '''Number of instances of this class (or subclasses) stored in the LDAP tree'''
        return sum(1 for x in cls.all_objs())

    def __iter__(cls):
        '''Iterate over instances of this class (or subclasses) stored in the LDAP tree'''
        for i in cls.all_objs(): yield i

    def __repr__(cls):
        return "<class '%s.%s' (%d objects)>" % (cls.__module__, cls.__name__, len(cls))




class LDAPObject(object):
    '''The base class of all LDAP-mapped classes. Each LDAP class inherits from
    LDAPObject but is an instance of LDAPClass. This class defines per-object methods
    such as reading or writing attributes, while LDAPClass defines per-class methods
    such as instantiating new objects'''
    __metaclass__ = LDAPClass
#    base_dn = None
#    rdn_attr = None
    _allowed_attrs = []

    def __init__(self, id=None, obj_dn=None):
        '''Construct an object, given either obj_dn (the string DN of the object)
        or id (a value for the RDN of the object)'''
        if obj_dn is None:
            obj_dn = tuple_to_dn(((type(self).rdn_attr, id),) + self.cls_dn_tuple)
        self._dn = obj_dn

    def get_dn(self):
        '''Return the DN of this object in string form'''
        return self._dn

    def __repr__(self):
        if self.exists():
            return '<' + type(self).__name__ + " " + self.get_dn() + '>'
        else:
            return "<no such object (%s)>" % type(self).__name__

    # Objects are equal if they refer to the same node in the LDAP tree
    def __eq__(self, other):
        return isinstance(other, type(self)) and self.get_dn() == other.get_dn()
    def __ne__(self, other):
        return not self == other

    # Internal functions to query LDAP and return/update raw data
    def _raw_readattrs(self, attrlist):
        res = lc.search(self.get_dn(), ldap.SCOPE_BASE, None, attrlist)[0][1]
        for a in attrlist:
            if a not in res:
                res[a] = []
        return res
    def _raw_modattrs(self, modlist):
        return lc.modify(self.get_dn(), modlist)
    def _raw_modrdn(self, newrdn):
        rdn_part = ((self.rdn_attr, newrdn),)
        r = lc.modrdn(self.get_dn(), tuple_to_dn(rdn_part))
        self._dn = tuple_to_dn(rdn_part + dn_to_tuple(self._dn)[1:])
        return r
    def _raw_passwd(self, new, old):
        lc.passwd(self.get_dn(), old, new)

    def get_attribute(self, name):
        '''Read an attribute from this object in the LDAP tree and convert the value
        to Python form. For the handling of multi-valued attributes, see ValueSet'''
        attr = Attribute.get_attribute(name)
        if attr.multival:
            return ValueSet(self, attr)
        else:
            n = attr.get_ldap_name()
            vals = self._raw_readattrs([n])[n]
            if len(vals) == 0:
                return None
            elif len(vals) > 1:
                raise AttributeError("Attribute %s seems to be multi-valued, but isn't declared as such" % name)
            else:
                return attr.ldap_to_py(vals[0])
            
    def get_all_attribute_pairs(self):
        '''Return a list of all the attribute-value pairs in the object'''
        # include all the backlink attrs as well, by default they don't show up under "*"
        d = self._raw_readattrs(["*"] + Attribute.list_backlink_attrs())
        return [(name, Attribute.get_attribute(name).ldap_to_py(val)) for name in d for val in d[name]]

    def dump(self):
        for k,v in self.get_all_attribute_pairs():
            print "%s: %s" % (k,v)

    def get_all_attributes(self):
        '''Return a list of all the attributes this object has (not the values)'''
        d = self._raw_readattrs(["*"] + Attribute.list_backlink_attrs())
        return [x for x in d.keys() if len(d[x]) > 0]
        
    def set_attribute(self, name, val):
        '''Update an attribute. Converts the value from Python form to LDAP form. See
        ValueSet for how to do this with multi-valued attributes'''
        attr = Attribute.get_attribute(name)
        if attr.multival:
            raise TypeError("%s is not a single-valued attribute, it cannot be directly assigned" % name)
        else:
            n = attr.get_ldap_name()
            if n == self.rdn_attr:
                self._raw_modrdn(attr.py_to_ldap(val))
            else:
                self._raw_modattrs([(ldap.MOD_REPLACE, n, attr.py_to_ldap(val))])

    def del_attribute(self, name):
        '''Delete all values for a given attribute from this object'''
        attr = Attribute.get_attribute(name)
        self._raw_modattrs([(ldap.MOD_DELETE, attr.get_ldap_name(), None)])

    def change(self, **attrs):
        pass


    # Allow Pythonic constructions for LDAP attributes:
    #  print self.attr
    #  print self['attr']
    #  self.attr = val
    #  del self.attr
    def __getitem__(self, name):
        if type(name) == int: raise TypeError("Not iterable")
        v = self.get_attribute(name)
        if v is not None:
            return v
        else:
            raise AttributeError("No such attribute: %s" % name)
    def __getattr__(self, name):
        if name.startswith("_"):
            # names that start with an underscore are not routed through LDAP
            raise AttributeError("No such attribute: " + name)
        if name == "trait_names" or "(" in name:
            # IPython causes some spurious calls to getattr, we have to ignore them
            raise AttributeError("No such attribute: " + name)
        return self[name]
    def __setattr__(self, name, val):
        if isinstance(val, ValueSet):
            # This is to work around some weirdness of Python
            # If I do user.memberOf += group, this calls the __iadd__ method
            # on ValueSet (see below) to add the element, but then does a
            # __setattr__ on user, which we want to avoid.
            return
        elif name.startswith("_"):
            # names that start with an underscore are not routed through LDAP
            self.__dict__[name] = val
        elif name in self.__dict__ or hasattr(type(self), name):
            # this isn't an LDAP attribute either
            ldebug("Not updating attribute %s of %s", name, self)
            return
        else:
            self.set_attribute(name, val)
    def __delattr__(self, name):
        if name.startswith("_"):
            # names that start with an underscore are not routed through LDAP
            del self.__dict__[name]
        else:
            self.del_attribute(name)
    

    def destroy(self):
        '''Delete this object from LDAP'''
        linfo("Destroying %s of type %s" % (self.get_dn(), type(self)))
        lc.delete(self.get_dn())

    def exists(self):
        '''Does this object exist in the LDAP tree?'''
        try:
            lc.search(self.get_dn(), ldap.SCOPE_BASE, None, [])
            return True
        except ldap.NO_SUCH_OBJECT:
            return False



    # Create is a class method, yet destroy is an instance method
    # This asymmetry makes sense: User.create('someuser') yet someuser.destroy()
    @classmethod
    def create(cls, **attrs):
        '''Create an object of this class'''
        if cls.rdn_attr not in attrs:
            raise TypeError("All %s objects must have a %s field" % (cls, cls.rdn_attr))
        if hasattr(cls, "default_objectclass"):
            if 'objectClass' not in attrs:
                attrs['objectClass'] = list(cls.default_objectclass)
        modlist = []
        backlinks = []
        for key in attrs:
            val = attrs[key]
            attribute = Attribute.get_attribute(key)
            if attribute.is_multival():
                if attribute.is_backlink_attr():
                    backlinks.append(key)
                else:
                    for v in val:
                        modlist.append((attribute.get_ldap_name(), attribute.py_to_ldap(v)))
            else:
                modlist.append((attribute.get_ldap_name(), attribute.py_to_ldap(val)))
            
        dn = tuple_to_dn(((cls.rdn_attr, attrs[cls.rdn_attr]),) + cls.cls_dn_tuple)
        linfo("Creating %s of type %s" %(dn, cls.__name__))
        lc.add(dn, modlist)
        assert(LDAPClass.get_class_by_dn(dn) is cls)

        ret_obj = cls(obj_dn = dn)
        
        for key in backlinks:
            for obj in attrs[key]:
                getattr(ret_obj, key).add(obj)
        
        return ret_obj

    @classmethod
    def search(cls, filter=None, **kw):
        '''Search for instances of this class in the LDAP tree'''

        if filter == None:
            filter = SearchFilter.all(**kw)

        if type(filter) == str:
            if hasattr(cls, "default_search_attrs"):
                filter = SearchFilter.any(**dict([(a,filter) for a in cls.default_search_attrs]))
            else:
                raise Exception("No query fields provided")

    

        #FIXME: list or generator?? search or search_s??
        def results():
            for (dn, _) in lc.search(cls.cls_dn_str, ldap.SCOPE_SUBTREE, filter.filterstr, []):
                if dn_to_tuple(dn) not in LDAPClass._classmap:
                    subcls = LDAPClass.get_class_by_dn(dn)
                    assert(issubclass(subcls, cls))
                    yield subcls(obj_dn = dn)
        return list(results())





match_exact = lambda attr, value: "(%s=%s)" % (attr, ldap.filter.escape_filter_chars(value))
match_wildcard = lambda attr, value: "(%s=%s)" % (attr, ldap.filter.escape_filter_chars(value).replace("\\2a","*"))
match_substring = lambda attr, value: "(%s=*%s*)" % (attr, ldap.filter.escape_filter_chars(value))
match_exact_or_substring = lambda attr, value: "(|%s%s)" % (match_exact(attr, value), match_substring(attr, value))
match_wildcard_or_substring = lambda attr, value: "(|%s%s)" % (match_wildcard(attr,value), match_substring(attr, value))
match_like = lambda attr, value: "(%s~=%s)" % (attr, ldap.filter.escape_filter_chars(value))
def match_ref(cls):
    if not issubclass(cls, LDAPObject):
        raise TypeError("%s is not an LDAP-mapped class" % cls)
    def rule(attr, obj):
        if isinstance(obj, str):
            obj = LDAPClass.get_object_by_dn(obj)
        if not isinstance(obj, cls):
            raise TypeError("%s is not an instance of %s" % (obj, cls))
        return match_exact(attr, obj.get_dn())
    return rule

def default_match(type):
    if type is int:
        return match_exact
    elif type is str:
        return match_wildcard_or_substring
    elif issubclass(type, LDAPObject):
        return match_ref(type)
    else:
        raise TypeError("Type %s not understood" % type)


class Attribute(object):
    '''Attributes of objects. Each attribute has:
         * a name: _ is normalised to -, so foo_bar is entered in LDAP as foo-bar
         * a type: this may be int, str, a LDAP class, or a type in square brackets.
             Examples: int -> Integer-valued attribute
                       [str] -> Multi-valued string attribute
                       [User] -> Multi-valued attribue whose values are the DNs
                                 of objects of type User (or a subclass)
         * a match rule: this can usually be ignored. Certain types allow substring
             search, some do not. Defaulting to substring search does not work since
             some LDAP attribute types (e.g. int) will return no values in that case.
         * a backlink attribute: For many-to-many relations (such as User.memberOf
             and Group.member), one of the attributes is kept as the canonical
             reference and one is labelled a "backlink". In the example above, member
             is an attribute of type [User], and memberOf is an attribute of type
             [Group] which is a backlink to member. So, when memberOf is updated, it
             will instead update the underlying member attribute of the appropriate
             group

    Attributes are not associated with a particular class, for instance various
    different types may have a "cn" attribute (Common Name). To register a new
    attribute, just call the constructor as e.g.
       Attribute("my_int_list_attr", [int])'''
    _known_attrs = {}

    def __init__(self, name, type, matchrule=None, backlink=None):
        if isinstance(type, list):
            if not len(type) == 1:
                raise TypeError("%s is not a supported type" % type)
            type = type[0]
            multival = True
        else:
            multival = False
        if matchrule is None:
            matchrule = default_match(type)

        self.name = name
        self.type = type
        self.multival = multival
        self.matchrule = matchrule

        if backlink is not None:
            ValueSet._register_backlink_attr(self.get_ldap_name(),
                                             Attribute._normalise_name(backlink))

        attrdesc = self._desc()
        known = Attribute._known_attrs
        ldapname = self.get_ldap_name()
        if ldapname in known:
            if known[ldapname]._desc() != attrdesc:
                lwarn("Attribute %s redefined (from %s to %s)" % (name, known[ldapname]._desc(), attrdesc))
        known[ldapname] = self

    def _desc(self):
        return (self.name, self.type, self.multival, self.matchrule)

    @staticmethod
    def _normalise_name(n):
        return n.replace("_","-")
    
    def get_ldap_name(self):
        '''Return the name as it is in the LDAP database'''
        return self._normalise_name(self.name)
    def get_type(self):
        return self.type
    def is_multival(self):
        return self.multival
    def is_backlink_attr(self):
        return self.get_ldap_name() in ValueSet._backlink_attrs
    
    def get_filter(self, val):
        '''Return an LDAP search filter to match this attribute against a given value'''
        return SearchFilter.from_raw_filter(self.matchrule(self.get_ldap_name(), self.py_to_ldap(val)))
    def py_to_ldap(self, val):
        '''Convert from Python format to LDAP (string) format'''
        if self.type in (int, str):
            if type(val) in (int,str):
                return str(val)
            else:
                raise TypeError("%r is not a %s" % (val, self.type.__name__))
        else:
            if isinstance(val, str):
                val = self.type(val)
            if not isinstance(val, self.type):
                raise TypeError("%s is not a %s" % (val, self.type.__name__))
            return val.get_dn()
    def ldap_to_py(self, val):
        '''Convert from LDAP (string) format to Python format'''
        if self.type in (int, str):
            return self.type(val)
        else:
            o = LDAPClass.get_object_by_dn(val)
            if not isinstance(o, self.type):
                raise TypeError("%s is not a %s" % (o, self.type))
            return o



    @staticmethod
    def get_attribute(name):
        '''Lookup an attribute of a given name'''
        n = Attribute._normalise_name(name)
        known = Attribute._known_attrs
        if n in known:
            return known[n]
        else:
            lwarn("Undeclared attribute %s. Defaulting to assuming it's a single-valued string." % name)
            return Attribute(name, str, match_exact_or_substring)

    @staticmethod
    def list_backlink_attrs():
        return ValueSet._backlink_attrs.keys()


class ValueSet(object):
    '''LDAP allows an attribute to have multiple values. This is modelled in Python as
    an attribute which is not represented by a single value but by a ValueSet. ValueSet
    objects support addition and removal of values, and traversal. The += and -= syntax
    is supported, so User("mu").memberOf += Group("webteam") works as expected'''
    _backlink_attrs = {}
    def __init__(self, obj, attr):
        self.obj = obj
        self.attr = attr

    @staticmethod
    def _register_backlink_attr(fwd, back):
        b = ValueSet._backlink_attrs
        if fwd in b:
            if b[fwd] != back:
                lwarn("Redeclared backlink for %s (was %s, now %s)" % (fwd, b[fwd], back))
        b[fwd] = back

    def __repr__(self):
        return repr(self._get_attr_list())


    def _get_attr_list(self):
        ldname = self.attr.get_ldap_name()
        return [self.attr.ldap_to_py(x) for x in
                self.obj._raw_readattrs([ldname])[ldname]]

    # Be more Pythonic: support len(set), for x in set, if x in set syntaxes.
    def __len__(self):
        return len(self._get_attr_list())
    def __iter__(self):
        return iter(self._get_attr_list())
    def __contains__(self, val):
        return val in self._get_attr_list()

    def first(self):
        '''Return the first item from the set'''
        return self._get_attr_list()[0]


    def add(self, val):
        '''Add a value to the set. This is a no-op if the value is
        already present'''
        if val in self:
            return
        ldname = self.attr.get_ldap_name()
        obj = self.obj
        attr = self.attr
        if ldname in ValueSet._backlink_attrs:
            (ldname, obj, val) = (ValueSet._backlink_attrs[ldname], val, obj)
            attr = Attribute.get_attribute(ldname)
        obj._raw_modattrs([(ldap.MOD_ADD,
                            ldname,
                            attr.py_to_ldap(val))])
        
    def remove(self, val):
        '''Remove a value from the set. Fails if it is not there'''
        ldname = self.attr.get_ldap_name()
        obj = self.obj
        attr = self.attr
        if ldname in ValueSet._backlink_attrs:
            (ldname, obj, val) = (ValueSet._backlink_attrs[ldname], val, obj)
            attr = Attribute.get_attribute(ldname)
        obj._raw_modattrs([(ldap.MOD_DELETE,
                            ldname,
                            attr.py_to_ldap(val))])
    
    def __iadd__(self, val):
        self.add(val)
        return self
    def __isub__(self, val):
        self.remove(val)
        return self



class SearchFilter(object):
    '''LDAP search filters. These specify a filter matching various conditions on an object
    based on the attributes of the object. See "from_raw_filter", "any", and "or" for how
    to construct them'''
    def __init__(self, _filterstr=None):
        assert _filterstr is not None
        self.filterstr = _filterstr

    @staticmethod
    def from_raw_filter(filt):
        '''Construct a search filter given an LDAP filter string'''
        return SearchFilter(_filterstr = filt)

    @staticmethod
    def match_everything():
        return SearchFilter.from_raw_filter("(objectClass=*)")

    @staticmethod
    def attr_match(name, val):
        '''Match a name->value pair of an attribute'''
        return Attribute.get_attribute(name).get_filter(val)

    @staticmethod
    def any(*filts, **keyvals):
        '''Construct a filter to match any of the given constraints. Non-keyword arguments
        must be SearchFilters, keyword arguments must be of the form attribute=value. e.g:
        SearchFilter.any(uid="mu", SearchFilter.any(member=somegroup, cn="foo"))

        SearchFilter.any() with no conditions matches everything'''
        filts = list(filts)
        for k,v in keyvals.iteritems():
            filts.append(Attribute.get_attribute(k).get_filter(v))
        if len(filts) == 0:
            return SearchFilter.match_everything()
        else:
            return SearchFilter.from_raw_filter("(|" + "".join(f.filterstr for f in filts) + ")")

    @staticmethod
    def all(*filts, **keyvals):
        '''Same as SearchFilter.any, but match all constraints rather than just one.
        SearchFilter.all() with no conditions is an error'''
        filts = list(filts)
        for k,v in keyvals.iteritems():
            filts.append(Attribute.get_attribute(k).get_filter(v))
        assert filts
        return SearchFilter.from_raw_filter("(&" + "".join(f.filterstr for f in filts) + ")")


    def inverse(self):
        '''The inverse of a filter: filter on things that do not match'''
        return SearchFilter.from_raw_filter("(!%s)" % self.filterstr)
    
    def __or__(self, other):
        '''a | b for SearchFilters a,b is shorthand for SearchFilter.any(a,b)'''
        return SearchFilter.any(self, other)
    def __and__(self, other):
        '''a & b for SearchFilters a,b is shorthand for SearchFilter.all(a,b)'''
        return SearchFilter.all(self, other)
    def __inv__(self):
        '''~a for a SearchFilter a is shorthand for a.inverse()'''
        return self.inverse()
