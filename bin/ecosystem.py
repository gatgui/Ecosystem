#!/usr/bin/python

# Copyright (c) 2014, Peregrine Labs, a division of Peregrine Visual Storytelling Ltd. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#    * Redistributions of source code must retain the above copyright
#      notice, this list of conditions and the following disclaimer.
#
#    * Redistributions in binary form must reproduce the above copyright
#      notice, this list of conditions and the following disclaimer in the
#      documentation and/or other materials provided with the distribution.
#
#    * Neither the name of Peregrine Visual Storytelling Ltd., Peregrine Labs
#      and any of it's affiliates nor the names of any other contributors
#      to this software may be used to endorse or promote products derived
#      from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
# IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
# EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
# PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import os
import glob
import re
# import copy
import getopt
import sys
import string
import subprocess
import platform


def determine_number_of_cpus():
    """
    Number of virtual or physical CPUs on this system, i.e.
    user/real as output by time(1) when called with an optimally scaling
    userspace-only program
    """

    # Python 2.6+
    try:
        import multiprocessing
        return multiprocessing.cpu_count()
    except (ImportError, NotImplementedError):
        pass

    # POSIX
    try:
        res = int(os.sysconf('SC_NPROCESSORS_ONLN'))

        if res > 0:
            return res
    except (AttributeError, ValueError):
        pass

    # Windows
    try:
        res = int(os.environ['NUMBER_OF_PROCESSORS'])

        if res > 0:
            return res
    except (KeyError, ValueError):
        pass

    # jython
    try:
        from java.lang import Runtime
        runtime = Runtime.getRuntime()
        res = runtime.availableProcessors()
        if res > 0:
            return res
    except ImportError:
        pass

    # BSD
    try:
        sysctl = subprocess.Popen(['sysctl', '-n', 'hw.ncpu'], stdout=subprocess.PIPE)
        sc_stdout = sysctl.communicate()[0]
        res = int(sc_stdout)

        if res > 0:
            return res
    except (OSError, ValueError):
        pass

    # Linux
    try:
        res = open('/proc/cpuinfo').read().count('processor\t:')

        if res > 0:
            return res
    except IOError:
        pass

    # Solaris
    try:
        pseudo_devices = os.listdir('/devices/pseudo/')
        expr = re.compile('^cpuid@[0-9]+$')

        res = 0
        for pd in pseudo_devices:
            if expr.match(pd) is not None:
                res += 1

        if res > 0:
            return res
    except OSError:
        pass

    # Other UNIXes (heuristic)
    try:
        try:
            dmesg = open('/var/run/dmesg.boot').read()
        except IOError:
            dmesg_process = subprocess.Popen(['dmesg'], stdout=subprocess.PIPE)
            dmesg = dmesg_process.communicate()[0]

        res = 0
        while '\ncpu' + str(res) + ':' in dmesg:
            res += 1

        if res > 0:
            return res
    except OSError:
        pass

    raise Exception('Can not determine number of CPUs on this system')


# set up some global variables
NUMBER_OF_PROCESSORS = determine_number_of_cpus()
MAKE_COMMAND = ['make', '-j', str(NUMBER_OF_PROCESSORS)]
CLEAN_COMMAND = ['make', 'clean']
MAKE_TARGET = 'Unix Makefiles'
if platform.system().lower() == 'windows':
    MAKE_COMMAND = ['jom']
    CLEAN_COMMAND = ['jom', 'clean']
    MAKE_TARGET = 'NMake Makefiles'
ECO_SHELL = os.environ.get("ECO_SHELL", "csh")
ENV_REF_EXP = re.compile(r"\$\{([^}]*)\}")
VER_SPLIT_EXP = re.compile(r"^([^\d]+)(\d.*)$")
SEM_VER_EXP = re.compile(r"(\d+\.){2,}\d+")


class ValueWrapper(object):
    """Wraps a value to be held by a Variable"""

    def __init__(self, value=None):
        super(ValueWrapper, self).__init__()
        self._value = value

    @property
    def _current_os(self):
        return platform.system().lower()

    @property
    def value(self):
        if isinstance(self._value, dict):
            v1 = self._value.get(self._current_os, None)
            if v1:
                v2 = self._value.get("common", None)
                if v2:
                    v1 = ([v1] if not isinstance(v1, list) else v1)
                    v2 = ([v2] if not isinstance(v2, list) else v2)
                    return v1 + filter(lambda x: x not in v1, v2)
                else:
                    return v1
            else:
                return self._value.get("common", None)
        else:
            return self._value

    @property
    def strict_value(self):
        return self._value.get('strict', False) if isinstance(self._value, dict) else False

    @property
    def absolute_value(self):
        if isinstance(self._value, dict):
            abs_value = self._value.get('abs', False)
            return (self._current_os in self._value['abs']) if isinstance(abs_value, list) else abs_value
        return False


class ValueExpr(ValueWrapper):
    def __init__(self, value=None):
        super(ValueExpr, self).__init__(value=value)


class Variable(object):
    """Defines a variable required by a tool"""

    def __init__(self, name):
        super(Variable, self).__init__()
        self.name = name
        self.dependency_re = None
        self.dependents = []
        self.values = []
        self.dependencies = []
        self.strict = False    # Do not inherit existing environment
        self.absolute = False  # Make path absolute

    def list_dependencies(self, value):
        """Checks the value to see if it has any dependency on other Variables, returning them in a list"""
        try:
            self.dependency_re = self.dependency_re or re.compile(r"\${\w*}")
            matched = self.dependency_re.findall(value)
            if matched:
                dependencies = [match[2:-1] for match in matched if match[2:-1] != self.name]
                return list(set(dependencies))
        except:
            pass
        return []

    def substitute_at(self, value, **subst_keys):
        for k, v in subst_keys.iteritems():
            value = value.replace("@"+k, v)
        return value
    
    def append_value(self, value, **subst_keys):
        """Sets and/or appends a value to the Variable"""
        is_expr = False
        if isinstance(value, ValueExpr):
            # ValueExpr is already a value wrapper
            value_wrapper = value
            is_expr = True
        else:
            value_wrapper = ValueWrapper(value)
        # Strict and absolute merge logic:
        #   If any of the appended value is strict, all are strict
        #   If any of the appended value is absolute, all are absolute
        if not self.strict:
            self.strict = value_wrapper.strict_value
        if not self.absolute:
            self.absolute = value_wrapper.absolute_value
        v = value_wrapper.value
        if v is None:
            return
        vl = ([v] if not isinstance(v, list) else v)
        for v in vl:
            _is_expr = isinstance(v, ValueExpr)
            v = self.substitute_at(v.value if _is_expr else v, **subst_keys)
            if is_expr or _is_expr:
                try:
                    ev = eval(v)
                    if not isinstance(ev, list):
                        ev = [str(ev)]
                    else:
                        ev = map(str, ev)
                except Exception, e:
                    print("Failed to evaluate value expression: %s" % v)
                    continue
            else:
                ev = [v]
            for v in ev:
                if v not in self.values:
                    self.values.append(v)
                    for var_dependency in self.list_dependencies(v):
                        if not var_dependency in self.dependencies:
                            self.dependencies.append(var_dependency)

    def has_value(self):
        if len(self.values) > 0:
            return True
        return False

    def get_env(self):
        value = ''
        count = 0
        for var_value in self.values:
            if count != 0:
                value = value + os.pathsep
            # Do not make path absolute if it starts with a environment variable reference
            if self.absolute and not var_value.startswith("${"):
                pathpat = os.path.abspath(ENV_REF_EXP.sub("*", var_value)).replace("\\", "/")
                if len(glob.glob(pathpat)) > 0:
                    var_value = os.path.abspath(var_value).replace("\\", "/")
            value = value + var_value
            count += 1
        return value


class Version(object):
    def __init__(self, s=None):
        super(Version, self).__init__()
        if s is not None:
            self.value = s
            m = SEM_VER_EXP.match(self.value)
            self.semantic = (m is not None)
            if m is not None:
                spl = map(int, s.split("."))
                self.patch = spl[-1]
                self.min = spl[-2]
                self.maj = spl[-3]
                self.extra = spl[:-3]
        else:
            self.value = ""
            self.semantic = False
            self.maj = -1
            self.min = -1
            self.patch = -1
            self.extra = []
    
    def __str__(self):
        return self.value
    
    def __repr__(self):
        return self.value
    
    def __eq__(self, rhs):
        return (self.value == rhs.value)
    
    def __ne__(self, rhs):
        return (self.value != rhs.value)
    
    def __lt__(self, rhs):
        return self.is_older_than(rhs, inclusive=False)
    
    def __le__(self, rhs):
        return self.is_older_than(rhs, inclusive=True)
    
    def __gt__(self, rhs):
        return self.is_newer_than(rhs, inclusive=False)
    
    def __ge__(self, rhs):
        return self.is_newer_than(rhs, inclusive=True)
    
    def is_valid(self):
        return (self.value is not None)
    
    def clone(self):
        c = Version()
        c.value = self.value
        c.semantic = self.semantic
        c.maj = self.maj
        c.min = self.min
        c.patch = self.patch
        c.extra = self.extra[:]
        return c
    
    def is_newer_than(self, rhs, inclusive=True):
        if self.semantic and rhs.semantic:
            if len(self.extra) != len(rhs.extra):
                return False
            for i in xrange(len(self.extra)):
                if self.extra[i] > rhs.extra[i]:
                    return True
                elif self.extra[i] < rhs.extra[i]:
                    return False
            if self.maj > rhs.maj:
                return True
            elif self.maj < rhs.maj:
                return False
            if self.min > rhs.min:
                return True
            elif self.min < rhs.min:
                return False
            if self.patch > rhs.patch:
                return True
            elif self.patch < rhs.patch:
                return False
            return (True if inclusive else False)
        else:
            if inclusive:
                return (self.value == rhs.value)
            else:
                return False
    
    def is_older_than(self, rhs, inclusive=True):
        if self.semantic and rhs.semantic:
            if len(self.extra) != len(rhs.extra):
                return False
            for i in xrange(len(self.extra)):
                if self.extra[i] < rhs.extra[i]:
                    return True
                elif self.extra[i] > rhs.extra[i]:
                    return False
            if self.maj < rhs.maj:
                return True
            elif self.maj > rhs.maj:
                return False
            if self.min < rhs.min:
                return True
            elif self.min > rhs.min:
                return False
            if self.patch < rhs.patch:
                return True
            elif self.patch > rhs.patch:
                return False
            return (True if inclusive else False)
        else:
            if inclusive:
                return (self.value == rhs.value)
            else:
                return False
    
    def is_compatible(self, rhs, forward_only=False):
        if self.semantic and rhs.semantic:
            if self.extra == rhs.extra and self.maj == rhs.maj:
                return (self.min == rhs.min if forward_only else self.min >= rhs.min)
            else:
                return False
        else:
            return (self.value == rhs.value)


class Requirement(object):
    def __init__(self, s=None):
        super(Requirement, self).__init__()
        
        self.name = None
        self.fix = None
        self.upper = None
        self.upper_strict = False
        self.lower = None
        self.lower_strict = False
        
        if s is not None:
            restriction = 0
            if s.endswith("+"):
                restriction = 1
                s = s[:-1]
            elif s.endswith("-"):
                restriction = -1
                s = s[:-1]
            
            m = SEM_VER_EXP.search(s)
            
            if m is not None:
                if s[m.end(0):]:
                    raise Exception("Invalid requirement specification: '%s'" % s)
                
                self.name = s[:m.start(0)]
                
                v = Version(m.group(0))
                
                if restriction == 0:
                    self.fix = v
                elif restriction == 1:
                    self.lower = v
                else:
                    self.upper = v
            
            else:
                if restriction != 0:
                    raise Exception("Invalid requirement specification: '%s' (+/- only available for semantic versioning)" % s)
                
                m = VER_SPLIT_EXP.match(s)
                
                if m is not None:
                    self.name = self.group(1)
                    vs = self.group(2)
                    if vs:
                        self.fix = Version(vs)
                else:
                    self.name = s
    
    def __str__(self):
        s = ""
        if self.name is not None:
            if self.fix is not None:
                s += " %s" % self.fix
            else:
                if self.lower is not None:
                    s += " %s%s" % ((">" if self.lower_strict else ">="), self.lower)
                if self.upper is not None:
                    if s:
                        s += ","
                    s += " %s%s" % (("<" if self.upper_strict else "<="), self.upper)
            s = self.name + s
        return s
    
    def __repr__(self):
        return str(self)
    
    def is_valid(self):
        return (self.name is not None)
    
    def is_fixed(self):
        return (self.is_valid() and self.fix is not None)
    
    def is_flexible(self):
        return (self.is_valid() and self.fix is None)
    
    def is_free(self):
        return (self.is_valid() and self.fix is None and self.upper is None and self.lower is None)
    
    def clone(self):
        r = Requirement()
        r.name = self.name
        r.fix = (None if self.fix is None else self.fix.clone())
        r.upper = (None if self.upper is None else self.upper.clone())
        r.upper_strict = self.upper_strict
        r.lower = (None if self.lower is None else self.lower.clone())
        r.lower_strict = self.lower_strict
        return r
    
    def matches(self, ver, check_compatibility=True):
        # Only check compatibility if requirement is not a range (?)
        if self.fix is not None:
            return (ver == self.fix)
        
        if self.upper is not None:
            if ver.is_newer_than(self.upper, inclusive=self.upper_strict):
                return False
            if self.lower is None and check_compatibility and not self.upper.is_compatible(ver, forward_only=False):
                #print("[1] %s and %s are not compatible" % (ver, self.upper))
                return False
        
        if self.lower is not None:
            if ver.is_older_than(self.lower, inclusive=self.lower_strict):
                return False
            if self.upper is None and check_compatibility and not ver.is_compatible(self.lower, forward_only=False):
                #print("[2] %s and %s are not compatible" % (ver, self.lower))
                return False
        
        return True
    
    def merge(self, rhs, in_place=False):
        if rhs.name != self.name:
            return (False if in_place else None)
        
        if self.fix is not None:
            if rhs.fix is not None and self.fix == rhs.fix:
                return (True if in_place else self.clone())
            else:
                return (False if in_place else None)
        
        else:
            c = (self if in_place else self.clone())
            
            if rhs.fix is not None:
                # does it fall in [lower, upper] range
                if c.lower is not None and rhs.fix.is_older_than(c.lower, inclusive=c.lower_strict):
                    return (False if in_place else None)
                
                if c.upper is not None and rhs.fix.is_newer_than(c.upper, inclusive=c.upper_strict):
                    return (False if in_place else None)
                
                c.fix = rhs.fix
                c.lower = None
                c.lower_strict = False
                c.upper = None
                c.upper_strict = False
            
            else:
                lower = c.lower
                lower_strict = c.lower_strict
                if lower is None or (rhs.lower is not None and rhs.lower.is_newer_than(lower, inclusive=True)):
                    lower = rhs.lower
                    lower_strict = rhs.lower_strict
                
                upper = c.upper
                upper_strict = c.upper_strict
                if upper is None or (rhs.upper is not None and rhs.upper.is_older_than(upper, inclusive=True)):
                    upper = rhs.upper
                    upper_strict = rhs.upper_strict
                
                if upper is not None and \
                   lower is not None and \
                   (upper.is_older_than(lower, lower_strict) or \
                    lower.is_newer_than(upper, upper_strict)):
                    return (False if in_place else None)
                
                c.upper = upper
                c.upper_strict = upper_strict
                c.lower = lower
                c.lower_strict = lower_strict
                
                if c.lower is not None and c.upper is not None and c.lower == c.upper:
                    if c.lower_strict or c.upper_strict:
                        return (False if in_place else None)
                    c.fix = c.lower
                    c.lower = None
                    c.upper = None
            
            return (True if in_place else c)


class Tool(object):
    """Defines a tool - more specifically, a version of a tool"""
    
    def __init__(self, filename):
        super(Tool, self).__init__()
        try:
            with open(filename, 'r') as f:
                self.in_dictionary = eval(f.read(), globals(), {"eval": ValueExpr})
            
            if self.in_dictionary:
                self.path = os.path.abspath(os.path.dirname(filename)).replace("\\", "/")
                self.tool = self.in_dictionary['tool']
                self.version = Version(self.in_dictionary['version'])
                self.platforms = self.in_dictionary['platforms']
                self.requirements = []
                for req in self.in_dictionary['requires']:
                    self.requirements.append(Requirement(req))
        except IOError:
            print 'Unable to find file {0} ...'.format(filename)
        except Exception, e:
            print('Failed to read tool environment: %s' % filename)
            raise e
    
    @property
    def platform_supported(self):
        """Check to see if the tool is supported on the current platform"""
        return platform.system().lower() in self.platforms if self.platforms else False
    
    def get_vars(self, env):
        for name, value in self.in_dictionary['environment'].items():
            if name not in env.variables:
                env.variables[name] = Variable(name)
            env.variables[name].append_value(value, path=self.path, platform=platform.system().lower(), tool=self.tool, version=str(self.version))
        
        # check for optional parameters
        if 'optional' in self.in_dictionary:
            for optional_name, optional_value in self.in_dictionary['optional'].items():
                if optional_name in env.tools:
                    for name, value in optional_value.items():
                        if name not in env.variables:
                            env.variables[name] = Variable(name)
                        env.variables[name].append_value(value, path=self.path, platform=platform.system().lower(), tool=self.tool, version=str(self.version))


def list_tools(verbose=False):
    environment_files = []
    environment_file_names = set()
    environment_locations = os.getenv('ECO_ENV')

    if environment_locations:
        for environment_location in environment_locations.split(os.pathsep):
            if verbose:
                sys.stderr.write("Process directory \"%s\"\n" % environment_location)
            for environment_file in glob.glob(environment_location + "/*.env"):
                if verbose:
                    sys.stderr.write("  Process file \"%s\"\n" % environment_file)
                file_name = os.path.basename(environment_file)
                ignore = (file_name in environment_file_names)
                if not ignore:
                    if sys.platform == "win32":
                        ignore = (file_name.lower() in environment_file_names)
                    if not ignore:
                        environment_file_names.add(file_name)
                        environment_files.append(environment_file)
                    else:
                        if verbose:
                            sys.stderr.write("    Already processed\n")
                else:
                    if verbose:
                        sys.stderr.write("    Already processed\n")

    return [Tool(file_path) for file_path in environment_files]


def list_available_tools(verbose=False):
    return sorted([t.tool + str(t.version) for t in list_tools(verbose)])


class Environment(object):
    """Once initialized this will represent the environment defined by the wanted tools"""
    def __init__(self, wants, environment_directory=None, force=False, verbose=False):
        super(Environment, self).__init__()
        self.tools = {}  # tool name -> (tool object, reference count)
        self.variables = {}
        self.wants = {}  # tool name -> Requirement
        self.success = True
        self.force = force

        for want in wants:
            req = Requirement(want)
            creq = self.wants.get(req.name, req)
            if creq != req and not creq.merge(req, in_place=True):
                raise Exception("Invalid wants")
            self.wants[req.name] = creq

        possible_tools = list_tools(verbose)
        versions = {}  # tool name -> Requirement

        versioned_tools = {}
        for t in possible_tools:
            if not t.version.is_valid():
                continue
            versioned_tools[t.tool + str(t.version)] = t

        # Local helper function
        def unref_dependencies(tool):
            for dependency in tool.requirements:
                to, rc = self.tools.get(dependency.name, (None, 0))
                if to is not None:
                    rc -= 1
                    if rc == 0:
                        if verbose:
                            sys.stderr.write("Remove tool requirement: %s\n" % dependency.name)
                        unref_dependencies(to)
                        del(self.tools[dependency.name])
        
        
        wants_changed = True
        loop_count = 1
        
        while wants_changed:
            if verbose:
                sys.stderr.write("=== Loop existing tools %d\n" % loop_count)
                sys.stderr.write("=> Resolved so far: %s\n" % versions.values())
                sys.stderr.write("=> Wanted list: %s\n" % self.wants.values())
            loop_count += 1
            
            wants_changed = False
            
            for new_tool in possible_tools:
                if new_tool.platform_supported:
                    # Check if tool is wanted
                    if new_tool.tool in self.wants:
                        # Check if new_tool matches requirements
                        # Note: wants requirements includes current environment requirements
                        req = self.wants[new_tool.tool]
                        if verbose:
                            sys.stderr.write("Check %s %s against %s\n" % (new_tool.tool, new_tool.version, req))
                        if not req.matches(new_tool.version):
                            if verbose:
                                sys.stderr.write("Skip %s %s: doesn't match requirements (%s)\n" % (new_tool.tool, new_tool.version, req))
                            continue
                        
                        # Check against current environment version
                        cur_tool, ref_cnt = self.tools.get(new_tool.tool, (None, 1))
                        
                        # cur_tool.version
                        cur_req = versions.get(new_tool.tool, None)
                        
                        if cur_tool is not None:
                            # Tool was already required, check if version requirement matches
                            if cur_tool.version != new_tool.version:
                                if verbose:
                                    sys.stderr.write("%s already required: %s\n" % (cur_tool.tool, cur_tool.version))
                                
                                if cur_req is not None and not cur_req.matches(new_tool.version):
                                    raise Exception("Version conflict for tool: %s %s %s %s" % (new_tool.tool, new_tool.version, op, cur_tool.version))
                                
                                if new_tool.version.is_older_than(cur_tool.version, inclusive=False):
                                    if verbose:
                                        sys.stderr.write("Skip older tool version: %s %s (< %s)\n" % (new_tool.tool, new_tool.version, cur_tool.version))
                                    continue
                                
                                if verbose:
                                    sys.stderr.write("Update tool version: %s %s -> %s\n" % (new_tool.tool, cur_tool.version, new_tool.version))
                            
                            else:
                                # Same tool, same version, nothing specific to do
                                continue
                        
                        dependencies_conflict = False
                        dependencies_change_wants = False
                        dependencies_reqs = {}
                        conflict_message = ""
                        
                        # Loop though tool additional requirements
                        for dependency in new_tool.requirements:
                            # Merge wants requirements
                            if dependency.name in self.wants:
                                new_req = self.wants[dependency.name].merge(dependency)
                                if new_req is None:
                                    # Check if dependency.name in self.tools?
                                    dependencies_conflict = True
                                    conflict_message = "Skip %s %s: requirements conflict (%s / %s)" % (new_tool.tool, new_tool.version, self.wants[dependency.name], dependency)
                                    break
                            else:
                                dependencies_change_wants = True
                                new_req = dependency.clone()
                            
                            # Check against current environment
                            if dependency.name in self.tools:
                                dreq = versions[dependency.name]
                                
                                if not new_req.merge(dreq, in_place=True):
                                    dependencies_conflict = True
                                    conflict_message = "Skip %s %s: environment conflict (%s / %s)" % (new_tool.tool, new_tool.version, new_req, dreq)
                                    break
                            
                            dependencies_reqs[dependency.name] = new_req
                        
                        # Skip tool if dependencies cannot be satisfied
                        if dependencies_conflict:
                            if verbose:
                                sys.stderr.write("%s\n" % conflict_message)
                            continue
                        else:
                            wants_changed = (wants_changed or dependencies_change_wants)
                        
                        # Loop through dependencies a second time to increments references and update wanted list
                        for dependency in new_tool.requirements:
                            if dependency.name in self.tools:
                                tool, refcnt = self.tools[dependency.name]
                                self.tools[dependency.name] = (tool, refcnt + 1)
                            
                            self.wants[dependency.name] = dependencies_reqs[dependency.name]
                        
                        
                        if verbose:
                            sys.stderr.write("Add tool %s %s\n" % (new_tool.tool, new_tool.version))
                        
                        
                        if cur_tool is not None and cur_tool.version != new_tool.version:
                            # We're replacing cur_tool with new_tool, as such we should remove all its requirements too
                            # Note that other tools may have the same requirements so that requirements should
                            #   be reference counted and removed only when no other tool require them
                            unref_dependencies(cur_tool)
                        
                        # Replace tool version, keeping the same reference count
                        self.tools[new_tool.tool] = (new_tool, ref_cnt)
                        
                        # Update version requirements
                        if cur_req is not None:
                            if verbose:
                                sys.stderr.write("  -> merge wants requirements %s in %s\n" % (req, cur_req))
                            if not cur_req.merge(req, in_place=True):
                                # Note: we should not reach this block
                                raise Exception("%s %s requirements conflict (%s / %s)" % (cur_tool.tool, cur_tool.version, cur_req, req))
                        else:
                            if verbose:
                                sys.stderr.write("  -> set requirements to wants requirements\n")
                            cur_req = req.clone()
                        
                        # Update version requirement info
                        versions[new_tool.tool] = cur_req
                        if verbose:
                            sys.stderr.write("  -> requirements: %s\n" % cur_req)
                        
                        # Remove from wanted list if it is an exact version
                        if cur_req.is_fixed() and new_tool.tool in self.wants:
                            if verbose:
                                sys.stderr.write("  -> version was fixed, remove from wants\n")
                            del(self.wants[new_tool.tool])
            
            if wants_changed:
                if verbose:
                    sys.stderr.write("=> Wanted list: %s\n" % self.wants.values())
                for n in self.wants.keys():
                    vr = self.wants[n]
                    if n in self.tools:
                        t = self.tools[n]
                        if vr.matches(t[0].version):
                            if verbose:
                                sys.stderr.write("  Remove %s from wanted list\n" % n)
                            del(self.wants[n])
                    
        
        # clean remaining wants that are in the environment and have flexible version
        changed = True
        while changed:
            changed = False
            for n in self.wants.keys():
                if n in self.tools:
                    changed = True
                    del(self.wants[n])
                break
        
        if len(self.wants) != 0:
            missing_tools = ', '.join([k for k, _ in self.wants.iteritems()])
            print 'Unable to resolve all of the required tools ({0} is missing).\nPlease check your list and try again!'.format(missing_tools)
            if verbose:
                sys.stderr.write("Successfully Resolved: %s\n" % versions.keys())
            self.success = False

        for tool_name, tool in self.tools.items():
            tool[0].get_vars(self)

        # check and see if any of the variables dependencies are defined locally to the tool or are considered external
        ext_dependencies = []
        for name, var in self.variables.items():
            if var.dependencies:
                for dep in var.dependencies:
                    if dep not in self.variables:
                        if dep not in ext_dependencies:
                            ext_dependencies.append(dep)
                    else:
                        self.variables[dep].dependents.append(name)

        # now check to see if they're already set in the environment
        missing_dependencies = set([dep for dep in ext_dependencies if not os.getenv(dep)])
        if missing_dependencies:
            missing_vars = ', '.join(missing_dependencies)
            print 'Unable to resolve all of the required variables ({0} is missing).\nPlease check your list and try again!'.format(missing_vars)
            self.success = False

    def get_var(self, var):
        if self.success:
            if var.name not in self.defined_variables:
                for dependency in var.dependencies:
                    if dependency in self.variables:
                        self.get_var(self.variables[dependency])
                var_value = var.get_env()
                if platform.system().lower() == 'windows':
                    self.value = self.value + 'set ' + var.name + '=' + ENV_REF_EXP.sub(r"%\1%", var_value)
                elif ECO_SHELL == 'csh':
                    self.value = self.value + 'setenv ' + var.name + ' ' + var_value
                else:
                    self.value = self.value + var.name + '=' + ENV_REF_EXP.sub(r"$\1", var_value)
                if os.getenv(var.name):
                    if not self.force and not var.strict:
                        if platform.system().lower() == 'windows':
                            var_ref = '%' + var.name + '%'
                        elif ECO_SHELL == 'csh':
                            var_ref = '${' + var.name + '}'
                        else:
                            var_ref = '$' + var.name
                        if var_value == '':
                            self.value = self.value + var_ref
                        else:
                            self.value = self.value + os.pathsep + var_ref
                self.value = self.value + '\n'
                self.defined_variables.append(var.name)

    def get_var_env(self, var):
        if self.success:
            if var.name not in self.defined_variables:
                for dependency in var.dependencies:
                    if dependency in self.variables:
                        self.get_var_env(self.variables[dependency])
                var_value = var.get_env()
                if var.name in os.environ:
                    if not self.force and not var.strict:
                        if var_value == '':
                            var_value = os.environ[var.name]
                        else:
                            var_value = var_value + os.pathsep + os.environ[var.name]
                self.defined_variables.append(var.name)
                os.environ[var.name] = var_value

    def get_env(self, set_environment=False):
        # combine all of the variable in all the tools based on a dependency list
        if self.success:
            self.defined_variables = []
            self.value = '# Environment created via Ecosystem\n'

            for var_name, variable in self.variables.items():
                if self.variables[var_name].has_value():
                    if not set_environment:
                        self.get_var(variable)
                    else:
                        self.get_var_env(variable)

            if not set_environment:
                return self.value

            # TODO check if we need this repetition
            for env_name, env_value in os.environ.items():
                os.environ[env_name] = os.path.expandvars(env_value)
            for env_name, env_value in os.environ.items():
                os.environ[env_name] = os.path.expandvars(env_value)


def call_process(arguments):
    if type(arguments) in (unicode, str):
        subprocess.call(arguments, shell=True)
    else:
        subprocess.call(arguments)


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    # Don't rely on argparse to retrieve the command to and its arguments
    #   (while it as a nargs='+' option for an argument, it stills insist on
    #    interpreting the arguments collected as if it were its own arguments...)
    # Any arguments after the -r/--run flag will be considered as part of the command to run
    # This allows use of commands arguments and flags without having the need to double quote them:
    #   eco -t maya2014 -r maya -command "print(\"hello\\n\")"
    # instead of:
    #   eco -t fx_maya -r "maya -command \"print(\\\"hello\\\\n\\\");\""
    run_application = None
    
    idx = (argv.index("-r") if "-r" in argv else (argv.index("--run") if "--run" in argv else None))
    if idx is not None:
        run_application = argv[idx+1:]
        nargs = len(run_application)
        if nargs == 0:
            run_application = None
        elif nargs == 1:
            run_application = run_application[0]
        argv = argv[:idx]

    # parse the (command line) arguments; python 2.7+ (or download argparse)
    import argparse
    description = 'Peregrine Ecosystem, environment, build and deploy management toolset v0.6.0'
    parser = argparse.ArgumentParser(prog='ecosystem',
                                     formatter_class=argparse.RawTextHelpFormatter,
                                     description=description,
                                     add_help=False,
                                     epilog='''
Example:
    python ecosystem.py -t maya2014,vray3.05,yeti1.3.0 -r maya
                                     ''')
    parser.add_argument('-t', '--tools', type=str, default=None,
                        help='specify a list of tools required separated by commas')
    parser.add_argument('-l', '--listtools', action='store_true',
                        help='list the available tools')
    parser.add_argument('-b', '--build', action='store_true',
                        help='run the desired build process')
    parser.add_argument('-d', '--deploy', action='store_true',
                        help='build and package the tool for deployment')
    parser.add_argument('-f', '--force', action='store_true',
                        help='force the full CMake cache to be rebuilt')
    parser.add_argument('-m', '--make', action='store_true',
                        help='just run make')
    parser.add_argument('-s', '--setenv', action='store_true',
                        help='output setenv statements to be used to set the shells environment')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='verbose output')
    parser.add_argument('-h', '--help', action='store_true',
                        help='show this help')

    args = parser.parse_args(argv)

    if args.help:
        parser.print_help()
        return 0

    if args.listtools:
        for tool in list_available_tools(args.verbose):
            print tool
        return 0

    tools = args.tools.split(',') if args.tools is not None else []
    set_environment = args.setenv
    force_rebuild = args.force
    quick_build = args.make
    run_build = args.build
    deploy = args.deploy
    if deploy:
        force_rebuild = True
        run_build = True
        quick_build = False

    try:
        if run_build:
            env = Environment(tools, verbose=args.verbose)
            if env.success:
                env.get_env(os.environ)
                build_type = os.getenv('PG_BUILD_TYPE')

                if not quick_build:
                    if force_rebuild:
                        try:
                            open('CMakeCache.txt')
                            os.remove('CMakeCache.txt')
                        except IOError:
                            print "Cache doesn't exist..."

                    call_process(['cmake', '-DCMAKE_BUILD_TYPE={0}'.format(build_type), '-G', MAKE_TARGET, '..'])

                if deploy:
                    MAKE_COMMAND.append("package")

                call_process(MAKE_COMMAND)

        elif run_application:
            env = Environment(tools, verbose=args.verbose)
            if env.success:
                env.get_env(os.environ)
                call_process(run_application)

        elif set_environment:
            env = Environment(tools, verbose=args.verbose)
            if env.success:
                output = env.get_env()
                if output:
                    print output
        return 0
    except Exception, e:
        import traceback
        sys.stderr.write('ERROR: {0:s}\n'.format(str(e)))
        traceback.print_exc(file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
