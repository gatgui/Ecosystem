import sys
sys.path.insert(0, ".")

import ecosystem

r0 = ecosystem.Requirement("tool2.0.0+")
r1 = ecosystem.Requirement("tool2.13.3-")
r2 = r0.merge(r1)

v0 = ecosystem.Version("2.13.5")
v1 = ecosystem.Version("1.12.0")
v2 = ecosystem.Version("2.12.3")

print("%s matches %s ? %s [True]"  % (v0, r0, r0.matches(v0)))
print("%s matches %s ? %s [False]" % (v1, r0, r0.matches(v1)))
print("%s matches %s ? %s [True]"  % (v2, r0, r0.matches(v2)))
print("%s matches %s ? %s [False]" % (v0, r1, r1.matches(v0)))
print("%s matches %s ? %s [False]" % (v1, r1, r1.matches(v1)))
print("%s matches %s ? %s [True]"  % (v2, r1, r1.matches(v2)))
print("%s matches %s ? %s [False]" % (v0, r2, r2.matches(v0)))
print("%s matches %s ? %s [False]" % (v1, r2, r2.matches(v1)))
print("%s matches %s ? %s [True]"  % (v2, r2, r2.matches(v2)))
