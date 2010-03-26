#!/usr/bin/env python
#
# Copyright (C) 2008 Boris Manojlovic <boris@steki.net>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
__author__="Boris Manojlovic"
__date__ ="$Mar 24, 2010 12:09:29 AM$"
__version__="0.1"
#############################################################
#
# What this script do....
# For start it needs:
#	python-pysnmp >= 4.1.10 (a must!)
# 	libsmi-0.4.8 >= (a must too :) )
#	python-pysnmp-mibs >= 0.0.5
#
# convert your mib files to pysnmp mib files and than
# you will be able to use this tool successfully
#
#############################################################

import pysnmp
import string
import sys
import re
from optparse import OptionParser
from pysnmp.smi import builder, view
from time import gmtime, strftime


SNMP_VERSION_MAP = {1:1, 2:4, 3:6 }

parser = OptionParser(version="%%prog  %s" % __version__)

parser.add_option("-i", "--input-file",
                  help="File containing snmpwalked device "
                  "'oids=result' mapped values",
                  metavar="FILENAME")

parser.add_option("-o", "--output-file", default='output.xml',
                  help="Output file where zabbix template will be written ",
                  metavar="FILENAME")

parser.add_option("-v", "--verbose", default=False,
                  action="store_true", dest="verbose",
                  help="very long names for items")

parser.add_option("-s", "--snmp-version",
                  type="int", default=1,
                  help="don't print status messages to stdout")

parser.add_option("-c", "--community",
                  metavar="public", default='public',
                  help="don't print status messages to stdout")

parser.add_option("-l", "--snmp-security-level",
                  type="int", default=0,
                  help="SNMPv3 security level")

parser.add_option("-n", "--snmp-security-name",
                  default='',
                  help="SNMPv3 security name")

parser.add_option("-a", "--snmp-auth-passphrase",
                  default='',
                  help="SNMPv3 auth passphrase")

parser.add_option("-p", "--snmp-priv-passphrase",
                  default='',
                  help="SNMPv3 priv passphrase")
(options, args) = parser.parse_args()

mibBuilder = builder.MibBuilder() # this takes too much time... but it load everything we need
mibBuilder.loadTexts=1
if len(sys.argv) < 2:
  parser.print_help(),
  exit(-1)


mibBuilder.loadModules()
mibViewController = view.MibViewController(mibBuilder)

def get_xmlheader():
  xml = '''<?xml version="1.0" encoding="UTF-8"?>
<zabbix_export version="1.0" date="%s" time="%s">
        <hosts>
                <host name="Template_%s">
                        <proxy_hostid>0</proxy_hostid>
                        <useip>1</useip>
                        <dns></dns>
                        <ip>127.0.0.1</ip>
                        <port>10050</port>
                        <status>3</status>
                        <useipmi>0</useipmi>
                        <ipmi_ip>127.0.0.1</ipmi_ip>
                        <ipmi_port>623</ipmi_port>
                        <ipmi_authtype>0</ipmi_authtype>
                        <ipmi_privilege>2</ipmi_privilege>
                        <ipmi_username></ipmi_username>
                        <ipmi_password></ipmi_password>
                        <groups>
                                <group>Templates</group>
                        </groups>
                        <triggers/>
                        <items>
''' % (strftime("%d.%m.%y", gmtime()),strftime("%H.%M", gmtime()), options.input_file.split('.')[0])
    # end of if
  return xml
  # end of get_xmlheader

def get_xmlfooter():
  xml = '''                        </items>
                        <templates/>
                        <graphs/>
                        <macros/>
                </host>
        </hosts>
        <dependencies/>
</zabbix_export>
'''
  return xml
  # end of get_xmlfooter

def get_xmlitems(data):
  xml = '''				<item type="%i" key="%s" value_type="%s">
					<description>%s</description>
					<ipmi_sensor></ipmi_sensor>
					<delay>30</delay>
					<history>90</history>
					<trends>365</trends>
					<status>0</status>
					<data_type>0</data_type>
					<units></units>
					<multiplier>0</multiplier>
					<delta>%s</delta>
					<formula>1</formula>
					<lastlogsize>0</lastlogsize>
					<logtimefmt></logtimefmt>
					<delay_flex></delay_flex>
					<authtype>0</authtype>
					<username></username>
					<password></password>
					<publickey></publickey>
					<privatekey></privatekey>
					<params></params>
					<trapper_hosts></trapper_hosts>
					<snmp_community>%s</snmp_community>
					<snmp_oid>%s</snmp_oid>
					<snmp_port>161</snmp_port>
					<snmpv3_securityname>%s</snmpv3_securityname>
					<snmpv3_securitylevel>%i</snmpv3_securitylevel>
					<snmpv3_authpassphrase>%s</snmpv3_authpassphrase>
					<snmpv3_privpassphrase>%s</snmpv3_privpassphrase>
					<applications/>
				</item>
''' % data
  return xml
  # end of get_xmlitems

if options.input_file == None:
    print "ERROR: Missing input filename <MANDATORY>"
    parser.print_help(),
    exit(-1)

out_file = open(options.output_file,'w')
in_file = open(options.input_file,'r')
p = re.compile('(\'|\"|<|>)')
newline = re.compile('(\\\\n)')
creturn = re.compile('(\\\\r)')

out_file.write( get_xmlheader())  # print header


for line in in_file.readlines():
    delta = 0  # default delta is 0
    oidlocal = line.split(' ')[0]
    try:
      modName, symName, suffix = mibViewController.getNodeLocation(pysnmp.proto.rfc1902.ObjectName(oidlocal))
    except:
      continue
    tup = string.join(map(str,suffix),'.')
    keyname = string.join((options.input_file.split('.')[0],symName,tup),'.')
    mibNode, = mibBuilder.importSymbols(modName, symName)
    try:
      valuetype = repr(mibNode.getSyntax())
      description = repr(mibNode.getDescription())
    except:
      valuetype="Integer"
      description = symName

    if keyname[-1] == '.':
      keyname = keyname[:-1]                    # don't save trailing dot
    description = newline.sub(' ', description) # replace \n with space...
    description = creturn.sub(' ', description) # replace \r with space...
    description = p.sub('',description)[0:254]  # remove all stupid quotes and clip to 255 chars (db max...)
    if len (description) == 0: 		        # if none add symName if nothing else...
      description = symName
    #print into xml....
    if re.compile("Intege").match(valuetype):
      valuetype = 3
    elif re.compile("Unsigned32").match(valuetype):
      valuetype = 3
    elif re.compile("Gauge").match(valuetype):
      valuetype = 3
    elif re.compile("IANAifType").match(valuetype):
      valuetype = 3
    elif re.compile("Counter").match(valuetype):
      valuetype = 3
    elif re.compile("SnmpAdminString").match(valuetype):
      valuetype = 4
    elif re.compile("InterfaceIndex").match(valuetype):
      valuetype = 3
    elif re.compile("IpAddress").match(valuetype):
      valuetype = 3
    elif re.compile("ObjectIdentifier").match(valuetype) or re.compile(".*Pointer").match(valuetype):
      continue	# not interested in OID objects (maybe)
    elif re.compile("AutonomousType").match(valuetype) or re.compile("ProductID").match(valuetype):
      continue	# not interested in OID objects (maybe)
    elif re.compile("IANAipRouteProtocol").match(valuetype):
      continue  # not interested in routing table...
    elif re.compile("InetAutonomousSystemNumber").match(valuetype):
      continue  # not interested in AS number? :) bellow it is ignored totally with all routing data
    elif re.compile("Bits").match(valuetype):
      continue  # what a hell is this???
    elif re.compile("OctetString").match(valuetype):
      valuetype = 4
    elif re.compile("PhysAddress").match(valuetype):
      valuetype = 1
    elif re.compile("RowStatus").match(valuetype):
      valuetype = 3
    elif re.compile("StorageType").match(valuetype):
      valuetype = 3
    elif re.compile("TestAndIncr").match(valuetype):
      valuetype = 3
    elif re.compile("TimeStamp").match(valuetype):
      valuetype = 3
    elif re.compile("TimeTick").match(valuetype):
      valuetype = 3
    elif re.compile(".*DisplayString").match(valuetype):
      valuetype = 1
    elif re.compile("KBytes").match(valuetype):
      valuetype = 1
    elif re.compile("DateAndTime").match(valuetype):
      valuetype = 1
    elif re.compile("TruthValue").match(valuetype):
      valuetype = 3
    elif re.compile("Float").match(valuetype):
      valuetype = 0
    elif valuetype == "None":
      valuetype = 3
    else:
        raise UnboundLocalError("Should NOT be here - UNKNOWN TYPE RETURNED\n\n valuetype=%s\noid=%s" % (valuetype,oidlocal))

    # with this we will specificaly show speed per second
    if re.compile("ifInOctets").match(symName) or re.compile("ifOutOctets").match(symName):
      delta = 1

    ################ complete removal of stufff...
    # not interested in vacm elements... (maybe someone need it I don't)
    if re.compile("^\.1\.3\.6\.1\.6\.3\.16").match(oidlocal) and not options.verbose:
      continue
    # ignoring atIfIndex, atPhysAddress, atNetAddress ...
    if re.compile("^\.1\.3\.6\.1\.2\.1\.3\.1\.1").match(oidlocal) and not options.verbose:
      continue
    # ignoring many...
    if re.compile("^\.1\.3\.6\.1\.2\.1\.4\.(19|20|21|23|24|34)").match(oidlocal) and not options.verbose:
      continue
    if re.compile("^\.1\.3\.6\.1\.2\.1\.6\.(13|19|20)").match(oidlocal) and not options.verbose:
      continue
    # ignoring udpLocalAddress
    if re.compile("^\.1\.3\.6\.1\.2\.1\.7\.(5|7)").match(oidlocal) and not options.verbose:
      continue
    # ignoring sysOR*
    if re.compile("^\.1\.3\.6\.1\.2\.1\.1\.(8|9)").match(oidlocal) and not options.verbose:
      continue
    # ignoring crazy stuff as processlist and so on...
    if re.compile("^\.1\.3\.6\.1\.2\.1\.25\.(3|4|5|6)").match(oidlocal) and not options.verbose:
      continue
    if re.compile("^\.1\.3\.6\.1\.2\.1\.(88|92)").match(oidlocal) and not options.verbose:
      continue
    ############## description changer
    # too long description and it is rather stupid to use it...
    if re.compile("^\.1\.3\.6\.1\.2\.1\.11").match(oidlocal) and not options.verbose:
      description = symName
    # too long description and it is rather stupid to use it...
    if re.compile("^\.1\.3\.6\.1\.6\.3\.1\.1\.6").match(oidlocal) and not options.verbose:
      description = symName
    # This one cleans most of descriptions so if you like more junk text just comment it :)
    # too long description and it is rather stupid to use it...
    if re.compile("^\.1\.3\.6\.1\.2\.1\.[1-6]\.").match(oidlocal) and not options.verbose:
      #print >>sys.stderr,oidlocal
      description = symName


    out_file.write(get_xmlitems((SNMP_VERSION_MAP[options.snmp_version],
                        keyname,
                        valuetype,
                        description,
                        delta,
                        options.community,
                        oidlocal[1:],
                        options.snmp_security_name,
                        options.snmp_security_level,
                        options.snmp_auth_passphrase,
                        options.snmp_priv_passphrase
                        )))



out_file.write( get_xmlfooter()) # finalize xml...

in_file.close()
out_file.close()

print "[DONE] output file=%s" % options.output_file
