#!/usr/bin/python
################################################################################
#                                                                              #
#    Licensed under the Apache License, Version 2.0 (the "License"); you may   #
#    not use this file except in compliance with the License. You may obtain   #
#    a copy of the License at                                                  #
#                                                                              #
#         http://www.apache.org/licenses/LICENSE-2.0                           #
#                                                                              #
#    Unless required by applicable law or agreed to in writing, software       #
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT #
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the  #
#    License for the specific language governing permissions and limitations   #
#    under the License.                                                        #
#                                                                              #
################################################################################
import pan.xapi
import xml.etree.ElementTree as ET
import sys
import requests
import acitoolkit.acitoolkit as aci
import re
import yaml

config = yaml.load(open('/usr/lib/yaml/creds.yaml'))
#These define the username and password used for both the firewall and APIC.  In this case the username/passwords are the same for both.
name = config['user']['user']
pwd = config['user']['password']
#This creates and defines the set of information used to pull EGP Endpoints and populate vsys.  The format of the sets is ('Tenant','EGP-NAME', 'PANW VSYS')
ten_epg_vsys=set()
ten_epg_vsys = (('Demo1','Demo1-L2-S2','vsys3'),('Demo1','Demo1-L2-S1','vsys3'),('Demo1','DB-L3-EPG','vsys3'),\
('Demo1','Web-L3-EPG','vsys3'),('Demo-2','WEB-EPG-L3','vsys4'),('Demo-2','Demo2-L2-S2','vsys4'),('Demo-2','Demo2-L2-S1','vsys4'),\
('Demo-2','DB-EPG-L3','vsys4'),('Demo1','Demo1-L2-S2','vsys6'),('Demo1','Demo1-L2-S1','vsys6'),('Demo1','DB-L3-EPG','vsys6'),\
('Demo1','Web-L3-EPG','vsys6'),('Demo-2','WEB-EPG-L3','vsys6'),('Demo-2','Demo2-L2-S2','vsys6'),('Demo-2','Demo2-L2-S1','vsys6'),('Demo-2','DB-EPG-L3','vsys6'))
# Define the IP of the firewall
firewallip='10.3.4.243'
#This is a lazy list of vsys that are in the above set.
dagvsyslist=('vsys3','vsys4','vsys6')


def FW_Commit(Firewall,fwkey):
	#Commit and monitor commit job for completion
	call = "https://%s/api/?type=commit&cmd=<commit><force></force></commit>&key=%s" % (Firewall, fwkey)
	r = requests.get(call, verify=False)
	tree = ET.fromstring(r.text)
	jobid = tree[0][1].text
	print "Commit job - " + str(jobid)
	committed = 0
	while (committed == 0):
		call = "https://%s/api/?type=op&cmd=<show><jobs><id>%s</id></jobs></show>&key=%s" % (Firewall, jobid, fwkey)
		r = requests.get(call, verify=False)
		tree = ET.fromstring(r.text)
		if (tree[0][0][5].text == 'FIN'):
			print "Commit status - " + str(tree[0][0][5].text) + " " + str(tree[0][0][12].text) + "% complete"
			committed = 1
		else:
			status = "Commit status - " + str(tree[0][0][5].text) + " " + str(tree[0][0][12].text) + "% complete"
			print '{0}\r'.format(status),


def DAG_Exists(Firewall,fwkey,Tag,fwvsys):
	type = "op"
	cmd = "<show><object><dynamic-address-group><all></all></dynamic-address-group></object></show>"
	call = "https://%s/api/?type=%s&cmd=%s&key=%s&vsys=%s" % (Firewall, type, cmd, fwkey ,fwvsys)
	fw_results=requests.get(call, verify=False)
	if fw_results.status_code == 200:
		foundit = 0
		root = ET.fromstring(fw_results.text)
		for entry in root.findall("./result/dyn-addr-grp/entry"):
			name = entry.find('group-name')
			vsys = entry.find('vsys')
			#print name.text,vsys.text
			if (name.text == Tag and vsys.text == fwvsys):
				#print name.text,vsys.text
				foundit = 1
	if foundit == 1:
		return 1
	else:
		return 0

def DAG_Create(Firewall,fwkey,Tag,vsys):
    #print "Tag = %s" % Tag
    type = "config"
    action = "set"
    xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='%s']/address-group/entry[@name='"%(vsys) + Tag + "']/dynamic"
#    print xpath
    element = "<filter>'" + Tag + "'</filter>"
    call = "https://%s/api/?type=%s&action=%s&xpath=%s&element=%s&key=%s" % (Firewall, type, action, xpath, element,fwkey)
    fw_results=requests.get(call, verify=False)
    if fw_results.status_code == 200:
        root = ET.fromstring(fw_results.text)
        if root.attrib['status'] == "success":
            return 1
        else:
            return 0
    else:
        return 0

def pan_apikey(puser, ppass, phost):
    try:
        pxapi = pan.xapi.PanXapi(api_username=puser, api_password=ppass, hostname=phost)
        key = pxapi.keygen()
    except:
        print "\nFAILURE: Wrong credentials or hostname/IP.\n"
        sys.exit()
    return key
    
def regdynamic(apikey, host, add, remove, fwvsys):
    """Register Dynamic Address Object."""
    type = "user-id"

    xml_blob = "<uid-message><version>1.0</version><type>update</type><payload><register>"
    if add !=0:
        for value in add: 
            xml_blob+='<entry identifier="%s" ip="%s"/>' % (value[1], value[0])
    xml_blob +="</register><unregister>"
    if remove !=0:
        for value2 in remove: 
            xml_blob+='<entry identifier="%s" ip="%s"/>' % (value2[1], value2[0])
    xml_blob +="</unregister></payload></uid-message>"
    #print xml_blob
    call = "https://%s/api/?type=%s&vsys=%s&cmd=%s&key=%s" % (host, type, fwvsys, xml_blob, apikey)
    #print call
    fw_results=requests.get(call, verify=False)
    if fw_results.status_code == 200:
        root = ET.fromstring(fw_results.text)
        if root.attrib['status'] == "success":
            return 1
        else:
            return 0
    else:
        return 0

def apicepg(url,login,password,epglist):
	# Login to an APIC and retrieve EPG information
	#print epglist
	epgiplist=set()
	modepgip=set()
	modten=()
	session = aci.Session(url, login, password)
	resp = session.login()
	if not resp.ok:
		print '%% Could not login to APIC'
		sys.exit(0)

	# Download all of the Endpoints and store desired ones in a set
	endpoints = aci.Endpoint.get(session)
	for ep in endpoints:
		try:
			epg = ep.get_parent()
		except AttributeError:
			continue
		app_profile = epg.get_parent()
		tenant = app_profile.get_parent()
		if ep.if_dn:
			for dn in ep.if_dn:
				match = re.match('protpaths-(\d+)-(\d+)', dn.split('/')[2])
				if match:
					if match.group(1) and match.group(2):
						int_name = "Nodes: " + match.group(1) + "-" + match.group(2) + " " + ep.if_name
		else:
			int_name = ep.if_name
		try:
			data = (ep.mac, ep.ip, tenant.name, app_profile.name, epg.name,ep.if_name, ep.timestamp)
			modepg='%s--%s'%(tenant.name,epg.name)
			for modten in epglist:
				#print modten[0],'==',modepg,"!"
				if modepg == modten[0]:
					modepgip=(ep.ip,modepg,modten[1])
					print modepgip
					epgiplist.add(modepgip)
					#print data
		except ValueError, e:
			continue
	return epgiplist

def DAG_Membership(Firewall,fwkey,Tag,virtualsys):
	out=()
	output = set()
	type = "op"
	cmd = "<show><object><dynamic-address-group><name>%s</name></dynamic-address-group></object></show>" % Tag
	call = "https://%s/api/?type=%s&cmd=%s&key=%s&vsys=%s" % (Firewall, type, cmd, fwkey, virtualsys)
	fw_results=requests.get(call, verify=False)
	if fw_results.status_code == 200:
		root = ET.fromstring(fw_results.text)
		for entry in root.findall("./result/dyn-addr-grp/entry"):
			name = entry.find('group-name')
			members = entry.findall('member-list/entry')
			if name.text == Tag:
				for member in members:
					out=(member.find('.').attrib['name'], Tag, virtualsys)
					output.add(out)
	#print output
	return output

def main(luser,lpass,lhost,tenepgvsys):
	tagip=set()
	aciip=set()
	removeip=set()
	fwdaglist=set()
	desireddaglist=set()
	updatedaglist=set()
	deldag=set()
	tempDAGMembers=set()
	lkey = pan_apikey(puser=luser, ppass=lpass, phost=lhost)

#   create desired DAGS list
	print "\nThis is the list of DAGS that are going to be checked: "
	for n in tenepgvsys:
		#desireddaglist = ['Demo1--Demo1-L2-S2', 'Demo1--Demo1-L2-S1', 'Demo1--DB-L3-EPG', 'Demo1--Web-L3-EPG', 'Demo-2--WEB-EPG-L3', 'Demo-2--Demo2-L2-S2', 'Demo-2--Demo2-L2-S1', 'Demo-2--DB-EPG-L3']
		tn=("%s--%s"%(n[0],n[1]),"%s"%(n[2])) 
		desireddaglist.add(tn)
		print tn

#   Find out which DAGs need to be added.
	print "\nLIST OF DAGs that need to be added to the firewall:\n"	
	for b in desireddaglist:
		if DAG_Exists(lhost,lkey,b[0],b[1]) == 0: 
			updatedaglist.add(b)
			print b
	if len(updatedaglist) != 0:
		for t in updatedaglist:
			DAG_Create(lhost,lkey,t[0],t[1])
		FW_Commit(lhost,lkey)
	else:
		print "\n--NO DAGs need to be added to the firewall---\n"

#  Get current DAGS from firewall
	print "\n This is the DAG information currently in the firewall:\n"

	for m in desireddaglist:
		#print m
		tempDAGMembers = DAG_Membership(lhost,lkey,m[0],m[1])
		if len(tempDAGMembers) !=0:		
			for d in tempDAGMembers:
				print d
				tagip.add(d)
				
#   Get ACI EPG Endpoint IPs from APIC
	print "\n This is the DAG information obtained from the APIC:\n"
	aciip=apicepg('https://10.3.4.238',luser,lpass,desireddaglist)
	#print "\n ACILIST:\n",aciip

#   Identify the DAGs that need to be removed
	deldag = tagip - aciip
	#print "deldag = ",deldag
	
#   Identify which DAGs need to be updated
	fwdaglist = aciip - tagip
	#print "fwdaglist add = ",fwdaglist
	if len(deldag) !=0 or len(fwdaglist)!=0:
		print "\nDAG IPS have changed and some need to be added to the firewall Here is the API update:\n"
		for dvl in dagvsyslist:
			fwdagdel=set()
			fwdagadd=set()
			print "\nThese dags need to be updated in %s"%(dvl)
			print "\nThese dags need to be deleted in %s"%(dvl)
			for dglst in deldag:
				if dglst[2] == dvl:
					print dglst
					fwdagdel.add(dglst)
			print "\nThese dags need to be added in %s"%(dvl)
			for aglst in fwdaglist:			
				if aglst[2] == dvl:
					print aglst
					fwdagadd.add(aglst)		
			if len(fwdagadd) !=0 or len(fwdagdel)!=0:
				regdynamic(lkey, lhost, fwdagadd , fwdagdel, dvl)
	else:
		print "\nDAG IPs do not need to be modified"
#	FW_Commit(lhost,lkey)  
	print "\n--------------------Done-------------------------------"

main(name,pwd,firewallip,ten_epg_vsys)
