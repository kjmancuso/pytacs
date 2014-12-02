#!/usr/bin/python
"""
PyTACS LDAP User Source

Must have the following options defined
	host	The hostname or ip address of the LDAP server
	port	The port number the LDAP server is listening on
	dnfmt	An LDAP DN with the token %s where the username should be inserted
"""

import Errors
import pyt_ldap

class pyt_ldap_attributes(pyt_ldap.pyt_ldap):
	"""A user source based on an LDAP directory,
	adding the requirement for certain attibutes to be present
	and/or have certain values"""

	__required__ = ['host', 'port', 'dnfmt']

	def __init__(self, name, modconfig):
		"Prepare LDAP settings"
		pyt_ldap.pyt_ldap.__init__(self, name, modconfig)
		keys = [item.lower() for item in self.modconfig['attrs'].split(',')]
		values = [item.lower() for item in self.modconfig['values'].split(',')]
		if len(keys) != len(values):
			raise Errors.ConfigurationError("pkt_ldap_attributes: keys/values length mismatch")
		del self.modconfig['values']
		self.modconfig['attrs'] = dict(zip(keys, values))
		print "%s" % (self.modconfig['attrs'], )
	
	def checkUser(self, user, password):
		"Verify a user against the table"
		bind_dn = self.modconfig['dnfmt'] % user
		userobj = self.getUser(bind_dn, password)
		if not userobj:
			return False
		for key, value in self.modconfig['attrs'].items():
			if not userobj.has_key(key):
				return False	# Failed 'required' test
			if len(value) > 0:
				if not value in userobj[key]:
					return False	# Failed 'value' test
		return True

if __name__ == '__main__':
	d = pyt_ldap_attributes({'host': '192.168.100.60', 'port': '389', 'dnfmt': 'cn=%s,ou=people,dc=haqa,dc=net', 'attrs': 'objectClass,sn,mail', 'values': 'inetOrgPerson,,'})
	print "%s" % (d.checkUser('fred', 'password1'), )
