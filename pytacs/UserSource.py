#!/usr/bin/python
"""
PyTACS User Source Base Class
"""

import Errors
import PyTACSModule

class UserSource(PyTACSModule.PyTACSModule):
	"A source of users for authentication"

	__required__ = []
	__registry__ = 'usersources'

	def __init__(self, name, modconfig):
		"Initialise the module and record this user source"
		PyTACSModule.PyTACSModule.__init__(self, name, modconfig)

	def checkUser(self, user, password):
		"Verify a user against the datasource"
		return false
