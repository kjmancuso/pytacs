#!/usr/bin/python
"""
PyTACS MySQL User Source

Must have the following options defined
	host
	user
	pass
	db
	table
	user_column
	pass_column
"""

import UserSource

class pyt_mysql(UserSource.UserSource):
	"A user source based on a MySQL table"

	__required__ = ['host', 'user', 'pass', 'db', 'table', 'user_column', 'pass_column']

	def __init__(self, name, modconfig):
		"Prepare MySQL settings"
		UserSource.UserSource.__init__(self, name, modconfig)

	def checkUser(self, user, password):
		"Verify a user against the MySQL table"
		return false

