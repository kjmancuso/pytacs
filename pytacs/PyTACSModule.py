#!/usr/bin/python
"""
PyTACS Base Module Class
"""

import Errors

class PyTACSModule(object):
	"A basic module with required config entry support"

	__required__ = []
	__registry__ = None

	def __init__(self, name, modconfig):
		"Prepare whatever is needed"
		self.modconfig = modconfig
		for key in self.__required__:
			if not self.modconfig.has_key(key):
				raise Errors.ConfigurationError("Required option '%s' missing [%s:%s]" % (key, name, self.__class__.__name__.split('.')[-1], ))

	def __reg_module__(self, globals, name):
		"Register this module in the appropriate registry"
		globals[self.__registry__][name] = self

