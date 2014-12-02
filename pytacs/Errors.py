#!/usr/bin/python
"""
PyTACS Error Classes
"""

class PyTACSError(Exception):
	"The root of all PyTACS errors and exceptions"
	pass

class ConfigurationError(PyTACSError):
	"Something in a configuration file was incorrect"
	pass
