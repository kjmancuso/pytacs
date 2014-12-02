#!/usr/bin/python

import getopt
import logging, logging.handlers
import SocketServer
import threading
import os
import sys
import pytacs.Errors

config = {
	'fork':			True,
	'syslog':		True,
	'loglevel':		10,	# 10 = debug
	'pidfile':		'/var/run/pytacs.pid',
	'configfile':	'/etc/pytacs.conf',
	'configdir':	'/etc/pytacs.d',
	'kill':			False,
	'modules':		{}
}

optshort = "?hfesdqP:k"
optlong = ['help', 'forground', 'stderr', 'syslog', 'debug', 'quiet', 'pidfile=', 'kill']

def help():
	"Display commandline syntax and help"
	print """PyTACS Command Line Options

  -h  -?  --help            Display this help
  -f  --foreground          Keep the server in the forground (Implies -e)
  -e  --stderr              Send log messages to stderr (Instead of syslog)
  -s  --syslog              Send log messages to syslog (Even if -f)
  -d  --debug               Enable debugging messages
  -q  --quiet               Only log errors
  -p  --pidfile <file>      Where to save the server's process id
  -k  --kill                Kill the currently running server
"""
	sys.exit(-1)

def readConfig(file):
	"Read in settings from <file>"
	global config
	blocks = {'options': {}, 'modules': {}}
	block = ""
	for line in open(file, "r"):
		line = line.strip()
		if len(line) == 0:
			continue
		if line[0] == ';':
			continue
		if line[0] == '[' and line[-1] == ']':
			block = line[1:-1]
			if not blocks.has_key(block):
				blocks[block] = {}
			continue
		if block=="":
			raise "Configuration error: setting outside block [%s] %s" % (file, line, )
		items = line.split('=', 1)
		if len(items) != 2:
			raise "Configuration error: setting without equals sign [%s] %s" % (file, line, )
		blocks[block][items[0].strip()] = items[1].strip()

	# Process standard 'options' settings
	for key, value in blocks['options'].items():
		key = key.lower()
		if key == 'syslog':
			if value != "0" or value.lower == "on" or value.lower() == 'true':
				config['syslog'] = True
			else:
				config['syslog'] = False
		elif key == 'foreground':
			if value != "0" or value.lower == "on" or value.lower() == 'true':
				config['fork'] = False
				config['syslog'] = False
			else:
				config['fork'] = True
		else:
			raise "Configuration error: Invalid option [%s] %s=%s" % (file, key, value, )

	# Store module(s) settings
	for key, value in blocks['modules'].items():
		modopts = {}
		if blocks.has_key(key):
			modopts = blocks[key]
			del blocks[key]
		modopts['__module__'] = value
		config['modules'][key] = modopts
	del blocks['modules']
	for key, value in blocks.items():
		config[key] = value

if __name__ == '__main__':
	# Set up the framework
	globals()['servers'] = {}
	globals()['usersources'] = {}

	# Read config file(s)
	readConfig(config['configfile'])
	for dirpath, dirs, files in os.walk(config['configdir']):
		dirs[:] = []
		for file in files:
			readConfig(os.path.join(dirpath, file))

	# Read options
	try:
		opts, nonopts = getopt.getopt(sys.argv[1:], optshort, optlong)
	except getopt.GetoptError:
		print sys.exc_info()[1]
		help()
		sys.exit(-1)
	for opt, value in opts:
		if opt == '-h' or opt == '-?' or opt == '--help':
			help()
		if opt == '-f' or opt == '--foreground':
			config['fork'] = False
			config['syslog'] = False
		if opt == '-e' or opt == '--stderr':
			config['syslog'] = False
		if opt == '-s' or opt == '--syslog':
			config['syslog'] = True
		if opt == '-d' or opt == '--debug':
			config['loglevel'] = 10
		if opt == '-q' or opt == '--quiet':
			config['loglevel'] = 40
		if opt == '-p' or opt == '--pidfile':
			config['pidfile'] = value
		if opt == '-k' or opt == '--kill':
			config['kill'] = True

	# Open logs
	rootlog = logging.getLogger('')
	rootlog.setLevel(config['loglevel'])
	if config['syslog']:
		syslog = logging.handlers.SysLogHandler(
			address='/dev/log',
			facility=logging.handlers.SysLogHandler.LOG_DAEMON,
		)
		syslog.setLevel(config['loglevel'])
		syslog.log_format_string = '<%%d>PyTACS[%d]: %%s\000' % (os.getpid(), )
		rootlog.addHandler(syslog)

	# Check if a pidfile exists
	if os.path.exists(config['pidfile']):
		# Is that process still running?
		pid = int(open(config['pidfile']).read())
		if config['kill']:
			try:
				os.kill(pid, 1)
				logging.info("Running copy (pid %d) killed" % (pid, ), exc_info=0)
				sys.stderr.write("Server stopped\n")
				sys.exit(0)
			except:
				raise
		try:
			os.kill(pid, 0)
			logging.error("Server already running as pid %d" % (pid, ), exc_info=0)
			sys.stderr.write("Server already running\n")
			sys.exit(1)
		except:
			pass
	if config['kill']:
		logging.error("No running server to kill")
		sys.stderr.write("No running server to kill\n")
	# Fork
	if config['fork']:
		pid = os.fork()
		if pid:
			# Record the pid in the pid-file and then exit
			open(config['pidfile'], "w").write("%d" % pid)
			sys.exit(0)
		# Close tty(s)
		si = open('/dev/null', 'a+')
		os.dup2(si.fileno(), 0)
		os.dup2(si.fileno(), 1)
		os.dup2(si.fileno(), 2)
		si.close()

	# Load modules from config file(s)
	for key, value in config['modules'].items():
		modname = value['__module__']
		mod = __import__("pytacs.%s" % (modname, ), globals(), locals())
		mod = getattr(mod, modname) # Get the sub module
		cls = getattr(mod, modname) # Get the class
		obj = cls(key, value)
		config['modules'][key]['__instance__'] = obj
		obj.__reg_module__(globals(), key)

	# Log either started or exited
	if len(globals()['servers']) == 0:
		logging.debug("No servers configured - Exiting")
	else:
		logging.debug("%s servers configured - Running" % (len(globals()['servers'])))
