#!/usr/bin/python
"""
PyTACS TACACS+ listener and handler
"""

import logging
import Errors
import PyTACSModule
import SocketServer
import threading
import Packet

class TACACSPlusHandler(SocketServer.StreamRequestHandler):
	"Simple TACACS+ connection handler. Decode the packet and process"

	def handle(self):
		"Handle a tacacs packet"
		client = self.client_address[0]
		secret = self.server.clients.get(client, None)
		logging.debug("Entering packet loop")
		while 1:
			data = self.request.recv(4096)
			if not data:
				break
			packet = Packet.Packet.decode(data, secret)
			if packet.getSeqNo() == 1:
				self.session = {}
				self.start = packet
			else:
				if packet.getType() != self.start.getType():
					logging.error("Packet type mismatch")
					break
			if packet.getType() == Packet.TAC_PLUS_AUTHEN:
				reply = self.processAuthen(packet)
			elif packet.getType() == Packet.TAC_PLUS_AUTHOR:
				reply = self.processAuthor(packet)
			elif packet.getType() == Packet.TAC_PLUS_ACCT:
				reply = self.processAcct(packet)
			else:
				logging.error("Bad packet type: %s" % packet._type)
				break
			if reply.getSeqNo() < 3:
				reply.setFlag(Packet.TAC_PLUS_SINGLE_CONNECT_FLAG)
			self.request.send(reply.encode())
		self.session = None
		self.start = None
		logging.debug("Packet loop exited")
		self.request.shutdown(2)
		self.request.close()

	def processAuthen(self, packet):
		"Process an Authorization packet"
		reply = packet.reply()
		return reply

	def processAuthor(self, packet):
		"Process an Authorization packet"
		pass

	def processAcct(self, packet):
		"Process an Authorization packet"
		pass

class TACACSPlusListener(SocketServer.ThreadingTCPServer):
	"TCP Listener for PyTACS server"

	allow_reuse_address = 1

	def __init__(self, addr):
		"Initialize the socket, start the thread"
		SocketServer.ThreadingTCPServer.__init__(self, addr, TACACSPlusHandler)

class pyt_tacacs_server(PyTACSModule.PyTACSModule, threading.Thread):

	__required__ = ['address', 'port', 'clients']
	__registry__ = 'servers'

	def __init__(self, name, modconfig):
		"Start the tacacs server and record it in the server list"
		self.running = True
		PyTACSModule.PyTACSModule.__init__(
			self,
			name,
			modconfig,
		)
		threading.Thread.__init__(
			self,
			name="PyTACS TACACS+ Listener (%s)" % (name, ),
		)
		self.listener = TACACSPlusListener(
			(self.modconfig['address'], int(self.modconfig['port'])),
		)
		self.start()

	def stop(self):
		"Set the flag to stop the thread"
		self.running = false

	def run(self):
		"Start listening"
		logging.info("Starting %s" % self.getName())
		while self.running:
			self.listener.handle_request()

	def __reg_module__(self, globals, name):
		"Register this module and grab the secrets"
		PyTACSModule.PyTACSModule.__reg_module__(self, globals, name)
		clients = self.modconfig['clients']
		self.listener.clients = globals['config'][clients]
