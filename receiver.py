

from stp_packet import *
import socket
import sys
import pickle
import time
from random import seed


class Receiver: 
	def __init__(self, port, file):	
		self.port = int(port)					# connection port 
		self.file = file						# name of the file to write to
		self.socket = self.open_connection()	# receiver socket
		self.start_time = time.time()			# program execution time

		# init seq/ack vars
		self.seq_no = 0				# receiver seq number
		self.ack_no = 0 			# sender next expected seq num
		self.dup_ack_no = 0			# keep track of dup ack ack number
		self.buffer = {}			# buffer to store out of order packets
		self.received_bytes = b''	# received bytes that is ready to write to file

		# states
		self.listen = True
		self.syn_rcv = False
		self.established = False 
		self.closed = False
		self.close_wait = False 
		self.last_ack = False

		# stats for receiver 
		self.bytes_received = 0
		self.total_seg_received = 0
		self.data_seg_received = 0
		self.error_seg_received = 0
		self.dup_data_received = 0
		self.dup_ack =  0

		
	def handshake(self):
		while True: 
			# listen state
			if self.listen == True:
				print("\n==== STATE: LISTEN ====")
				syn, client_addr = self.receive()
				# receive syn
				if self.receive_syn(syn):
					self.update_log("rcv", self.get_packet_type(syn), syn)
					#acknowledge sender SYN
					self.ack_no += 1
					self.total_seg_received += 1
					synack = STPPacket(b'', self.seq_no, self.ack_no, ack=True, syn=True)
					self.send(synack,client_addr)
					self.update_log("snd", self.get_packet_type(synack), synack)
					#increment seq for SYNACK
					self.seq_no += 1
					self.syn_rcv = True 
					self.listen = False

			# synack sent 
			if self.syn_rcv == True:
				print("\n==== STATE: SYNACK SENT =====T")
				ack, client_addr = self.receive()
				# receive ack 
				if self.receive_ack(ack):
					self.update_log("rcv", self.get_packet_type(ack), ack)
					# update stats
					self.total_seg_received += 1
					# update state
					self.established = True 
					self.syn_rcv = False
					break


	# initialize socket
	def open_connection(self):
		try:
			# create socket
			s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			return s
		except socket.error:
			print("Socket creation failed")
			sys.exit()

	# send packet across
	def send(self, packet, addr):
		# serialize packet
		pkt = pickle.dumps(packet)
		# send packet to sender 
		self.socket.sendto(pkt, addr)


	# update log dile
	def update_log(self, action, packet_type, packet):
		# execution time in seconds
		excution_time = time.time() - self.start_time

		# write to receiver log 
		with open("Receiver_log.txt", 'a+') as f:
			f.write('{}\t{}\t{}\t{}\t{}\t{}\n'.format(
				action, excution_time, packet_type,
				packet.seq_no, len(packet.data), packet.ack_no))
	
	# receive packet from socket
	def receive(self):
		data, addr = self.socket.recvfrom(4096)

		# deserialize packet
		packet = pickle.loads(data)
		return packet, addr

	# check if received packet is a syn
	def receive_syn(self, packet): 
		if packet.syn:
			return True
		return False

	# check if received packet is an ack
	def receive_ack(self, packet):
		if packet.ack: 
			return True
		return False

	# check if received packet is a fin
	def receive_fin(self, packet):
		if packet.fin: 
			return True
		return False

	# write stats to receiver log
	def write_stats(self):
		with open("Receiver_log.txt", 'a+') as f:
			f.write("=======================================================================\n")
			f.write("Amount of data received (bytes)\t{}\n".format(self.bytes_received))
			f.write("Total Segments Received\t{}\n".format(self.total_seg_received))
			f.write("Data segments received\t{}\n".format(self.data_seg_received))
			f.write("Data segments with Bit Errors\t{}\n".format(self.error_seg_received))
			f.write("Duplicate data segments received\t{}\n".format(self.dup_data_received))
			f.write("Duplicate ACKs sent\t{}\n".format(self.dup_ack))
			f.write("=======================================================================\n")
	
	# get packet type
	def get_packet_type(self, packet):
		if len(packet.data) > 0:
			return 'D'
		else:
			result = ''
			if packet.fin:
				result += 'F'
			elif packet.syn:
				result += 'S'
			if packet.ack:
				result += 'A'
			return result

	# receive packet, send ack and update log file
	def receive_packet(self):

		# while in established state
		while self.established: 
			# receive packet form socket
			packet, addr = self.receive()

			# check if packet receive is not empty
			if packet is not None : 

				# check if received packet is a fin packet
				if self.receive_fin(packet):
					# close connection
					self.total_seg_received += 1
					self.update_log("rcv", self.get_packet_type(packet), packet)
					self.close(packet, addr)
				else: 
					
					# receive packet containing payload 
					
					payload = packet.data

					# check if packet is corrupted
					if(receiver_checksum(payload) + packet.checksum != 0xFFFF):

						# update stats
						data_len = len(packet.data)
						self.bytes_received += data_len
						self.error_seg_received += 1
						self.data_seg_received += 1
						self.total_seg_received += 1

						# update log file 
						self.update_log("rcv/corr", self.get_packet_type(packet), packet)
						continue
					
					# buffer all new accepted packet that is not duplicate - could be out of order
					if packet.seq_no not in self.buffer.keys() and packet.seq_no >= self.ack_no:
						self.buffer[packet.seq_no] = packet
						self.data_seg_received += 1
						self.total_seg_received += 1

					# check if the packet is out of order
					if packet.seq_no == self.ack_no:
						# move window up; everything past this has been acknowledged
						# in order packet
						# update stats
						data_len = len(packet.data)
						self.bytes_received += data_len
						
						# update log
						self.update_log("rcv", self.get_packet_type(packet), packet)

						# update ack num, removed in order packet from buffer
						self.update_buffer()
						
						# create ack and send it
						ack = STPPacket(b'',self.seq_no, self.ack_no, ack=True)
						self.send(ack, addr)

						# update log file
						self.update_log("snd", self.get_packet_type(ack), ack)
						
					
					elif packet.seq_no < self.ack_no:
						# duplicate packet 
						
						# update stats
						self.dup_data_received += 1
						data_len = len(packet.data)
						self.data_seg_received += 1
						self.total_seg_received += 1
						self.bytes_received += data_len

						# update log
						self.update_log("rcv", self.get_packet_type(packet), packet)

						# create ack, send ack and update log file
						ack = STPPacket(b'',self.seq_no, self.ack_no, ack=True)
						self.send(ack, addr)
						self.update_log("snd/DA", self.get_packet_type(ack), ack)
						self.dup_ack += 1
						
					elif packet.seq_no > self.ack_no and packet.seq_no != self.dup_ack_no:
						# receive out of order packet

						# update stats
						data_len = len(packet.data)
						self.bytes_received += data_len
						self.dup_ack_no = packet.seq_no

						#update log file
						self.update_log("rcv", self.get_packet_type(packet), packet)

						# create ack, send ack and update log file
						ack = STPPacket(b'',self.seq_no, self.ack_no, ack=True)
						self.send(ack, addr)
						self.update_log("snd/DA", self.get_packet_type(ack), ack)
						self.dup_ack += 1
							

					elif packet.seq_no > self.ack_no and packet.seq_no == self.dup_ack_no:
						# duplicate out of order packet

						# update stats
						data_len = len(packet.data)
						self.bytes_received += data_len
						self.dup_data_received += 1
						self.data_seg_received += 1
						self.total_seg_received += 1

						# update log 
						self.update_log("rcv", self.get_packet_type(packet), packet)

						# create ack, send ack and update log file
						ack = STPPacket(b'',self.seq_no, self.ack_no, ack=True)
						self.send(ack, addr)
						self.update_log("snd/DA", self.get_packet_type(ack), ack)
						self.dup_ack += 1

	# release out of order packet in buffer and append to received_bytes
	def update_buffer(self):
		# releasing in order buffer 
		while self.ack_no in list(self.buffer.keys()):
			packet = self.buffer[self.ack_no]
			data_len = len(packet.data)
			self.received_bytes += packet.data
			del(self.buffer[self.ack_no])
			self.ack_no += data_len
		
	# write received bytes to file
	def write_file(self):
		# writing to file
		with open(self.file, "wb") as f: 
			f.write(self.received_bytes)

	# close connection
	def close(self, packet, addr):
		self.seq_no = packet.ack_no
		self.ack_no = packet.seq_no + 1
		ack = STPPacket('',self.seq_no, self.ack_no, ack=True)
		self.send(ack, addr)
		self.update_log("snd","A", ack)
		self.established = False
		self.close_wait = True
		while True: 

			if self.close_wait == True: 
				# create fin
				fin = STPPacket(b'', self.seq_no, self.ack_no, fin=True)

				# send fin
				self.send(fin, addr)

				# update log 
				self.update_log("snd", "F", fin)

				# update state
				self.close_wait = False
				self.last_ack = True

			elif self.last_ack == True:
				print("====last ack====")
				ack, addr = self.receive()

				# update ack
				self.update_log("rcv", "A", ack)

				# update stats
				self.total_seg_received += 1

				# update state
				self.last_ack = False 
				self.closed = True
				print("Connection closed")
				break

	# close socket, write to file and write stats to log 
	def close_connection(self):
		self.write_file()
		self.write_stats()
		self.socket.close()
	


if __name__ == '__main__':
	if len(sys.argv) != 3:
		print("Usage: python receiver.py receiver_port file_r.pdf")
	else:
		# grab args, create socket and bind
		receiver_port, file_r = sys.argv[1:]
		receiver = Receiver(receiver_port, file_r)
		receiver.socket.bind(('', receiver.port))

		# clean the file before use
		f = open("Receiver_log.txt", "w")
		f.close()
		f = open(file_r, "w")
		f.close()

		# 3 ways handshake
		receiver.handshake() 

		# receive packet from sender
		receiver.receive_packet()
		
		# close connection 
		receiver.close_connection()




