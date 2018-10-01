from stp_packet import *
import socket
import sys
import pickle
import time
from random import seed


class Receiver: 
	def __init__(self, port, file):
		self.port = int(port)
		self.file = file
		self.socket = self.open_connection()
		self.start_time = time.time()

		# init seq/ack vars
		self.seq_no = 0
		self.ack_no = 0 			#sender next expected seq num
		self.buffer = {}
		self.received_bytes = b''

		#states
		self.listen = True
		self.syn_rcv = False
		self.synack_sent = False
		self.established = False 
		self.end = False
		self.close_wait = False 
		self.last_ack = False

		#stats for receiver 
		self.bytes_received = 0
		self.total_seg_received = 0
		self.data_seg_received = 0
		self.error_seg_received = 0
		self.dup_data_received = 0
		self.dup_ack =  0

		
	def initiate_connection(self):
		while True: 
			if self.listen == True:
				print("\n==== STATE: LISTEN ====")
				syn, client_addr = self.receive()
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
					print(synack.seq_no)
					print(synack.ack_no)
					print(synack.ack)
					print(synack.syn)
					self.synack_sent = True 
					self.listen = False

			if self.synack_sent == True:
				print("\n==== STATE: SYNACK SENT =====T")
				ack, client_addr = self.receive()
				if self.receive_ack(ack):
					self.update_log("rcv", self.get_packet_type(ack), ack)
					self.total_seg_received += 1
					self.established = True 
					self.synack_sent = False
					break



	def open_connection(self):
		try:
			s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			return s
		except socket.error:
			("Socket creation failed")
			sys.exit()

	def send(self, packet, addr):
		pkt = pickle.dumps(packet)
		self.socket.sendto(pkt, addr)


	def update_log(self, action, packet_type, packet):
		#execution time in miliseconds
		excution_time = (time.time() - self.start_time) * 1000
		with open("Receiver_log.txt", 'a+') as f:
			f.write('{}\t{}\t{}\t{}\t{}\t{}\n'.format(
				action, excution_time, packet_type,
				packet.seq_no, len(packet.data), packet.ack_no))
	
	def receive(self):
		data, addr = self.socket.recvfrom(4096)
		packet = pickle.loads(data)
		return packet, addr

	def receive_syn(self, packet): 
		if packet.syn:
			return True
		return False

	def receive_ack(self, packet):
		if packet.ack: 
			return True
		return False

	def receive_fin(self, packet):
		if packet.fin: 
			return True
		return False

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

	def receive_packet(self):
		# keep track of dup_ack sent with the same seq_num
		sent_dup_ack = 0
		while self.established: 
			packet, addr = self.receive()
			if packet is not None : 
				print("packet is not none")
				if self.receive_fin(packet):
					# close connection
					self.total_seg_received += 1
					self.update_log("rcv", self.get_packet_type(packet), packet)
					self.close(packet, addr)
				else: 
					# receive packet containing payload 
					# check if packet is corrupted
					payload = packet.data
					print("receive packet with seq_num", packet.seq_no)
					if(receiver_checksum(payload) + packet.checksum != 0xFFFF):
						print("checking packet")
						self.error_seg_received += 1
						self.total_seg_received += 1
						self.update_log("rcv/corr", self.get_packet_type(packet), packet)
						print("incorrect checksum, return previous ack")
						ack = STPPacket(b'',self.seq_no, self.ack_no, send_time=-1, ack=True)
						self.send(ack, addr)
						if sent_dup_ack == 0: 
							self.update_log("snd", self.get_packet_type(ack),ack)
							sent_dup_ack += 1
						else: 
							self.update_log("snd/DA", self.get_packet_type(ack), ack)
							sent_dup_ack += 1
							self.dup_ack += 1
						print("sent_dup_ack", sent_dup_ack)
						continue
					
					# buffer all new accepted packet that is not duplicate - could be out of order
					if packet.seq_no not in self.buffer.keys():
						print("adding packet to buffer", packet.seq_no)
						self.buffer[packet.seq_no] = packet
						self.data_seg_received += 1
						self.total_seg_received += 1

					# check if the packet is out of order
					if packet.seq_no == self.ack_no:
						print("in order packet") 
						# move window up; everything past this has been acknowledged
						# in order packet
						sent_dup_ack = 0
						self.update_log("rcv", self.get_packet_type(packet), packet)
						#update ack num, removed in order packet from buffer
						self.update_buffer()
						send_time = packet.send_time
						ack = STPPacket(b'',self.seq_no, self.ack_no, send_time=send_time, ack=True)
						print("sending ack")
						self.send(ack, addr)
						self.update_log("snd", self.get_packet_type(ack), ack)
						sent_dup_ack += 1
					elif packet.seq_no < self.ack_no and packet.seq_no in self.buffer.keys():
						print("received dup data segment")
						# duplicate data 
						self.dup_data_received += 1
						self.update_log("rcv/dup", self.get_packet_type(packet), packet)
					elif packet.seq_no > self.ack_no:
						print("receieved out of order packet")
						self.update_log("rcv", self.get_packet_type(packet), packet)
						# out of order packet
						if sent_dup_ack == 0:
							send_time = packet.send_time
							ack = STPPacket(b'',self.seq_no, self.ack_no, send_time=send_time, ack=True)
							self.send(ack, addr)
							self.update_log("snd", self.get_packet_type(ack),ack)
							sent_dup_ack += 1
						else:
							ack = STPPacket(b'',self.seq_no, self.ack_no, send_time=-1, ack=True)
							self.send(ack, addr)
							self.update_log("snd/DA", self.get_packet_type(ack), ack)
							sent_dup_ack += 1
							self.dup_ack += 1
						print("sent_dup_ack", sent_dup_ack)

	def update_buffer(self):
		print("releasing packet in buffer")
		while self.ack_no in list(self.buffer.keys()):
			packet = self.buffer[self.ack_no]
			data_len = len(packet.data)
			self.bytes_received += data_len
			self.received_bytes += packet.data
			del(self.buffer[self.ack_no])
			self.ack_no += data_len
		

	def write_file(self):
		print("writing to file")
		with open(self.file, "wb+") as f: 
			f.write(self.received_bytes)

	def close(self, packet, addr):
		print("closing")
		self.seq_no = packet.ack_no
		self.ack_no = packet.seq_no + 1
		ack = STPPacket('',self.seq_no, self.ack_no, ack=True)
		self.send(ack, addr)
		self.update_log("snd","A", ack)
		self.established = False
		self.close_wait = True
		while True: 
			if self.close_wait == True: 
				fin = STPPacket(b'', self.seq_no, self.ack_no, fin=True)
				self.send(fin, addr)
				self.update_log("snd", "F", fin)
				self.close_wait = False
				self.last_ack = True

			elif self.last_ack == True:
				print("====last ack====")
				ack, addr = self.receive()
				self.update_log("rcv", "A", ack)
				self.total_seg_received += 1
				self.last_ack = False 
				self.closed = True
				print("Connection closed")
				break

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
		f = open("Receiver_log.txt", "w")
		f.close()
		f = open(file_r, "w")
		f.close()

		receiver.initiate_connection() 
		receiver.receive_packet()
		receiver.close_connection()




