# stp packet structure
class STPPacket:
	def __init__(self, data, seq_no, ack_no, checksum=0,send_time=0, ack=False, syn=False, fin=False):
		self.data = data			# payload
		self.seq_no = seq_no		# seq number of the packet
		self.ack_no = ack_no		# ack number of the packet
		self.ack = ack				# ack flag to indicate ack
		self.syn = syn				# syn flag to indicate syn
		self.fin = fin				# fin flag to indicate fin
		self.checksum = checksum	#checksum of the payload
		self.send_time = send_time 	# to keep track of the send time of a packet


# calculate the checksum of a packet at the sender
def checksum(payload):
	sum = 0
	# checksum for 16-bit word 
	# 1 character is 8 bit , so has to combine 2 character to get 16-bit 
	for i in range(0, len(payload)-1, 2):
		word = payload[i] + (payload[i+1] << 8)
		c = sum + word
		# wrap around
		sum = (c & 0xffff) + (c >> 16)
	result = ~sum & 0xffff
	return result

# calculate the checksum of a packet at the receiver
def receiver_checksum(payload):
	sum = 0
	# checksum for 16-bit word 
	# 1 character is 8 bit , so has to combine 2 character to get 16-bit 
	for i in range(0, len(payload)-1, 2):
		word = payload[i] + (payload[i+1] << 8)
		c = sum + word
		# wrap arround
		sum = (c & 0xffff) + (c >> 16)
	result = sum & 0xffff
	return result

# corrupt the data in a packet
def corrupt(payload):
	flipped = ''
	for i in range(0, len(payload)):
		if i != 0:
			flipped += payload.decode('iso-8859-1')[i]
		else:
			flipped += chr((ord(payload.decode('iso-8859-1')[i]) ^ 1))
	return flipped.encode('iso-8859-1')