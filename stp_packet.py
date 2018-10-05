
class STPPacket:
	def __init__(self, data, seq_no, ack_no, checksum=0,send_time=0, ack=False, syn=False, fin=False):
		self.data = data
		self.seq_no = seq_no
		self.ack_no = ack_no
		self.ack = ack
		self.syn = syn
		self.fin = fin
		self.checksum = checksum
		self.send_time = send_time 	# to keep track of the send time of a packet



def checksum(payload):
	sum = 0
	# checksum for 16-bit word 
	# 1 character is 8 bit , so has to combine 2 character to get 16-bit 
	for i in range(0, len(payload)-1, 2):
		# word = ord(payload[i]) + (ord(payload[i+1]) << 8)
		word = payload[i] + (payload[i+1] << 8)
		c = sum + word
		#wrap around
		sum = (c & 0xffff) + (c >> 16)
	result = ~sum & 0xffff
	return result

def receiver_checksum(payload):
	sum = 0
	for i in range(0, len(payload)-1, 2):
		word = payload[i] + (payload[i+1] << 8)
		c = sum + word
		sum = (c & 0xffff) + (c >> 16)
	result = sum & 0xffff
	return result

def corrupt(payload):
	flipped = ''
	for i in range(0, len(payload)):
		if i != 0:
			flipped += payload.decode('iso-8859-1')[i]
		else:
			flipped += chr((ord(payload.decode('iso-8859-1')[i]) ^ 1))
	return flipped.encode('iso-8859-1')