
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

	def __lt__(self, other):
		return self.seq_no < other.seq_no
	
	def __eq__(self, other):
		return self.seq_no == other.seq_no
	
# def wrap_around(a, b):
# 	c = a + b
# 	result = (c & 0xffff) + (c >> 16)
# 	return result

# def bubbleSort()
# 	n = len(arr)
	
# 		# Traverse through all array elements
# 		for i in range(n):
	
# 			# Last i elements are already in place
# 			for j in range(0, n-i-1):
	
# 				# traverse the array from 0 to n-i-1
# 				# Swap if the element found is greater
# 				# than the next element
# 				if arr[j] > arr[j+1] :
# 					arr[j], arr[j+1] = arr[j+1], arr[j]

def checksum(payload):
	sum = 0
	# print(payload)
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