import socket
import sys
import pickle
from stp_packet import *
import time
import random
from threading import Timer


class Timeout:
    def __init__(self, gamma, timeout=0, estRTT=500, devRTT=250):
        self.timeout = timeout
        self.estRTT = estRTT
        self.devRTT = devRTT
        self.alpha = 0.125
        self.beta = 0.25
        self.gamma = gamma

    def initial_timeout(self):
        self.timeout = (self.estRTT + (self.gamma * self.devRTT)) /1000
        print("timeout ", self.timeout)
        return self.timeout

    def calc_timeout(self, sampleRTT):
        self.estRTT = ((1 - self.alpha) * self.estRTT) + (self.alpha * sampleRTT)
        self.devRTT = ((1 - self.beta) * self.devRTT) + \
            (self.beta * abs(sampleRTT - self.estRTT))
        self.timeout = (self.estRTT + (self.gamma * self.devRTT))/1000
        print("DevRTT" , self.devRTT)
        print("timeout ", self.timeout)
        return self.timeout


class Sender:
    def __init__(self, receiver_host_ip, receiver_port, file, MWS, MSS, gamma, pDrop, pDuplicate, pCorrupt, pOrder, maxOrder, pDelay, maxDelay, seed):
        self.receiver_ip = receiver_host_ip
        self.receiver_port = int(receiver_port)
        self.file = file
        self.mws = int(MWS)
        self.mss = int(MSS)
        self.gamma = int(gamma)
        self.pDrop = float(pDrop)
        self.pDuplicate = float(pDuplicate)
        self.pCorrupt = float(pCorrupt)
        self.pOrder = float(pOrder)
        self.maxOrder = int(maxOrder)
        self.pDelay = float(pDelay)
        self.maxDelay = int(maxDelay)
        self.seed = int(seed)
        self.socket = self.open_connection()
        self.timer = None
        self.start_time = time.time()
        self.timeout = Timeout(self.gamma)
        self.timer_flag = False
        self.send_time = None 
        self.prev_time = None
    

        # states of sender
        self.closed = True
        self.syn_sent = False
        self.established = False
        self.end = False
        self.fin_wait = False
        self.fin_wait_2 = False
        self.time_wait = False

        # stats for sender for printing to text file
        self.file_size = 0
        self.seg_trans = 0
        self.pld_seg = 0
        self.dropped_seg = 0
        self.corrupted_seg = 0
        self.reordered_seg = 0
        self.dup_seg = 0
        self.delayed_seg = 0
        self.timeout_rxt_seg = 0
        self.fast_rxt_seg = 0
        self.dup_acks = 0

        self.seq_no = 0  			# sequence number for sender
        self.ack_no = 0  			# acknowledge number for sender
        self.order_buffer = []		#  buffer to save packet for reordering
        self.packet_buffer = {} 	# send but not yet acknowledge packet
        self.total_seq_no = 0		# total seq_num 
        self.bytes_sent = 0			# last byte sent
        self.send_base = 0			# oldest unacked segment
        self.dup_num = 0 			# use to keep track if we have received 3 dup_acks
        self.contents = []			# contents of a file
        self.order_count = 0        # used to keep track of packet sent for packet reordering
        self.pld = 0
        
        

        random.seed(self.seed)
        self.socket.settimeout(0.1)
        
    # 3 ways handshake
    def handshake(self):
        while True:
            if self.closed is True:
                # closed state
                print("\n==== STATE: CLOSED ====")
                # send syn
                syn = STPPacket(b'', self.seq_no, self.ack_no,syn=True)
                self.send(syn)
                # update log
                self.update_log("snd",self.get_packet_type(syn) , syn)
                # update state
                self.closed = False
                self.syn_sent = True

            elif self.syn_sent is True:
                # syn sent
                print("\n====STATE: SYN SENT====")
                synack = sender.receive()
                if self.receive_synack(synack):
                    self.ack_no = synack.seq_no + 1
                    self.update_log("rcv", self.get_packet_type(synack), synack)
                    print("SYNACK received")
                    # send ACK
                    self.seq_no += 1
                    ack = STPPacket(b'', self.seq_no, self.ack_no, ack=True)
                    self.send(ack)
                    self.update_log("snd", self.get_packet_type(ack) , ack)
                    # 3-way-handshake complete
                    self.established = True
                    print("==== STP CONNECTION ESTABLISHED ===\n")
                    break

    # create socket
    def open_connection(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            return s
        except socket.error:
            print("Socket creation failed")
            sys.exit()

    # send packet through socket to receiver
    def send(self, packet):
        self.seg_trans += 1
        pkt = pickle.dumps(packet)
        self.socket.sendto(pkt, (self.receiver_ip, self.receiver_port))

    # receive packet from socket
    def receive(self):
        data, addr = self.socket.recvfrom(4096)
        packet = pickle.loads(data)
        return packet

    # calculate the size of the file
    def calc_total_payload(self):
        with open(self.file, 'rb') as f:
            file_contents = f.read()
        # get file size
        self.file_size = len(file_contents)
        # calculate total seq number
        self.total_seq_no = self.seq_no + len(file_contents)
        

    # read file and split file contents into parts with size mss.
    def process_data(self):
        with open(self.file, 'rb') as f:
            file_contents = f.read()
        self.contents = [file_contents[i: self.mss+i] for i in range(0, len(file_contents), self.mss)]

    # updtae log 
    def update_log(self, action, packet_type, packet):
        # execution time in miliseconds
        excution_time = (time.time() - self.start_time) * 1000
        # open file and write to file
        with open("Sender_log.txt", 'a+') as f:
            f.write('{}\t{}\t{}\t{}\t{}\t{}\n'.format(
                    action, excution_time, packet_type,
                    packet.seq_no, len(packet.data), packet.ack_no))


    # check for synack packet
    def receive_synack(self, stp_packet):
        if stp_packet.syn and stp_packet.ack:
            return True
        return False

    # check for ack packet
    def receive_ack(self, stp_packet):
        if stp_packet.ack:
            return True
        return False

    #check for fin packet
    def receive_fin(self, stp_packet):
        if stp_packet.fin:
            return True
        return False

    # update log file and close connection
    def close(self):
        self.socket.close()
        self.write_stats()
    
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

    # timeout retransmission of a packet
    def retransmission(self, packet):
        print("timeout retransmission", packet.seq_no)
        if len(self.order_buffer) > 0:
            self.order_count += 1
        self.timeout_rxt_seg += 1
        self.send_time = -1
        self.pld_send(packet, retransmit=True)

    # 
    def send_file(self):
        self.bytes_sent = 1 # initialise to 1 because send base is always 1 more than the actual bytes sent
        self.send_base += 1
        print("maxOrder ", self.maxOrder)
        while True:
            # send packet after maxOrder packets have been sent
            if (self.order_count == self.maxOrder and self.pOrder > 0 and self.bytes_sent - self.send_base <= self.mws):
                print("sending held back segment")
                packet = self.order_buffer.pop()
                self.order_count = 0
                self.update_log("snd/rord", self.get_packet_type(packet), packet)
                # we set retransmit equals true so that the seq_num wont be counted twice
                self.send(packet)
                print ("sending held back segment with seq_num ".format( packet.seq_no))
                   
            
            # check if last byte sent - last byte acked < mws and if we still have more to send
            while(self.bytes_sent - self.send_base < self.mws and self.bytes_sent < self.file_size):
                print("cur seq num is {}".format(self.seq_no))
                print("still less than mss", (self.bytes_sent-self.send_base))
                print("order_count", self.order_count)
               
                # if there is more to send
                if self.bytes_sent < self.file_size:
                    # event: receive data from application layer
                    index = int(self.bytes_sent / self.mss)
                    print("bytes sent 1 is ",self.bytes_sent) 

                    # get the payload from a list of payloads
                    payload = self.contents[index]
                    print("about to send payload ")

                    # create the packet
                    packet = STPPacket(payload, self.seq_no, self.ack_no, checksum=checksum(payload))

                    # save the sent packet in buffer 
                    self.packet_buffer[self.seq_no] = packet
                    
                    # pass to pld
                    result = self.pld_send(packet)
                    
                    # increment last bytes sent
                    self.bytes_sent += len(payload)
                else: 
                    break
                    
                # event: retransmit after timer timeout, send the segment with the smallest seq num
                if (self.timer_flag is False):
                    # if the is the first packet we send, we use the initial timeout, else use new timeout
                    if (self.send_base == 1):
                        timeout = self.timeout.initial_timeout()
                    else:
                        timeout = self.timeout.timeout
                    self.timer_flag = True
                    self.send_time = time.time()
                  
                    

                # if we have packet for reordering
                if len(self.order_buffer) > 0 and result != 0:
                    # increment order_count to keep track of send packets for packet reordering
                    self.order_count += 1
                    
                # if drop packets, we continue the loop    
                if result == -1: 
                    continue

            try:
                # event: ACK received
                print("waiting for ack")
                ack = self.receive()
                # record the time of receive
                recv_time = time.time()
                if self.receive_ack(ack):

                    # get the ack number
                    received_ack = ack.ack_no
                    print("received ack: ", received_ack)
                    
                    # send base start from 1
                    # if (self.send_base == 0):
                    #     self.send_base += 1

                    # receiver has received all bytes up to received ack
                    if received_ack > self.send_base:
                        print("received ack: {} and the current send base is {}".format(received_ack, self.send_base))
                        # stop timer on previous packet. new send base 
                        if self.timer_flag is True:
                            self.timer_flag = False
                        self.update_log("rcv", self.get_packet_type(ack), ack)

                        # ack_num will be 1 more than last acked byte
                        self.send_base = received_ack
                        print("new send_base ", self.send_base)

                        # remove packets
                        remove_key = [key for key in self.packet_buffer.keys() if key < self.send_base]
                        for key in remove_key:
                            del(self.packet_buffer[key])
                            print("delete packet with seq_num {} in buffer".format(key))
                        print("buffer length is ", len(self.packet_buffer.keys()))

                        # finish when the ack num equals to the total seq_num
                        if (ack.ack_no == self.total_seq_no):
                            print("closing")
                            self.established = False
                            self.end = True 
                            self.timer_flag = False
                            break
                        # calculate SampleRTT
                        if self.send_time != -1:
                            sampleRTT = recv_time - self.send_time
                            timeout = self.timeout.calc_timeout(sampleRTT)
                        else: 
                            timeout = self.timeout.timeout
                        if len(self.packet_buffer) > 0:
                            packet = self.packet_buffer[self.send_base]
                            # retransmit on timeout 
                            print("setting timer with timeout ", timeout)
                            # new timer 
                            self.timer_flag = True
                            self.send_time = time.time()
                        self.dup_num = 0
                        continue
                    else:
                        print("receive dup ack")
                        # total dup_acks
                        self.dup_acks += 1
                        # dup_ack for fast retransmission
                        self.dup_num += 1
                        self.update_log("rcv/DA", self.get_packet_type(ack), ack)
                        if (self.dup_num == 3):
                            print("fast retransmission")
                            self.dup_num = 0
                            retransmit_packet = self.packet_buffer[self.send_base]
                            self.fast_retransmit(retransmit_packet)
                        continue
            except socket.timeout:
                # timeout retransmission
                if ((time.time() - self.send_time) >= self.timeout.timeout):
                    packet = self.packet_buffer[self.send_base]
                    self.retransmission(packet)
                continue
                
    # fast retransmission after receiving 3 dup acks    
    def fast_retransmit(self, packet):
        self.fast_rxt_seg += 1
        self.send_time = -1
        if len(self.order_buffer) > 0:
            self.order_count += 1
        self.pld_send(packet, retransmit=True)
       

    # pld module
    def pld_send(self, packet, retransmit=False):
        self.pld_seg += 1
        if not retransmit:
            payload = packet.data
            self.seq_no = packet.seq_no + len(payload)
            print("next seq_no is", self.seq_no)

        self.pld += 5
        if  random.random() < self.pDrop:
            self.pld -= 4
            print(self.pld)
            print("dropping packet with seq_num{}".format(packet.seq_no))
            self.dropped_seg += 1
            self.seg_trans += 1
            self.update_log("drop", self.get_packet_type(packet), packet)
            return -1
 
        elif random.random() < self.pDuplicate:
            self.pld -= 3
            print(self.pld)
            print("duplicate packet with seq_num{}".format(packet.seq_no))
            self.send(packet)
            self.send(packet)
            self.dup_seg += 1
            self.pld_seg += 1 
            self.update_log("snd", self.get_packet_type(packet), packet)
            self.update_log("snd/dup", self.get_packet_type(packet), packet)
            return 1

        elif random.random() < self.pCorrupt:
            self.pld -= 2
            print(self.pld)
            print("corrupting packet with seq_num{}".format(packet.seq_no))
            corrupted = corrupt(packet.data)
            seq_no = packet.seq_no
            ack_no = packet.ack_no
            checksum = packet.checksum
            new_packet = STPPacket(corrupted, seq_no, ack_no, checksum)
            self.send(new_packet)
            self.corrupted_seg += 1
            self.update_log("snd/corr", self.get_packet_type(packet), packet)
            return 1

        elif random.random() < self.pOrder:
            self.pld -= 1
            print(self.pld)
            if len(self.order_buffer) != 0:
                self.send(packet)
                if not retransmit:
                    self.update_log("snd", self.get_packet_type(packet), packet)
                else:
                    self.update_log("snd/RXT", self.get_packet_type(packet), packet)
                return 1
            else:
                print("holding back packet with seq_num {}".format(packet.seq_no))
                self.order_buffer.append(packet)
                self.reordered_seg += 1
                return 0

        elif random.random() < self.pDelay:
            print(self.pld)
            print("Delaying packet with seq_num {}".format(packet.seq_no))
            self.delayed_seg += 1
            delay_timer = Timer((random.uniform(0, self.maxDelay))/1000, self.delay_send, [packet])
            delay_timer.start()
            return 0
        else: 
            print("pld calls: ", self.pld)
            print("send packet without pld")
            self.send(packet)
            if not retransmit:
                self.update_log("snd", self.get_packet_type(packet), packet)
            else:
                self.update_log("snd/RXT", self.get_packet_type(packet), packet)
            return 1
    
    # send a packet after delay between 0 and maxDelay
    def delay_send(self, packet):
        if len(self.order_buffer) > 0:
            self.order_count += 1
        self.update_log("snd/dely", self.get_packet_type(packet), packet)
        self.send(packet)


    # write stats to log file
    def write_stats(self):
        with open("Sender_log.txt", 'a+') as f:
            f.write(
                "=======================================================================\n")
            f.write("Size of the file (in Bytes)\t{}\n".format(self.file_size))
            f.write("Segments transmitted (including drop & RXT)\t{}\n".format(
                self.seg_trans))
            f.write("Number of Segments handled by PLD\t{}\n".format(self.pld_seg))
            f.write("Number of Segments dropped\t{}\n".format(self.dropped_seg))
            f.write("Number of Segments Corrupted\t{}\n".format(
                self.corrupted_seg))
            f.write("Number of Segments Re-ordered\t{}\n".format(self.reordered_seg))
            f.write("Number of Segments Duplicated\t{}\n".format(self.dup_seg))
            f.write("Number of Segments Delayed\t{}\n".format(self.delayed_seg))
            f.write("Number of Retransmissions due to TIMEOUT\t{}\n".format(
                self.timeout_rxt_seg))
            f.write("Number of FAST RETRANSMISSION\t{}\n".format(
                self.fast_rxt_seg))
            f.write("Number of DUP ACKS received\t{}\n".format(self.dup_acks))
            f.write(
                "=======================================================================")

    # connection termination 
    def close_connection(self):
        while True:
            if self.end is True:
                fin = STPPacket(b'', self.seq_no, self.ack_no, fin=True)
                self.send(fin)
                self.update_log("snd", self.get_packet_type(fin), fin)
                self.seq_no += 1
                print("fin sent")
                self.fin_wait = True
                self.end = False
            elif self.fin_wait is True:
                print("====fin_wait_1====")
                ack = self.receive()
                if self.receive_ack(ack):
                    self.update_log("rcv", self.get_packet_type(ack), ack)
                    self.fin_wait = False
                    self.fin_wait_2 = True
            elif self.fin_wait_2 is True:
                print("====fin_wait_2====")
                fin = self.receive()
                if self.receive_fin(fin):
                    self.update_log("rcv", self.get_packet_type(fin), fin)
                    self.ack_no = fin.seq_no + 1
                    ack1 = STPPacket(b'', self.seq_no, self.ack_no, ack=True)
                    self.send(ack1)
                    self.update_log("snd", self.get_packet_type(ack1), ack1)
                    self.fin_wait_2 = False
                    self.time_wait = True
            elif self.time_wait is True:
                print("====time_wait====")
                self.close()
                self.time_wait = False
                self.closed = True
                print("Connection closed")
                break


if __name__ == '__main__':

    # check if user input correct command 
    if len(sys.argv) != 15:
        print(" python sender.py receiver_host_ip receiver_port file.pdf MWS MSS gamma pDrop pDuplicate pCorrupt pOrder maxOrder pDelay maxDelay seed")
    else:
        # clear content in Sender_log.txt
        f = open("Sender_log.txt", "w")
        f.close()

        # setup sender
        receiver_host_ip, receiver_port, file, MWS, MSS, gamma, pDrop, pDuplicate, pCorrupt, pOrder, maxOrder, pDelay, maxDelay, seed = sys.argv[
            1:]
        print("Sender initialised")
        sender = Sender(receiver_host_ip, receiver_port, file, MWS, MSS, gamma,
                        pDrop, pDuplicate, pCorrupt, pOrder, maxOrder, pDelay, maxDelay, seed)

        # 3 ways handshake
        sender.handshake()

        # read pdf file and break them into parts with size of mss
        sender.process_data()

        # calculate the size of the file
        sender.calc_total_payload()

        # send file to receiver
        sender.send_file()

        # close connection after the file has send across
        if sender.end is True:
            sender.close_connection()



# loop (forever) { 
#     switch(event)
#         event: data received from application above
#             create TCP segment with sequence number NextSeqNum 
#             if (timer currently not running)
#                 start timer
#             pass segment to IP NextSeqNum=NextSeqNum+length(data) 
#             break;

#         event: timer timeout
#             retransmit not-yet-acknowledged segment with
#                 smallest sequence number 
#             start timer
#             break;

#         event: ACK received, with ACK field value of y 
#             if (y > SendBase) {
#                 SendBase=y
#                 if (there are currently any not-yet-acknowledged segments)
#                     start timer 
#                 }
#             else { /* a duplicate ACK for already ACKed
#                 segment */
#                 increment number of duplicate ACKs
#                     received for y
#                 if (number of duplicate ACKS received for y==3)
#                     /* TCP fast retransmit */
#                     resend segment with sequence number y
#                 }
#             break;
# }
