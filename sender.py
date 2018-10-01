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
        return self.timeout

    def calc_timeout(self, sampleRTT):
        self.estRTT = ((1 - self.alpha) * self.estRTT) + (self.alpha * sampleRTT)
        self.devRTT = ((1 - self.beta) * self.devRTT) + \
            (self.beta * abs(sampleRTT - self.estRTT))
        self.timeout = (self.estRTT + (self.gamma * self.devRTT))/1000
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
        self.maxDelay = int(maxDelay)/1000
        self.seed = int(seed)
        self.socket = self.open_connection()
        self.timer = None
        self.start_time = time.time()
        self.timeout = Timeout(self.gamma)
        self.timer_flag = False
    

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

        random.seed(self.seed)
        
    def handshake(self):
        while True:
            if self.closed is True:
                # closed state
                print("\n==== STATE: CLOSED ====")
                syn = STPPacket(b'', self.seq_no, self.ack_no,syn=True)
                self.send(syn)
                self.update_log("snd",self.get_packet_type(syn) , syn)
                self.closed = False
                self.syn_sent = True

            elif self.syn_sent is True:
                # syn sent
                print("\n====STATE: SYN SENT====")
                synack = sender.receive()
                if self.receive_synack(synack):
                    print(synack.seq_no)
                    print(synack.ack_no)
                    print(synack.ack)
                    print(synack.syn)
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

    def open_connection(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            return s
        except socket.error:
            print("Socket creation failed")
            sys.exit()

    def send(self, packet):
        self.seg_trans += 1
        pkt = pickle.dumps(packet)
        self.socket.sendto(pkt, (self.receiver_ip, self.receiver_port))

    def receive(self):
        data, addr = self.socket.recvfrom(4096)
        packet = pickle.loads(data)
        return packet

    def calc_total_payload(self):
        with open(self.file, 'rb') as f:
            file_contents = f.read()
        self.file_size = len(file_contents)
        self.total_seq_no = self.seq_no + len(file_contents)
        print("final seq_num is {}".format(self.total_seq_no))
        print("file size: {}".format(self.file_size))

    def process_data(self):
        with open(self.file, 'rb') as f:
            file_contents = f.read()
        # print ([file_contents[ i : self.mss+i ] for i in range(0, len(file_contents),self.mss)])
        self.contents = [file_contents[i: self.mss+i]
                        for i in range(0, len(file_contents), self.mss)]

    def update_log(self, action, packet_type, packet):
        # execution time in miliseconds
        excution_time = (time.time() - self.start_time) * 1000
        with open("Sender_log.txt", 'a+') as f:
            f.write('{}\t{}\t{}\t{}\t{}\t{}\n'.format(
                    action, excution_time, packet_type,
                    packet.seq_no, len(packet.data), packet.ack_no))

    # def create_packet(self, index):
    #     payload = self.contents[index]
    #     # print(payload)
    #     # packet = STPPacket(payload, self.seq_no, self.ack_no, checksum(payload.decode('iso-8859-1')))
    #     packet = STPPacket(payload, self.seq_no,
    #                     self.ack_no, checksum=checksum(payload))
    #     # print(packet.checksum)
    #     return packet

    def receive_synack(self, stp_packet):
        if stp_packet.syn and stp_packet.ack:
            return True
        return False

    def receive_ack(self, stp_packet):
        if stp_packet.ack:
            return True
        return False

    def receive_fin(self, stp_packet):
        if stp_packet.fin:
            return True
        return False

    def close(self):
        if self.timer_flag:
            self.timer.cancel()
            self.timer_flag = False
        self.socket.close()
        self.write_stats()
    
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

    def retransmission(self, packet):
        print("timeout retransmission")
        self.timeout_rxt_seg += 1
        packet.send_time = -1
        # packet = STPPacket(data, seq_no, ack_no, checksum=checksum, send_time=-1)
        self.update_log("snd/RXT", self.get_packet_type(packet), packet)
        self.pld_send(packet, retransmit=True)


    def send_file(self):
        order_count = 0
        while True:
            print("cur seq num is {}".format(self.seq_no))
            if(self.bytes_sent - self.send_base < self.mws and self.send_base < self.file_size):
                print("still less than mss")
                print 
                if(order_count == self.maxOrder and self.pOrder > 0):
                    print("sending held back segment")
                    packet = self.order_buffer.pop()
                    order_count = 0
                    # we set retransmit equals true so that the seq_num wont be counted twice
                    self.send(packet)
                    print ("sending held back segment with seq_num ".format( packet.seq_no))
                    continue
                print("bytes sent is ",self.bytes_sent)

                # # retransmit unacked packets
                # if (self.bytes_sent >= self.file_size and len(self.packet_buffer.keys()) > 0):
                #     print("There are still unacked packets that need to be resent even though self.last_sent ")
                #     l = sorted(self.packet_buffer.keys())
                #     print("list is ", l)
                #     packet = self.packet_buffer[self.send_base]
                #     result = self.pld_send(packet, retransmit=True) 
                # else:
                if self.bytes_sent < self.file_size:
                    # event: receive data from application layer
                    index = int(self.bytes_sent / self.mss)
                    payload = self.contents[index]
                    print("about to send payload ")
                    packet = STPPacket(payload, self.seq_no, self.ack_no, checksum=checksum(payload), send_time=time.time())
                    self.packet_buffer[self.seq_no] = packet
                    result = self.pld_send(packet)

                # event: retransmit after timer timeout, send the segment with the smallest seq num
                if (self.timer_flag is False):
                    if (self.send_base == 0):
                        timeout = self.timeout.initial_timeout()
                    else:
                        timeout = self.timeout.timeout
                    index = int(self.send_base / self. mss)
                    payload = self.contents[index]
                    packet = STPPacket(payload,self.send_base, self.ack_no, checksum=checksum(payload), send_time=time.time())
                    print("if timeout, sending ")
                    self.timer_flag = True
                    self.timer = Timer(timeout, self.retransmission, [packet])
                    self.timer.start()

                self.bytes_sent += self.mss           
                if result == -1: 
                    continue
                elif result == 1 and len(self.order_buffer) > 0:
                    order_count += 1
                

            # event: ACK received
            print("waiting for ack")
            ack = self.receive()
            recv_time = time.time()
            if self.receive_ack(ack):
                received_ack = ack.ack_no
                if received_ack > self.send_base:
                    print("received ack: {} and the current send base is {}".format(received_ack, self.send_base))
                    # stop timer on previous packet. new send base 
                    if self.timer_flag:
                        self.timer.cancel()
                        self.timer_flag = False
                    self.update_log("rcv", self.get_packet_type(ack), ack)
                    # ack_num will be 1 more than last acked byte
                    self.send_base = received_ack
                    print("new send_base ",self.send_base )
                    # clear up retransmission timer 
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
                        break
                    # calculate SampleRTT
                    if ack.send_time != -1:
                        sampleRTT = recv_time - ack.send_time
                        timeout = self.timeout.calc_timeout(sampleRTT)
                    else: 
                        timeout = self.timeout.timeout
                    if len(self.packet_buffer) > 0:
                        packet = self.packet_buffer[self.send_base]
                        #retransmit on timeout 
                        self.timer = Timer(timeout, self.retransmission, [packet])
                        self.timer.start()
                        self.timer_flag = True
                else: 
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
            
    def fast_retransmit(self, packet):
        self.fast_rxt_seg += 1
        packet.send_time = -1
        self.pld_send(packet, retransmit=True)
        self.update_log("snd/RXT", self.get_packet_type(packet), packet)

    def pld_send(self, packet, retransmit=False):
        self.pld_seg += 1

        if not retransmit:
            payload = packet.data
            self.seq_no = packet.seq_no + len(payload)
            print("next seq_no is", self.seq_no)
       
        if  random.random() < self.pDrop:
            print("dropping packet with seq_num{}".format(packet.seq_no))
            self.dropped_seg += 1
            self.seg_trans += 1
            self.update_log("drop", self.get_packet_type(packet), packet)
            return -1

        elif random.random() < self.pDuplicate:
            print("duplicate packet with seq_num{}".format(packet.seq_no))
            self.send(packet)
            self.send(packet)
            self.dup_seg += 1
            if retransmit is False:
                self.update_log("snd/dup", self.get_packet_type(packet), packet)
            else:
                self.update_log("snd/RXT", self.get_packet_type(packet), packet)
            return 1

        elif random.random() < self.pCorrupt:
            print("corrupting packet with seq_num{}".format(packet.seq_no))
            corrupted = corrupt(packet.data)
            seq_no = packet.seq_no
            ack_no = packet.ack_no
            checksum = packet.checksum
            new_packet = STPPacket(corrupted, seq_no, ack_no, checksum)
            self.send(new_packet)
            self.corrupted_seg += 1
            if retransmit is False:
                self.update_log("snd/corr", self.get_packet_type(packet), packet)
            else:
                self.update_log("snd/RXT", self.get_packet_type(packet), packet)
            return 1

        elif random.random() < self.pOrder:
            if len(self.order_buffer) != 0:
                self.send(packet)
                if retransmit is False:
                    self.update_log("snd/rord", self.get_packet_type(packet), packet)
                else:
                    self.update_log("snd/RXT", self.get_packet_type(packet), packet)
                return 1
            else:
                print("holding back packet with seq_num {}".format(packet.seq_no))
                self.order_buffer.append(packet)
                self.reordered_seg += 1
                return 0

        elif random.random() < self.pDelay:
            print("Delaying packet with seq_num {}".format(packet.seq_no))
            self.delayed_seg += 1
            delay_timer = Timer(random.uniform(0, self.maxDelay), self.delay_send, [packet])
            delay_timer.start()
            return 1
        else: 
            print("send packet without pld")
            self.send(packet)
            if not retransmit:
                self.update_log("snd", self.get_packet_type(packet), packet)
            return 1
    
    def delay_send(self, packet):
        self.update_log("snd/dely", self.get_packet_type(packet), packet)
        self.send(packet)


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
    

# def is_retransmit(self, next_seq_num):
#     seq_num = next_seq_num - (self.mss + 1)
#     for i in range(len(self.retransmit_buffer)) {
#         if seq_num in self.retransmit_buffer.keys(){
#             del(self.retransmit_buffer[seq_num])
#             return True 
#         }
#     }
#     return False


if __name__ == '__main__':
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

        sender.handshake()
        sender.process_data()
        sender.calc_total_payload()

        # while sender.established:
        # 	sender.create_packet(0)
        # 	sender.established = False
        # 	if not sender.established:
        # 		sender.end = True
        # 		break

        sender.send_file()
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
