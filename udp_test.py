import socket
import time
import random
import string

# Define the host address
UDP_IP = "192.168.15.14"
MY_IP = "192.168.15.15"

# Function to generate a random string of random length
def get_random_string():
    length = random.randint(0, 1400)  # Random string length between 0 and 1400
    ascii_chars = string.ascii_letters + string.digits + string.punctuation + ' '  # All ASCII characters
    result_str = ''.join(random.choice(ascii_chars) for i in range(length))
    return result_str

def send_msg(send_port):
    # Create a new socket for sending
    send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    # Bind the socket to the source IP address and port
    try:
        send_sock.bind((MY_IP, send_port))
    except Exception as e:
        print("Port is: ",send_port)
        time.sleep(0.5)
        raise(e)


    MESSAGE = get_random_string().encode('utf-8', 'ignore')  # Generate a random string of random length and encode it

    send_sock.sendto(MESSAGE, (UDP_IP, send_port+1))
    #print(f"Message sent from port {send_port}!")
    
    send_sock.close()  # Close the sending socket, so a new one can be created for the next message
    return MESSAGE

def recv_msg_start(recv_port):
    # Create a socket for receiving and bind it to the receive port
    recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    recv_sock.bind((MY_IP, recv_port))
    recv_sock.setblocking(0)  # Set the socket to be non-blocking

    return recv_sock
    

def recv_msg_end(recv_sock,msg):
    returnV = 1
    try:
        data, addr = recv_sock.recvfrom(1400)
        #print("Received message: ", data)
        if(msg == data):
            #print("Passed")
            returnV = 0
        else:
            #print("Incorrect")
            pass
    except socket.error:
        #print("No data received")
        pass

    recv_sock.close()  # Close the receiving socket
    return returnV

cnt = 0

#IDK why, but without this, the initall comm will fail
for i in range(10):
    r_sock = recv_msg_start(20023 + 1)
    time.sleep(0.01)
    msg = send_msg(20023)
    time.sleep(0.1)
    recv_msg_end(r_sock, msg)
    time.sleep(0.1)

while True:
    PORT = random.randint(5500,60000)  # Random port a

    r_sock = recv_msg_start(PORT + 1)
    msg = send_msg(PORT)
    time.sleep(0.01)
    if(recv_msg_end(r_sock, msg)!=0):
        print("Failed after, CNT:{0}".format(cnt))
        break
    else:
        cnt += 1
    if(cnt >= 10000):
        print("Successed {0} times".format(cnt))
        break
    #time.sleep(0.01)