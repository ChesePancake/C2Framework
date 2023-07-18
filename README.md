# C2Framework

This is a proof-of-concept command and control framework being developed during my free time.
I started this program to learn more about Python, so expect some potentially unconventional methods.
I also didn't prioritize making it the most user-friendly, so my apologies for any inconvenience.

# Disclaimers
The fact that this is a proof of concept also means that I cannot guarantee compatibility on every machine.
I take no responsibility for any damages caused by, but not limited to, potential bugs, user error, unethical and unlawful usage, or natural disasters.

Of course, this is for educational purposes only, so please refrain from using it for malicious intent.
If you choose to do so, be aware that it is not advanced enough to avoid detection. You have been warned, you will get caught.


## Okay now that that's done, the technical details:

### Firstly, the modules used:
- rsa
- PIL
- fastapi
- pydantic
- uvicorn
- subprocess
- getpass
- ImageGrab
- pyttsx3
- requests
- pynput

To install these:
```shell 
pip install rsa PILLOW fastapi uvicorn pyttsx3 requests pynput
```
I also used curses, which should be included in the python standard library.
However, if you are using Windows, you need [windows-curses]{https://pypi.org/project/windows-curses/}.

To install:
```shell
pip install windows-curses
```
Apologies if I missed any module, but that should be all.

### Setup:
Both the client and server have a section at the start to fetch my ip and api key from a .json file, but you can remove this and hardcode them.

### Then some info about the program:
Features implemented so far:
- Text-to-speech(TTS)
- Remote shell execution
- Screenshots
- Filetransfer
- Keylogger

The data sent is encrypted using rsa. I did not bother routing the traffic through any proxies.
The client doesn't have any kind of persistence, though I might add some in the future.
For communication, tcp sockets are primarily used. REST API is used to inform the server that TTS is done and to deliver key presses from the keylogger.

Keylogger info is split into two .txt files: 'data' and 'data_raw'. 
Currently, it recognizes backspaces and ctrl+backspace (although the latter is untested) and formats it in the 'data' file for fancy points and better readability.
The 'data_raw' file contains the raw keylogger information.
Both keylogger info and screenshots are stored in the same directory as the python server script and are assigned unique names.

### Contribute!
I didn't prioritize making the code beautiful, and I apologize for that. However, I tried to be smart while making the functions, so adding features shouldn't be too complicated.

Lastly, there is no documentation provided in the code. *shrug* go figure.