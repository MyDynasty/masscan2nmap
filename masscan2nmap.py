#!/usr/bin/python3
# coding=utf-8

import nmap
import os
import psycopg2

database = 'test'
host = '1.1.1.1'
dport = '5432'
user = 'user'
password = 'password'

ip_info = dict()
os.system('masscan -p 1-65535 -iL ip.txt -oL port.list --rate 10000')
with open('port.list', 'r') as file:
    a = file.read()
ip_info = dict()
with open('port.list', 'r') as file:
    for i in file:
        if(not(('masscan' in i)or('end' in i))):
            ip = i.split()[3]
            port  = i.split()[2]
            if(ip in ip_info):
                ip_info[ip].append(port)
            else:
                ip_info[ip]=[port]
ip_list = list(ip_info.keys())

def Scan(ip):
    global ip_info
    ports = str(ip_info[ip]).strip('[|]|\'').replace("', '",',')
    nm = nmap.PortScanner()
    nm.scan(ip, ports, '-sS -sV -Pn -T4')
    port_info = nm[ip]['tcp']

    conn = psycopg2.connect(database=database, host=host, port=dport, user=user, password=password)
    cur = conn.cursor()
    for port in ports:
        cur.execute("INSERT INTO public.\"ipINFO\"(ip, port, product, extrainfo, cpe) VALUES (ip, i, 'Huawei VRP sshd', 'protocol 1.99', 'cpe:/o:huawei:vrp');" % (ip,port,port_info[int(port)]['product'], port_info[int(port)]['extrainfo'], port_info[int(port)]['cpe']))
    conn.commit()
    conn.close()
