#!/usr/bin/python3
# coding=utf-8

import nmap
import os
import psycopg2
#from multiprocessing.dummy import Pool as ThreadPool
from multiprocessing import Pool as ThreadPool
from libnmap.process import NmapProcess
from libnmap.reportjson import ReportDecoder,ReportEncoder
from libnmap.parser import NmapParser,NmapParserException


database = '*'
hhost = 'iceqboo.com'
dport = '*'
user = '*'
password = '*'

ip_info = dict()
os.system('masscan -p 1-65535 -iL ip.txt -oL port.list --rate 1000')
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
    '''不稳定，暂时弃用'''
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
    conn.close

def Scan1(ip):
    global ip_info
    ports = str(ip_info[ip]).strip('[|]|\'').replace("', '",',')
    nmap_proc = NmapProcess(ip, options='-sT -sV -p ' + ports + ' -script-args http.useragent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_2) AppleWebKit/537.36"')
    nmap_proc.run()
    nmap_repot = NmapParser.parse(nmap_proc.stdout)
    conn = psycopg2.connect(database=database, host=hhost, port=dport, user=user, password=password)

    cur = conn.cursor()
    for host in nmap_repot.hosts:
        for serv in host.services:
            while True:
                try:
                    cur.execute("select * from assets where ip='%s' and port='%s'" % (host.address, str(serv.port)))
                    tmp = cur.fetchall()
                    if (len(tmp) == 0):
                        cur.execute(
                            "INSERT INTO public.\"assets\"(ip, port, protocol, state, service, banner) values ('%s', '%s', '%s', '%s', '%s', '%s')" % (
                                host.address, str(serv.port), serv.protocol, serv.state, serv.service, serv.banner))
                    else:
                        cur.excute(
                            "UPDATE assets SET protocol='%s', state='%s', service='%s', banner='%s' WHERE ip='%s' and port='%s';" % (
                                serv.protocol, serv.state, serv.service, serv.banner, host.address, str(serv.port)))
                    print("%s\t%s\t%s\t%s\t%s\t%s" % (
                                host.address, str(serv.port), serv.protocol, serv.state, serv.service, serv.banner))
                    break
                except:
                    print("retry: %s:%s" % (host.address, str(serv.port)))
    conn.commit()
    conn.close()


pool = ThreadPool(1)
pool.map(Scan1, ip_list)
pool.close()
#pool.join()

#Scan1(ip_list[0])
