#!/bin/python3.6

# Predefined modules
import re
import os

from datetime import *
from threading import Thread
from scapy.all import *
from time import ctime
from netfilterqueue import NetfilterQueue

# classes

# Digital forensics
class DFORENSICS:
    def __init__(self,interface,clients,bssid,num):
        self.run,self.interface,self.clients=True,interface,clients
        self.DF=None
        self.pt=Thread(target=None)
        self.packet={}
        self.lp='static/logs/info/'
        self.pp='static/logs/evidence/'
        self.dt=open('static/source/hackcode.txt','r').read().split('\n')
        self.disallow=open('static/APconf/dnsblock','r').read().split('\n')
        self.BSSID=bssid
        self.num=num
        self.fold()

    # Python 3.9 start
    def pmstart(self):
        os.system('iptables -F')
        os.system('iptables -A INPUT -i '+self.interface+' -j NFQUEUE --queue-num '+str(self.num))
        # os.system('iptables -A OUTPUT -p udp --dport 53 -j NFQUEUE')
        nfqueue=NetfilterQueue()
        nfqueue.bind(self.num,self.scan)
        try:
            nfqueue.run()
        except KeyboardInterrupt:
            os.system('iptables -F')

    def scan(self,p):
        try: Thread(target=self.devidence,args=(p,)).start()
        except Exception as e:print(e)
        sp=self.pmodify(p)
        if sp == 'drop':
            p.drop()
        else:
            p.set_payload(bytes(sp))
            p.accept()

    def pmodify(self,p):
        try:
            mp=Ether(p.get_payload())
            if mp[Ether].type==2048: pass
            mp=ARP(p.get_payload())
            if mp.haslayer(ARP):
                if mp.hwsrc not in self.clients:
                    return 'drop'
            else: pass
            mp=IP(p.get_payload())
            if mp.haslayer(DNS):
                if mp.haslayer(DNSRR):
                    try:
                        qname = mp[DNSQR].qname
                        if qname in self.disallow:
                            mp[DNS].an=DNSRR(rrname=qname,rdata=str('192.168.28.1'))
                            mp[DNS].ancount=1
                            del mp[IP].len
                            del mp[IP].chksum
                            del mp[UDP].len
                            del mp[UDP].chksum
                    except: pass
            for rp in re.findall('|'.join(list(set(self.dt))),str(mp[Raw].load).replace('[','').replace(']','')):match.append(rp)
            if match: return 'drop'
        except:pass
        return mp

    def devidence(self,mp):
        match=[]
        info={}
        try:
            # p=ARP(mp.get_payload())
            # if p.haslayer(ARP): info['psrc'],info['pdst']=p[ARP].psrc,p[ARP].pdst
            # p=Ether(mp.get_payload())
            # ips=info['src']=str(p[Ether].src).replace(':','.')
            # ipd=info['dst']=str(p[Ether].dst).replace(':','.')
            p=IP(mp.get_payload())
            ips=p[IP].src.replace('.','')
            ipd=p[IP].dst.replace('.','')
            info['ipv4_src'],info['ipv4_dst']=p[IP].src,p[IP].dst
            if p.haslayer(DNS):
                try: info['type'],info['sport'],info['dport'],info['rdata']='DNS response',p[UDP].sport,p[UDP].dport,p[DNSRR].rdata.decode()
                except: info['type']='DNS Request'
                info['qname']=p[DNSQR].qname.decode()
            if p.haslayer(TCP):
                chk,dchk=p[TCP].sport,p[TCP].dport
                if chk!=443: info['type'],info['sport'],info['dport']='TCP Request',chk,dchk
                else: info['type'],info['sport'],info['dport']='TCP Response',dchk,chk
            try: 
                info['raw']=p[Raw].load
                for rp in re.findall('|'.join(list(set(self.dt))),str(p[Raw].load).replace('[','').replace(']','')):match.append(rp)
                if match: info['match']=match
            except: info['raw']=None
            info['packet']=p.summary()
            info['time']=ctime()
            if match:open(self.pp+'/'+ips+' '+str(ctime())+'.log','w').write(str(info)+'\n')
            if info!={} and info['type']:
                # open(self.lp+'/packet.log','a').write(str(info)+'\n')
                if ips in self.clients:
                    self.handle('os.mknod(self.lp+"/"+val+".log")',ips)
                    with open(self.lp+'/'+ips+'.log','a') as fp: fp.write(str(info)+'\n')
                elif ipd in self.clients:
                    self.handle('os.mknod(self.lp+"/"+val+".log")',ipd)
                    with open(self.lp+'/'+ipd+'.log','a') as fp: fp.write(str(info)+'\n')
                else:
                    self.handle('os.mknod(self.lp+"/"+val+".log")',ips)
                    self.handle('os.mknod(self.lp+"/"+val+".log")',ipd)
                    with open(self.lp+'/'+ips+'.log','a') as fp: fp.write(str(info)+'\n')
                    with open(self.lp+'/'+ipd+'.log','a') as fp: fp.write(str(info)+'\n')
        except Exception as e:print(e)
        # print(info)

    def fold(self):self.disallow=open('static/APconf/dnsblock','r').readlines()

    def phandle(self,ip,p):
        try: self.packet[ip].append(p)
        except:
            self.packet[ip]=[]
            self.packet[ip].append(p)

    def handle(self,code,val):
        try: eval(code)
        except: pass


DFORENSICS('usb0',[],'7e:01:23:c9:d3:46',1).pmstart()