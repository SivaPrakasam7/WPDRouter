#!/bin/python3

# Predefined modules
from sets import *
# Created modules
from static.modules.packages import *

# classes

# wifi class
class WIFI:
    def __init__(self,interface):
        self.interface,self.run,self.info=interface,True,{}
        Thread(target=self.channel_changer).start()
        self.THRESH=6
        self.ssidDicct={}
        self.ssidCtn={}

    def channel_changer(self):
        ch=1
        while self.run:
            try:
                os.system('iwconfig '+self.interface+' channel '+str(ch))
                ch=(ch%14)+1
                sleep(0.5)
            except KeyboardInterrupt: break

    def start(self):
        self.info.clear()
        sniff(iface=self.interface,prn=self.scan,timeout=5)

    def scan(self,p):
        wifi={}
        if p.haslayer(Dot11):
            try:
                typ,subtype=p[Dot11].type,p[Dot11].subtype
                if typ==0:
                    # if subtype==4: wifi['clients']=p[Dot11].addr2 # client request wasted
                    if subtype==8 or subtype==5: # Beacon frame and client response
                        clt=p[Dot11].addr1
                        wifi['bssid']=p[Dot11].addr2
                        wifi['ssid']=p[Dot11Elt].info.decode()
                        if '\x00' in wifi['ssid']: wifi['ssid']='Hidden Access Point'
                        try: wifi['dbm_signal']=str(p.dBm_AntSignal)+' dbm'
                        except: wifi['dbm_signal']='N/A'
                        stats=p[Dot11Beacon].network_stats()
                        wifi['channel']=stats.get('channel')
                        wifi['crypto']=[s for s in stats.get('crypto')][0]
                        wifi['rates']=str(stats.get('rates')[0])+' Mbps'
                        if clt not in ['ff:ff:ff:ff:ff:ff','00:00:00:00:00:00',wifi['bssid']]: wifi['clients']=clt
                    if subtype==11: wifi['bssid'],wifi['clients']=p[Dot11].addr2,p[Dot11].addr1 # Authendication of client
                    if subtype==12: wifi['deauth'],wifi['clients']='Deauthendication detected of client ',p[Dot11].addr1 # Deauthendication of client
                if typ==1 and subtype==11: wifi['bssid'],wifi['clients']=p[Dot11].addr2,p[Dot11].addr1
                if typ==2 and len(self.info): # new connection
                    addr1,addr2,addr3=p[Dot11].addr1,p[Dot11].addr2,p[Dot11].addr3
                    if subtype==0 and addr2 != addr3: wifi['bssid'],wifi['clients']=addr2,addr3
                    if subtype==8: wifi['bssid'],wifi['clients'],wifi['eapol']=addr1,addr2,p
                    if subtype==12: wifi['bssid'],wifi['clients']=addr1,addr2
                wifi['info']=self.fakeap(p)
                try:
                    if wifi['clients'] not in self.info[wifi['bssid']]['clients']: self.info[wifi['bssid']]['clients'].append(wifi['clients'])
                except:
                    if wifi['bssid'] not in self.info.keys() and len(wifi)>2: wifi['clients'],self.info[wifi['bssid']]=[],wifi
            except: pass

    def fakeap(self,p):
        if p.getlayer(Dot11).subtype==80:
            ssid=p[Dot11].info.decode()
            bssid=p[Dot11].addr2
            stamp=str(p[Dot11].timestamp)
            if bssid not in self.ssidDict:
                self.ssidDict[bssid]=[]
                self.ssidCnt[bssid]=0
            elif(long(stamp)<long(self.ssidDict[bssid][-1])):
                self.ssidCnt[bssid]+=1
            if(self.ssidCnt[bssid]>self.THRESH):
                return self.ssidDict[bssid].append(stamp)
        return None

# hotspot
class AP:
    def __init__(self,interface,network,drange,time):
        self.interface,self.network=interface,network
        dinit=drange.split('.')[-1]
        self.drange='{}2,{},255.255.255.0,{}h'.format(drange.replace(dinit,''),drange,time)
        self.host='hostapd.conf'
        self.dns='dnsmasq.conf'

        # Configuration
        os.system('ifconfig '+self.interface+' up 192.168.28.1 netmask 255.255.255.0')
        os.system('route add -net 192.168.28.0 netmask 255.255.255.0 gw 192.168.28.1')
        os.system('iptables --table nat --append POSTROUTING --out-interface '+self.network+' -j MASQUERADE')
        os.system('iptables --append FORWARD --in-interface '+self.interface+' -j ACCEPT')
        os.system('echo 1 > /proc/sys/net/ipv4/conf/all/proxy_arp')
        os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')

    def start(self,ssid,password):
        self.ssid=ssid
        self.password=password

        #create hostapd.conf
        self.confreplace(self.host,'interface',self.interface)
        self.confreplace(self.host,'ssid',self.ssid)
        self.confreplace(self.host,'wpa_passphrase',self.password)
        
        #create dnsmasq.conf
        self.confreplace(self.dns,'interface',self.interface)
        self.confreplace(self.dns,'dhcp-range',self.drange)

        subprocess.Popen('dnsmasq -C static/APconf/dnsmasq.conf -d',shell=True)
        self.map=subprocess.Popen('hostapd static/APconf/hostapd.conf',shell=True)
        while self.map.poll() is None: pass
        self.stop()

    def confreplace(self,file,var,val):
        temp=[]
        with open('static/APconf/'+file,'r') as rfp:
            for cont in rfp.readlines():
                if var in cont and var not in '_ssid':
                    temp.append(cont.replace(cont,var+'='+val+'\n'))
                else:
                    temp.append(cont)
        with open('static/APconf/'+file,'w') as wfp: wfp.write(''.join([t for t in temp]))

    def stop(self):
        os.system('iptables -F')
        os.system('echo 0 > /proc/sys/net/ipv4/conf/all/proxy_arp')
        os.system('echo 0 > /proc/sys/net/ipv4/ip_forward')