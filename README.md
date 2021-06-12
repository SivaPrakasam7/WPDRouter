# WPDRouter

Description
---
  Wireless security, Pen-testing, Digital Forensics techniques included. That wirelessly penetrate all connected clients then monitor Dot11 signal. Create Documentation and pen-testing documentation. It has monitoring web interface networking activity.
  
run with follownig command
---
  root#./setup\n
  root# python router

required
---

python3.6 required for netfilterqueue package support

login <a href="https://ngrok.com/">ngrok</a> to get authendication token

You may modify your configuration in router file
---
      class ROUTER:
        def __init__(self):
            self.wrun,self.prun,self.frun,self.wifi=True,True,True,{}
            self.SSID='{Setup your SSID}'
            self.BSSID=''
            self.IP='192.168.28.1'
            self.drange='192.168.28.30'
            self.dtime='24'
            self.PASSWD='{Setup router password}'
            self.BASEDIR=['/root/']
            self.result={}
            self.mail="{your mail id with less secure app permission}"
            self.passwd="{mail password}"
            self.num=1
            self.BS=BASIC()
            self.url=[]
            self.clients=[]
            self.arp={}
            self.ipath=defaultdict(list)
            self.ppath=defaultdict(list)
            self.lp='static/logs/info/'
            self.pp='static/logs/evidence/'
            self.clients=open('static/APconf/accept','r').readlines()
        
Hardware requirement - 2 wlan interface and 1 ethernet connection\n
wlan0 - enable internet access\n
wlan1 - monitoring Dot11 packets around that\n
ethernet - network access transfer to the wlan0 interface
