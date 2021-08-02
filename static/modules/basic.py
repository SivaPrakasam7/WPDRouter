#!/bin/python3

# Predefined modules
import smtplib
import json
import requests
import hashlib
import pwd
import stat
import datetime
import pprint

from collections import defaultdict
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
# Created modules
from static.modules.packages import *

# classes

class BASIC:
    def __init__(self):
        self.server=smtplib.SMTP('smtp.gmail.com',587)
        self.server.starttls()
        self.url=["",""]

    def msend(self,mail,passwd):
        while True:
            try:
                req1=json.loads(requests.get('http://127.0.0.1:4040/api/tunnels/admin').text)
                req2=json.loads(requests.get('http://127.0.0.1:4040/api/tunnels/rdesk').text)
                self.url[0]=req1['public_url']
                self.url[1]=req2['public_url']
                break
            except Exception as e: pass
        msg=MIMEMultipart()
        msg['subject']='WPD Router'
        msg.attach(MIMEText('WPD Main admin panel : '+self.url[0]+'\nRemote desktop : '+self.url[1]+'/vnc.html','plain'))
        # self.server.login(mail,passwd)
        # self.server.sendmail(mail,mail,msg.as_string())
        self.server.quit()
        return self.url

    def rdesk(self):
        subprocess.call("x11vnc -display :0 -autoport -localhost -bg -xkb -ncache -ncache_cr -quiet -forever -rfbauth /root/.vnc/passwd",shell=True)
        subprocess.Popen("/usr/share/novnc/utils/launch.sh --listen 8081 --vnc localhost:5900",shell=True)