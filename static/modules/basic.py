#!/bin/python3

# Predefined modules
import smtplib
import json
import requests
import subprocess
import chromedriver_autoinstaller
import joblib
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.neighbors import KNeighborsClassifier
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
# Created modules
# from static.modules.packages import *

# classes

class BASIC:
    def __init__(self):
        self.server=smtplib.SMTP('smtp.gmail.com',587)
        self.server.starttls()
        self.url=["",""]
        try:self.dt=open('static/source/hackcode.txt','r').readlines()
        except:
            self.hcodescrap()
            self.dt=open('static/source/hackcode.txt','r').readlines()
        try:
            self.knn=joblib.load('static/source/malware_by_knn.pkl')
        except: 
            self.train_test()
            self.knn=joblib.load('static/source/malware_by_knn.pkl')

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
        msg.attach(MIMEText('WPD Main admin panel : '+self.url[0]+'\nRemote desktop : '+self.url[1]+'/vnc.html\nSystem file scan : '+self.url[0]+'/scanme','plain'))
        self.server.login(mail,passwd)
        self.server.sendmail(mail,mail,msg.as_string()) # 'vjkannan55@gmail.com'
        self.server.quit()
        return self.url

    def rdesk(self):
        subprocess.call("x11vnc -display :0 -autoport -localhost -bg -xkb -ncache -ncache_cr -quiet -forever -rfbauth /home/siva/.vnc/passwd",shell=True)
        subprocess.Popen("/usr/share/novnc/utils/launch.sh --listen 8081 --vnc localhost:5900",shell=True)

    def hcodescrap(self):
        code=[]
        mcode=0
        ocode=0
        soup=BeautifulSoup(requests.get('https://gtfobins.github.io/').content,'html5lib') #2447
        for url in ['https://gtfobins.github.io'+a['href'] for a in soup.findAll('a') if '/gtfobins/' in a['href'] and '#' not in a['href']]:
            print(url)
            suop1=BeautifulSoup(requests.get(url).content,'html5lib')
            for sd in suop1.findAll('pre'):
                data=sd.text.split('\n')
                for i,d in enumerate(data):
                    for rp in re.findall(r'\w*attacker[\\]share\w*',d):d=d.replace(rp,'file_to_share')
                    if re.findall(r' -c [\'|"]| -e [\'|"]|cat >.*<<.*',d):
                        code.append([' '.join(data[i:]).replace('# press return twicereset','').replace('\\','/'),1])
                        break
                    else: code.append([d.replace('\\','/'),1])
        with open('static/source/hackcode.txt','w+') as w:
            for d in code:
                l=0
                md=d[0].replace('[','').replace(']','').replace('<file name>','file_to_lp').replace('username','file_to_name').strip()
                if md in ['','^'] or len(md.split('=')) == 2 or len(md.split(' ')) <3: pass
                else:
                    ocode+=1
                    x=re.findall(r'http\w:[\w\.\/\?\=\&\%]+',md)
                    if x:
                        for rp in x:md=md.replace(rp,'http\w:[\w\.\/\?\=\&\%]+')
                    else:
                        for s in self.symbols:md=md.replace(s,'\\'+s)
                    for p in self.parser:
                        match=re.findall(p,md)
                        if match:
                            l+=len(match)
                            for rp in match:
                                md=md.replace(rp,str(p))
                    match1=re.findall(r'file_to_\w*|output_file|where_to\w*',md)
                    if match1:
                        l+=len(match1)
                        for rp in match1:md=md.replace(rp,'[\w\-_\/]+')
                    cmd=md.replace("\\\\","\\")
                    md+='||'+cmd.replace(str(self.parser[2]),str(self.parser[0]).replace('=',''))+'||'+cmd.replace(str(self.parser[2]),'http\w:[\w\.\/\?\=\&\%]+')
                    md='|'.join(list(set(md.split('||'))))
                    md=md.replace("\\\\","\\").replace("\[","[").strip()
                    data=[d[0],md,len(d[0].split(' ')),l,self.matcher(d[0].replace('[','').replace(']',''),md)]
                    if re.findall(r'\w*pass\w*|\w*/bin/\w*| sh |\W*shadow\w*|\w*bash\w*',md): 
                        w.write(data)
                    elif re.findall(r'^export .*|^cp .*|^mv .*|^rm .*|^cat .*|^echo .*',md):pass
                    elif d[1] == 1:
                        w.write(data)
                    else:pass
                    if re.findall(md.strip(),d[0].replace('[','').replace(']','')):
                        mcode+=1
                        print([d[0].replace('[','').replace(']',''),mcode,ocode,l,md],'\n\n\n\n\n')

    def train_test(self):
        dt=pd.read_csv('static/source/data.csv',sep='|')
        x=dt.drop(['Name','md5','legitimate'], axis=1).values
        y=dt['legitimate'].values
        # Train model
        x_train,x_test,y_train,y_test=train_test_split(x,y,test_size=0.20)
        knn=KNeighborsClassifier(n_neighbors=5)
        knn.fit(x_train,y_train)
        print(knn.score(x_test,y_test))
        joblib.dump(knn,'static/source/malware_by_knn.pkl')