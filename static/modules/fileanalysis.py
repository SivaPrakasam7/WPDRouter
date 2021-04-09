#!/bin/python3

# Predefined modules
try:
    import hashlib
    import pwd
    import stat
    import datetime
    import pprint
    import pefile
    import pandas as pd
    import joblib
    import subprocess
    import os
    import array
    import math
    import psutil
    import requests
    import platform
    import cpuinfo
    import re
    import csv
    import json
    import sklearn.ensemble as ek
    import urllib.request
    import datetime

    from collections import defaultdict
    from bs4 import BeautifulSoup
    from threading import Thread
    from getmac import get_mac_address
    from time import *
    from sklearn.model_selection import train_test_split
    from sklearn.neighbors import KNeighborsClassifier
    from sklearn.feature_selection import SelectFromModel
except Exception as e:
    print('Please install required packages '+e)
# Created modules

# classes
# Hack inbuilt
class HACKIN:
    def __init__(self,url):
        print('Scanning in this path '+os.getcwd())
        self.url=url
        self.detail={}
        self.threads=[]
        self.hashsize=defaultdict(list)
        self.hash1k=defaultdict(list)
        self.fullhash={}
        self.score=0
        self.ostype=os.name
        self.parser=[r'=[ a-z0-9A-Z\.\-\/\'\"_\@]+',r'[\w\-_]+=',r'\$[A-Z_]+',r'\([A-Z_\"\']\)'] #,r'\"[A-Z_]+',r'\'[A-Z_]+'] #   link parser, file and directory parser, Variable parser, Variable usage parser
        self.symbols=['$',';','(',')','^','|','*','.',',','+']
        self.head=['ocode','code','word_count','match_count','match_score']
        self.perm={0:'---',1:'--x',2:'-w-',3:'-wx',4:'r--',5:'r-x',6:'rw-',7:'rwx'}
        self.ftype={'S_ISDIR':'dir','S_ISLNK':'link','S_ISFIFO':'fifo','S_ISSOCK':'socket','S_ISCHR':'char','S_ISBLK':'block','S_ISDOOR':'door','S_ISPORT':'port','S_ISWHT':'whiteout','S_ISREG':'regular'}
        self.ctime=datetime.datetime.now().strftime("%H:%M")
        try:self.dt=open('hackcode.txt','r').readlines()
        except:
            urllib.request.urlretrieve(self.url+'/static/source/hackcode.txt','hackcode.txt')
            self.dt=open('hackcode.txt','r').readlines()
        self.sysinfo(os.getcwd())

    def sysinfo(self,path):
        ip=get_mac_address(interface='wlan0')
        self.clscache()
        self.detail['files']=defaultdict(dict)
        d=defaultdict(dict)
        sys=platform.uname()
        d['system']=sys.system+' '+sys.machine+' '+sys.node
        d['release']=sys.release
        d['version']=sys.version
        d['processor']=cpuinfo.get_cpu_info()['brand_raw']
        nstat=psutil.net_if_addrs()
        d['interfaces']=len(nstat.keys())
        for k in nstat.keys():
            d[k]=nstat[k][0].address
            try: d['ipv6']=nstat[k][1].address
            except: pass
        # d['ipv4']=requests.get('https://api.ipify.org/').text
        cpus=psutil.cpu_freq()
        d['cpu_min']=cpus.min
        d['cpu_max']=cpus.max
        # d['cpu']={'min':cpus.min,'max':cpus.max,'used':cpus.current,'percentage':psutil.cpu_percent(percpu=True)}
        vmem=psutil.virtual_memory()
        d['ram']=self.bytes(vmem.total)
        # d['ram']={'perentage':'{:.1f} %'.format(vmem.percent),'total':self.bytes(vmem.total),'available':self.bytes(vmem.available),'used':self.bytes(vmem.used),'free':self.bytes(vmem.free)}
        # try:
        #     bat=psutil.sensors_battery()
        #     d['battery']={'percentage':'{:.1f} %'.format(bat.percent),'time':self.secs(bat.secsleft),'pluged':bat.power_plugged}
        # except: pass
        for ds in psutil.disk_partitions():
            dsu=psutil.disk_usage(ds.mountpoint)
            # d['files']=self.fparse(ds.mountpoint)
            d['storage'][ds.device]={'mount':ds.mountpoint,'fstype':ds.fstype,'total':self.bytes(dsu.total),'used':self.bytes(dsu.used),'free':self.bytes(dsu.free),'percentage':'{:.1f} %'.format(dsu.percent)}
        for pid in psutil.pids():
            try:
                inf=psutil.Process(pid).as_dict()
                d['process'][pid]={'name':inf['name'],'status':inf['status'],'user':inf['username'],'cpu':'{:.1f} %'.format(inf['cpu_percent']),'memory':'{:.1f} %'.format(inf['memory_percent']),'cwd':inf['cwd'],'threads':inf['num_threads'],'connections':[[cn.laddr,cn.raddr] for cn in inf['connections']]}
                # 'cmdline', 'connections', 'cpu_affinity', 'cpu_num', 'cpu_percent', 'cpu_times', 'create_time', 'cwd', 'environ', 'exe', 'gids', 'io_counters', 'ionice', 'memory_full_info', 'memory_info', 'memory_maps', 'memory_percent', 'name', 'nice', 'num_ctx_switches', 'num_fds', 'num_handles', 'num_threads', 'open_files', 'pid', 'ppid', 'status', 'terminal', 'threads', 'uids', 'username'
            except: pass
        d['files']=self.fparse(path)
        d['duplicates']=self.chkdup()
        d['analysis']=None
        d['scan_time']=str(datetime.datetime.now().strftime("%H:%M"))+' '+str(datetime.datetime.now().strftime("%x"))
        self.detail=d
        open(str(ip).replace(':','')+'.json','w').write(json.dumps(self.detail,indent=4))
        print(requests.post(self.url+'/upload/'+str(ip).replace(':','')+'.json',data=json.dumps(self.detail,indent=4)).text)

    def clscache(self):
        if self.ostype=="posix":
            os.system("sudo sh -c 'sync; echo 3 > /proc/sys/vm/drop_caches'")
            os.system("sudo find /tmp -type f -atime +5 -delete")
            os.system("sudo apt autoremove")
            os.system("sudo apt autoclean")
        elif self.ostype == "nt":
            os.system("ipconfig/flushDNS")
            os.system("del /q/f/s %\TEMP%\*")
        else:pass

    def fparse(self,path):
        l=0
        sysfile=defaultdict(list)
        for r,d,f, in os.walk(path):
            for fname in f:
                ext=None
                ex=fname.split('.')
                if len(ex)!=1:ext=ex[-1]
                else:ext='NO_EXT'
                fpath=os.path.join(r,fname)
                try:
                    print(fpath)
                    fpath=os.path.realpath(fpath)
                    self.hashsize[os.path.getsize(fpath)].append(fpath)
                    l+=1
                    sysfile[ext].append(self.fsystem(path,fpath))
                except Exception as e: print(e)
        return {'total':l,'scanned path':path,'detail':sysfile}

    def chkdup(self):
        dub=defaultdict(dict)
        for sizeb,files in self.hashsize.items():
            if len(files)<2: pass
            else:
                for fname in files:
                    try:
                        shash=self.gethash(fname,first_chunk_only=True)
                        self.hash1k[(shash,sizeb)].append(fname)
                    except: pass
        for __,flist in self.hash1k.items():
            if len(flist) < 2: pass
            else:
                for fname in flist:
                    print(fname)
                    try:
                        fhash=self.gethash(fname,first_chunk_only=False)
                        duplicate=self.fullhash.get(fhash)
                        if duplicate:
                            dub[fname]=duplicate
                            # print("Duplicate found {} and {}".format(fname,duplicate))
                        else: self.fullhash[fhash]=fname
                    except: pass
        return dub

    def gethash(self,fname,first_chunk_only=False,hash=hashlib.sha1):
        hashobj=hash()
        fobj=open(fname,'rb')
        if first_chunk_only: hashobj.update(fobj.read(1024))
        else:
            for chunk in self.chkread(fobj): hashobj.update(chunk)
        hashed=hashobj.digest()
        fobj.close()
        return hashed

    def chkread(self,fobj,chunk_size=1024):
        while True:
            chunk=fobj.read(chunk_size)
            if not chunk: return
            yield chunk

    def fsystem(self,path,fname):
        f={}
        stat=os.stat(fname)
        f['path']=fname
        f['permission'],f['type']=self.pmode(stat.st_mode)
        f['size']=[stat.st_size,self.bytes(stat.st_size)]
        f['last_acess_time']=self.secs(stat.st_atime)
        f['last_modification_time']=self.secs(stat.st_mtime)
        f['current_time']=self.secs(stat.st_ctime)
        f['user']=self.handle(stat,"pwd.getpwuid(var.st_uid).pw_name")
        f['group']=self.handle(stat,"pwd.getpwuid(var.st_gid).pw_name")
        f['hard_disk_count']=self.handle(stat,"var.st_nlink")
        # For hacking analysis AI
        if fname.split('.')[-1] == 'exe':
            f['malicious']=EXMALWARE(self.url).analyze(fname)
        else:
            try:
                x=re.findall('|'.join(list(set(self.dt))),open(fname,'r').read().replace('\n',''))
                if x: f['malicious']=[True,[p.replace("'","") for p in x]]
                else: f['malicious']=[False,x]
            except:f['malicious']='Unreadable'
        f['analysis']=None
        return f

    def pmode(self,ch):
        t=""
        for k,chk in self.ftype.items():
            if eval('stat.'+k+'('+str(ch)+')'): t=chk
        p=oct(ch)[-3:]
        return [p,self.perm[int(p[0])]+self.perm[int(p[1])]+self.perm[int(p[2])]],t

    # link with fsystem function but create dataset hacking code with file permission
    def hackAI(self,data):pass

    # common functions
    def bytes(self,size):
        for s in ['bytes','KB','MB','GB','TB']:
            if size < 1024.0:
                return '{:3.1f} {:s}'.format(size,s)
            size/=1024.0

    def secs(self,sec):
        mm,ss=divmod(int(sec),60)
        hh,mm=divmod(mm,60)
        return '{:d}:{:2d}:{:2d}'.format(hh,mm,ss)

    def handle(self,var,val):
        try: return eval(val)
        except: return None

# Malware analysis for exe files or windows
class EXMALWARE:
    def __init__(self,url):
        self.url=url
        try:self.knn=joblib.load('malware_by_knn.pkl')
        except:
            urllib.request.urlretrieve(self.url+'/static/source/malware_by_knn.pkl','malware_by_knn.pkl')
            self.knn=joblib.load('malware_by_knn.pkl')

    def analyze(self,path):
        peinfo=self.getinfo(path)
        data=[[peinfo[x] for x in peinfo.keys()]]
        if 0==self.knn.predict(data)[-1]: return True
        else: return False
        # print(['malicious','legitimate'][result]

    def getinfo(self,fpath):
        res={}
        pe=pefile.PE(fpath)
        res['Machine']=pe.FILE_HEADER.Machine
        res['SizeOfOptionalHeader']=pe.FILE_HEADER.SizeOfOptionalHeader
        res['Characteristics']=pe.FILE_HEADER.Characteristics
        res['MajorLinkerVersion']=pe.OPTIONAL_HEADER.MajorLinkerVersion
        res['MinorLinkerVersion']=pe.OPTIONAL_HEADER.MinorLinkerVersion
        res['SizeOfCode']=pe.OPTIONAL_HEADER.SizeOfCode
        res['SizeOfInitializedData']=pe.OPTIONAL_HEADER.SizeOfInitializedData
        res['SizeOfUninitializedData']=pe.OPTIONAL_HEADER.SizeOfUninitializedData
        res['AddressOfEntryPoint']=pe.OPTIONAL_HEADER.AddressOfEntryPoint
        res['BaseOfCode']=pe.OPTIONAL_HEADER.BaseOfCode
        try: res['BaseOfData']=pe.OPTIONAL_HEADER.BaseOfData
        except AttributeError: res['BaseOfData']=0
        res['ImageBase']=pe.OPTIONAL_HEADER.ImageBase
        res['SectionAlignment']=pe.OPTIONAL_HEADER.SectionAlignment
        res['FileAlignment']=pe.OPTIONAL_HEADER.FileAlignment
        res['MajorOperatingSystemVersion']=pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
        res['MinorOperatingSystemVersion']=pe.OPTIONAL_HEADER.MinorOperatingSystemVersion
        res['MajorImageVersion']=pe.OPTIONAL_HEADER.MajorImageVersion
        res['MinorImageVersion']=pe.OPTIONAL_HEADER.MinorImageVersion
        res['MajorSubsystemVersion']=pe.OPTIONAL_HEADER.MajorImageVersion
        res['MajorSubsystemVersion']=pe.OPTIONAL_HEADER.MajorSubsystemVersion
        res['MinorSubsystemVersion']=pe.OPTIONAL_HEADER.MinorSubsystemVersion
        res['SizeOfImage']=pe.OPTIONAL_HEADER.SizeOfImage
        res['SizeOfHeaders']=pe.OPTIONAL_HEADER.SizeOfHeaders
        res['CheckSum']=pe.OPTIONAL_HEADER.CheckSum
        res['Subsystem']=pe.OPTIONAL_HEADER.Subsystem
        res['DllCharacteristics']=pe.OPTIONAL_HEADER.DllCharacteristics
        res['SizeOfStackReserve']=pe.OPTIONAL_HEADER.SizeOfStackReserve
        res['SizeOfStackCommit']=pe.OPTIONAL_HEADER.SizeOfStackCommit
        res['SizeOfHeapReserve']=pe.OPTIONAL_HEADER.SizeOfHeapReserve
        res['SizeOfHeapCommit']=pe.OPTIONAL_HEADER.SizeOfHeapCommit
        res['LoaderFlags']=pe.OPTIONAL_HEADER.LoaderFlags
        res['NumberOfRvaAndSizes']=pe.OPTIONAL_HEADER.NumberOfRvaAndSizes
        # Sections
        res['SectionsNb']=len(pe.sections)
        entropy=list(map(lambda x:x.get_entropy(), pe.sections))
        res['SectionsMeanEntropy']=sum(entropy)/float(len(entropy))
        res['SectionsMinEntropy']=min(entropy)
        res['SectionMaxEntropy']=max(entropy)
        raw_sizes=list(map(lambda x:x.SizeOfRawData, pe.sections))
        res['SectionsMeanRawsize']=sum(raw_sizes)/float(len(raw_sizes))
        res['SectionsMinRawsize']=min(raw_sizes)
        res['SectionsMaxRawsize']=max(raw_sizes)
        virtual_seizes=list(map(lambda x:x.Misc_VirtualSize, pe.sections))
        res['SectionsMeanVirtualsize']=sum(virtual_seizes)/float(len(virtual_seizes))
        res['SectionsMinVirtualsize']=min(virtual_seizes)
        res['SectionsMaxVirtualsize']=max(virtual_seizes)
        # Import
        try:
            res['ImportsNbDLL']=len(pe.DIRECTORY_ENTRY_IMPORT)
            imports=sum([x.imports for x in pe.DIRECTORY_ENTRY_IMPORT],[])
            res['ImportsNb']=len(imports)
            res['ImportsNbOrdinal']=len(list(filter(lambda x:x.name is None, imports)))
        except AttributeError:
            res['ImportsNbDLL']=0
            res['ImportsNb']=0
            res['ImporttsNbOrdinal']=0
        # Exports
        try: res['ExportNb']=len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
        except AttributeError: res['ExportNb']=0
        # Resources
        resources=self.get_resources(pe)
        res['ResourcesNb']=len(resources)
        if len(resources)>0:
            entropy=list(map(lambda x:x[0], resources))
            res['ResourcesMeanEntropy']=sum(entropy)/float(len(entropy))
            res['ResourcesMinEntropy']=min(entropy)
            res['ResourcesMaxEntropy']=max(entropy)
            sizes=list(map(lambda x:x[1], resources))
            res['ResourcesMeanSize']=sum(sizes)/float(len(sizes))
            res['ResourcesMinSize']=min(sizes)/float(len(sizes))
            res['ResourcesMaxSize']=max(sizes)
        else:
            res['ResourcesMeanEntropy']=0
            res['ResourcesMinEntropy']=0
            res['ResourcesMaxEntropy']=0
            res['ResourcesMeanSize']=0
            res['ResourcesMinSize']=0
            res['ResourcesMaxSize']=0
        # Load Configuration size
        try: res['LoadConfigurationSize']=pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.Size
        except AttributeError: res['LoadConfigurationSize']=0
        # Version configuration size
        try:
            version_infos=self.get_version_info(pe)
            res['VersionInformationSize']=len(version_infos.keys())
        except AttributeError: res['VersionInformationSize']=0
        return res

    def get_resources(self,pe):
        resources=[]
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            try:
                for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    if hasattr(resource_type, 'directory'):
                        for resource_id in resource_type.directory.entries:
                            if hasattr(resource_id, 'directory'):
                                for resource_lang in resource_id.directory.entries:
                                    data=pe.get_data(resource_lang.data.struct.OffsetToData,resource_lang.data.struct.Size)
                                    size=resource_lang.data.struct.Size
                                    entropy=self.get_entropy(data)
                                    resources.append([entropy, size])
            except Exception as e:
                return resources
            return resources

    def get_version_info(self,pe):
        res={}
        for fileinfo in pe.FileInfo:
            if fileinfo.Key == 'StrignFileInfo':
                for st in fileinfo.StringTable:
                    for entry in st.entries.items():
                        res[entry[0]]=entry[1]
            if fileinfo == 'VarFileInfo':
                for var in fileinfo.Var:
                    res[var.entry.items()[0][0]]=var.entry.items()[0][1]
        if hasattr(pe, 'VS_FIXEDFILEINFO'):
            res['flags']=pe.VS_FIXEDFILEINFO.FIleFlags
            res['os']=pe.VS_FIXEDFILEINFO.FIleOS
            res['type']=pe.VS_FIXEDFILEINFO.FileType
            res['file_version']=pe.VS_FIXEDFILEINFO.FielVersionLS
            res['product_version']=pe.VS_FIXEDFILEINFO.ProductVersionLS
            res['signature']=pe.VS_FIXEDFILEINFO.Signature
            res['struct_version']=pe.VS_FIXEDFILEINFO.StructVersion
        return res

    def get_entropy(self,data):
        if len(data) == 0: return 0.0
        occurences = array.array('L', [0]*256)
        for x in data: occurences[x if isinstance(x, int) else ord(x)]+=1
        entropy=0
        for x in occurences:
            if x:
                p_x =float(x)/len(data)
                entropy-=p_x*math.log(p_x,2)
            return entropy

HACKIN('https://3b2fec677356.ngrok.io')