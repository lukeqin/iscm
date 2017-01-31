#!/usr/bin/env python2.6
#! -*- coding: utf-8 -*-

import os
import sys
import time
import re
import tornado.ioloop
import tornado.web
import tornado.httpserver
import logging
import logging.config
import ConfigParser
from tornado.options import define,options

'''get ip'''
import socket
import fcntl
import struct

iscmlogger = logging.getLogger()
eiscmlogger = logging.getLogger('log03')

define("port", default=7777, help="run on the given port", type=int)

class ConfHandler(tornado.web.RequestHandler):
    def get_ipaddr(self, ifname):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            return socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s', ifname[:15]))[20:24])
        except Exception,e:
            return None
        
    def get_HwAddr(self, ifname): 
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) 
        info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', ifname[:15])) 
        return ''.join(['%02x:' % ord(char) for char in info[18:24]])[:-1] 
    
    def get_netdevif(self):
        d = os.popen('ip link show').readlines()
        netdev = []
        for i in range(len(d)):
            line = d[i].strip('\n')
            if 'mtu' in line:
                netdevtmp = []
                tline = line.split(':')
                netdevtmp.append(tline[0])
                netdevtmp.append(tline[1].strip(' '))
                netdevtmp.append(self.get_ipaddr(netdevtmp[1]))
                netdevtmp.append(self.get_HwAddr(netdevtmp[1]))
                if 'UP' in line:
                    netdevtmp.append('UP')
                else:
                    netdevtmp.append('DOWN')
                netdev.append(netdevtmp)
        return netdev
    
    def get_routeif(self):
        d = os.popen('route -n').readlines()
        routeif = []
        for i in d:
            if "Kernel IP routing table" in i:
                continue
            elif "Destination" in i:
                continue
            else:
                routetmp = []
                routeif.append(i.strip('\n').split())
        return routeif
    
    def get_dnsif(self):
        d = os.popen('grep "^nameserver" /etc/resolv.conf').readlines()
        dnsif = []
        for i in d:
            dnsif.append(i.strip('\n').split()[1])
        return dnsif
    
    def get_serinfo(self):
        d = os.popen('ps -ef | grep -E "Aservice|Bservice" | grep -Ev "grep"').readlines()
        ser = []
        for i in range(len(d)):
            line = d[i].strip('\n')
            sertmp = []
            if "Aservice" in line:
                t = line.split()
                sertmp.append(t[7])
                sertmp.append('127.0.0.1')
                sertmp.append(t[8])
                ser.append(sertmp)
            elif "Bservice" in line:
                t = line.split()
                sertmp.append(t[7])
                sertmp.append(t[8])
                sertmp.append(t[9])
                ser.append(sertmp)
            else:
                continue
        return ser
      
    def get(self):
        iscmlogger.info('ConfHandler get.')
        ifbond = 0
        try:
            #get netdev info
            netdevinfo = self.get_netdevif()
            #end get netdev info
            
            #check if bond
            for i in netdevinfo:
                if i[1] == "bond0":
                    ifbond = 1
            #end check if bond 
            
            #get net route
            routeif = self.get_routeif()
            #get net route
            
            #get dns info
            dnsif = self.get_dnsif()
            #end get dns info
            
            #get service info
            serif = self.get_serinfo()
            #end get service info
            
        except Exception,e:
            eiscmlogger.error(e)        
        self.render('config.html', netdevinfo=netdevinfo, ifbond=ifbond, routeif=routeif,
                    dnsif=dnsif, serif=serif)
    
    def post(self):
        iscmlogger.info('ConfHandler post.')
        self.write("You wrote " + "post")

class SetServiceHandler(tornado.web.RequestHandler):
    def get(self):
        iscmlogger.info("SetServiceHandler get")
    
    def post(self):
        iscmlogger.info("SetServiceHandler post")
        stype = self.get_argument('servicetype')
        sip = self.get_argument('serviceip', default="")
        sport = self.get_argument('serviceport')
        serviceConf = "/etc/supervisord.d/" + sport + ".ini"
        if stype == "Aservice":
            str = "[program:Aservice" + sport + "]" + "\n" \
                "command = /home/test/services/Aservice " + sport + "\n" \
                "directory=/home/test/services" + "\n" \
                "autostart=true" + "\n" \
                "autorestart=true" + "\n" \
                "startsecs=3" + "\n"
        else:
            str = "[program:Bservice" + sport + "]" + "\n" \
                "command = /home/test/services/Bservice " + sip + " " + sport + "\n" \
                "directory=/home/test/services" + "\n" \
                "autostart=true" + "\n" \
                "autorestart=true" + "\n" \
                "startsecs=3" + "\n"
        fileid = open(serviceConf, 'w+')
        fileid.write(str)
        fileid.close()
        os.system("/etc/init.d/supervisord restart")
        url = "/" 
        iscmlogger.info(url)
        time.sleep(2)
        self.redirect(url)

class StopServiceHandler(tornado.web.RequestHandler):
    def get(self):
        iscmlogger.info("StopServiceHandler get")
        sport = self.get_argument('sport')
        comstr = "find /etc/supervisord.d/ -name " + "'" + sport + "*" + "'"
        findfilename = os.popen(comstr).readlines()[0].strip("\n")
        if findfilename == "":
            self.write("1")
        else:
            comstr = "rm -f " + findfilename
            data = os.system(comstr)
            if data == 0:
                data = os.system("/etc/init.d/supervisord restart")
                self.write("0")
            else:
                self.write("1")

    def post(self):
        iscmlogger.info("StopServiceHandler post")
        
class UpInterfaceHandler(tornado.web.RequestHandler):
    def get(self):
        iscmlogger.info("UpInterfaceHandler get")
        interf = self.get_argument('interf')
        data = os.system("ip link set %s up" % interf)
        if data == 0:
            self.write("0")
        else:
            self.write("1")
    
    def post(self):
        iscmlogger.info("UpInterfaceHandler post")

class DownInterfaceHandler(tornado.web.RequestHandler):
    def get(self):
        iscmlogger.info("DownInterfaceHandler get")
        interf = self.get_argument('interf')
        data = os.system("ip link set %s down" % interf)
        if data == 0:
            self.write("0")
        else:
            self.write("1")
    
    def post(self):
        iscmlogger.info("DwnInterfaceHandler post")  
        
class SetInterfaceHandler(tornado.web.RequestHandler):
    def ipformatchk(self, ip_str):
        pattern = r"\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
        if re.match(pattern, ip_str):
            return True
        else:
            return False
        
    def setipaddresses(self, setip, setnetmask, setinterf):
        #set one interface's IP addresses temporarily
        os.system("ip link set %s up" % setinterf)
        os.system("ip addr flush %s" % setinterf)
        if os.system("ip addr add %s/%s dev %s" % (setip, setnetmask, setinterf)):
            return False
        else:
            return True
    
    def setnameservers(self, nameservers):
        #set nameservers
        with open("/etc/resolv.conf", "w") as fp:
            for nameserver in nameservers:
                fp.write("nameserver %s%s" % (nameserver, os.linesep))
        return True

    def setdefaultroute(self, setgateway, setinterf):
        #set default route temporarily
        os.system("ip route del default")
        if os.system("ip route add default via %s dev %s" % (setgateway, setinterf)):
            return False
        else:
            return True
    
    def setippermanently(self, str, setinterf):
        #set ip permanently.
        filename = "/etc/sysconfig/network-scripts/ifcfg-" + setinterf
        with open(filename, "w") as fp:
            fp.write(str)
        return True
    
    def get(self):
        iscmlogger.info("SetInterfaceHandler get")
    
    def post(self):
        iscmlogger.info("SetInterfaceHandler post")  
        setinterf = self.get_argument('set_inter') 
        setip = self.get_argument('set_ip')
        setnetmask = self.get_argument('set_netmask')
        setgateway = self.get_argument('set_gateway')
        setdns1 = self.get_argument('set_dns1')
        setdns2 = self.get_argument('set_dns2')
        nameservers = list()
        nameservers.append(setdns1)
        nameservers.append(setdns2)
        #print setinterf, setip, setnetmask, setgateway
        if (setinterf != "" and self.ipformatchk(setip) and self.ipformatchk(setnetmask) and self.ipformatchk(setgateway) and \
            self.ipformatchk(setdns1) and self.ipformatchk(setdns2)):
            #set one interface ip temporarily. 
            if self.setipaddresses(setip, setnetmask, setinterf):
                #set one interface route temporarily.
                if self.setnameservers(nameservers):
                    if self.setdefaultroute(setgateway, setinterf):
                        #set one interface ip and route permanently.
                        str = "DEVICE=" + setinterf + "\n" \
                            "BOOTPROTO=none" + "\n" \
                            "ONBOOT=yes" + "\n" \
                            "TYPE=Ethernet" + "\n" \
                            "IPV6INIT=no" + "\n" \
                            "USERCTL=no" + "\n" \
                            "IPADDR=" + setip + "\n" \
                            "NETMASK=" + setnetmask + "\n" \
                            "GATEWAY=" + setgateway + "\n" \
                            "DNS1=" + setdns1 + "\n" \
                            "DNS2=" + setdns2 + "\n"
                        #start to set ip permanently.
                        if self.setippermanently(str, setinterf):
                            #view homepage
                             url = "/" 
                             self.redirect(url)
                        else:
                            self.write("设置IP、掩码和网关失败！请检查输入的IP、掩码或网关！")
        else:
            self.write("设置IP、掩码和网关失败！请检查输入的IP、掩码或网关！")
        
settings = {
    "static_path":os.path.join(os.path.dirname(__file__), "static"),
    "template_path":os.path.join(os.path.dirname(__file__),"template"),
    "login_url":"/",
}

application = tornado.web.Application([
    (r'/',ConfHandler),
    (r'/setservice',SetServiceHandler),
    (r'/stopservice',StopServiceHandler),
    (r'/upinterface',UpInterfaceHandler),
    (r'/downinterface',DownInterfaceHandler),
    (r'/setinterface',SetInterfaceHandler),
], **settings)

def initLog():
    try:
        logging.config.fileConfig(fname='conf/log.conf', defaults=None, disable_existing_loggers=True)
        return 0
    except Exception, e:
        eiscmlogger.error(e)
 
if __name__ == "__main__":
    if initLog():
        eiscmlogger.error('Log modul initialization failed!')
    else:
        iscmlogger.info('Log modul initialization successful!')
    http_server = tornado.httpserver.HTTPServer(application)
    http_server.listen(7777)
    tornado.ioloop.IOLoop.instance().start()

