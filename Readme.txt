PROJECT OVERVIEW
-----------------
For this project, a virtual infrastructure was set up using VirtualBox (VB) as the virtual environment. Every step of the project is documented with screenshots, where the commands used and key findings are highlighted within red squares.

# General Information  
- Virtual Hosts OS: Linux (SDA.ova, Kali Linux)  
- Network Adapter: Bridged  
- Note that throughout this documentation, two different IP addresses are referenced for the SDA VM. This is due to the use of DHCP, which caused the VM's IP address to change after certain modifications were made to the VM."

# Task I: Define IP and IP Range of Kali Machine  
The command $ifconfig revealed that the IP address of the Kali VM is 192.168.1.8, and the network's IP range is 192.168.1.0/24.  

# Task II: Scan the Network to Determine the Target's IP  
The command $nmap -sV 192.168.1.0/24 revealed that the target's IP address is 192.168.1.7 and its hostname is vm-sda.  

 ##Note that root privileges were used for this exercise; using the same command with sudo would produce the same output. Since this is a lab environment the chosen command is used for completing three tasks. In a real life scenario the chosen command, from a personal point of view the optimal command would be $nmap -sS -Pn -T0 192[.]168[.]1[.]0/24 

Explanation:
- -sS (SYN scan): Does not complete the TCP handshake, reducing the likelihood of detection by IDS/IPS systems.
- -Pn (no ping scan): Avoids detection by disabling host discovery.
- -T0 (slowest scan): Sends packets slowly to reduce network traffic spikes and evade detection.

# Task III: Finding Open Ports on the Target  
The output from Task II indicated that the target has three open ports: 80, 21, and 22.  

# Task IV: Banner Grabbing  
The banner grab results from the command in Task II provided the following details:  
- Port 21/tcp: vsftpd 3.0.5  
- Port 22/tcp: OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)  
- Port 80/tcp: Apache HTTPD 2.4.52 (Ubuntu)  

# Task V: Brute Force Attack on One of the Services  
In this task, Hydra was used to perform a brute force attack on an FTP service. The creation of user and password lists was done using the following methods:  
1. AI-Generated Lists (ChatGPT): Userv1.txt, Passv1.txt  
2. Credentials Discovered on GitHub: Userv2.txt, Passv2.txt  
 ##Note that the usernames and passwords obtained from both methods         have been saved in the files userv1.txt and passv1.txt, respectively.  
3. Using Hydra's password list (rockyou.txt) from Kali Linux: Due to the large size of the rockyou.txt file (approximately 14 million passwords), only the first 100 passwords were selected, saved in the file passv3.txt.  

Conclusion: The brute force attack was unsuccessful as none of the provided usernames or passwords were correct.



EXTRA TASK  
============  
# Task I: HTTP Service Manual Analysis  
In this task, the website was accessed locally via the VM IP address (192.168.1.5). Using the Inspect Element tool, a base64-encoded message was discovered, which pointed to the file directory-list-lowercase-2.3-medium.txt. This file was used to identify potential usernames for the VM.

# Task II: Getting USER FLAG  
->The command $plocate directory-list-lowercase-2.3-medium.txt was executed to locate the file containing a list of potential usernames. During exploration of directories containing admin panels, config files, and management tools, a hint was discovered in the /requests/ directory. This hint suggested using the rockyou-10.txt file as a password list, which was downloaded from GitHub.  

Given the large size of the wordlists, brute-forcing both lists with Hydra would be time-consuming. To optimize the process, the username was first determined using a dummy password, "password," with the following command:
       $hydra -L directory-list-lowercase-2.3-medium.txt -p password ssh://192.168.1.5 -t 4 -V -d
This revealed the username to be "Uranus."

->With this information, the password was found using:
    $hydra -l Uranus -P rockyou-10.txt 192.168.1.5 ssh -t 4 -I
The password was successfully identified as "butterfly."

-> The VM was then accessed remotely via SSH using the credentials obtained:
   $ ssh uranus@192.168.1.5

RETRIVED FLAG : flag{h4CK3R}

# Task III: Getting ROOT FLAG  
->The command $ cat ~/.bash_history revealed an additional hint: a base64-encoded message suggesting that the root password is three characters long.  
->A list of potential passwords, each three characters long, was generated using the crunch tool:
     $ crunch 3 3 abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()' -o r_wordlist.txt

->Hydra was used for brute-force testing with the following command:
     $hydra -l root -P r_wordlist.txt 192.168.1.5 ssh -t 4 -I
This process successfully identified the root password as "666."

-> The VM was then accessed remotely via SSH using the credentials obtained:
   $ ssh root@192.168.1.5

RETRIVED FLAG : flag{1337}




TABLE  OF SCREENSHOTS 
--------------------------------------------------------------------------------------------------------------------------------
TASK      SCREENSHOT                                         SCREENSHOT DESCRIPTION
I	  VMs.png, NetworkRange.png	                     Virtual machines within the VirtualBox hypervisor
II	  NmapScan.png, SDA_VM.png	                     Nmap scan results: Target IP, open ports, services, and versions
III	  NmapScan.png	                                     Nmap scan results: Target IP, open ports, services, and versions.
IV	  NmapScan.png	                                     Nmap scan results: Target IP, open ports, services, and versions.
V	  Hydra_AI&GIT.png, Hydra_AutomaticFile.png	     Brute force results using AI & Git credentials
--------------------------------------------------------------------------------------------------------------------------------
Extra-I   Website.png, Hydra_User_BruteForce.png	     First hint hidden within the website.
Extra-II  UserCredentials-Phase I.png	                     Files utilized for brute forcing to determine VM credentials.	
          UserCredentials-Phase II.png	                     Identification of the username.	
          UserCredentials-Phase III.png	                     Second hint hidden within the website, useful to find the password.
          UserCredentials-Phase IV.png                       Identification of the password.
          UserCredentials-Phase V.png                        Remote access as user Uranus of SDA VM. 
Extra-III RootCredentials-Phase I.png                        First hint hidden within bash_history.Identification of root credentials.
          RootCredentials-Phase II.png                       Remote access as root of SDA VM.
--------------------------------------------------------------------------------------------------------------------------------
          PythonTools.png                                    Python3, Scapy and PyCharm versions
          VM_2.png                                           Virtual machines within the VirtualBox hypervisor


