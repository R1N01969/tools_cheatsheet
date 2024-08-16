## Linux
```sh
# ns, a, aaaa, mx, ptr, cname, txt
host -t mx domian_name (DNS_SERVER_IP)
dig ns domain_name (@DNS_SERVER_IP)
nslookup type=TXT domain_name (DNS_SERVER_IP)
dnsrecon -d domain_name -t std


for ip in $(cat /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt); do host $ip.megacorpone.com; done | grep -v "not found"

dnsenum --dnsserver DNS_SERVER_IP --enum -p 0 -s 0 -o subdomains.txt -f /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt domain_name
```