```sh
route                                                             
# Kernel IP routing table
# Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
# 192.168.45.0    0.0.0.0         255.255.255.0   U     0      0        0 tun0
# 192.168.150.0   192.168.45.254  255.255.255.0   UG    0      0        0 tun0
sudo route add -net 172.16.106.0 gw 192.168.45.254 netmask 255.255.255.0 tun0
```