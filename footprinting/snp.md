# NMAP
```
sudo nmap --script=nfs-ls -Pn  10.129.202.5 -sV -p111,2049
```
# Mounting
```
sudo mount -t nfs 10.129.202.5:/ ./target-NFS/ -o nolock
```
