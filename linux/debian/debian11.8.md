# some note  

## 1. system install  
1) download link: https://cdimage.debian.org/mirror/cdimage/archive/11.8.0/amd64/iso-dvd/  

2) when install debian, create new user to login with password. by default, root is not allowed to login with a password.  

3) use a network mirror  

## 2.upload public key  
```
mkdir /root/.ssh && chmod 700 /root/.ssh  
upload Identity.pub into /root/.ssh  
mv Identity.pub authorized_keys && chmod 600 authorized_keys  
```

## 3.update source.list(optional)  
note: debian11.8 codename **bullseye**  
```
mv /etc/apt/sources.list /etc/apt/sources.list.bak  
deb https://mirrors.tuna.tsinghua.edu.cn/debian/ bullseye main contrib non-free
# deb-src https://mirrors.tuna.tsinghua.edu.cn/debian/ bullseye main contrib non-free

deb https://mirrors.tuna.tsinghua.edu.cn/debian/ bullseye-updates main contrib non-free
# deb-src https://mirrors.tuna.tsinghua.edu.cn/debian/ bullseye-updates main contrib non-free

deb https://mirrors.tuna.tsinghua.edu.cn/debian/ bullseye-backports main contrib non-free
# deb-src https://mirrors.tuna.tsinghua.edu.cn/debian/ bullseye-backports main contrib non-free

deb https://security.debian.org/debian-security bullseye-security main contrib non-free
# deb-src https://security.debian.org/debian-security bullseye-security main contrib non-free 
```

## 4. update vim  
```
apt remove vim-tiny  
apt remove vim-common  
apt install vim  
```

## 5. add sudo for user
`echo "username    ALL=(ALL:ALL) ALL" | sudo tee /etc/sudoers.d/username`

## 6. software install  
```
1) apt update  
2) apt install build-essential  
```

