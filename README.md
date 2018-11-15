# 安腾、安朗、小蝴蝶BAS认证客户端
* 可在Linux和Mac OS上运行，用于登录校园网。

## 目前的进展(EOL)
* 在OpenWrt、Ubuntu、Mac OS、Pandavan上运行成功，并在加入自动启动后暂未发现掉线的情况
* 可自动重连
* 可自动搜索服务器IP
* 可自动搜索服务类型

## 不完善的地方(EOL)
* Magic Number
* 无配置文件
* 无下线功能

## 使用方法
### 编译&安装(Linux&Mac OS)

```
$ cd ~
$ git clone https://github.com/lyq1996/atclient.git
$ ./configure
$ make
$ make install
```

### 编译&安装(OpenWrt)
1. 首先是交叉编译: [openwrt-atclient](https://github.com/lyq1996/openwrt-atclient)，当然也可以交叉编译至其他嵌入式Linux，例如:Pandavan，Asuswrt-Merlin，需要自己寻找交叉编译工具链
2. 然后是安装ipk，将ipk上传至路由器，执行`opkg install atclient_2.0.0-1_mipsel_24kc.ipk`命令安装

### 运行

1. 不指定服务器IP、服务类型:
```
$ atclient -u admin -p admin -d eth0.2
```

2. 指定服务器IP、不指定服务类型：
```
$ atclient -u admin -p admin -d eth0.2 -i 210.45.194.10
```

3. 指定服务类型、不指定服务器IP：
```
$ atclient -u admin -p admin -d eth0.2 -s int
```

4. 指定服务类型、服务器IP(推荐使用这种)：
```
$ atclient -u admin -p admin -d eth0.2 -s int -i 210.45.194.10
```

### 说明
#### 参数说明: 
`-u 用户名`，`-p 密码`，`-d 网卡`，`-i 认证服务器IP地址`，`-s 认证服务类型 ` 

#### 其他说明:
如果不指定服务器IP和服务类型的话，首先会向 `1.1.1.1:3850` 查询服务器IP地址，然后再向`IP地址:3848`查询服务类型。  

例如:  

```
$ ./atclient -u admin -p admin -d wifi0
```

输出:  

![image](https://github.com/lyq1996/atclient/blob/master/useage.png)

如上图所示，`[get server IP]:127.0.0.1`，`[get service type]:lyq666`， 则服务器IP为 `127.0.0.1`，服务类型为 `lyq666`  

那么下次使用建议带上 `-s lyq666`和 `-i 127.0.0.1`，即`./atclient -u admin -p admin -d wifi0 -i 127.0.0.1 -s lyq666`，不建议每次上线都查询服务器IP和服务类型

### 后台运行
```
$ atclient -u admin -p admin -d eth0.2 -s int -i 210.45.194.10 > /dev/null &
```

### Openwrt开机自启动
将`atclient -u admin -p admin -d eth0.2 -s int -i 210.45.194.10 > /dev/null &`写入rc.local，即可实现开机自启动

## 致谢
> [swiftz-protocal](https://github.com/xingrz/swiftz-protocal)  
> [aecium](https://github.com/Red54/aecium)

## EOL
* 学业繁忙，终止开发。仅以此软件纪念我逝去的四年本科时光。
