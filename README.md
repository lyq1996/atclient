# 安腾、安朗、小蝴蝶BAS认证客户端

## 适用于Linux
* 可交叉编译至OpenWrt平台运行
交叉编译教程: [这里](https://lyq1996.github.io/2017/02/22/build_mentohust_for_mips/)    
PS:虽然是交叉编译mentohust的,但原理是一样的

## 目前的进展
* 已在OpenWrt上运行成功,并在加入自动启动后暂未发现掉线的情况
* 可自动重连

## 不完善的地方
* 代码乱七八糟
* 手动输入服务器ip
* ~~手动输入服务类型(int、internet)~~(已添加)  
* 没有配置文件
* 没有后台模式
* 不能下线

## 使用方法
编译
```
$ cd ~
$ git clone https://github.com/lyq1996/atclient.git
$ ./configure
$ make
$ make install
```
运行
```
$ atclient -u admin -p admin -d eth0.2 -i 210.45.194.10 
```
后台运行
```
$ atclient -u admin -p admin -d eth0.2 -i 210.45.194.10 >/dev/null &
```

## 致谢
> [swiftz-protocal](https://github.com/xingrz/swiftz-protocal)  
> [aecium](https://github.com/Red54/aecium)