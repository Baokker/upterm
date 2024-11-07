# Share Terminal For CoVsCode

使用`upterm`搭建

## 适用平台

- Linux
- macOS
- 暂时不支持Windows（需要进一步调研）

## 安装方法

### 本地客户端

首先安装Go（[下载地址](https://go.dev/doc/install)），然后执行以下命令：

```console
git clone https://github.com/Baokker/upterm.git
cd upterm
git checkout share_terminal
go install ./cmd/upterm/... # 如果慢的话考虑使用国内代理，此处不赘述
```

使用教程见后

### 服务器端

首先安装Go（[下载地址](https://go.dev/doc/install)）
并且安装screen（`sudo apt install screen`）
然后执行以下命令：

```console
git clone https://github.com/Baokker/upterm.git
cd upterm
git checkout share_terminal
go install ./cmd/... # 包括uptermd # 如果慢的话考虑使用国内代理，此处不赘述

screen -S uptermd
uptermd --ws-addr 0.0.0.0:8090 --ssh-addr 0.0.0.0:2222
```

之后按`Ctrl+A`，然后按`D`退出screen，使其保持在后端运行
可以使用`screen -r uptermd`重新进入

## 连接方法

```
upterm host --server ws://115.159.118.160:8090 # 服务器IP和端口按情况更改
```

## 当前服务器部署地址与端口

IP: 115.159.118.160

- sshd 2222 
- ws **8090**
- Prometheus 9090

请保持端口开放，以便他人连接

## 如何与CoVsCode结合

在CoVsCode的client和server上都有`share_terminal`分支，checkout之后可以看到相关代码。

具体来说，在CoVsCode的基础上增加了共享终端的功能（BeginShareTerminal）。

在任一用户发起终端后，系统将执行upterm，生成一个共享终端的URL，然后将这个URL发送给其他用户。

其他用户通过这个URL可以连接到共享终端，进行协作。

在此基础上，我们增加它的灵活性和安全性，隐私性。

## 未来计划

- [ ] 支持Windows
- [ ] 更细粒度的共享终端权限设置
- [ ] 更好的协作感知
- [ ] 更好的协作感知
- [ ] ...

## 相关链接

- [upterm](https://upterm.dev/)
- [CoVsCode](https://github.com/cscw-and-se/coVscode-2024)
- [CoVsCode Server](https://github.com/cscw-and-se/coVscode-2024-server)

## 论文draft

- 腾讯文档：[ShareTerminal(Draft)](https://docs.qq.com/doc/DWVNuZHpqa0JjYXBl?scene=f1626417ebcf515f652b09ecXqTBt1)
- 本科毕设：见Repository

## 常用命令

查看端口占用

```bash
sudo lsof -i -P -n
sudo lsof -i -P -n | grep 8090 # 查看8090端口
```

screen相关指令
```bash
screen -S uptermd # 新建screen
screen -r uptermd # 重新进入
screen -ls # 查看所有screen
```

查看安装位置

```bash
which uptermd
```


