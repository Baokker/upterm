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
go install ./cmd/upterm/...
```

### 服务器端

首先安装Go（[下载地址](https://go.dev/doc/install)），然后执行以下命令：

```console
git clone https://github.com/Baokker/upterm.git
cd upterm
git checkout share_terminal
go install ./cmd/upterm/...

cp systemd/uptermd.service /etc/systemd/system/uptermd.service
systemctl daemon-reload
systemctl start uptermd
```

## 连接方法

```
upterm host --server ws://115.159.118.160:8090 # 服务器IP和端口按情况更改
```

## 当前服务器部署地址与端口

ws://115.159.118.160

sshd 2222
ws **8090**
Prometheus 9090

## 如何与CoVsCode结合

在CoVsCode的client和server上都有`share_terminal`分支，checkout之后可以看到相关代码。



## 未来计划

- [ ] 支持Windows
- [ ] 更细粒度的共享终端权限设置

## 相关链接

- [upterm](https://upterm.dev/)
- [CoVsCode](https://github.com/cscw-and-se/coVscode-2024)
- [CoVsCode Server](https://github.com/cscw-and-se/coVscode-2024-server)

## 论文draft

- 腾讯文档：[ShareTerminal(Draft)](https://docs.qq.com/doc/DWVNuZHpqa0JjYXBl?scene=f1626417ebcf515f652b09ecXqTBt1)
- 本科毕设（请联系本人以获取）