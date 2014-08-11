纯真IP库
========================

纯真IP库的研究学习．

# 在线资源

## 相关帖子

- http://linuxtoy.org/archives/python-ip.html
- https://linuxtoy.org/archives/python-qqwry.html
- http://ylinux.org/blog/article/106

## qqwry.dat 下载

- http://www.cz88.net/ （官网）
- https://github.com/jianlee/ylinux/blob/master/tools/IP/QQWry/qqwry.dat.xz

## 纯真IP库 txt 格式（使用本程序dump）

- https://github.com/jianlee/ylinux/blob/master/tools/IP/QQWry/ip.txt.xz

Changelog
=================

2014年8月11日
-----------------

根据LinuxToy网友依云 ( http://lilydjwg.is-programmer.com/ ) 建议：
https://linuxtoy.org/archives/python-qqwry.html#comment-331128

更新：

1. 显示版本信息
2. 增加自动更新纯真IP数据库功能
3. 使用 mmap 操作数据库文件对象，效率提升一倍：
   https://linuxtoy.org/archives/python-qqwry.html#comment-331220

2014年8月9日 重写程序
----------------------------

1. 实现完整查询纯真IP库.
2. 可完整dump出所有ip记录，并与纯真官方的查询程序比对正确.

2009年5月29日
--------------------

### 1. 工具下面网友的建议，修改"o += len(cArea) + 1"

    http://linuxtoy.org/archives/python-ip.html#comment-113960
    因为这个时候我已经把得到的字符串变成utf-8编码了，长度会有变化！


联系我们
============

- 社区： https://ylinux.org
- 邮件： info@ylinux.org
- QQ群： Linux与云计算 232629450

![扫描二维码](http://ylinux.org/static/img/join-qq-qun232629450.png)


