# SharpDomainInfo
域内自动化信息收集工具
## 简介
根据攻防以及域信息收集经验dump快而有用的域信息

可直接利用当前域权限或是提供连接信息查询

```
域控dnshostname-ip
MAQ值
域管理员组成员sAMAccountName-tel-mail(tel-mail可钓鱼)
admincount=1的成员sAMAccountName-tel-mail(tel-mail可钓鱼)
不可被委派的敏感用户
OU列表和描述
带有描述的user和computer
不做Kerberos域认证的用户
Kerberoastable的用户
域内除了DC 存在的servers
非约束委派/约束委派/RBCD
mS-DS-CreatorSID信息
ADCS信息/ESC1 ESC8
```

过滤的ACE类型

```
WriteDacl
GenericAll
GenericWrite
WriteProperty
WriteOwner
Self
Self-Membership bf9679c0-0de6-11d0-a285-00aa003049e2
AllExtendedRights
User-Force-Change-Password 00299570-246d-11d0-a768-00aa006e0529
Validated-SPN  f3a64788-5306-11d1-a9c5-0000f80367c1
DS-Replication-Get-Changes 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
DS-Replication-Get-Changes-All 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2
```

ACL扫描可能出现rule.IdentityReference.Value(ACL规则中的身份引用)无法输出或是一些默认存在的ACL规则未过滤

```
自己实际测试中，在域内主机上分别使用Localquery.QueryLdap_GetACLInfo(ldapPath)和Remotequery.QueryLdap_GetACLInfo(ldapPath, username, password), 返回的rule.IdentityReference.Value的类型有sid和名称。

在域内主机Localquery.QueryLdap_GetACLInfo和域外主机Remotequery.QueryLdap_GetACLInfo测试 目前没问题

后面再想办法改改【又不是不能用】
```

## 使用说明

```
SharpDomainInfo.exe
[*]SharpDomainInfo.exe
    https://github.com/0neAtSec/SharpDomainInfo

Usage:
    SharpDomainInfo.exe -help
    SharpDomainInfo.exe -localdump
    SharpDomainInfo.exe -h dc-ip -u user -p password -d domain.com
    execute-assembly /path/to/SharpDomainInfo.exe -localdump
```
## 示例

```
SharpDomainInfo.exe -localdump
SharpDomainInfo.exe -h 192.168.149.132 -u tom -p 0ne@123456 -d ad.test

[*]SharpDomainInfo.exe
    https://github.com/0neAtSec/SharpDomainInfo

[*]Domain Controllers - ips:

DC-2016.AD.TEST - 192.168.149.132
Windows Server 2016 Standard

[*]ms-DS-MachineAccountQuota:

MAQ=0

[*]Domain Admins's sAMAccountName:

sAMAccountName: admin
tel: 1111111
mail: 11111111

sAMAccountName: Administrator

[*]User Objects with Elevated Domain Rights-admincount=1:

sAMAccountName: admin
tel: 1111111
mail: 11111111

[*]Accounts Not Trusted for Delegation:

sAMAccountName: user123

[*]All organizational units (OU):

ou: IT

ou: 人事部
description: 人事部描述

ou: 管理部
description: 管理部描述

[*]User Objects With Description:

sAMAccountName: Administrator
description: 管理计算机(域)的内置帐户

sAMAccountName: add
description: qaz@123

sAMAccountName: admin
description: sxasxasxxxx

[*]Computer Objects With Description:

sAMAccountName: DC-2016$
description: dc

sAMAccountName: pc$
description: user可控

[*]Kerberos Pre-Authentication Disabled:

sAMAccountName: asas

[*]Kerberoastable Users:

sAMAccountName: spnuser1

sAMAccountName: lisi

[*]Look for places (servers) to move laterally - ips:

ADCS-2012.AD.TEST
Windows Server 2012 R2 Standard

[*]Unconstrained Delegation Computer:

DC-2016.AD.TEST
Windows Server 2016 Standard


[*]Constrained Delegation:

lisi ==>
cifs/ADCS-2012.AD.TEST
cifs/ADCS-2012

pc$ ==>
HOST/DC-2016.AD.TEST/AD.TEST
HOST/DC-2016.AD.TEST
HOST/DC-2016
HOST/DC-2016.AD.TEST/AD
HOST/DC-2016/AD

[*]Resource Based Constrained Delegation (RBCD):

krbtgt <==
add
lisi

[*]mS-DS-CreatorSID:

zhangsan -add-> Win10$

[*]ADCS - ips:

Root CA: AD-ADCS-2012-CA
ADCS-2012.AD.TEST - 192.168.149.138
[401]http://192.168.149.138/certsrv/certfnsh.asp

[*]ESC1-vulnerability-template:

ESC1_test

[*]ACL_info:

AD\user ----AllExtendedRights ----> CN=pc
AD\user ----WriteProperty ----> CN=pc
AD\user ----Self ----> CN=pc
AD\user ----Validated-SPN ----> CN=pc
AD\user ----Self ----> CN=pc
AD\user ----WriteProperty ----> CN=pc
AD\user ----WriteProperty ----> CN=pc
AD\user ----WriteProperty ----> CN=pc
AD\user ----WriteProperty ----> CN=pc
AD\acluser ----GenericWrite ----> CN=李四
AD\acluser ----Self ----> CN=李四
AD\acluser ----WriteProperty ----> CN=李四
AD\tom ----AllExtendedRights ----> CN=李四
AD\tom ----ForceChangePassword ----> CN=李四
AD\lisi ----AllExtendedRights ----> CN=win12
AD\lisi ----WriteProperty ----> CN=win12
AD\lisi ----Self ----> CN=win12
AD\lisi ----Validated-SPN ----> CN=win12
AD\lisi ----Self ----> CN=win12
AD\lisi ----WriteProperty ----> CN=win12
AD\lisi ----WriteProperty ----> CN=win12
AD\lisi ----WriteProperty ----> CN=win12
AD\lisi ----WriteProperty ----> CN=win12
AD\lisi ----GenericWrite ----> CN=普通用户
AD\lisi ----Self ----> CN=普通用户
AD\lisi ----WriteProperty ----> CN=普通用户
AD\user221 ----AllExtendedRights ----> DC=AD
AD\user221 ----DS-Replication-Get-Changes ----> DC=AD
AD\user221 ----AllExtendedRights ----> DC=AD
AD\user221 ----DS-Replication-Get-Changes-All ----> DC=AD
```



## TODO

- ~~ACL扫描~~
- 其它信息收集
- ~~域外连接查询~~

## 免责声明

本工具仅面向**合法授权**的企业安全建设行为，如您需要测试本工具的可用性，请自行搭建靶机环境。

在使用本工具时，您应确保该行为符合当地的法律法规，并且已经取得了足够的授权。**请勿对非授权目标进行扫描。**

如您在使用本工具的过程中存在任何非法行为，您需自行承担相应后果，作者将不承担任何法律及连带责任。

在安装并使用本工具前，请您**务必审慎阅读、充分理解各条款内容**，限制、免责条款或者其他涉及您重大权益的条款可能会以加粗、加下划线等形式提示您重点注意。 除非您已充分阅读、完全理解并接受本协议所有条款，否则，请您不要安装并使用本工具。您的使用行为或者您以其他任何明示或者默示方式表示接受本协议的，即视为您已阅读并同意本协议的约束。