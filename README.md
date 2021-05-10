# jeesite_des

Jeesite 4 的前端用户名密码的DES算法

## 使用

```
dependencies:
  jeesite_des: ^0.0.1
```

```
    // key 是 thinkgem,jeesite,com, 对 'system' 进行加密
    String result = JeesiteDesUtils.encode('system', 'thinkgem,jeesite,com');
```