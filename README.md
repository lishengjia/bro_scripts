# bro_scripts

## 此脚本可以在bro http log中记录如下信息：
> * http request header name 和 value
> * http response header name 和 value
> * request body
> * response body
> * response time

## 使用流程：

1，Bro采用编译安装，目前测试过Bro2.4和Bro2.5

2，安装自定义脚本
```
# mv http-custom /usr/local/bro/share/bro/base/protocols
```
3，修改配置文件
```
echo '@load base/protocols/http-custom' >> /usr/local/bro/share/bro/site/local.bro
```
4，Bro重新加载脚本
```
/usr/local/bro/bin/broctl deploy
```
