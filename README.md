# docker_bt
The warehouse used to generate baota mirrors
用来生成宝塔镜像的仓库

跳过首页登录账户
```
sed -i "s|if (bind_user == 'True') {|if (bind_user == 'REMOVED') {|g" /www/server/panel/BTPanel/static/js/index.js
rm -f /www/server/panel/data/bind.pl
```


### 安装环境
    
    # 生成镜像命令
    $ docker build -f Dockerfile -t imocence/bt:v7.7.0 .

    # 启动方法

    ## 生成并运行一个新的容器：
    $ docker run --name bt_cn -it imocence/bt:v7.7.0 /bin/sh

    ## 方法二，使用docker-compose.yml启动
    $ docker-compose up -d