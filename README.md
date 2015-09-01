基于tshark的web数据包分析工具
=========================

#概述
    显示数据包列表，数据包解码，显示专家信息（告警与提示），以及会话

#安装运行
安装virtualenv :

    sudo pip install virtualenv

创建并激活虚拟环境 :

    cd iDigger-mini
    virtualenv env
    source env/bin/activate

安装依赖 :

    pip install -r requirements.txt

上一部可能遇到的问题 :

    安装pyshark时需要编译python-lxml源码，需要安装如下依赖：
    sudo apt-get install libxml2-dev libxslt-dev python2.7-dev
    编译lxml源码时可能会遇到-lz not found，此时需要安装libzip-dev
    sudo apt-get install libzip-dev
    
运行 :
    
    python manage.py runserver

在浏览器中输入 http://127.0.0.1:8000/
即可看到数据包列表
