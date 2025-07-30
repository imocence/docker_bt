#!/bin/bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

setup_path="/www"
pyenv_path="$setup_path/server/panel/pyenv"
download_Url='https://download.bt.cn';
panelPort=8888
HTTP_S="http"

Red_Error(){
	echo '=================================================';
	printf '\033[1;31;40m%b\033[0m\n' "$@";
	exit 1;
}

Install_Check(){
	if [ "${INSTALL_FORCE}" ];then
		return
	fi
	echo -e "----------------------------------------------------"
	echo -e "检查已有其他Web/mysql环境，安装宝塔可能影响现有站点及数据"
	echo -e "Web/mysql service is alreday installed,Can't install panel"
	echo -e "----------------------------------------------------"
	echo -e "已知风险/Enter yes to force installation"
	read -p "输入yes强制安装: " yes;
	if [ "$yes" != "yes" ];then
		echo -e "------------"
		echo "取消安装"
		exit;
	fi
	INSTALL_FORCE="true"
}

Get_Pack_Manager(){
	if [ -f "/usr/bin/yum" ] && [ -d "/etc/yum.repos.d" ]; then
		PM="yum"
	elif [ -f "/usr/bin/apt-get" ] && [ -f "/usr/bin/dpkg" ]; then
		PM="apt-get"
	fi
}

System_Check(){
  echo "========================== Update software source =========================="
	if [ "${PM}" = "apt-get" ]; then
	  if [ -f "/etc/apt/sources.list.d/debian.sources" ];then
      sed -i "s^http://deb.debian.org^http://mirrors.tuna.tsinghua.edu.cn^g" /etc/apt/sources.list.d/debian.sources
    else
      sed -i "s^http://deb.debian.org^http://mirrors.tuna.tsinghua.edu.cn^g" /etc/apt/sources.list
    fi
    if command -v timedatectl &> /dev/null; then
      timedatectl set-timezone Asia/Shanghai
      timedatectl set-ntp true
      timedatectl status
    fi
    apt update
    apt install -y autoconf automake procps wget curl libcurl4-openssl-dev gcc make unzip tar openssl libssl-dev gcc libxml2 libxml2-dev
    apt install -y zlib1g zlib1g-dev libjpeg-dev libpng-dev lsof libpcre3 libpcre3-dev cron net-tools swig build-essential libffi-dev
    apt install -y libbz2-dev libncurses-dev libsqlite3-dev libreadline-dev tk-dev libgdbm-dev libdb-dev libdb++-dev libpcap-dev libzip-dev
    apt install -y xz-utils git qrencode sqlite3 at mariadb-client rsyslog iproute2 locales libtool m4 libonig5 libsodium23
    if [ ! -d '/etc/letsencrypt' ];then
      mkdir -p /etc/letsencryp
      mkdir -p /var/spool/cron
      if [ ! -f '/var/spool/cron/crontabs/root' ];then
        echo '' > /var/spool/cron/crontabs/root
        chmod 600 /var/spool/cron/crontabs/root
      fi
    fi
  else
    VER_ID=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2)
    if [ $VER_ID -eq 8 ];then
      sudo sed -i 's/mirror.centos.org/mirrors.tuna.tsinghua.edu.cn/g' /etc/yum.repos.d/CentOS-AppStream.repo
      sudo sed -i 's/mirrorlist/#mirrorlist/g' /etc/yum.repos.d/CentOS-AppStream.repo
      sudo sed -i 's/#baseurl/baseurl/g' /etc/yum.repos.d/CentOS-AppStream.repo
      sudo sed -i 's/enabled=1/enabled=0/g' /etc/yum.repos.d/CentOS-Extras.repo
    else
      if [ ! -f "/etc/yum.repos.d/CentOS-Base.repo.bak" ];then
        cp /etc/yum.repos.d/CentOS-Base.repo /etc/yum.repos.d/CentOS-Base.repo.bak
      fi
      sed -i 's|^mirrorlist=|#mirrorlist=|g' /etc/yum.repos.d/CentOS-Base.repo
      sed -i 's|^#baseurl=|baseurl=|g' /etc/yum.repos.d/CentOS-Base.repo
      RELEASE_VER=$(grep -oP '(?<=release )\d+\.\d+\.\d+' /etc/centos-release)
      sed -i "s|mirror.centos.org/centos/\$releasever|mirrors.tuna.tsinghua.edu.cn/centos-vault/$RELEASE_VER|g" /etc/yum.repos.d/CentOS-Base.repo
    fi
    yum makecache
    yum install -y bzip2-devel c-ares crontabs db4-devel freetype gcc gdbm-devel icu iproute libcurl-devel libffi-devel libicu-devel
    yum install -y libjpeg-devel libpcap-devel libpng-devel libwebp libxml2 libxslt* lsof make mariadb ncurses-devel net-tools
    yum install -y openssl pcre qrencode readline-devel rsyslog sqlite-devel tk-devel unzip vixie-cron wget xz-devel zlib zlib-devel
    yum clean all
  fi
  echo "========================== Check LNMP environment =========================="
	MYSQLD_CHECK=$(ps -ef |grep mysqld|grep -v grep|grep -v /www/server/mysql)
	PHP_CHECK=$(ps -ef|grep php-fpm|grep master|grep -v /www/server/php)
	NGINX_CHECK=$(ps -ef|grep nginx|grep master|grep -v /www/server/nginx)
	HTTPD_CHECK=$(ps -ef |grep -E 'httpd|apache'|grep -v /www/server/apache|grep -v grep)
	if [ "${PHP_CHECK}" ] || [ "${MYSQLD_CHECK}" ] || [ "${NGINX_CHECK}" ] || [ "${HTTPD_CHECK}" ];then
		Install_Check
	fi
}

Set_Ssl(){
    SET_SSL=true
    if [ "${SSL_PL}" ];then
    	SET_SSL=""
    fi
}

Install_Python_Lib(){
	echo "========================== Check python environment =========================="
	echo "setting python"
	if [ "${PM}" = "apt-get" ]; then
	  wget -nv -O - "https://download.bt.cn/install/pyenv/pyenv-debian12-x64.tar.gz" |tar -zxf - -C /www/server/panel
	else
	  #wget -nv -O - "https://download.bt.cn/install/pyenv/pyenv-el7-x64.tar.gz" |tar -zxf - -C /www/server/panel
	  wget -nv -O - "https://gitee.com/imocence/quicken/releases/download/v4/pyenv-el7-x64.tar.gz" |tar -zxf - -C /www/server/panel
	fi
	chmod +x $pyenv_path/bin/*
  if command -v $pyenv_path/bin/python3 &> /dev/null; then
  ln -sf $pyenv_path/bin/python3 /usr/bin/btpython
    echo "python3 已安装！"
  else
    echo "未找到 Python 环境，开始安装 Python！"
    if [ "${PM}" = "apt-get" ]; then
      apt update && apt install python3 -y
    else
      yum install python3 -y
    fi
  fi
  if [ -f "/usr/bin/python3" ];then
    rm -f /usr/bin/python3
	fi
	ln -sf $pyenv_path/bin/python3 /usr/bin/python3
  echo "setting pip"
  if command -v $pyenv_path/bin/pip3 &> /dev/null || command -v pip3 &> /dev/null; then
    ln -sf $pyenv_path/bin/pip3 /usr/bin/btpip
    echo "pip 已安装！"
  else
    echo "未找到 pip 环境，开始安装 Python！"
    if [ "${PM}" = "apt-get" ]; then
      apt install python3-pip -y
    else
      yum install python3-pip -y
    fi
  fi
	if [ -f "/usr/bin/pip3" ];then
    rm /usr/bin/pip3
  fi
  echo "setting pip source for tsinghua"
  ln -sf $pyenv_path/bin/pip3 /usr/bin/pip3
  if pip3 config list | grep -q 'pypi.tuna.tsinghua.edu.cn'; then
      echo "pip3 已配置清华源"
  else
    pip3 config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple
    pip3 config set global.break-system-packages true
    pip3 config set global.trusted-host pypi.tuna.tsinghua.edu.cn
	fi
  
	echo "True" > /www/disk.pl
	if [ ! -w /www/disk.pl ];then
		Red_Error "ERROR: Install python env fielded." "ERROR: /www目录无法写入，请检查目录/用户/磁盘权限！"
	fi
	
	if [ -f "/www/server/panel/pymake.pl" ];then
		os_version=""
		rm -f /www/server/panel/pymake.pl
	fi
	echo "=================================================="
}

Install_Bt(){
  if [ -d "${setup_path}/server/panel/install" ]; then
      echo "安装文件存在!!"
  else
      wget -nv -O - "https://github.com/imocence/docker_bt/releases/download/release-v7.7.0/LinuxPanel-7.7.0.tar.gz" |tar -zxf - -C /www/server/panel
  fi
	if [ -f ${setup_path}/server/panel/data/port.pl ];then
		panelPort=$(cat ${setup_path}/server/panel/data/port.pl)
	fi
	if [ "${PANEL_PORT}" ];then
		panelPort=$PANEL_PORT
	else
	  panelPort=8888
	fi
	mkdir -p ${setup_path}/server/panel/install
	mkdir -p /www/server
	mkdir -p /www/wwwroot
	mkdir -p /www/wwwlogs
	mkdir -p /www/backup/database
	mkdir -p /www/backup/site
	chmod 444 /www/server/panel/data/plugin.json
	chmod 444 /www/server/panel/data/repair.json

	if [ ! -d "/etc/init.d" ];then
		mkdir -p /etc/init.d
	fi

	if [ -f "/etc/init.d/bt" ]; then
		/etc/init.d/bt stop
		sleep 1
	fi

	if [ ! -f ${setup_path}/server/panel/tools.py ] || [ ! -f ${setup_path}/server/panel/BT-Panel ];then
		Red_Error "ERROR: Failed to download, please try install again!" "ERROR: 下载宝塔失败，请尝试重新安装！"
	fi

	rm -f ${setup_path}/server/panel/class/*.pyc
	rm -f ${setup_path}/server/panel/*.pyc

	cp /www/server/panel/init.sh /etc/init.d/bt && chmod +x /etc/init.d/bt
	chmod -R 600 ${setup_path}/server/panel
	chmod -R +x ${setup_path}/server/panel/script
	ln -sf /etc/init.d/bt /usr/bin/bt
	echo "${panelPort}" > ${setup_path}/server/panel/data/port.pl

	if [ ! -f "${setup_path}/server/panel/data/installCount.pl" ];then
		echo "1 $(date)" > ${setup_path}/server/panel/data/installCount.pl
	elif [ -f "${setup_path}/server/panel/data/installCount.pl" ];then
		INSTALL_COUNT=$(cat ${setup_path}/server/panel/data/installCount.pl|awk '{last=$1} END {print last}')
		echo "$((INSTALL_COUNT+1)) $(date)" >> ${setup_path}/server/panel/data/installCount.pl
	fi 
}

Set_Bt_Panel(){
	Run_User="www"
	wwwUser=$(cat /etc/passwd|cut -d ":" -f 1|grep ^www$)
	if [ "${wwwUser}" != "www" ];then
		groupadd ${Run_User}
		useradd -m -d /www -s /sbin/nologin -g ${Run_User} ${Run_User}
		mkdir -p /www/.config/composer
		echo "{}" > /www/.config/composer/composer.json
		chown -R ${Run_User}:${Run_User} /www
		mkdir -p /root/.config/composer && echo "{}" > /root/.config/composer/composer.json
	fi

	password='a123456'
	if [ "$PANEL_PASSWORD" ];then
		password=$PANEL_PASSWORD
	fi
	sleep 1
	admin_auth="/www/server/panel/data/admin_path.pl"
	if [ ! -f "${admin_auth}" ] || [ ! -s "${admin_auth}" ]; then
		echo "/bt" > ${admin_auth}
	fi
	if [ "${SAFE_PATH}" ];then
		auth_path=$SAFE_PATH
		echo "/${auth_path}" > ${admin_auth}
	fi
	chmod -R 700 $pyenv_path/bin
	if [ ! -f "$pyenv_path/n.pl" ];then
		btpip install docxtpl==0.16.7 pymongo psycopg2-binary
		btpip install flask -U
		btpip install flask-sock
		btpip install -I gevent
		btpip install simple-websocket==0.10.0 natsort
		btpip uninstall enum34 -y
		btpip install geoip2==4.7.0 brotli PyMySQL
		btpip install -r $pyenv_path/pip.txt
	fi
	auth_path=$(cat ${admin_auth})
	cd ${setup_path}/server/panel/
	/etc/init.d/bt start
	btpython -m py_compile tools.py
	username=$(btpython tools.py panel ${password})
	if [ "$PANEL_USER" ];then
		username=$PANEL_USER
	fi
	cd ~
	echo "${password}" > ${setup_path}/server/panel/default.pl
	chmod 600 ${setup_path}/server/panel/default.pl
	sleep 3
	if [ "$SET_SSL" == true ]; then
		if [ ! -f "/www/server/panel/pyenv/n.pl" ];then
        	btpip install -I pyOpenSSl 2>/dev/null
    	fi
    	echo "========================================"
    	echo "正在开启面板SSL，请稍等............ "
    	echo "========================================"
        SSL_STATUS=$(btpython /www/server/panel/tools.py ssl)
        if [ "${SSL_STATUS}" == "0" ] ;then
        	echo -n " -4 " > /www/server/panel/data/v4.pl
        	btpython /www/server/panel/tools.py ssl
        fi
    	echo "证书开启成功！"
    	echo "========================================"
    fi
	/etc/init.d/bt stop
	sleep 5
	/etc/init.d/bt start 	
	sleep 5
	isStart=$(ps aux |grep 'BT-Panel'|grep -v grep|awk '{print $2}')
	LOCAL_CURL=$(curl 127.0.0.1:${panelPort}/login 2>&1 |grep -i html)
	LOSF_CHECK=$(lsof -i :${panelPort}|grep btpython)
	if [ -z "${isStart}" ] && [ -z "${LOSF_CHECK}" ];then
		/etc/init.d/bt 22
		cd /www/server/panel/pyenv/bin
		touch t.pl
		ls -al python3 python
		lsattr python3 python
		btpython /www/server/panel/BT-Panel
		Red_Error "ERROR: The BT-Panel service startup failed." "ERROR: 宝塔启动失败"
	fi

	PANEL_USER="admin"
	if [ "$PANEL_USER" ];then
		cd ${setup_path}/server/panel/
		btpython -c 'import tools;tools.set_panel_username("'$PANEL_USER'")'
		cd ~
	fi
	if [ -f "/usr/bin/sqlite3" ] ;then
	    sqlite3 /www/server/panel/data/db/panel.db "UPDATE config SET status = '1' WHERE id = '1';" > /dev/null 2>&1
    fi
}

Set_Firewall(){
	sshPort=$(cat /etc/ssh/sshd_config | grep 'Port '|awk '{print $2}')
	if [ "${PM}" = "apt-get" ]; then
		echo "ubuntu|debian 系统中设置防火墙"
		if command -v nft >/dev/null; then
			apt-get remove nftables -y
		fi
		apt-get install -y ufw
		ufw allow 20/tcp 21/tcp 22/tcp 80/tcp 443/tcp 888/tcp ${panelPort}/tcp ${sshPort}/tcp 39000:40000/tcp
		ufw_status=`ufw status`
		echo y|ufw enable
		ufw default deny
		ufw reload
		if [ "${ufw_status}" == '' ];then
			service iptables restart3
		fi
	else
		echo "redhat|centos 系统中设置防火墙"
		if command -v iptables >/dev/null; then
			iptables -I INPUT -p tcp -m state --state NEW -m tcp --dport 20 -j ACCEPT
			iptables -I INPUT -p tcp -m state --state NEW -m tcp --dport 21 -j ACCEPT
			iptables -I INPUT -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT
			iptables -I INPUT -p tcp -m state --state NEW -m tcp --dport 80 -j ACCEPT
			iptables -I INPUT -p tcp -m state --state NEW -m tcp --dport 443 -j ACCEPT
			iptables -I INPUT -p tcp -m state --state NEW -m tcp --dport ${panelPort} -j ACCEPT
			iptables -I INPUT -p tcp -m state --state NEW -m tcp --dport ${sshPort} -j ACCEPT
			iptables -I INPUT -p tcp -m state --state NEW -m tcp --dport 39000:40000 -j ACCEPT
			#iptables -I INPUT -p tcp -m state --state NEW -m udp --dport 39000:40000 -j ACCEPT
			iptables -A INPUT -p icmp --icmp-type any -j ACCEPT
			iptables -A INPUT -s localhost -d localhost -j ACCEPT
			iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
			iptables -P INPUT DROP
			service iptables save
			sed -i "s#IPTABLES_MODULES=\"\"#IPTABLES_MODULES=\"ip_conntrack_netbios_ns ip_conntrack_ftp ip_nat_ftp\"#" /etc/sysconfig/iptables-config
			iptables_status=$(service iptables status | grep 'not running')
			if [ "${iptables_status}" == '' ];then
				service iptables restart3
			fi
		else
			AliyunCheck=$(cat /etc/redhat-release|grep "Aliyun Linux")
			[ "${AliyunCheck}" ] && return
			yum install firewalld -y
			[ "${Centos8Check}" ] && yum reinstall python3-six -y
			systemctl enable firewalld
			systemctl start firewalld
			firewall-cmd --set-default-zone=public > /dev/null 2>&1
			firewall-cmd --permanent --zone=public --add-port=20/tcp --add-port=21/tcp --add-port=22/tcp > /dev/null 2>&1
			firewall-cmd --permanent --zone=public --add-port=80/tcp --add-port=443/tcp > /dev/null 2>&1
			firewall-cmd --permanent --zone=public --add-port=${panelPort}/tcp --add-port=${sshPort}/tcp > /dev/null 2>&1
			firewall-cmd --permanent --zone=public --add-port=39000-40000/tcp > /dev/null 2>&1
			#firewall-cmd --permanent --zone=public --add-port=39000-40000/udp > /dev/null 2>&1
			firewall-cmd --reload
		fi
	fi
}

Get_Ip_Address(){
	getIpAddress=$(wget -qO- --timeout=60 --tries=1 --connect-timeout=10 https://www.bt.cn/Api/getIpAddress)
	if [ -z "${getIpAddress}" ] || [ "${getIpAddress}" = "0.0.0.0" ]; then
		isHosts=$(cat /etc/hosts|grep 'www.bt.cn')
		if [ -z "${isHosts}" ];then
			echo "" >> /etc/hosts
			echo "116.213.43.206 www.bt.cn" >> /etc/hosts
			getIpAddress=$(wget -qO- --timeout=60 --tries=1 --connect-timeout=10 https://www.bt.cn/Api/getIpAddress)
			if [ -z "${getIpAddress}" ];then
				sed -i "/bt.cn/d" /etc/hosts
			fi
		fi
	fi
	
	CN_CHECK=$(wget -qO- --timeout=60 --tries=1 --connect-timeout=10 https://api.bt.cn/api/isCN)
	if [ "${CN_CHECK}" == "True" ];then
        echo "True" > /www/server/panel/data/domestic_ip.pl
        cat /www/server/panel/data/domestic_ip.pl
	else
		echo "True" > /www/server/panel/data/foreign_ip.pl
	fi

	ipv4Check=$(btpython -c "import re; print(re.match('^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$','${getIpAddress}'))")
	if [ "${ipv4Check}" == "None" ];then
		ipv6Address=$(echo ${getIpAddress}|tr -d "[]")
		ipv6Check=$(btpython -c "import re; print(re.match('^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$','${ipv6Address}'))")
		if [ "${ipv6Check}" == "None" ]; then
			getIpAddress="SERVER_IP"
		else
			echo "True" > ${setup_path}/server/panel/data/ipv6.pl
			sleep 1
			/etc/init.d/bt restart
		fi
	fi

	if [ "${getIpAddress}" != "SERVER_IP" ];then
		echo "${getIpAddress}" > ${setup_path}/server/panel/data/iplist.txt
	fi
	LOCAL_IP=$(ip addr | grep -E -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -E -v "^127\.|^255\.|^0\." | head -n 1)
}

Setup_Count(){
	wget -qO- --timeout=60 --tries=1 --connect-timeout=10 https://www.bt.cn/Api/SetupCount?type=Linux\&o=$1 > /dev/null 2>&1
	if [ "$1" != "" ];then
		echo $1 > /www/server/panel/data/o.pl
		cd /www/server/panel
		btpython tools.py o
	fi
	echo /www > /var/bt_setupPath.conf
}

Start_Count(){
	wget -qO- --timeout=60 --tries=1 --connect-timeout=10 https://www.bt.cn/Api/SetupCountPre?type=Linux\&o=$1 > /dev/null 2>&1
	echo /www > /var/bt_setupPath.conf
	echo "check_certificate = off" >> /etc/wgetrc 
}

function touch_ltd() {
    if [[ -f /www/server/panel/data/install_ltd.pl ]]; then
        chattr -i /www/server/panel/data/install_ltd.pl
        rm -f /www/server/panel/data/install_ltd.pl
    fi
    touch /www/server/panel/data/install_ltd.pl
    echo "install_ltd" > /www/server/panel/data/install_ltd.pl
    chattr +i /www/server/panel/data/install_ltd.pl
}

Install_Main(){
  Get_Pack_Manager
  Set_Ssl
  System_Check
	Install_Python_Lib
	Install_Bt
	
	Set_Bt_Panel
	if command -v systemctl >/dev/null; then
    systemctl enable bt
	else
	  update-rc.d bt defaults
	fi
	Set_Firewall

	Get_Ip_Address
	Setup_Count ${IDC_CODE}
	pip3 cache purge
}

echo "
+----------------------------------------------------------------------
| Bt-WebPanel FOR CentOS/Ubuntu/Debian
+----------------------------------------------------------------------
| Copyright © 2015-2099 BT-SOFT(http://www.bt.cn) All rights reserved.
+----------------------------------------------------------------------
| The WebPanel URL will be http://SERVER_IP:${panelPort} when installed.
+----------------------------------------------------------------------
| 为了您的正常使用，请确保使用全新或纯净的系统安装宝塔面板，不支持已部署项目/环境的系统安装
+----------------------------------------------------------------------
| 当前您正在安装的是宝塔面板稳定版-7.7.0
+----------------------------------------------------------------------
"

while [ ${#} -gt 0 ]; do
	case $1 in
		-u|--user)
			PANEL_USER=$2
			shift 1
			;;
		-p|--password)
			PANEL_PASSWORD=$2
			shift 1
			;;
		-P|--port)
			PANEL_PORT=$2
			shift 1
			;;
		--safe-path)
			SAFE_PATH=$2
			shift 1
			;;
		--ssl-disable)
			SSL_PL="disable"
			;;
		-y)
			go="y"
			;;
		*)
			IDC_CODE=$1
			;;
	esac
	shift 1
done

while [ "$go" != 'y' ] && [ "$go" != 'Y' ] && [ "$go" != 'n' ]
do
	read -p "Do you want to install Bt-Panel to the $setup_path directory now?(y/n): " go;
done

if [ "$go" == 'n' ];then
	exit;
fi

if [ -f "/www/server/panel/BT-Panel" ];then
	AAPANEL_CHECK=$(grep www.aapanel.com /www/server/panel/BT-Panel)
	if [ "${AAPANEL_CHECK}" ];then
		echo -e "----------------------------------------------------"
		echo -e "检查已安装有aapanel，无法进行覆盖安装宝塔面板"
		echo -e "如继续执行安装将移去aapanel面板数据（备份至/www/server/aapanel路径） 全新安装宝塔面板"
		echo -e "aapanel is alreday installed,Can't install panel"
		echo -e "is install Baota panel,  aapanel data will be removed (backed up to /www/server/aapanel)"
		echo -e "Beginning new Baota panel installation."
		echo -e "----------------------------------------------------"
		echo -e "已知风险/Enter yes to force installation"
		read -p "输入yes开始安装: " yes;
		if [ "$yes" != "yes" ];then
			echo -e "------------"
			echo "取消安装"
			exit;
		fi
		bt stop
		sleep 1
		mv /www/server/panel /www/server/aapanel
	fi
fi

ARCH_LINUX=$(cat /etc/os-release |grep "Arch Linux")
if [ "${ARCH_LINUX}" ] && [ -f "/usr/bin/pacman" ];then
	pacman -Sy 
	pacman -S curl wget unzip firewalld openssl pkg-config make gcc cmake libxml2 libxslt libvpx gd libsodium oniguruma sqlite libzip autoconf inetutils sudo --noconfirm
fi

startTime=$(date +%s)
echo "Start time: $startTime"

Install_Main

if [ "${PM}" = "apt-get" ]; then
  apt clean && rm -rf /var/cache/apt/archives/*
else
  if command -v dnf >/dev/null; then
    dnf clean all && rm -rf /var/cache/dnf
  else
    yum clean all && rm -rf /var/cache/yum
  fi
fi

PANEL_SSL=$(cat /www/server/panel/data/ssl.pl 2> /dev/null)
if [ "${PANEL_SSL}" == "True" ];then
  HTTP_S="https"
fi

if [ -f "/www/server/panel/data/ipv6.pl" ];then
  getIpAddress="[${getIpAddress}]"
fi

echo > /www/server/panel/data/bind.pl
echo -e "=================================================================="
echo -e "\033[32mCongratulations! Installed successfully!\033[0m"
echo -e "=============注意：首次打开面板浏览器将提示不安全================="
echo -e ""
echo -e " 请选择以下其中一种方式解决不安全提醒"
echo -e " 1、下载证书，地址：https://dg2.bt.cn/ssl/baota_root.pfx  双击安装,密码【www.bt.cn】"
echo -e " 2、点击【高级】-【继续访问】或【接受风险并继续】访问"
echo -e " 教程：https://www.bt.cn/bbs/thread-117246-1-1.html"
echo -e " mac用户请下载使用此证书：https://dg2.bt.cn/ssl/baota_root.crt"
echo -e ""
echo -e "========================面板账户登录信息=========================="
echo -e ""
echo -e " 【云服务器】请在安全组放行 $panelPort 端口"
echo -e " 外网面板地址: ${HTTP_S}://${getIpAddress}:${panelPort}${auth_path}"
echo -e " 内网面板地址: ${HTTP_S}://${LOCAL_IP}:${panelPort}${auth_path}"
echo -e " username: $username"
echo -e " password: $password"
echo -e ""
echo -e "=================================================================="
endTime=`date +%s`
((outTime=($endTime-$startTime)/60))
if [ "${outTime}" -le "5" ];then
    echo ${download_Url} > /www/server/panel/install/d_node.pl
  if [ -f " /www/server/panel/data/foreign_ip.pl" ];then
    rm -f /www/server/panel/install/d_node.pl
  fi
fi
if [ "${outTime}" == "0" ];then
  ((outTime=($endTime-$startTime)))
  echo -e "Time consumed:\033[32m $outTime \033[0mseconds!"
else
  echo -e "Time consumed:\033[32m $outTime \033[0mMinute!"
fi