#!/bin/bash

if [ $(id -u) != "0" ]; then
    printf "Co loi: Ban phai dang nhap bang user root!\n"
    exit
fi

if [ -f /var/cpanel/cpanel.config ]; then
echo "Server cua ban da cai san WHM/Cpanel, neu ban muon dung script Servertut"
echo "Hay cai moi lai he dieu hanh, khuyen dung centos 6 64bit"
echo "Chao tam biet !"
exit
fi

if [ -f /etc/psa/.psa.shadow ]; then
echo "Server cua ban da cai san Plesk, neu ban muon dung script Servertut"
echo "Hay cai moi lai he dieu hanh, khuyen dung centos 6 64bit"
echo "Chao tam biet !"
exit
fi

if [ -f /etc/init.d/directadmin ]; then
echo "Server cua ban da cai san DirectAdmin, neu ban muon dung script Servertut"
echo "Hay cai moi lai he dieu hanh, khuyen dung centos 6 64bit"
echo "Chao tam biet !"
exit
fi

if [ -f /etc/init.d/webmin ]; then
echo "Server cua ban da cai san webmin, neu ban muon dung script Servertut"
echo "Hay cai moi lai he dieu hanh, khuyen dung centos 6 64bit"
echo "Chao tam biet !"
exit
fi

if [ -f /etc/servertut/servertut.scripts.conf ]; then
echo "Server cua ban da cai san Servertut Script"
echo "Neu ban muon nang cap, hay su dung lenh servertut-menu"
echo "Chao tam biet !"
exit
fi

if [[ $(arch) != "x86_64" ]] ; then
echo "Servertut Script chi hoat dong tren 64bit, vui long cai lai OS 64bit."
exit
fi

yum -y install gawk bc
wget -q http://servertut.com/downloads/scripts/calc -O /bin/calc && chmod +x /bin/calc

clear
printf "=========================================================================\n"
printf "Chung ta se kiem tra cac thong so VPS cua ban de dua ra cai dat hop ly \n"
printf "=========================================================================\n"

cpuname=$( awk -F: '/model name/ {name=$2} END {print name}' /proc/cpuinfo )
cpucores=$( awk -F: '/model name/ {core++} END {print core}' /proc/cpuinfo )
cpufreq=$( awk -F: ' /cpu MHz/ {freq=$2} END {print freq}' /proc/cpuinfo )
svram=$( free -m | awk 'NR==2 {print $2}' )
svhdd=$( df -h | awk 'NR==2 {print $2}' )
svswap=$( free -m | awk 'NR==4 {print $2}' )

if [ -f "/proc/user_beancounters" ]; then
svip=$(ifconfig venet0:0 | grep 'inet addr:' | awk -F'inet addr:' '{ print $2}' | awk '{ print $1}')
else
svip=$(ifconfig eth0 | grep 'inet addr:' | awk -F'inet addr:' '{ print $2}' | awk '{ print $1}')
fi


printf "=========================================================================\n"
printf "Thong so server cua ban nhu sau \n"
printf "=========================================================================\n"
echo "Loai CPU : $cpuname"
echo "Tong so CPU core : $cpucores"
echo "Toc do moi core : $cpufreq MHz"
echo "Tong dung luong RAM : $svram MB"
echo "Tong dung luong swap : $svswap MB"
echo "Tong dung luong o dia : $svhdd GB"
echo "IP cua server la : $svip"
printf "=========================================================================\n"
printf "=========================================================================\n"
sleep 3


clear
printf "=========================================================================\n"
printf "Chuan bi qua trinh cai dat... \n"
printf "=========================================================================\n"

echo -n "Nhap vao ten mien chinh cua ban roi an [ENTER]: " 
read svdomain
if [ "$svdomain" = "" ]; then
	svdomain="servertut.com"
echo "Ban nhap sai, trinh cai dat se dung servertut.com lam ten mien chinh"
fi

echo -n "Nhap vao port phpmyadmin ban muon roi an [ENTER]: " 
read svport
if [ "$svport" = "" ] || [ "$svport" = "80" ] || [ "$svport" = "443" ] || [ "$svport" = "22" ] || [ "$svport" = "3306" ] || [ "$svport" = "25" ] || [ "$svport" = "465" ] || [ "$svport" = "587" ]; then
	svport="2313"
echo "PhpMyAdmin port khong the bo trong hoac trung voi port service khac su dung"
echo "Script se dat PMA port la 2313"
fi

echo -n "Nhap vao port btsync ban muon roi an [ENTER]: " 
read syncport
if [ "$syncport" = "" ] || [ "$syncport" = "80" ] || [ "$syncport" = "443" ] || [ "$syncport" = "22" ] || [ "$syncport" = "syncport" ] || [ "$syncport" = "25" ] || [ "$syncport" = "465" ] || [ "$syncport" = "587" ] || [ "$syncport" = "$svport" ]; then
	syncport="8888"
echo "BTsync port khong the bo trong hoac trung voi port service khac su dung"
echo "Script se dat btsync port la 8888"
fi

echo -n "Nhap vao email cua ban roi an [ENTER]: " 
read umail
if [ "$umail" = "" ]; then
	umail="info@$svdomain"
echo "Ban nhap sai, trinh cai dat se dung email info@$svdomain"
fi

echo -n "Nhap vao ma bao mat ca nhan vao roi an [ENTER]: " 
read ukey
if [ "$ukey" = "" ]; then
	ukey="123456"
echo "Ban nhap sai, trinh cai dat se dung key 123456"
fi


printf "=========================================================================\n"
printf "Hoan tat qua trinh chuan bi... \n"
printf "=========================================================================\n"

rm -f /etc/localtime
ln -sf /usr/share/zoneinfo/Asia/Ho_Chi_Minh /etc/localtime

if [ -s /etc/selinux/config ]; then
sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
fi

rpm -Uvh http://servertut.com/downloads/scripts/epel.rpm
rpm -Uvh http://servertut.com/downloads/scripts/remi.rpm
wget -q http://servertut.com/downloads/scripts/MariaDB.repo -O /etc/yum.repos.d/MariaDB.repo

service sendmail stop
chkconfig sendmail off
service xinetd stop
chkconfig xinetd off
service saslauthd stop
chkconfig saslauthd off
service rsyslog stop
chkconfig rsyslog off
service postfix stop
chkconfig postfix off

yum -y remove mysql*
yum -y remove php*
yum -y remove httpd*
yum -y remove sendmail*
yum -y remove postfix*
yum -y remove rsyslog*

yum -y update

clear
printf "=========================================================================\n"
printf "Chuan bi xong, bat dau cai dat... \n"
printf "=========================================================================\n"
sleep 3


mkdir -p /usr/local/servertut
cd /usr/local/servertut

groupadd nginx
useradd -g nginx -d /dev/null -s /sbin/nologin nginx

yum -y install gcc-c++ pcre-dev pcre-devel zlib-devel make openssl-devel
sleep 1
wget -q https://github.com/pagespeed/ngx_pagespeed/archive/release-1.6.29.5-beta.zip
sleep 1
unzip release-1.6.29.5-beta
sleep 1
cd ngx_pagespeed-release-*
wget -q https://dl.google.com/dl/page-speed/psol/1.6.29.5.tar.gz
sleep 1
tar -xzf 1.6.29.5.tar.gz
sleep 1
cd ..
wget -q http://nginx.org/download/nginx-1.4.2.tar.gz
sleep 1
tar -xzf nginx-1.4.2.tar.gz
sleep 1
cd nginx-1.4.2
./configure --prefix=/usr/share/nginx --sbin-path=/usr/sbin/nginx --with-http_ssl_module --conf-path=/etc/nginx/nginx.conf --with-http_gzip_static_module --with-http_realip_module --group=nginx --user=nginx --pid-path=/var/run/nginx.pid --with-http_stub_status_module --add-module=/usr/local/servertut/ngx_pagespeed-release-1.6.29.5-beta
sleep 1
make
sleep 1
make install
sleep 1
rm -f /etc/init.d/nginx

wget -q http://servertut.com/downloads/servertut-1.0/nginx -O /etc/init.d/nginx && chmod +x /etc/init.d/nginx


    cat > "/etc/nginx/ngx_pagespeed.conf" <<END
	pagespeed On;
	pagespeed FileCachePath "/var/cache/ngx_pagespeed/";
	pagespeed EnableFilters combine_css,combine_javascript;
	location ~ "\.pagespeed\.([a-z]\.)?[a-z]{2}\.[^.]{10}\.[^.]+" { add_header "" ""; }
	location ~ "^/ngx_pagespeed_static/" { }
	location ~ "^/ngx_pagespeed_beacon$" { }
	location /ngx_pagespeed_statistics { allow 127.0.0.1; deny all; }
	location /ngx_pagespeed_message { allow 127.0.0.1; deny all; }
	location /pagespeed_console { allow 127.0.0.1; deny all; }
END


yum -y install MariaDB-server MariaDB-client exim syslog-ng cronie
yum -y --enablerepo=remi install php-common php-fpm php-gd php-mysql php-pdo php-xml php-mbstring php-mcrypt php-pecl-apc php-curl php-soap

clear
printf "=========================================================================\n"
printf "Cai dat xong, bat dau cau hinh... \n"
printf "=========================================================================\n"
sleep 3


	ramformariadb=$(calc $svram/10*6)
	ramforphpnginx=$(calc $svram-$ramformariadb)
	max_children=$(calc $ramforphpnginx/30)
	memory_limit=$(calc $ramforphpnginx/5*3)M
	mem_apc=$(calc $ramforphpnginx/5)M
	buff_size=$(calc $ramformariadb/10*8)M
	log_size=$(calc $ramformariadb/10*2)M

service httpd stop 
chkconfig httpd off
chkconfig --add mysql
chkconfig --levels 235 mysql on
chkconfig --add nginx
chkconfig --levels 235 nginx on
chkconfig --add php-fpm
chkconfig --levels 235 php-fpm on
chkconfig --add exim
chkconfig --levels 235 exim on
chkconfig --add syslog-ng
chkconfig --levels 235 syslog-ng on

service mysql start
service exim start
service syslog-ng start

mkdir -p /home/$svdomain/public_html
mkdir /home/$svdomain/private_html
mkdir /home/$svdomain/logs
chmod 777 /home/$svdomain/logs


mkdir -p /var/cache/ngx_pagespeed
mkdir -p /var/log/nginx
chown -R nginx:nginx /var/cache/ngx_pagespeed
chown -R nginx:nginx /var/log/nginx
chown -R nginx:nginx /var/lib/php/session

rm -f /etc/nginx/nginx.conf
    cat > "/etc/nginx/nginx.conf" <<END

user  nginx;
worker_processes  $cpucores;
worker_rlimit_nofile 65536;

error_log  /var/log/nginx/error.log warn;
pid        /var/run/nginx.pid;


events {
    worker_connections  2048;
}


http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;

    log_format  main  '\$remote_addr - \$remote_user [\$time_local] "\$request" '
                      '\$status \$body_bytes_sent "\$http_referer" '
                      '"\$http_user_agent" "\$http_x_forwarded_for"';

    access_log  off;
    sendfile on;
    tcp_nopush on;
    tcp_nodelay off;
    types_hash_max_size 2048;
    server_tokens off;
    server_names_hash_bucket_size 128;
    client_max_body_size 20m;
    client_body_buffer_size 256k;
    client_body_in_file_only off;
    client_body_timeout 60s;
    client_header_buffer_size 256k;
    client_header_timeout  20s;
    large_client_header_buffers 8 256k;
    keepalive_timeout 10;
    keepalive_disable msie6;
    reset_timedout_connection on;
    send_timeout 60s;
    gzip on;
    gzip_static on;
    gzip_disable "msie6";
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_buffers 16 8k;
    gzip_http_version 1.1;
    gzip_types text/plain text/css application/json application/x-javascript text/xml application/xml application/xml+rss text/javascript;



  # Cloudflare module cho nginx
    set_real_ip_from   204.93.240.0/24;
    set_real_ip_from   204.93.177.0/24;
    set_real_ip_from   199.27.128.0/21;
    set_real_ip_from   173.245.48.0/20;
    set_real_ip_from   103.21.244.0/22;
    set_real_ip_from   103.22.200.0/22;
    set_real_ip_from   103.31.4.0/22;
    set_real_ip_from   141.101.64.0/18;
    set_real_ip_from   108.162.192.0/18;
    set_real_ip_from   190.93.240.0/20;
    set_real_ip_from   188.114.96.0/20;  
    set_real_ip_from   197.234.240.0/22;
    set_real_ip_from   198.41.128.0/17;
    real_ip_header     CF-Connecting-IP;

    include /etc/nginx/conf.d/*.conf;
}
END

rm -rf /etc/nginx/conf.d
mkdir -p /etc/nginx/conf.d
    cat > "/etc/nginx/conf.d/$svdomain.conf" <<END
server {
	    server_name www.$svdomain;
	    rewrite ^(.*) http://$svdomain\$1 permanent;
    	}
server {
	    listen   80 default_server;

    	access_log off;
    	error_log off;
    	# error_log /home/$svdomain/logs/error.log;
    	root /home/$svdomain/public_html;
	index index.php index.html index.htm;
    	server_name $svdomain;
 
    	location / {
		try_files \$uri \$uri/ /index.php?\$args;
   	    }
 
    	location ~ \.php$ {
		fastcgi_split_path_info ^(.+\.php)(/.+)$;
        	include /etc/nginx/fastcgi_params;
        	fastcgi_pass  unix:/var/run/php-fpm/php-fpm.sock;
        	fastcgi_index index.php;
		fastcgi_connect_timeout 60;
		fastcgi_send_timeout 180;
		fastcgi_read_timeout 180;
		fastcgi_buffer_size 256k;
		fastcgi_buffers 4 256k;
		fastcgi_busy_buffers_size 256k;
		fastcgi_temp_file_write_size 256k;
		fastcgi_intercept_errors on;
        	fastcgi_param SCRIPT_FILENAME /home/$svdomain/public_html\$fastcgi_script_name;
    	}
	location /nginx_status {
  		stub_status on;
  		access_log   off;
	}
    	location /php_status {
            	fastcgi_pass  unix:/var/run/php-fpm/php-fpm.sock;
            	fastcgi_index index.php;
            	fastcgi_param SCRIPT_FILENAME  /home/$svdomain/public_html\$fastcgi_script_name;
            	include /etc/nginx/fastcgi_params;
    	}
	location ~ /\. {
		deny all;
	}
        location = /favicon.ico {
                log_not_found off;
                access_log off;
        }
       location = /robots.txt {
              allow all;
              log_not_found off;
              access_log off;
       }
	location ~* \.(3gp|gif|jpg|jpeg|png|ico|wmv|avi|asf|asx|mpg|mpeg|mp4|pls|mp3|mid|wav|swf|flv|exe|zip|tar|rar|gz|tgz|bz2|uha|7z|doc|docx|xls|xlsx|pdf|iso|eot|svg|ttf|woff)$ {
	        gzip_static off;
			add_header Pragma public;
			add_header Cache-Control "public, must-revalidate, proxy-revalidate";
			access_log off;
			expires 30d;
			break;
        }

        location ~* \.(txt|js|css)$ {
	        add_header Pragma public;
			add_header Cache-Control "public, must-revalidate, proxy-revalidate";
			access_log off;
			expires 30d;
			break;
        }
    }

server {
	    listen   $svport;
	 	access_log        off;
		log_not_found     off;
	 	error_log         off;
    	root /home/$svdomain/private_html;
	    index index.php index.html index.htm;
    	server_name $svdomain;
 
     	location / {
		try_files \$uri \$uri/ /index.php;
   	    }
    	location ~ \.php$ {
		fastcgi_split_path_info ^(.+\.php)(/.+)$;
        	include /etc/nginx/fastcgi_params;
        	fastcgi_pass  unix:/var/run/php-fpm/php-fpm.sock;
        	fastcgi_index index.php;
			fastcgi_connect_timeout 60;
			fastcgi_send_timeout 180;
			fastcgi_read_timeout 180;
			fastcgi_buffer_size 256k;
			fastcgi_buffers 4 256k;
			fastcgi_busy_buffers_size 256k;
			fastcgi_temp_file_write_size 256k;
			fastcgi_intercept_errors on;
        	fastcgi_param SCRIPT_FILENAME /home/$svdomain/private_html\$fastcgi_script_name;
    	}
        location ~* \.(bak|back|bk)$ {
		deny all;
	}
}
END


rm -f /etc/php-fpm.d/www.conf
    cat > "/etc/php-fpm.d/www.conf" <<END
[www]
listen = /var/run/php-fpm/php-fpm.sock
listen.allowed_clients = 127.0.0.1
user = nginx
group = nginx
pm = dynamic
pm.max_children = $max_children
pm.start_servers = 3
pm.min_spare_servers = 2
pm.max_spare_servers = 6
pm.max_requests = 500 
pm.status_path = /php_status
request_terminate_timeout = 120s
request_slowlog_timeout = 4s
slowlog = /home/$svdomain/logs/php-fpm-slow.log
rlimit_files = 131072
rlimit_core = unlimited
catch_workers_output = yes
env[HOSTNAME] = \$HOSTNAME
env[PATH] = /usr/local/bin:/usr/bin:/bin
env[TMP] = /tmp
env[TMPDIR] = /tmp
env[TEMP] = /tmp
php_admin_value[error_log] = /home/$svdomain/logs/php-fpm-error.log
php_admin_flag[log_errors] = on
php_value[session.save_handler] = files
php_value[session.save_path] = /var/lib/php/session
END


rm -f /etc/php.ini
    cat > "/etc/php.ini" <<END
[PHP]
engine = On
short_open_tag = Off
asp_tags = Off
precision = 14
output_buffering = 4096
zlib.output_compression = Off
implicit_flush = Off
unserialize_callback_func =
serialize_precision = 17
disable_functions = escapeshellarg,escapeshellcmd,exec,ini_alter,parse_ini_file,passthru,pcntl_exec,popen,proc_close,proc_get_status,proc_nice,proc_open,proc_terminate,show_source,shell_exec,symlink,system
disable_classes =
zend.enable_gc = On
expose_php = On
max_execution_time = 30
max_input_time = 60
memory_limit = $memory_limit
error_reporting = E_ALL & ~E_DEPRECATED & ~E_STRICT
display_errors = Off
display_startup_errors = Off
log_errors = On
log_errors_max_len = 1024
ignore_repeated_errors = Off
ignore_repeated_source = Off
report_memleaks = On
track_errors = Off
html_errors = On
variables_order = "GPCS"
request_order = "GP"
register_argc_argv = Off
auto_globals_jit = On
post_max_size = 180M
auto_prepend_file =
auto_append_file =
default_mimetype = "text/html"
default_charset = "UTF-8"
doc_root =
user_dir =
enable_dl = Off
cgi.fix_pathinfo=0
file_uploads = On
upload_max_filesize = 200M
max_file_uploads = 20
allow_url_fopen = On
allow_url_include = Off
default_socket_timeout = 60
cli_server.color = On

[Date]
date.timezone = Asia/Bangkok

[filter]

[iconv]

[intl]

[sqlite]

[sqlite3]

[Pcre]

[Pdo]

[Pdo_mysql]
pdo_mysql.cache_size = 2000
pdo_mysql.default_socket=

[Phar]

[mail function]
SMTP = localhost
smtp_port = 25
sendmail_path = /usr/sbin/sendmail -t -i
mail.add_x_header = On

[SQL]
sql.safe_mode = Off

[ODBC]
odbc.allow_persistent = On
odbc.check_persistent = On
odbc.max_persistent = -1
odbc.max_links = -1
odbc.defaultlrl = 4096
odbc.defaultbinmode = 1

[Interbase]
ibase.allow_persistent = 1
ibase.max_persistent = -1
ibase.max_links = -1
ibase.timestampformat = "%Y-%m-%d %H:%M:%S"
ibase.dateformat = "%Y-%m-%d"
ibase.timeformat = "%H:%M:%S"

[MySQL]
mysql.allow_local_infile = On
mysql.allow_persistent = On
mysql.cache_size = 2000
mysql.max_persistent = -1
mysql.max_links = -1
mysql.default_port =
mysql.default_socket =
mysql.default_host =
mysql.default_user =
mysql.default_password =
mysql.connect_timeout = 60
mysql.trace_mode = Off

[MySQLi]
mysqli.max_persistent = -1
mysqli.allow_persistent = On
mysqli.max_links = -1
mysqli.cache_size = 2000
mysqli.default_port = 3306
mysqli.default_socket =
mysqli.default_host =
mysqli.default_user =
mysqli.default_pw =
mysqli.reconnect = Off

[mysqlnd]
mysqlnd.collect_statistics = On
mysqlnd.collect_memory_statistics = Off

[OCI8]

[PostgreSQL]
pgsql.allow_persistent = On
pgsql.auto_reset_persistent = Off
pgsql.max_persistent = -1
pgsql.max_links = -1
pgsql.ignore_notice = 0
pgsql.log_notice = 0

[Sybase-CT]
sybct.allow_persistent = On
sybct.max_persistent = -1
sybct.max_links = -1
sybct.min_server_severity = 10
sybct.min_client_severity = 10

[bcmath]
bcmath.scale = 0

[browscap]

[Session]
session.save_handler = files
session.use_cookies = 1
session.use_only_cookies = 1
session.name = PHPSESSID
session.auto_start = 0
session.cookie_lifetime = 0
session.cookie_path = /
session.cookie_domain =
session.cookie_httponly =
session.serialize_handler = php
session.gc_probability = 1
session.gc_divisor = 1000
session.gc_maxlifetime = 1440
session.bug_compat_42 = Off
session.bug_compat_warn = Off
session.referer_check =
session.cache_limiter = nocache
session.cache_expire = 180
session.use_trans_sid = 0
session.hash_function = 0
session.hash_bits_per_character = 5
url_rewriter.tags = "a=href,area=href,frame=src,input=src,form=fakeentry"

[MSSQL]
mssql.allow_persistent = On
mssql.max_persistent = -1
mssql.max_links = -1
mssql.min_error_severity = 10
mssql.min_message_severity = 10
mssql.compatability_mode = Off

[Assertion]

[mbstring]

[gd]

[exif]

[Tidy]
tidy.clean_output = Off

[soap]
soap.wsdl_cache_enabled=1
soap.wsdl_cache_dir="/tmp"
soap.wsdl_cache_ttl=86400
soap.wsdl_cache_limit = 5

[sysvshm]

[ldap]
ldap.max_links = -1

[mcrypt]

[dba]

END

rm -f /etc/php-fpm.conf
    cat > "/etc/php-fpm.conf" <<END
include=/etc/php-fpm.d/*.conf

[global]
pid = /var/run/php-fpm/php-fpm.pid
error_log = /home/$svdomain/logs/php-fpm.log
emergency_restart_threshold = 10
emergency_restart_interval = 60s
process_control_timeout = 10s
daemonize = yes
END

rm -f /etc/my.cnf.d/server.cnf
    cat > "/etc/my.cnf.d/server.cnf" <<END
[server]

[mysqld]
skip-host-cache
skip-name-resolve
collation-server = utf8_unicode_ci
init-connect='SET NAMES utf8'
character-set-server = utf8
skip-character-set-client-handshake

user = mysql
default_storage_engine = InnoDB
socket = /var/lib/mysql/mysql.sock
pid_file = /var/lib/mysql/mysql.pid

key_buffer_size = 32M
myisam_recover = FORCE,BACKUP
max_allowed_packet = 16M
max_connect_errors = 1000000
datadir = /var/lib/mysql/
tmp_table_size = 32M
max_heap_table_size = 32M
query_cache_type = ON
query_cache_size = 2M
long_query_time = 5
max_connections = 5000
thread_cache_size = 50
open_files_limit = 65536
table_definition_cache = 1024
table_open_cache = 1024
innodb_flush_method = O_DIRECT
innodb_log_files_in_group = 2
innodb_log_file_size = $log_size
innodb_flush_log_at_trx_commit = 2
innodb_file_per_table = 1
innodb_buffer_pool_size = $buff_size

log_error = /home/$svdomain/logs/mysql.log
log_queries_not_using_indexes = 0
slow_query_log = 1
slow_query_log_file = /home/$svdomain/logs/mysql-slow.log

[embedded]

[mysqld-5.5]

[mariadb]

[mariadb-5.5]
END


    cat >> "/etc/security/limits.conf" <<END
* soft nofile 65536
* hard nofile 65536
nginx soft nofile 65536
nginx hard nofile 65536
END

ulimit  -n 65536


rm -f /etc/php.d/apc.ini
    cat > "/etc/php.d/apc.ini" <<END
extension = apc.so
apc.enabled=1
apc.shm_segments=1
apc.shm_size=$mem_apc
apc.num_files_hint=1024
apc.user_entries_hint=4096
apc.ttl=7200
apc.use_request_time=1
apc.user_ttl=7200
apc.gc_ttl=3600
apc.cache_by_default=1
apc.filters
apc.mmap_file_mask=/apc.XXXXXX
apc.file_update_protection=2
apc.enable_cli=0
apc.max_file_size=1M
apc.stat=0
apc.stat_ctime=0
apc.canonicalize=0
apc.write_lock=1
apc.report_autofilter=0
apc.rfc1867=0
apc.rfc1867_prefix =upload_
apc.rfc1867_name=APC_UPLOAD_PROGRESS
apc.rfc1867_freq=0
apc.rfc1867_ttl=3600
apc.include_once_override=0
apc.lazy_classes=0
apc.lazy_functions=0
apc.coredump_unmap=0
apc.file_md5=0
apc.preload_path
END

mkdir -p /etc/servertut/menu

rm -f /etc/servertut/servertut.scripts.conf
    cat > "/etc/servertut/servertut.scripts.conf" <<END
mainsite="$svdomain"
priport="$svport"
portsync="$syncport"
email="$umail"
prikey="$ukey"
serverip="$svip"
END


rm -f /var/lib/mysql/ib_logfile0
rm -f /var/lib/mysql/ib_logfile1
rm -f /var/lib/mysql/ibdata1


rm -f /bin/mysql_secure_installation
wget -q http://servertut.com/downloads/scripts/mysql_secure_installation -O /bin/mysql_secure_installation && chmod +x /bin/mysql_secure_installation
clear
printf "=========================================================================\n"
printf "Thiet lap co ban cho MariaDB ... \n"
printf "=========================================================================\n"
/bin/mysql_secure_installation
service mysql restart

clear
printf "=========================================================================\n"
printf "Hoan tat qua trinh cau hinh... \n"
printf "=========================================================================\n"
cd /home/$svdomain/private_html/
wget -q http://servertut.com/downloads/pma.tar.gz
tar -xf pma.tar.gz
rm -f pma.tar.gz

mkdir -p /var/lib/php/session
chown -R nginx:nginx /var/lib/php

rm -f /home/$svdomain/private_html/apc.conf.php
    cat > "/home/$svdomain/private_html/apc.conf.php" <<END
<?php
defaults('ADMIN_USERNAME','$umail');
defaults('ADMIN_PASSWORD','$ukey');
?>
END

wget -q http://servertut.com/downloads/btsync -O /etc/servertut/btsync && chmod +x /etc/servertut/btsync
rm -f /etc/servertut/sync.conf
    cat > "/etc/servertut/sync.conf" <<END
{ 
  "device_name": "$svdomain",
  "listening_port" : 0,
  "storage_path" : "/etc/servertut/.sync",
  "check_for_updates" : true, 
  "use_upnp" : true,
  "download_limit" : 0,                       
  "upload_limit" : 0, 
  "webui" :
  {
    "listen" : "0.0.0.0:$syncport",
    "login" : "$umail",
    "password" : "$ukey"
  }
}
END


    cat >> "/etc/rc.d/rc.local" <<END
cd /etc/servertut
./btsync --config sync.conf
END

wget -q http://servertut.com/downloads/scripts/servertut-check-downtime -O /bin/servertut-check-downtime && chmod +x /bin/servertut-check-downtime

    cat >> "/etc/cron.d/servertut.downtime.cron" <<END
SHELL=/bin/sh
* * * * * root /bin/servertut-check-downtime >/dev/null 2>&1
END


rm -f /home/$svdomain/private_html/downtime.txt
    cat > "/home/$svdomain/private_html/downtime.txt" <<END
=============================================================================
Danh sach nhung lan server mat ket noi, khong tinh reboot va shutdown - boot
=============================================================================
END


clear
printf "=========================================================================\n"
printf "Cau hinh hoan tat, bat dau them servertut-menu, nhanh thoi... \n"
printf "=========================================================================\n"

wget -q http://servertut.com/downloads/scripts/servertut-menu -O /bin/servertut-menu && chmod +x /bin/servertut-menu
wget -q http://servertut.com/downloads/scripts/servertut.scripts.version -O /etc/servertut/servertut.scripts.version && chmod 777 /etc/servertut/servertut.scripts.version
wget -q http://servertut.com/downloads/scripts/menu/servertut-apc-opcode -O /etc/servertut/menu/servertut-apc-opcode && chmod +x /etc/servertut/menu/servertut-apc-opcode
wget -q http://servertut.com/downloads/scripts/menu/servertut-btsync -O /etc/servertut/menu/servertut-btsync && chmod +x /etc/servertut/menu/servertut-btsync
wget -q http://servertut.com/downloads/scripts/menu/servertut-pagespeed -O /etc/servertut/menu/servertut-pagespeed && chmod +x /etc/servertut/menu/servertut-pagespeed
wget -q http://servertut.com/downloads/scripts/menu/servertut-downtime -O /etc/servertut/menu/servertut-downtime && chmod +x /etc/servertut/menu/servertut-downtime
wget -q http://servertut.com/downloads/scripts/menu/servertut-go-bo-scripts -O /etc/servertut/menu/servertut-go-bo-scripts && chmod +x /etc/servertut/menu/servertut-go-bo-scripts
wget -q http://servertut.com/downloads/scripts/menu/servertut-ioncube -O /etc/servertut/menu/servertut-ioncube && chmod +x /etc/servertut/menu/servertut-ioncube
wget -q http://servertut.com/downloads/scripts/menu/servertut-nang-cap-scripts -O /etc/servertut/menu/servertut-nang-cap-scripts && chmod +x /etc/servertut/menu/servertut-nang-cap-scripts
wget -q http://servertut.com/downloads/scripts/menu/servertut-phpmyadmin -O /etc/servertut/menu/servertut-phpmyadmin && chmod +x /etc/servertut/menu/servertut-phpmyadmin
wget -q http://servertut.com/downloads/scripts/menu/servertut-sao-luu-code -O /etc/servertut/menu/servertut-sao-luu-code && chmod +x /etc/servertut/menu/servertut-sao-luu-code
wget -q http://servertut.com/downloads/scripts/menu/servertut-sao-luu-data -O /etc/servertut/menu/servertut-sao-luu-data && chmod +x /etc/servertut/menu/servertut-sao-luu-data
wget -q http://servertut.com/downloads/scripts/menu/servertut-tao-database -O /etc/servertut/menu/servertut-tao-database && chmod +x /etc/servertut/menu/servertut-tao-database
wget -q http://servertut.com/downloads/scripts/menu/servertut-tat-tu-dong-sao-luu -O /etc/servertut/menu/servertut-tat-tu-dong-sao-luu && chmod +x /etc/servertut/menu/servertut-tat-tu-dong-sao-luu
wget -q http://servertut.com/downloads/scripts/menu/servertut-them-website -O /etc/servertut/menu/servertut-them-website && chmod +x /etc/servertut/menu/servertut-them-website
wget -q http://servertut.com/downloads/scripts/menu/servertut-tu-dong-sao-luu -O /etc/servertut/menu/servertut-tu-dong-sao-luu && chmod +x /etc/servertut/menu/servertut-tu-dong-sao-luu
wget -q http://servertut.com/downloads/scripts/menu/servertut-xoa-database -O /etc/servertut/menu/servertut-xoa-database && chmod +x /etc/servertut/menu/servertut-xoa-database
wget -q http://servertut.com/downloads/scripts/menu/servertut-xoa-website -O /etc/servertut/menu/servertut-xoa-website && chmod +x /etc/servertut/menu/servertut-xoa-website
wget -q http://servertut.com/downloads/scripts/menu/servertut-park-domain -O /etc/servertut/menu/servertut-park-domain && chmod +x /etc/servertut/menu/servertut-park-domain
wget -q http://servertut.com/downloads/scripts/menu/servertut-redirect-domain -O /etc/servertut/menu/servertut-redirect-domain && chmod +x /etc/servertut/menu/servertut-redirect-domain



    cat > "/tmp/sendmail.sh" <<END
#!/bin/bash

echo -e 'Subject: Servertut Script - Chuc mung cai dat thanh cong!\nChao ban!\n\nChuc mung ban da hoan thanh qua trinh cai dat va cau hinh server bang Servertut Scripts, neu ban co bat ky cau hoi hay gop y nao, vui long truy cap http://servertut.com/threads/1/\n\nSau day la thong tin server moi cua ban, vui long doc can than va luu giu cung nhu bao mat nhung thong tin sau day\nTen website chinh : http://$svdomain/\nLink PhpMyAdmin: http://$svdomain:$svport/\nLink Downtime Statics : http://$svdomain:$svport/downtime.txt\nLink APC Statics : http://$svdomain:$svport/apc.php\nLink BTsync Manager : http://$svdomain:$syncport/\nUpload source len : /home/$svdomain/public_html/\nDoi voi APC Statics va BTsync Manager, ban can dang nhap voi username chinh la email nay $umail , password chinh la ma bao mat ca nhan $ukey\n\nLuu y doi voi nhung ban nao chua dns ten mien ve ip cua server $svip , hoac dang dung cloudflare tren domain nay, cac ban co the thay $svdomain bang $svip de truy cap vao APC Statics, Downtime Statics va BTsync Manager, vi du link PMA : http://$svip:$svport/\nCam on ban da tin dung Servertut Script\n\nServertut.Com !' | exim  $umail
END
chmod +x /tmp/sendmail.sh
/tmp/sendmail.sh
rm -f /tmp/sendmail.sh


echo "Servertut Scripts da gan nhu cai dat hoan tat"
read -r -p "Ban co muon cai dat them firewall khong? [y/N] " response
case $response in
    [yY][eE][sS]|[yY]) 

clear
printf "=========================================================================\n"
printf "Cai dat CSF... \n"
printf "=========================================================================\n"
rm -fv csf.tgz
wget -q http://www.configserver.com/free/csf.tgz
sleep 1
tar -xzf csf.tgz
sleep 1
cd csf
sleep 1
sh install.sh
cd ..
sleep 1
rm -f csf.tgz
rm -rf csf
sleep 1
service csf start

        ;;
    *)
        echo "Se khong cat dat firewall !"
if [ -f /etc/sysconfig/iptables ]; then
service iptables start
iptables -I INPUT -p tcp --dport 80 -j ACCEPT
iptables -I INPUT -p tcp --dport 22 -j ACCEPT
iptables -I INPUT -p tcp --dport 25 -j ACCEPT
iptables -I INPUT -p tcp --dport 443 -j ACCEPT
iptables -I INPUT -p tcp --dport 465 -j ACCEPT
iptables -I INPUT -p tcp --dport 587 -j ACCEPT
iptables -I INPUT -p tcp --dport $svport -j ACCEPT
iptables -I INPUT -p tcp --dport $syncport -j ACCEPT
service iptables save
fi
        ;;
esac
clear
printf "=========================================================================\n"
printf "Servertut Scripts da hoan tat qua trinh cai dat... \n"
printf "Vui long check mail $umail de biet thong tin chi tiet ! \n"
printf "=========================================================================\n"
printf " \n"
printf "=========================================================================\n"
printf "Server se tu dong khoi dong lai sau 3s nua.... \n"
printf "=========================================================================\n"
sleep 3
reboot
exit
