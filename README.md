# NextCloud mit LDAP inkl. WEBGUI

von Robert Hartings und Alexander Niersmann


# Server

Es werden zwei Server von NetCup bezogen. 

Ein Server wird nur für LDAP genutzt. Auf dem anderen Server läuft ein NGINX Webserver, sodass NextCloud und phpldap erreichbar sind. Diese machen wir, damit LDAP und die anderen Systeme nicht auf einer Maschine laufen, um so eine realistische LDAP Nutzung zu simulieren.

## Serverhardware

Beide Server sind mit folgender Hardware ausgerüstet.

| Hardware | Value |
|---|---|
| CPU | 1vCore |
| RAM | 2 GB |
| DISK | 20 GB SSD (RAID 10) |
| Network Speed | 1000 MBit/s |

# Serverkonfiguration

Neuste Updates auf den Servern installieren:

1. `apt update`
2. `apt upgrade -y`

Alte unbenötigte Dateien entfernen:
1. `apt autoremove -y`

Nutzer mit sudo Rechten anlegen, damit der Root Account nicht mehr genutzt werden muss:
1. `adduser USERNAME`
2. `adduser USERNAME sudo`

Die Nutzer erhalten ein sicheres Passwort, ein SSH-Key wäre die sichere Variante wird aufgrund der nicht vorhanden Kritikalität nicht verwendet. Im Allgemeinen empfiehlt sich einen SSH-Key zu nutzen.

Das Root Passwort wird geändert, damit ein mögliches mitlesen des E-Mailverkehrs zwischen Hoster und Mieter nicht zu einer Kompromittierung des Servers führt.
1. `passwd`

Der Root Nutzer erhält ein sicheres Passwort. Im Folgenden werden nur noch die User Accounts mit sudo-Berechtigung genutzt.

In der SSH-Config wird der Login von Root unterbinden, umso einen mögliches Brutforcen des Root Passworts zu verhindern:
1. `sudo nano /etc/ssh/sshd_config`
2. Zeile `PermitRootLogin` von `yes` auf `no` ändern, damit ein Login via SSH auf Root nicht mehr möglich ist.
3. Falls alle Nutzer ssh-Keys hinterlegt haben, kann `PasswordAuthentication` von `yes` auf `no` gesetzt werden, da jedoch nur Passwörter genutzt worden sind bleibt der Wert auf `yes`
4. SSH (Deamon)  mit `sudo systemctl restart ssh` neustarten, damit die Änderungen übernommen werden.

Beide Server erhalten einen Hostname zur leichteren Identifizierung. Der Nextcloud Server erhält den Hostname `cloud` und der LDAP Server den Hostname `ldap`.
1. Hostname setzen durch `sudo hostnamectl set-hostname HOSTNAME`

Um auch IPv6 zu nutzen müssen Einstellungen im Network Interface gemacht werden. IPv6 wird vorausschauend aktiviert, es könnte gebraucht werden.
1. `sudo nano /etc/netplan/01-netcfg.yaml`
2. IPv4 und IPv6 Konfigurationen werden statisch an einen Adapter vergeben. DHCP wird nicht weiter genutzt.
3. Änderungen werden mit `sudo netplan apply` angewendet.

Die aktuelle Konfiguration sieht wie folgt aus:

```
# This file describes the network interfaces available on your system
# For more information, see netplan(5).
network:
  version: 2
  renderer: networkd
  ethernets:
    eth0:
      addresses: [94.16.123.148/22, "2a03:4000:21:848::1/64"]
      gateway4: 94.16.120.1
      gateway6: fe80::1
      nameservers:
        addresses: [46.38.225.230, 46.38.252.230, "2a03:4000:0:1::e1e6", "2a03:4000:8000::fce6"]
```

Die Adressen, Gateways und Nameserver sind von Netcup vorgegeben worden.

Für IPv4 und IPv6 wurde bei beiden Servern ein rDNS Eintrag gesetzt. Für den NextCloud Server wurde die Domain cloud.hartlab.de und den LDAP Server die Domain ldap.hartlab.de genutzt und auch in die DNS Einstellungen der Domain übernommen. So ist eine Nutzung der IP-Adressen für SSH 
und Weboberfläche nicht mehr notwendig. Des Weiteren ist nur mit einem Domainnamen ein Zertifikat von Let's Encrypt beantragbar. 

## Cloud Server - NextCloud & phpldapadmin

### Nextcloud 

Für Nextcloud wurde eine Subdomain (cloud.hardlab.de) auf die IP des Servers (Cloud Server im Folgenden) angelegt. Dies dient der einfachereren Handhabung der Installation, für die Anwendung durch Benutzer und Zertifikate.

#### Vorbereitung des Cloud Servers  

Zunächst muss der Cloud Server für künfitge Schritte vorbereitet werden, dazu wurde in die root-Shell gewechselt und diverse "Standard"-Pakete installiert.
Diese sind **normalerweise** auf den meisten Ubuntu-Distributionen installiert, dennoch wurden diese zur Verringerung von Fehlerursachen installiert/geupdated.

```
sudo -s
apt install curl gnupg2 git lsb-release ssl-cert ca-certificates apt-transport-https tree locate software-properties-common dirmngr screen htop net-tools zip unzip curl ffmpeg ghostscript libfile-fcntllock-perl -y
```

Da im späteren Verlauf weitere, spezifische Pakete gebraucht werden, müssen wir zusätzliche Software-Respositories zu unseren vorhandenen hinzufügen.
Diese sind speziell für Nginx, PHP 7.x und MariaDB.  
  
```
cd /etc/apt/sources.list.d
echo "deb [arch=amd64] http://nginx.org/packages/mainline/ubuntu $(lsb_release -cs) nginx" | tee nginx.list
echo "deb [arch=amd64] http://ppa.launchpad.net/ondrej/php/ubuntu $(lsb_release -cs) main" | tee php.list
echo "deb [arch=amd64] http://ftp.hosteurope.de/mirror/mariadb.org/repo/10.4/ubuntu $(lsb_release -cs) main" | tee mariadb.list
```

Nun müssen noch die erforderlichen Keys geladen werden um den neuen Quellen zu vertrauen. (In der Reihenfolge: Nginx, PHP and MariaDB).

```
curl -fsSL https://nginx.org/keys/nginx_signing.key | sudo apt-key add -
apt-key adv --recv-keys --keyserver hkp://keyserver.ubuntu.com:80 4F4EA0AAE5267A6C
apt-key adv --recv-keys --keyserver hkp://keyserver.ubuntu.com:80 0xF1656F24C74CD1D8
```

Nun updaten wir noch einmal den Server und generieren selbst-signierte Zertifikate. Letztere werden später nicht mehr gebraucht.

```
apt update && apt upgrade -y
make-ssl-cert generate-default-snakeoil -y
```

Zum Abschluss der Vorbereitung werden alte Instanzen, falls vorhanden, von Nginx entfernt.

```
apt remove nginx nginx-extras nginx-common nginx-full -y --allow-change-held-packages
```

#### Installation und Konfigurierung von Nginx

Als Webserver benutzen wir für diese Serverkonfiguration Nginx. Dieser wird im späteren Verlauf auch zur Installation von phpLDAPadmin genutzt.  
  


Zuerst gehen wir sicher, dass keine Instanz von Apache läuft und installieren dann Nginx. Ersteres machen wir um sicherzugehen, dass keine Anwendung auf Port 80 läuft. 

```
systemctl stop apache2.service && systemctl disable apache2.service
apt install nginx -y
systemctl enable nginx.service
```

Nun werden die default-Einstellungen von Nginx für unsere Bedürfnisse angepasst. Vor den Änderungen wird ein Backup der Datei erstellt...  

```
mv /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak && touch /etc/nginx/nginx.conf
nano /etc/nginx/nginx.conf
```

... und folgende Einstellungen übernommen:

```
user www-data;
worker_processes auto;
pid /var/run/nginx.pid;
events {
    worker_connections 1024;
    multi_accept on; use epoll;
}
http {
    server_names_hash_bucket_size 64;
    upstream php-handler {
        server unix:/run/php/php7.3-fpm.sock;
    }
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log warn;
    set_real_ip_from 127.0.0.1;
    set_real_ip_from 94.16.123.148; # Server-IP
    real_ip_header X-Forwarded-For;
    real_ip_recursive on;
    include /etc/nginx/mime.types;
    #include /etc/nginx/proxy.conf;
    #include /etc/nginx/ssl.conf;
    #include /etc/nginx/header.conf;
    #include /etc/nginx/optimization.conf; 
    default_type application/octet-stream;
    sendfile on;
    send_timeout 3600;
    tcp_nopush on;
    tcp_nodelay on;
    open_file_cache max=500 inactive=10m;
    open_file_cache_errors on;
    keepalive_timeout 65;
    reset_timedout_connection on;
    server_tokens off;
    resolver 94.16.123.148 valid=30s;
    resolver_timeout 5s;
    include /etc/nginx/conf.d/*.conf;
}
```

**Anmerkung:** Im http-Block sind die 4 includes (proxy.conf, ssl.conf, header.conf und optimization.conf) noch auskommentiert, diese werden erst später eingerichtet und eingesetzt.  
  
Nun testen und starten wir den Server um sicherzugehen, dass bei den Einstellungen nichts schief gelaufen ist.
    
```
nginx -t && service nginx restart
```    

Zuletzt erstellen wir noch die benötigten Ordner für Nextcloud (nc_data) und Let's Encrypt (letsencrypt) und weisen diese der Gruppe www-data zu um Nginx Zugriff zu gewähren.

```
mkdir -p /var/nc_data /var/www/letsencrypt
chown -R www-data:www-data /var/nc_data /var/www
```

#### Installation und Konfigurierung von PHP 7.3 (fpm)

Für Nextcloud sowie phpLDAPadmin brauchen wir PHP, wir nutzen PHP 7.3-fpm (FastCGI-Prozessmanager) um die (zum Zeitpunkt der Erstellung des Servers/der Dokumentation) neuste PHP zu nutzen und die Prozesse durch fpm zu beschleunigen.  

Zur Installation für PHP und der benötigen Module für unsere Zwecke nutzen wir folgenden Befehl:

```
apt update && apt install php7.3-fpm php7.3-gd php7.3-mysql php7.3-curl php7.3-xml php7.3-zip php7.3-intl php7.3-mbstring php7.3-json php7.3-bz2 php7.3-ldap php-apcu imagemagick php-imagick php-smbclient -y
```

**Anmerkung:** Diese Pakete stammen unter anderem aus dem Repository welches wir bei der Einrichtung des Servers hinzugefügt haben. 

Nun schauen wir ob die Zeitzone, die genutzt wird die ist, die wir brauchen. 
```
date
```

Zum setzen der Zeitzone kann dieser Befehl genutzt werden: 
 ```
timedatectl set-timezone Europe/Berlin
```

Als nächsten ändern wir ein paar Einstellungen aus in diversen PHP-Konfigurations-Dateien, diese werden vorher gebackuped.

```
cp /etc/php/7.3/fpm/pool.d/www.conf /etc/php/7.3/fpm/pool.d/www.conf.bak
cp /etc/php/7.3/cli/php.ini /etc/php/7.3/cli/php.ini.bak
cp /etc/php/7.3/fpm/php.ini /etc/php/7.3/fpm/php.ini.bak
cp /etc/php/7.3/fpm/php-fpm.conf /etc/php/7.3/fpm/php-fpm.conf.bak
cp /etc/ImageMagick-6/policy.xml /etc/ImageMagick-6/policy.xml.bak
```

**Anmerkung:** Die folgenden Befehle ändern nur Werte in den Konfigurations-Dateien, diese Änderungen können auch mit einem beliebigen Editor vorgenommen werden. Die Terminaleingaben ersparen in diesem Fall das manuelle Suchen.  


Zuerst beginnen wir mit `/etc/php/7.3/fpm/pool.d/www.conf`, dort werden ein paar Pfade, die auskommentiert sind, wieder aktiviert.

```
sed -i "s/;env\[HOSTNAME\] = /env[HOSTNAME] = /" /etc/php/7.3/fpm/pool.d/www.conf
sed -i "s/;env\[TMP\] = /env[TMP] = /" /etc/php/7.3/fpm/pool.d/www.conf
sed -i "s/;env\[TMPDIR\] = /env[TMPDIR] = /" /etc/php/7.3/fpm/pool.d/www.conf
sed -i "s/;env\[TEMP\] = /env[TEMP] = /" /etc/php/7.3/fpm/pool.d/www.conf
sed -i "s/;env\[PATH\] = /env[PATH] = /" /etc/php/7.3/fpm/pool.d/www.conf
```

Als nächstes ändern wir `/etc/php/7.3/cli/php.ini`, hier werden ein paar Größen wie maximale Dateigröße bei Uploads und maximale Ausführungszeit geändert, da wir auch beabsichtien den Cloud für größere Datein zu nutzen.

```
sed -i "s/output_buffering =.*/output_buffering = 'Off'/" /etc/php/7.3/cli/php.ini
sed -i "s/max_execution_time =.*/max_execution_time = 3600/" /etc/php/7.3/cli/php.ini
sed -i "s/max_input_time =.*/max_input_time = 3600/" /etc/php/7.3/cli/php.ini
sed -i "s/post_max_size =.*/post_max_size = 10240M/" /etc/php/7.3/cli/php.ini
sed -i "s/upload_max_filesize =.*/upload_max_filesize = 10240M/" /etc/php/7.3/cli/php.ini
sed -i "s/;date.timezone.*/date.timezone = Europe\/\Berlin/" /etc/php/7.3/cli/php.ini
```

Diese und weitere Einstellungen werden auch in die Datei `/etc/php/7.3/fpm/php.ini` übernommen. Hier stellen wir zusätzliche Optionen für den fpm ein zur Verbesserung für die Performance.
``` 
sed -i "s/memory_limit = 128M/memory_limit = 512M/" /etc/php/7.3/fpm/php.ini
sed -i "s/output_buffering =.*/output_buffering = 'Off'/" /etc/php/7.3/fpm/php.ini
sed -i "s/max_execution_time =.*/max_execution_time = 3600/" /etc/php/7.3/fpm/php.ini
sed -i "s/max_input_time =.*/max_input_time = 3600/" /etc/php/7.3/fpm/php.ini
sed -i "s/post_max_size =.*/post_max_size = 10240M/" /etc/php/7.3/fpm/php.ini
sed -i "s/upload_max_filesize =.*/upload_max_filesize = 10240M/" /etc/php/7.3/fpm/php.ini
sed -i "s/;date.timezone.*/date.timezone = Europe\/\Berlin/" /etc/php/7.3/fpm/php.ini
sed -i "s/;session.cookie_secure.*/session.cookie_secure = True/" /etc/php/7.3/fpm/php.ini
sed -i "s/;opcache.enable=.*/opcache.enable=1/" /etc/php/7.3/fpm/php.ini
sed -i "s/;opcache.enable_cli=.*/opcache.enable_cli=1/" /etc/php/7.3/fpm/php.ini
sed -i "s/;opcache.memory_consumption=.*/opcache.memory_consumption=128/" /etc/php/7.3/fpm/php.ini
sed -i "s/;opcache.interned_strings_buffer=.*/opcache.interned_strings_buffer=8/" /etc/php/7.3/fpm/php.ini
sed -i "s/;opcache.max_accelerated_files=.*/opcache.max_accelerated_files=10000/" /etc/php/7.3/fpm/php.ini
sed -i "s/;opcache.revalidate_freq=.*/opcache.revalidate_freq=1/" /etc/php/7.3/fpm/php.ini
sed -i "s/;opcache.save_comments=.*/opcache.save_comments=1/" /etc/php/7.3/fpm/php.ini
```

Und letztendlich ändern wir noch die Rechte für PS, EPI, PDF und XPS Dateien in der `/etc/ImageMagick-6/policy.xml`. Das erlaubt und das Verarbeiten dieser Dateien durch PHP.

```
sed -i "s/rights=\"none\" pattern=\"PS\"/rights=\"read|write\" pattern=\"PS\"/" /etc/ImageMagick-6/policy.xml
sed -i "s/rights=\"none\" pattern=\"EPI\"/rights=\"read|write\" pattern=\"EPI\"/" /etc/ImageMagick-6/policy.xml
sed -i "s/rights=\"none\" pattern=\"PDF\"/rights=\"read|write\" pattern=\"PDF\"/" /etc/ImageMagick-6/policy.xml
sed -i "s/rights=\"none\" pattern=\"XPS\"/rights=\"read|write\" pattern=\"XPS\"/" /etc/ImageMagick-6/policy.xml
```

Nun starten wir PHP und Nginx neu um die Einstellungen zu übernehmen.

```
service php7.3-fpm restart
service nginx restart
```

#### Installation und Konfiguration von MariaDB

Als Datenbanksoftware haben wir MariaDB gewählt, da diese neben MySQL von Nextcloud empfohlen wird. 

Zuerst müssen wir die MariaDB-Pakete runterladen und installieren.

```
apt update && apt install mariadb-server -y
```

Um zu sehen ob dies erfolgreich war kann man die mysql-Version prüfen.
```
mysql --version
```

Das sollte eine ähnliche Ausgabe wie die Folgende erzeugen: 
```
mysql  Ver 15.1 Distrib 10.4.8-MariaDB, for debian-linux-gnu (x86_64) using readline 5.2
```

Als nächstes muss die Datenbank gesichert werden, der Prozess wird mit folgendem Befehl gestartet:
``` 
mysql_secure_installation
```

Nun werden diverse Abfragen durchgeführt, dieser werden wie angegeben beantwortet und Testzugänge/-daten zu entfernen, ein root-Passwort feszulegen und einen entfernen Zugriff auf das root-Konto zu unterbinden.

```
Switch to unix_socket authentication [Y/n] N
Enter current password for root (enter for none): <ENTER>
Set root password? [Y/n] Y
Remove anonymous users? [Y/n] Y
Disallow root login remotely? [Y/n] Y
Remove test database and access to it? [Y/n] Y
Reload privilege tables now? [Y/n] Y
```

Als nächstes müssen wir die Konfigurationsdatei ändern, dazu stoppen wir mysql, erstellen wieder ein Backup und öffnen diese in einem Editor.

```
service mysql stop
mv /etc/mysql/my.cnf /etc/mysql/my.cnf.bak
nano /etc/mysql/my.cnf
```

Diese Einstellungen werden wir für die Installation von Nextcloud verwenden: 
``` 
[client]
 default-character-set = utf8mb4
 port = 3306
 socket = /var/run/mysqld/mysqld.sock
[mysqld_safe]
 log_error=/var/log/mysql/mysql_error.log
 nice = 0
 socket = /var/run/mysqld/mysqld.sock
[mysqld]
 basedir = /usr
 bind-address = 127.0.0.1
 binlog_format = ROW
 bulk_insert_buffer_size = 16M
 character-set-server = utf8mb4
 collation-server = utf8mb4_general_ci
 concurrent_insert = 2
 connect_timeout = 5
 datadir = /var/lib/mysql
 default_storage_engine = InnoDB
 expire_logs_days = 10
 general_log_file = /var/log/mysql/mysql.log
 general_log = 0
 innodb_buffer_pool_size = 1024M
 innodb_buffer_pool_instances = 1
 innodb_flush_log_at_trx_commit = 2
 innodb_log_buffer_size = 32M
 innodb_max_dirty_pages_pct = 90
 innodb_file_per_table = 1
 innodb_open_files = 400
 innodb_io_capacity = 4000
 innodb_flush_method = O_DIRECT
 key_buffer_size = 128M
 lc_messages_dir = /usr/share/mysql
 lc_messages = en_US
 log_bin = /var/log/mysql/mariadb-bin
 log_bin_index = /var/log/mysql/mariadb-bin.index
 log_error=/var/log/mysql/mysql_error.log
 log_slow_verbosity = query_plan
 log_warnings = 2
 long_query_time = 1
 max_allowed_packet = 16M
 max_binlog_size = 100M
 max_connections = 200
 max_heap_table_size = 64M
 myisam_recover_options = BACKUP
 myisam_sort_buffer_size = 512M
 port = 3306
 pid-file = /var/run/mysqld/mysqld.pid
 query_cache_limit = 2M
 query_cache_size = 64M
 query_cache_type = 1
 query_cache_min_res_unit = 2k
 read_buffer_size = 2M
 read_rnd_buffer_size = 1M
 skip-external-locking
 skip-name-resolve
 slow_query_log_file = /var/log/mysql/mariadb-slow.log
 slow-query-log = 1
 socket = /var/run/mysqld/mysqld.sock
 sort_buffer_size = 4M
 table_open_cache = 400
 thread_cache_size = 128
 tmp_table_size = 64M
 tmpdir = /tmp
 transaction_isolation = READ-COMMITTED
 user = mysql
 wait_timeout = 600
[mysqldump]
 max_allowed_packet = 16M
 quick
 quote-names
[isamchk]
 key_buffer = 16M 
```

Wichtig in diesem Fall sind unter anderem `transaction_isolation = READ-COMMITTED` (normalerweise default-Einstellung für Transaktionen) und unser gewünschtes Encoding ` default-character-set = utf8mb4`

Nun starten wir MariaDB neu und verbinden uns.

``` 
service mysql restart
mysql -uroot -p
```

Nach Eingabe des Passworts erstellen wir die Datenbank, die Nextcloud benötigt.
```
CREATE DATABASE nextcloud CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci; CREATE USER nextcloud@localhost identified by '<Passwort>'; GRANT ALL PRIVILEGES on nextcloud.* to nextcloud@localhost; FLUSH privileges; quit;
```

`<Passwort>` muss in diesem Fall durch ein gültiges Passwort ersetzt werden.  

Danach prüfen wir ob das Transaktionslevel und Kollation richtig gesetzt sind.
``` 
mysql -h localhost -uroot -p -e "SELECT @@TX_ISOLATION; SELECT SCHEMA_NAME 'database', default_character_set_name 'charset', DEFAULT_COLLATION_NAME 'collation' FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='nextcloud'"
```

Die gewünschten Ergebnisse sind `READ-COMMITTED` und `utf8mb4_general_ci`.

#### Installation und Konfiguration von Redis

Wir nutzen Redis um die Performance von Nextcloud zu verbessern und die Belastung der Datenbank zu minimieren. Diese Schritt ist rein optional.

Zum Beginn muss Redis installiert werden.

```
apt update
apt install redis-server php-redis -y
```

Als nächstes passen wir die Konfiguration an und erteilen Redis die benötigten Gruppenrechte. Hier wird ebenfalls ein Backup der Konfigurations-Datei erstellt.
```
cp /etc/redis/redis.conf /etc/redis/redis.conf.bak
sed -i "s/port 6379/port 0/" /etc/redis/redis.conf
sed -i s/\#\ unixsocket/\unixsocket/g /etc/redis/redis.conf
sed -i "s/unixsocketperm 700/unixsocketperm 770/" /etc/redis/redis.conf
sed -i "s/# maxclients 10000/maxclients 512/" /etc/redis/redis.conf
usermod -aG redis www-data
```

Zum Schluss setzen wir `overcommit_memory ` auf 1 um bei einem fork nicht den kompletten Datenbestand zu kopieren. 
```
cp /etc/sysctl.conf /etc/sysctl.conf.bak
sed -i '$avm.overcommit_memory = 1' /etc/sysctl.conf
```

Nun muss der Server einmal mit `reboot now` neugestartet werden.

   
### phpldapadmin

Für das Webinterface wurde eine weiter Subdomain (wldap.hartlab.de) auf die IPs des Cloud Servers gebunden, damit die Konfiguration über NGINX leichter fällt und die Zugriffe nicht auf NextCloud ausgeführt werden.

#### Installation von phpLDAPadmin

Das Repository im Ubuntu/Debian Paketmanager kann nicht genutzt werden, da dieses noch aus dem Jahr 2013 stammt und Probleme mit PHP 7.* hat.

Um die aktuellste Version (von 2019) zu nutzen, kopiert man sich das git Verzeichnis mit `sudo git clone https://github.com/leenooks/phpLDAPadmin.git`.
Im Folgenden wird das Verzeichnis mit `sudo mv phpLDAPadmin /var/www/ldapadmin` verschoben. So liegen NextCloud und phpLDAPadmin an derselben Stelle und ein Suchen der Anwendung ist nicht nötig.

Jetzt muss die Konfiguration von phpLDAPadmin angepasst werden.
1. `cd /var/www/ldapadmin/config`  - Wechselt ins Verzeichnis und erleichtert die nächsten Schritte
2. `sudo cp config.php.exaple config.php` - Kopiert die Konfigurationsvorlage, die alte wird nicht gelöscht, falls diese nochmal benötigt wird
3. `nano config.php` - Konfiguration anpassen
	* `$config->custom->appearance['language'] = 'english';` - Setzt die Sprache auf Englisch
	* `$config->custom->appearance['timezone'] = 'Europe/Berlin';` - Setzt die Zeitzone der Anwendung auf Berlin, sodass diese mit der Uhrzeit von php und dem host-System übereinstimmt
	* `$config->custom->appearance['hide_template_warning'] = true;` - Schaltet Fehlermeldung von phpLDAPadmin Tempaltes aus, da diese keine Relevanz haben
	* `$servers->setValue('server','name','Hartlab LDAP Server');` - Stellt den Namen ein, welcher im Webinterface gezeigtg wird
	* `$servers->setValue('server','host','ldap.hartlab.de');` - Setzt den Host auf den das Interface zugreifen soll
	* `$servers->setValue('server','base',array('dc=hartlab,dc=de'));` - Setzt die BASE DN
	* `$servers->setValue('login','bind_id','');` - Leer lassen und auskommentieren, da sonst im Interface der Nutzername vorausgefüllt ist.
	* `$servers->setValue('login','bind_pass','')` - Leer lassen und auskommentieren, da keine Funktionalität gewonnen wird und nur das Passwort im Klartext in einer Datei steht.
	* `$servers->setValue('server','tls',true);` - TLS aktivieren, damit Interface und LDAP Server verschlüsselt kommunizieren könne. Der LDAP Server lehnt alle nicht TLS Verbindungen ab

#### NGINX & phpLDAPadmin

Im Folgenden muss eine NGINX Konfig angelegt werden, damit die Subdomain wldap.hartlab.de auf die phpLDAPadmin Anwendung zeigt.

Dazu legen wir eine neue config Datei im `conf.d` Ordner mit `sudo nano /etc/nginx/conf.d/ldapadmin.conf` an. Folgender Inhalt sollte übernommen werden.
```
server {
	server_name wldap.hartlab.de;
	listen 80;
	listen [::]:80;

	location ^~ /.well-known/acme-challenge {
		proxy_pass http://127.0.0.1:83;
		proxy_set_header Host $host;
	}
	
	location / {
		return 301 https://$host$request_uri;
	}
}


server {
	server_name wldap.hartlab.de;
	listen 443 ssl http2;
	listen [::]:443 ssl;

	location = /robots.txt {
		allow all;
		log_not_found off;
		access_log off;
	}
	
	client_max_body_size 10240M;
	
	root /var/www/ldapadmin/;
	index index.php index.html index.htm;

    # default php handler
    location ~ \.php$ {
            fastcgi_pass unix:/run/php/php7.3-fpm.sock;
            fastcgi_index index.php;
            fastcgi_param SCRIPT_FILENAME  $document_root/$fastcgi_script_name;
            include fastcgi_params;
            fastcgi_param HTTPS on;
    }

}
```

Es erfolgt ein rewrite aller Anfragen auf HTTPS. Mit der Ausnahme, dass die für Let's Encrypt benötigten Anfragen, weiterhin nur über HTTP bearbeitet werden und in den richtigen Ordner weiterleiten. Alle PHP Dateien werden mithilfe von PHP-FPM ausgeführt.

Nach diesen Einstellungen muss der NGINX Server mit `sudo systemctl restart nginx` neugestartet werden.

## LDAP Server

### ufw Firewall

Als Erstes wurde die ufw Firewall aktiviert um eingehende Verbindungen abzulehnen, um die Angriffsvektoren zu minimieren. Damit ein SSH Zugriff weiter möglich ist, wurde eine Regel für OpenSSH erstellt.
1. `sudo ufw default deny incoming` - Aller eingehender Traffic wird geblockt.
2. `sudo ufw allow OpenSSH` - Setzt die Regeln für IPv4 und IPv6
3. `sudo ufw enable` - Schaltet die Firewall aktiv

### Installation von LDAP / OpenLDAP

Installation von slapd - Stand-alone LDAP Daemon.

1. `sudo apt update` - Packet Index aktuallisieren
2. `sudo apt install slapd ldap-utils` - Installation von LDAP
3. `sudo dpkg-reconfigure slapd` - Rekonfiguration von slapd Packet
	* DNS Domain Name: hartlab.de
	* Organisationsname: hartlab
	* Administrator Passwort: Sichers Passwort vergeben
	* Database backend: MDB, da empfohlen
	* Datenbank beim löschen entfernen: Nein, damit DB auch nach nem reinstall bestehen bleibt
	* Alte Datenbank verschieben: Ja, damit keine Konfigurationsprobleme auftreten
4. Installation mit `ldapwhoami -H ldap:// -x` prüfen

Im folgenden muss der LDAP Traffic des Cloud Servers erlaubt werden, damit dieser eine LDAP Anbindug einrichten und nutzen kann.
1. `sudo ufw allow from 2a03:4000:21:848::1 to any port ldap` - LDAP über IPv6 (IPv6 Adresse des Cloud Servers)
2. `sudo ufw allow from 94.16.123.148 to any port ldap` - LDAP über IPv4 (IPv4 Adresse des Cloud Servers)
3. `sudo ufw status` - Firewall Einstellungen prüfen

### Zertifikat von Let's Encrypt

Ein Let's Encrypt Zertifikat wird genutzt, um die Verbindungen zum LDAP Server zu verschlüsseln.

Das Zertifikat wird von Let's Encrypt bezogen, da es dort kostenfrei ist, jedoch ist es hier nur für 90 Tage 
gültig und muss im besten Fall 30 Tage vorher neu bezogen werden.

Für die Generierung / Erstellung des Zertifikats wird der von Let's Encrypt empfohlene CertBot genutzt.
1. `sudo ufw allow 80` - Port 80 in der Firewall freigegeben, damit Let's Encrypt mit diesem Server kommunizieren kann.
2. `sudo apt update`
3. `sudo apt install certbot` - Certbot installieren
4. `sudo certbot certonly --standalone` - Nur Zertifikat beziehen und keine Konfiguration vornehmen
5. `sudo ls  /etc/letsencrypt/live` - Prüfen ob Zertifikat vorhanden ist
6. `sudo ufw delete allow 80` - Port 80 in der Firewall wieder auf default setzen, in diesem Fall auf deny

Zertifikate in Standard SSL Verzeichnis von Linux kopieren, damit der slapd Deamon Zugang erhält.
1. `sudo cp /etc/letsencrypt/live/ldap.hartlab.de/cert.pem /etc/ssl/certs/ldap.hartlab.de.cert.pem`
2. `sudo cp /etc/letsencrypt/live/ldap.hartlab.de/fullchain.pem /etc/ssl/certs/ldap.hartlab.de.fullchain.pem`
3. `sudo cp /etc/letsencrypt/live/ldap.hartlab.de/privkey.pem /etc/ssl/private/ldap.hartlab.de.privkey.pem`

Berechtigungen setzen, damit der slapd Deamon benötigte Berechtigung erhält, da die Let's Encrypt Zertifikate nur von Root 
gelesen werden können.
1. `sudo apt install ssl-cert` - Nur notwendig, wenn es sich um ein minimale Installation von Linux handelt, da sonst die 
ssl-cert Gruppe nicht gibt
2. `sudo chown :ssl-cert /etc/ssl/private/ldap.hartlab.de.privkey.pem` - Gruppe ssl-cert der Datei hinzufügen
3. `sudo chmopd 640 /etc/ssl/private/ldap.hartlab.de.privkey.pem` - Berechtigungen der Datei setzen, damit die System ssl-cert 
Gruppe die Datei lesen kann
4. `sudo usermod -aG ssl-cert openldap` - Nutzer openldap der Gruppe ssl-cert hinzufügen, damit das Zertifikat gelesen werden 
kann
5. `sudo systemctl restart slapd` - slapd Neustarten, damit die Zertifikate geladen werden

### slapd mit Zertifikat konfigurieren 

Erstellen einer LDIF - LDAP Data Interchange Format - Datei um die Konfiguration zu ändern, damit slapd die Zertifikate auch 
nutzt
1. Erstellen der Datei `cd ~` und `nano ssl.ldif` mit dem Inhalt:  
```
dn: cn=config
changetype: modify
add: olcTLSCACertificateFile
olcTLSCACertificateFile: /etc/ssl/certs/ldap.hartlab.de.fullchain.pem
-
add: olcTLSCertificateFile
olcTLSCertificateFile: /etc/ssl/certs/ldap.hartlab.de.cert.pem
-
add: olcTLSCertificateKeyFile
olcTLSCertificateKeyFile: /etc/ssl/private/ldap.hartlab.de.privkey.pem
```
2. Datei speichern und schließen
3. Änderungen mit `sudo ldapmodify -H ldapi:// -Y EXTERNAL -f ssl.ldif` anwenden, ein reload des slapd Deamons ist nicht 
notwendig, da ldapmodify dieses sleber macht
4. Mit `ldapwhoami -H ldap://ldap.hartlab.de -x -ZZ` die Konfiguration prüfen, der Hostname ist notwendig, da das Zertifikat 
abgeprüft wird.

STARTTLS erzwingen, damit keine unverschlüsselten Verbindungen möglich sind
1. Änderung der Hosts Datei, damit der FQDN richtig gesetzt ist mit `sudo nano /etc/hosts`
2. Die Zeile `127.0.1.1` finden und durch `127.0.1.1 ldap.hartlab.de ldap` erstezen, so ist der FQDN richtig gesetzt
3. Herausfinden, welcher Eintrag verändert werden soll `sudo ldapsearch -H ldapi:// -Y EXTERNAL -b "cn=config" -LLL -Q "(olcSuffix=*)" dn olcSuffix`
4. Ausgabe sollte folgendermaßen aussehen:
```
dn: olcDatabase={1}mdb,cn=config
olcSuffix: dc=hartlab,dc=de
```
5. Erstellen einer LDIF Datei um Änderungen vorzubereiten `nano ~/tls.ldif` und dem Inhalt:
```
dn: olcDatabase={1}mdb,cn=config
changetype: modify
add: olcSecurity
olcSecurity: tls=1
```
6. Änderungen laden mit `sudo ldapmodify -H ldapi:// -Y EXTERNAL -f tls.ldif`
7. Prüfen, ob nur noch eine Verbindung mit SSL möglich ist
	* `ldapsearch -H ldap:// -x -b "dc=example,dc=com" -LLL dn`, sollte mit der Fehlermeldung `TLS confidentiality 
required` scheitern
	* `ldapsearch -H ldap:// -x -b "dc=example,dc=com" -LLL -Z dn`, sollte ohne Fehlermeldung funktionieren
