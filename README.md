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
	* `$config->custom->appearance['hide_template_warning'] = true;` - Schaltet Fehlermeldung von phpLDAPadmin Tempaltes aus, da diese keine relevanz haben
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
