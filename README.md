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

Beide Server erhalten einen Hostname zur leichteren Identifizierung. Der Nextcloud Server erhält den Hostname `wpp` und der LDAP Server den Hostname `ldap`.
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

Nun updaten wir noch einmal den Server.

```
apt update && apt upgrade -y
```

Zum Abschluss der Vorbereitung werden alte Instanzen, falls vorhanden, von Nginx entfernt. Das machen wir um sicherzugehen, dass keine Anwendung auf Port 80 läuft. 

```
apt remove nginx nginx-extras nginx-common nginx-full -y --allow-change-held-packages
```

#### Installation und Konfigurierung von Apache2

Als Webserver benutzen wir für diese Serverkonfiguration Apache2. Dieser wird im späteren Verlauf auch zur Installation von phpLDAPadmin genutzt.  
  
```
apt install apache2 php7.2 php7.2-gd php7.2-json php7.2-mysql php7.2-curl php7.2-mbstring php7.2-intl php7.2-imagick php7.2-xml php7.2-zip libapache2-mod-php7.2 -y
systemctl enable apache2.service
```

Nun werden die Einstellungen von Apache für unsere Bedürfnisse angepasst. Dazu fügen wir Dateien für Nextcloud und phpLDAPAdmin hinzu.

```
touch /etc/apache2/sites-available/nextcloud.conf && touch /etc/apache2/sites-available/ldapapdmin.conf
nano /etc/apache2/sites-available/nextcloud.conf
```

Folgende Einstellungen werden für die Nextcloud übernommen:

```
#nextcloud.conf
<VirtualHost *:80>
ServerName wpp.hartlab.de

DocumentRoot /var/www

<Directory /var/www/nextcloud/>
  Options +FollowSymlinks
  AllowOverride All

 <IfModule mod_dav.c>
  Dav off
 </IfModule>

 SetEnv HOME /var/www/nextcloud
 SetEnv HTTP_HOME /var/www/nextcloud

</Directory>
RewriteEngine on
RewriteCond %{SERVER_NAME} =wpp.hartlab.de
RewriteRule ^ https://%{SERVER_NAME}%{REQUEST_URI} [END,NE,R=permanent]
</VirtualHost>
```

Und folgende für ldapadmin:

```
nano /etc/apache2/sites-available/ldapadmin.conf
```

```
Alias /ldapadmin "/var/www/ldapadmin/htdocs"
<Directory /var/www/ldapadmin/htdocs>
  Options +FollowSymlinks
  AllowOverride All
</Directory>
```

Im Grunde werden hier nur den lokalen Ordnern Adressen zugewiesen und im Falle von Nextcloud auch Weiterleitungen eingerichtet, damit alle Anfragen die sich auf Nextcloud beziehen an die Index Datei weitergeleitet werden.


### phpldapadmin

#### Vorraussetzungen für phpLDAPadmin

Zuerst müssen folgende PHP Module installiert werden, sofern diese noch nicht auf dem System vorhanden sind
1. `sudo apt install php7.2-ldap`
2. `sudo apt install php7.2-readline`
3. `sudo apt install php7.2-xml`

Desweiteren wird wegen der Zertifikate und der TLS Verschlüssel die folgenden Pakete installiert.
* `sudo apt install gnutls-bin ssl-cert`

Danach wird das Zertifikat der Zertifizierungsstelle (sihe LDAP Server - Übertragung des Zertifikates an den Cloud Servers) fertig einsatzbereit gemacht.
1. `sudo chown root:root cacert.pem` - Das Zertifikat soll root und nicht dem User gehören
2. `sudo mv cacert.pem /etc/ssl/certs` - Danach wird das Zertifikat in den Standard Linux Ordner verschoben.

Jetzt muss nur noch die `ldap.conf` angepasst werden.
1. `sudo nano /etc/ldap/ldap.conf` - LDAP Konfiguration anpassen
2. `TLS_CACERT /etc/ssl/certs/cacert.pem` -Pfad des Zertifikates angeben, damit LDAP weiß auf welches Zertifikat zugegriffen werden soll
3. `TLS_REQCERT demand` - Es soll nur eine Verbindung mit gültigem Zertifikat möglich sein, der Rest soll abgebrochen werden.

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

#### APACHE & phpLDAPadmin

PLS FIX IT NOW

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

### Zertifikat für TLS

Ein selbstsigniertes Zertifikat wird genutzt, um die Verbindungen zum LDAP Server zu verschlüsseln.

Dazu müssen die Pakete `gnutls-bin` und `ssl-cert` installiert werden.
* `sudo apt install gnutls-bin ssl-cert`

Als nächstest wird der private key für die Zertifizierungsstelle erstellet.
* `sh -c "certtool --generate-privkey > /etc/ssl/private/cakey.pem"`
    1. `--generate-privkey` - Certtool erstellt einen privaten Schlüssel

Danach wird ein Vorlage erstellt, um die Zertifizierungsstelle zu definieren. Dieses wird mit `sudo nano /etc/ssl/ca.info` gemacht und mit dem Inhalt befüllt:
```
cn = hartlab
ca
cert_signing_key
```

Nach dem diese Vorbereitungen abgeschlossen sind, kann nun ein selbstsigniertes Zertifikat erstellt werden.
* `certtool --generate-self-signed --load-privkey /etc/ssl/private/cakey.pem --template /etc/ssl/ca.info --outfile /etc/ssl/certs/cacert.pem`
    1. `--generate-self-signed` - Generiere eine selbstsigniertes Zertifikat
    2. `--load-privkey` - Gibt den privaten Key an, welcher genutzt werden soll
    3. `--template` - Definiert das Template
    4. `--outfile` - Gibt den Ausgabeort an

Erstelle einen privaten Schlüssel für den Server
* `certtool --generate-privkey --bits 2048 --outfile /etc/ssl/private/ldap_slapd_key.pem`
    1. `--generate-privkey` - Certtool erstellt einen privaten Schlüssel
    2. `--bits` - Gibt die Numer an bits für die Schlüsselerstellung an
    3. `--outfile` - Gibt den Ausgabeort an

Danach wird ein weiters Template für das Server Zertifikat erstellt. Dazu wird die Datei `/etc/ssl/ldap.info` angelegt und folgender Inhalt wird eingefügt.
```
organization = hartlab
cn = ldap.hartlab.de
tls_www_server
encryption_key
signing_key
expiration_days = 3650
```

Die angelegte Vorlage wird genutzt um das Server Zertifikat zu erstellen
* `certtool --generate-certificate --load-privkey /etc/ssl/private/ldap_slapd_key.pem --load-ca-certificate /etc/ssl/certs/cacert.pem --load-ca-privkey /etc/ssl/private/cakey.pem --template /etc/ssl/ldap.info --outfile /etc/ssl/certs/ldap_slapd_cert.pem`

Berechtigungen setzen, damit der slapd Deamon benötigte Berechtigung erhält.
2. `sudo chown :ssl-cert /etc/ssl/private/ldap_slapd_key.pem` - Gruppe ssl-cert der Datei hinzufügen
3. `sudo chmopd 640 /etc/ssl/private/ldap_slapd_key.pem` - Berechtigungen der Datei setzen, damit die System ssl-cert 
Gruppe die Datei lesen kann
4. `sudo usermod -aG ssl-cert openldap` - Nutzer openldap der Gruppe ssl-cert hinzufügen, damit das Zertifikat gelesen werden 
kann
5. `sudo systemctl restart slapd` - slapd Neustarten, damit die Zertifikate geladen werden können

### slapd mit Zertifikat konfigurieren 

Erstellen einer LDIF - LDAP Data Interchange Format - Datei um die Konfiguration zu ändern, damit slapd die Zertifikate auch 
nutzt
1. Erstellen der Datei `cd ~` und `nano certinfo.ldif` mit dem Inhalt:
```
dn: cn=config
changetype: modify
add: olcTLSCACertificateFile
olcTLSCACertificateFile: /etc/ssl/certs/cacert.pem
-
add: olcTLSCertificateFile
olcTLSCertificateFile: /etc/ssl/certs/ldap_slapd_cert.pem
-
add: olcTLSCertificateKeyFile
olcTLSCertificateKeyFile: /etc/ssl/private/ldap_slapd_key.pem

```
2. Datei speichern und schließen
3. Änderungen mit `sudo ldapmodify -H ldapi:// -Y EXTERNAL -f certinfo.ldif` anwenden, ein reload des slapd Deamons ist nicht 
notwendig, da ldapmodify dieses sleber macht
4. Mit `ldapwhoami -H ldap://ldap.hartlab.de -x -ZZ` die Konfiguration prüfen, der Hostname ist notwendig, da das Zertifikat 
abgeprüft wird.

### STARTTLS erzwingen

STARTTLS erzwingen, damit keine unverschlüsselten Verbindungen möglich sind
1. Änderung der Hosts Datei, damit der FQDN richtig gesetzt ist mit `sudo nano /etc/hosts`
2. Die Zeile `127.0.1.1` finden und durch `127.0.1.1 ldap.hartlab.de ldap` erstezen, so ist der FQDN richtig gesetzt
3. Herausfinden, welcher Eintrag verändert werden soll `sudo ldapsearch -H ldapi:// -Y EXTERNAL -b "cn=config" -LLL -Q "(olcSuffix=*)" dn olcSuffix`
4. Ausgabe sollte folgendermaßen aussehen:
```
dn: olcDatabase={1}mdb,cn=config
olcSuffix: dc=hartlab,dc=de
```
5. Erstellen einer LDIF Datei um Änderungen vorzubereiten `nano ~/enforceTLS.ldif` und dem Inhalt:
```
dn: olcDatabase={1}mdb,cn=config
changetype: modify
add: olcSecurity
olcSecurity: tls=1
```
6. Änderungen laden mit `sudo ldapmodify -H ldapi:// -Y EXTERNAL -f enforceTLS.ldif`
7. Prüfen, ob nur noch eine Verbindung mit SSL möglich ist
	* `ldapsearch -H ldap:// -x -b "dc=example,dc=com" -LLL dn`, sollte mit der Fehlermeldung `TLS confidentiality 
required` scheitern
	* `ldapsearch -H ldap:// -x -b "dc=example,dc=com" -LLL -Z dn`, sollte ohne Fehlermeldung funktionieren

### Änderungen an LDAP Konfig

Bearbeiten der `ldap.conf`, damit das vorher erstellte Zertifikat genutzt wird.
* `sudo nano /etc/ldap/ldap.conf`
    1. Eintrag `TLS_CACERT /etc/ssl/certs/cacert.pem` anlegen.

Anschließend wird der LDAP Deamon mit `sudo systemctl restart slapd` neugestart.

### Übertragung des Zertifikates an den Cloud Servers

Damit der Cloud Server dem Zertifikat der Zertifizierungsstelle traut, wird dieses auf den Cloud Server kopiert.
* `sudo scp /etc/ssl/certs/cacert.pem USERNAME@cloud.hartlab.de:~USERNAME/`

### Konfigurationsanpassungen

#### Erstellen eines Admin-Accounts für die slapd-Datenbank

Da standardmäßig kein Adminstrationsaccount für die slapd-Konfig Datenbank angelegt wird, erstellen wir diesen.
1. Erstellen eines ssha verschlüsselten Passworts: `slappasswd -h {ssha} >> config.ldif` und Ablage diese in der `config.ldif` Datei.
2. Ausfüllen der LDIF Datei mit den notwendigen Konfigurationsänderungen `nano config.ldif`

```
dn: cn=config
changetype: modify

dn: olcDatabase={0}config,cn=config
changetype: modify
add: olcRootDN
olcRootDN: cn=admin,cn=config

dn: olcDatabase={0}config,cn=config
changetype: modify
add: olcRootPW
olcRootPW: {SSHA}HASH_MEINES_PASSWORTS
```
3. `dn: olcDatabase={0}config,cn=config` bedeutet, dass die Änderungen in der Konfig Datenbank gemacht werden sollen
4. Zuerst wird ein Admin Account angelegt und dann wird dessen Passwort geändert
5. Änderungen auf dem LDAP-Server durchführen mit `sudo ldapadd -Y EXTERNAL  -h ldapi:/// -f config.ldif`
6. Testen der Änderungen mit `ldapsearch -W -LLL -D cn=admin,cn=config -b cn=config dn`

#### Konfiguration von Overlays

Overlays sind Software Komponenten, welche Funktionen bereitstellen. Diese sitzen zwischen Front- und Backend.

##### Passwort Policy Overlay

Als erstes muss das ppolicy Schema geladen werden, da sonst kein Passwort Policy eingestellt werden können
* ``ldapadd -W -D "cn=admin,cn=config" -f /etc/ldap/schema/ppolicy.ldif`

Danach muss das Passwort Policy Modul geladen werden, dazu erstellen wir die `ppolicymodule.ldif` Datei
```
dn: cn=module{0},cn=config
changetype: modify
add: olcModuleLoad
olcModuleLoad: ppolicy.la
```
und laden diese mit `ldapmodify -W -D "cn=admin,cn=config" -f ppolicymodule.ldif`

Im Folgenden erstellen wir uns erstes Passwort Policy Overlay `ppolicyoverlay.ldif`
```
dn: olcOverlay=ppolicy,olcDatabase={1}mdb,cn=config
objectClass: olcOverlayConfig
objectClass: olcPPolicyConfig
olcOverlay: ppolicy
olcPPolicyDefault: cn=userPasswordPolicy,ou=pwpolicies,dc=hartlab,dc=de
olcPPolicyHashCleartext: TRUE
olcPPolicyUseLockout: FALSE
olcPPolicyForwardUpdates: FALSE
```
* `olcPPolicyDefault` - Gibt den default dn für die Passwort Policy an
* `olcPPolicyHashCleartext` - Setzt fest, ob Klartext Passwörter mit dem standardmäßigen Hash-Algorithmus verschlüsselt werden soll
* `olcPPolicyUseLockout` - Setzt fest, ob AccountLocked als Fehler zurück gegeben werden soll, aus diesem können Hacker rückschlüsse ziehen
* `olcPPolicyForwardUpdates` - Nur für slave Konfiguration

Nun muss nur noch die Konfiguration geladen werden: `ldapadd -W -D cn=admin,cn=config -f ppolicyoverlay.ldif`

##### memberOf Overlay

Um in Queries leichter herauszufinden, welcher Nutzer in einer bestimmten Gruppe ist und weil NextCloud dieses Modul braucht, brauchen wir das memberOf Modul. 

Zuerst muss das Modul aktiviert werden, dazu legen wir uns die `memberOfmodule.ldif` Datei mit dem folgenden Inhalt
```
dn: cn=module{0},cn=config
changetype: modify
add: olcModuleLoad
olcModuleLoad: memberof.la
```
an und laden die Änderungen mit `ldapadd -W -D cn=admin,cn=config -f memberOfmodule.ldif`.

Im nächsten Schritt konfigurieren und aktivieren wir das Overlay. Dazu legen wir die Datei `memberOfconfig.ldif` an.
```
dn: olcOverlay=memberof,olcDatabase={1}mdb,cn=config
changetype: add
objectClass: olcConfig
objectClass: olcMemberOf
objectClass: olcOverlayConfig
objectClass: top
olcOverlay: memberof
olcMemberOfDangling: ignore
olcMemberOfRefInt: TRUE
olcMemberOfGroupOC: groupOfNames
olcMemberOfMemberAD: member
olcMemberOfMemberOfAD: memberOf
```

Danach wird das Overlay auf dem LDAP Server erstellt.
* `ldapadd -W -D cn=admin,cn=config -f memberOfconfig.ldif`

Damit die Integrität der Referenzen, bei Nutzeränderungen, bestehen bleibt muss ein weiters Overlay aktiviert werden.
1. `sudo nano refintmod.ldif`
```
dn: cn=module{0},cn=config
add: olcmoduleload
olcmoduleload: refint
```
2. `ldapmodify -W -D cn=admin,cn=config -f refintmod.ldif`
3.  `sudo nano refintconfig.ldif`
```
dn: olcOverlay=refint,olcDatabase={1}mdb,cn=config
objectClass: olcConfig
objectClass: olcOverlayConfig
objectClass: olcRefintConfig
objectClass: top
olcOverlay: refint
olcRefintAttribute: memberof member manager owner
```
4. `ldapadd -W -D cn=admin,cn=config -f refintconfig.ldif`
