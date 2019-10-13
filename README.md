# NextCloud mit LDAP ínkl. WEBGUI

von Robert Hartings und Alexander Niersmann


# Server

Server werden von NetCup bezogen. Ein Server wird für LDAP, der andere Server wird für NextCloud und phpldap genutzt. Diese machen wir, damit LDAP und die anderen Systeme nicht auf einer Maschiene laufen um so eine wirkliche LDAP Nutzung zu simulieren.

## Serverhardware

| Hardware | Value |
|---|---|
| CPU | 1vCore |
| RAM | 2 GB |
| DISK | 20 GB SSD (RAID 10) |
| Network Speed | 1000 MBit/s |

# Serverkonfiguration

Neuste Updates wurden installiert:

1. `apt update`
2. `apt upgrade -y`

Alte unbenötigte Dateien entfernen:
1. `apt autoremove -y`

Nutzer mit sudo Rechten anlegen, damit der Root Account nicht mehr genutzt werden muss:
1. `adduser USERNAME`
2. `adduser USERNAME sudo`

Die Nutzer erhalten ein sichers Passwort, ein SSH-Key wäre die sichere Varainte wird auf Grund der nicht vorhanden Kritikalität jedoch nicht verwendet. Es empfiehlt sich einen SSH-Key zu nutzen.

Das Root Passwort wird geändert, damit ein mögliches mitlesen des E-Mail Verkehrs zwischen Hoster und Mieter nicht zu einer Kompromittierung des Servers führt.
1. `passwd`

Der Root Nutzer erhält ein sichers Passwort. Im folgenden werden nur noch die User Accounts mit sudo-Berechtigung genutzt.

In der SSH-Config den Login von Root unterbinden, umso einen mögliches Brutforcen des Root Passworts zu verhindern:
1. `sudo nano /etc/ssh/sshd_config`
2. Zeile `PermitRootLogin` von `yes` auf `no` ändern, damit ein Login via SSH auf Root nicht mehr möglich ist.
3. Falls alle Nutzer ssh-Keys hinterlegt haben, kann `PasswordAuthentication` von `yes` auf `no` gesetzt werden, da jedoch nur Passwort genutzt worden ist bleibt der Wert auf `yes`
4. SSH (Deamon) neustarten mit `sudo systemctl restart ssh`, damit die Änderungen übernommen werden.

Beide Server erhalten einen Hostname zur leichteren Identifizierung. Der Nextcloud Server erhält den Hostname `cloud` und der LDAP Server den Hostname `ldap`.
1. Hostname setzen durch `sudo hostnamectl set-hostname HOSTNAME`

Um auch IPv6 zu nutzen müssen Einstellungen im Network Interface gemacht werden. IPv6 wird vorrausschauend aktiviert, es könnte gebraucht werden.
1. `sudo nano /etc/netplan/01-netcfg.yaml`
2. IPv4 und IPv6 Konfigurationen werden statisch an einen Adapter vergeben. DHCP wird nicht weiter genutzt.
3. Änderungen werden mit `sudo netplan apply` angewendet.

Für IPv4 und IPv6 wurde für beide Server ein rDNS gesetzt. Für den NextCloud Server wurde die Domain cloud.hartlab.de und den LDAP Server die Domain ldap.hartlab.de genutzt und auch in die Domain Einstellungen übernommen. So müssen wir uns die IP Adressen für SSH 
und Weboberfläche nicht merken, desweitern ist so nur ein Zertifikat von Let'sEncrypt erhältlich. 

## Cloud Server - NextCloud & phpldap

## LDAP Server

Als erstes wurde die ufw Firewall aktiviert um eingehende Verbindungen abzulehen, um die Angriffsvektoren zu minimieren. Damit ein SSH Zugriff weiter möglich ist wurde eine Regel für OpenSSH erstellt.
1. `sudo ufw default deny incoming` - Aller eingehender Traffic wird geblockt.
2. `sudo ufw allow OpenSSH` - Setzt die Regeln für IPv4 und IPv6
3. `sudo ufw enable` - Schaltet die Firewall aktiv

Installation von LDAP / OpenLDAP
1. `sudo apt update` - Packet Index aktuallisieren
2. `sudo apt install slapd ldap-utils` - Installation von LDAP
3. `sudo dpkg-reconfigure slapd` - Rekonfiguration von slapd Packet
	3.1 DNS Domain Name: hartlab.de
	3.2 Organisationsname: hartlab
	3.3 Administrator Passwort: Sichers Passwort vergeben
	3.4 Database backend: MDB, da empfohlen
	3.5 Datenbank beim löschen entfernen: Nein, damit DB auch nach nem reinstall bestehen bleibt
	3.6 Alte Datenbank verschieben: Ja, damit keine Konfigurationsprobleme auftreten
4. Installation mit `ldapwhoami -H ldap:// -x` prüfen

Im folgenden muss der LDAP Traffic des Cloud Servers erlaubt werden, damit dieser eine LDAP Anbindug einrichten und nutzen kann.
1. `sudo ufw allow from 2a03:4000:21:848::1 to any port ldap` - LDAP über IPv6
2. `sudo ufw allow from 94.16.123.148 to any port ldap` - LDAP über IPv4
3. `sudo ufw status` - Firewall Einstellungen prüfen

Zertifikat von Let's Encrypt

Das Let's Encrypt Zertifikat wird genutzt um die Verbindungen zum LDAP Server zu verschlüsseln.

Das Zertifikat wird von Let's Encrypt bezogen, da es dort kostenfrei ist. Das Zertifikat ist hierbei jedoch nur für 90 Tage 
gültig und muss im besten Fall 30 Tage vorher neubezogen werden.

Für die Generierung / Erstellung des Zertifikats wird der von Let's Encrypt empfohlene CertBot genutzt.
1. `sudo ufw allow 80` - Port 80 in der Firewall freigegeben, damit Let's Encrypt mit diesem Server kommunizieren kann.
2. `sudo apt update`
3. `sudo apt install certbot` - Certbot installieren
4. `sudo certbot certonly --standalone` - Nur Zertifiakt beziehen und keine Konfiguration vornehmen
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
5. `sudo systemctl restart slapd` - slapd neustarten, damit die Zertifikate geladen werden
