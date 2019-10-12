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

Im folgenden muss der Traffic des Cloud Servers erlaubt werden, damit dieser eine LDAP Anbindug einrichten und nutzen kann.
