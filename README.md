# PAM-Modul für die Online-Ausweisfunktion des Personalausweises

## Installation unter macOS

1. Download des Installers für macOS (Dateiendung `.pkg`)
2. Öffnen Sie die Datei und bestätigen Sie die Installation

## Installation unter Linux

1. Download des Quelltext-Pakets (Dateiendung `.tar.gz`)
2. Entpacken, Konfigurieren, Kompilieren und Installieren:
```
tar xzf eid-pam*.tar.gz
cd eid-pam*
./configure
make
sudo make install
```
Optionen können mit `./configure --help` angezeigt werden.

## Konfiguration

1. Benutzen Sie die AusweisApp2 oder einen anderen eID-Client, um initial Ihre PIN zu setzen
2. Nutzen Sie die Selbstauskunft, um in Ihrem Account die eID-Daten zu hinterlegen:
```
eid-add
```
3. Die Konfigurationsdateien zur Authentisierung mit PAM liegen typischerweise in `/etc/pam.d/`. Um beispielsweise für `sudo` auch die Authentisierung mit dem Personalausweis zu erlauben, fügen Sie der Datei `/etc/pam.d/sudo` folgende Zeile hinzu:
```pam
auth       sufficient     eid-pam.so
```
4. Um eine PIN-Änderung mittels `passwd` per AusweisApp2 auszulösen, fügen Sie der Datei `/etc/pam.d/passwd` folgende Zeile hinzu:
```
password   optional       eid-pam.so
```
