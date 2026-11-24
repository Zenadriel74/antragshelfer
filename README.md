# Antragshelfer

Passwortgeschützte Schritt-für-Schritt-Hilfe (eine HTML-Seite).
Der Inhalt in index.html ist verschlüsselt (PBKDF2 + AES-GCM) und wird erst im Browser mit dem Passwort entschlüsselt.
Quelle und Passwort liegen nur lokal im Ordner privat/ (per .gitignore ausgeschlossen).

Neu bauen: python build.py
