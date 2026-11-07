# Guide d Installation et de Flashage USB FAT32 : Autoradio ROCO K706 UIS7862

## 1. Presentation et Principes Fondamentaux de Securite

Ce guide detaille la procedure pas a pas pour installer la ROM allégee QF001 Debloat OS sur votre autoradio plateforme ROCO K706 equipé du processeur Unisoc UIS7862 ou UIS7862S (reference QF001).

### Garantie absolue d isolation et de securite du MCU
* Zero modification du micrologiciel MCU : Le paquet d installation update.zip est strictement limite a la partition logicielle Android (system.img et elements de demarrage associes). Il ne contient et n execute aucun composant de micrologiciel MCU (Microcontroller Unit).
* Zero risque pour les fonctions materielles de bord : La puce MCU originale assurant la gestion de l amplificateur audio TDA7851, de la radio TDA7708, des echanges avec le bus Canbus automobile et de la dalle tactile capacitive reste strictement intacte.
* Protection integrale : Aucun risque d alteration tactile, de dysfonctionnement des boutons physiques ou de perte sonore.


## 2. Preparation du Support Amovible USB

Pour garantir une reconnaissance immediate par le chargeur d amorcage et le systeme de recuperation de l autoradio, la cle USB doit respecter scrupuleusement les exigences suivantes :

### Criteres materiels de la cle USB
* Capacite recommandee : Utiliser une cle USB standard d une capacite comprise entre 8 Go et 32 Go.
* Protocole de communication : Cle USB 2.0 ou USB 3.0 compatible avec les prises USB arriere de l autoradio.

### Formatage et structure de partitionnement
* Table de partitionnement : MBR (Master Boot Record obligatoire, ne jamais utiliser le partitionnement GPT).
* Systeme de fichiers : FAT32 exclusif (File Allocation Table 32 bits, les formats exFAT et NTFS sont rejetes).
* Taille d allocation des blocs : 4096 octets (4 Ko par cluster).
* Nom du volume : Simple et sans caracteres speciaux (par exemple UPDATE ou USB).

### Depot du paquet de mise a jour
* Emplacement racine obligatoire : Placer le fichier update.zip directement a la racine absolue de la cle USB (par exemple E:\update.zip sous Windows ou /Volumes/UPDATE/update.zip sous macOS).
* Interdiction des dossiers : Ne jamais placer le paquet dans un dossier secondaire.
* Orthographe exacte : Le fichier doit obligatoirement porter le nom update.zip tout en minuscules, sans espace ni mention complementaire.
* Limite de taille FAT32 : Le fichier update.zip ne doit en aucun cas depasser 4294967295 octets (limite maximale autorisee de 4 Go pour le systeme de fichiers FAT32).


## 3. Precautions Prealables au Flashage Automobile

Le flashage d une partition systeme dans un environnement automobile exige quelques regles de prudence :

* Stabilite electrique imperative : Conserver le contact du vehicule allume ou faire tourner le moteur durant toute la duree de l operation. Une chute de tension de la batterie ou une coupure d alimentation pendant l ecriture de la partition systeme risquerait de corrompre les donnees en cours d enregistrement.
* Deconnexion des accessoires tiers : Debrancher prealablement les autres cles USB, modems cellulaires 4G ou adaptateurs de liaison pour smartphones afin d eviter toute confusion de peripherique d amorcage.
* Choix du connecteur USB : Raccorder la cle USB directement au faisceau USB arriere de l autoradio (cable principal 4 broches ou 6 broches relie au port USB de debogage et d installation).


## 4. Procedure de Flashage Etape par Etape

Deux methodes d installation sont disponibles sur la plateforme ROCO K706 :

### Methode A : Mise a jour depuis l interface des Parametres Android (Recommandee)

* Etape 1 : Mettre le contact du vehicule et patienter jusqu au demarrage complet de l autoradio.
* Etape 2 : Connecter la cle USB preparee au connecteur USB du vehicule.
* Etape 3 : Ouvrir le menu Parametres du systeme, naviguer dans la section Systeme, puis selectionner A propos de l appareil.
* Etape 4 : Choisir la commande Mise a jour locale ou Mise a jour du systeme via USB.
* Etape 5 : L autoradio detecte automatiquement l archive update.zip, controle sa signature cryptographique de securite, puis sollicite la confirmation de l utilisateur avant de redemarrer en mode de recuperation.
* Etape 6 : La mise a jour s execute automatiquement avec affichage d une barre de progression. Ne pas toucher a l ecran et ne pas couper le contact du vehicule pendant l operation.
* Etape 7 : Des l achevement de l ecriture, l autoradio redemarre automatiquement sur le nouveau systeme allégé et ergonomique. Vous pouvez alors debrancher la cle USB.

### Methode B : Detection Automatique au Demarrage a Froid (Mode Secours)

* Etape 1 : Autoradio hors tension ou contact coupe, brancher la cle USB contenant update.zip a sa racine.
* Etape 2 : Mettre le contact du vehicule. Si l autoradio est deja sous tension, introduire une pointe fine dans l orifice RST (Reset situe sur la facade avant de l appareil) pour provoquer un redemarrage materiel.
* Etape 3 : Le chargeur d amorcage examine les ports USB au demarrage, identifie le paquet update.zip valide et bascule directement sur le programme d installation.
* Etape 4 : Le processus d extraction et de programmation de la partition systeme debute.
* Etape 5 : Des que le systeme redemarre et affiche le logo de demarrage, debrancher aussitot la cle USB pour eviter que l installation ne se relance lors des prochains cycles.


## 5. Diagnostic, Resolution des Incidents et Restauration

### Incident 1 : La cle USB n est pas reconnue par l autoradio
* Cause frequente : Format de partition GPT au lieu de MBR, ou systeme de fichiers exFAT / NTFS.
* Action corrective : Rebrancher la cle sur votre ordinateur, reinitialiser la table de partition en MBR et formater en FAT32 avec des clusters de 4096 octets. S assurer que le fichier est bien nomme update.zip et situe a la racine.

### Incident 2 : Echec du controle de signature ou archive annoncee corrompue
* Cause frequente : Copie incomplete ou alteration du fichier lors du transfert.
* Action corrective : Verifier l empreinte SHA256 du fichier sur l ordinateur, formater a nouveau la cle USB et recopier proprement l archive update.zip. Ejecter la cle USB de maniere securisee avant de la retirer de l ordinateur.

### Incident 3 : Redemarrage continu ou ecran fige
* Action corrective : Debrancher la cle USB. Effectuer un appui maintenu de cinq secondes sur le bouton RST de la facade pour reinitialiser l appareil. Comme le microcode MCU d origine n a jamais ete modifie ni touche, le materiel ne subit aucun blocage physique irremediable. Le systeme redemarrera normalement ou permettra une nouvelle tentative d installation saine.
