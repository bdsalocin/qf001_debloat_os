# Original User Request

## 2026-11-06T21:34:16Z

Creation d une ROM modifiee complete pour autoradio plateforme ROCO K706 reference QF001 (UIS 7862 / 7862S) : debloating integral des services superflus et telemetries, optimisation des performances, integration d un environnement d accueil epure style iOS, preservation absolue du MCU et des fonctionnalites automobiles natives (son, radio TDA7708, ampli, Canbus, camera de recul).

Working directory: ~/teamwork_projects/qf001_debloat_os
Integrity mode: development

## Requirements

### R1. Environnement de construction et base QF001
Mettre en place l environnement de travail dans ~/teamwork_projects/qf001_debloat_os avec les outils de manipulation de firmware QF001 (ROM Builder, outils de deballage et remballage de super.img et system.img, signature).

### R2. Debloating en profondeur du systeme
Extraire la partition systeme et desinstaller tous les bloatwares et paquets de telemetrie inutiles en tache de fond, tout en preservant rigoureusement les pilotes materiels et daemons automobiles indispensables (Canbus, service audio, Bluetooth, radio, camera).

### R3. Integration d un environnement epure style iOS
Integrer un lanceur automobile minimaliste et ergonomique inspire de la clarte visuelle d iOS, en le definissant comme lanceur par defaut dans la partition systeme pour un demarrage direct sans menus parasites.

### R4. Preservation absolue du MCU et securite de flash
La ROM finale generee doit s appliquer sous forme d une archive update.zip destinee a une cle USB formatee en FAT32, sans ecraser ni modifier le micrologiciel MCU materiel existant du poste, garantissant zero risque d incompatibilite sonore ou tactile.

## Acceptance Criteria

### Securite et intégrité materielle
* [ ] Le paquet de mise a jour update.zip cible strictement la partition systeme Android sans alterer le MCU.
* [ ] La structure des partitions respecte parfaitement les cles de signature de la carte ROCO K706 QF001.

### Assainissement et performances
* [ ] La liste des bloatwares cibles est documentee et supprimee des dossiers d applications systemes.
* [ ] Les services audio, radio, Canbus et camera restent presents et intacts.

### Ergonomie et pret a l emploi
* [ ] L interface par defaut propose une ergonomie epuree avec acces direct a la navigation et a la musique.
* [ ] Le fichier d installation final est pret a etre depose sur cle USB FAT32 avec ses instructions pas a pas.


## 2026-11-07T00:00:50Z

Reprise des operations suite au redemarrage serveur. L utilisateur souhaite continuer les travaux. Merci de reprendre l orchestration et la resolution des 5 cas de validation challengers du jalon 2.


## 2026-11-07T08:42:17Z

Reprise des operations suite au redemarrage serveur. L utilisateur souhaite continuer les travaux. Les jalons 1, 2 et 3 sont valides (382 tests OK). Merci de reprendre l orchestration du jalon 4 (FAT32 Packager, CLI et guide pas a pas) ainsi que le jalon final M_final.
