# QF001 Debloat OS

Outil modulaire d assainissement et de personnalisation de firmware pour autoradios plateforme ROCO K706 reference QF001 (processeurs Unisoc UIS 7862 et 7862S).

## Architecture du projet

Le code respecte une separation stricte des responsabilites en couches metiers :

1. src/core : Moteur technique d extraction, de compression d images de partitions et de signature.
2. src/domain : Regles metiers de debloating, validation des listes d applications et preservation absolue des pilotes materiels.
3. src/customization : Injection des interfaces personnalisees style iOS et integration de l environnement MicroG.
4. src/cli : Point d entree en ligne de commande pour piloter les etapes de build.
5. config : Profils materiels, listes de blocage des telemetries et inventaire des services critiques preserves.

## Securite materielle

Ce projet applique une regle de securite stricte : seule la partition systeme Android fait l objet d un traitement. Le micrologiciel MCU reste inchange afin de preserver a 100% l amplificateur audio, le tuner radio et l ecran tactile.
