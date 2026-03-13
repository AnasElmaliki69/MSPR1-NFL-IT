# 🦅 Seahawks Monitoring

**Projet MSPR TPRE552 — Développement & Sécurité Informatique**
Bachelor CYB3R XP

👥 **Équipe projet**

* Anas EL MALIKI
* Mariama BENKHALID
* Xavier MEYER

---

## 📌 Présentation du projet

**Seahawks Monitoring** est une solution de supervision réseau conçue pour standardiser la collecte et l’analyse d’informations techniques dans des environnements **multi-sites**.

L’objectif est de permettre aux équipes support **N1 / N2** de disposer rapidement d’une vision fiable de l’état technique d’un site distant afin de :

* Réduire les interventions sur site
* Accélérer les diagnostics
* Améliorer la continuité de service
* Centraliser les données de supervision

La solution repose sur une **architecture distribuée agent / serveur centralisé.**

---

## 🧩 Architecture de la solution

### 🔹 Seahawks Harvester (Composant local)

Déployé sur une **machine virtuelle Linux**, ce composant permet :

* Le scan réseau (découverte IP et ports)
* Le calcul du nombre d’équipements détectés
* La mesure de la latence WAN
* La génération d’un rapport structuré local
* L’affichage d’un tableau de bord minimal

✅ Fonctionne **même en mode déconnecté** du centre.

---

### 🔹 Seahawks Nester (Plateforme centrale)

Déployée en **datacenter**, cette application web permet :

* La supervision des sondes déployées
* La consultation du dernier rapport reçu
* Le suivi de l’état de connexion des sites

La plateforme repose sur une **architecture web légère**, facilitant le déploiement et l’évolutivité.

---

## 📊 Modèle de données

Les rapports générés sont structurés au format **JSON**.

### Exemple :

```json
{
  "host_id": "vm-franchise-01",
  "scan_date": "2026-03-12 21:30",
  "devices_detected": 12,
  "average_latency_ms": 24,
  "open_ports_summary": ["22", "80", "443"],
  "version": "1.0.0"
}
```

Ce format permet :

* Une exploitation simple des données
* Une traçabilité des rapports
* Une intégration future dans des outils avancés de supervision

---

## 🔐 Sécurité de la solution

Plusieurs principes de cybersécurité sont intégrés dès la conception :

* Exécution avec **privilèges minimaux**
* Absence de stockage de mots de passe en clair
* Horodatage et versionnement des rapports
* Journalisation structurée des événements
* Limitation du périmètre de scan aux environnements autorisés

Ces choix garantissent **l’intégrité des données et la maintenabilité de la solution.**

---

## 📜 Journalisation & Observabilité

Un système de logs structurés permet de :

* Suivre les scans réalisés
* Identifier les erreurs réseau
* Faciliter les diagnostics des équipes support
* Permettre une intégration future dans une stack **ELK**

Chaque événement critique contient :

* Un timestamp
* Un niveau de criticité
* Le composant concerné

---

## 🔌 Continuité de service en mode déconnecté

Le Harvester conserve localement le **dernier rapport généré**.

Cela permet :

* Une consultation immédiate sur site
* Une synchronisation automatique lorsque la connexion est rétablie
* Une continuité opérationnelle pour les équipes support

---

## 🚀 Déploiement & Évolutivité

La solution est conçue pour être :

* Facilement clonable entre hyperviseurs
* Modulaire et évolutive

### Perspectives d’évolution :

* Télémaintenance sécurisée
* Haute disponibilité
* Intégration SIEM
* Automatisation du déploiement

---

## 👨‍💻 Organisation du projet

### Répartition des responsabilités

**Anas — Architecture & collecte réseau**

* Conception de l’architecture globale
* Définition du modèle de communication Harvester → Nester
* Conception du format des rapports JSON
* Étude des mécanismes de journalisation
* Prototype du moteur de scan réseau

**Mariama — Sécurité & documentation**

* Analyse des exigences de cybersécurité
* Mise en place des principes de moindre privilège
* Rédaction du runbook d’exploitation N1 / N2
* Documentation des procédures de déploiement
* Définition des stratégies de gestion des secrets

**Xavier — Plateforme centrale & supervision**

* Conception de la plateforme centralisée
* Définition de l’interface utilisateur
* Organisation du stockage des rapports
* Tests de consultation et restitution des données
* Préparation du support de soutenance

---

## 🔄 Workflow Git

Un repository **GitHub** a été utilisé afin d’assurer :

* La traçabilité des modifications
* La collaboration efficace entre les membres
* Le versioning du projet
* Le suivi structuré de l’avancement

---

## ✅ Conclusion

Le projet **Seahawks Monitoring** constitue une base opérationnelle permettant d’améliorer la supervision des infrastructures multi-sites.

La solution répond aux besoins métier tout en respectant les contraintes de sécurité et d’exploitabilité.

Les prochaines étapes consistent à :

* Finaliser le déploiement technique
* Réaliser des tests en environnement virtualisé
* Étendre progressivement les fonctionnalités

---

⭐ *Projet académique — Programme CYB3R XP*
