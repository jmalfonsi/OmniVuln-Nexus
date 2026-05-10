# OmniVuln-Nexus 🛡️🤖

**OmniVuln-Nexus** est un framework de pointe dédié à la détection, la validation et le triage automatisé de vulnérabilités logicielles (C/C++). Il combine l'analyse statique avancée (via Code Property Graph - CPG) et l'intelligence artificielle générative, orchestrée par des flux d'agents complexes.

## 🚀 Fonctionnalités Clés

- **Orchestration LangGraph** : Un pipeline de triage cyclique et conditionnel permettant de raffiner les hypothèses de vulnérabilité jusqu'à leur validation ou rejet.
- **Entraînement GRPO (Group Relative Policy Optimization)** : Infrastructure complète pour le fine-tuning de LLMs (comme Qwen2.5-Coder) via l'apprentissage par renforcement, basé sur un système de récompenses par curriculum (compilation, crash fuzzer, validité de la stacktrace).
- **Schémas Pydantic Stricts** : Définition rigoureuse des interfaces de données pour garantir l'interopérabilité entre les LLMs et les outils d'analyse statique.
- **Validation en Sandbox** : Exécution isolée des harnais de fuzzing (libFuzzer) pour confirmer les vulnérabilités avec des sanitizers (ASAN/UBSAN/MSAN).

## 📁 Structure du Projet

```text
omnivuln/
├── schemas/           # Modèles de données Pydantic (Hypothèses, Findings)
├── orchestration/     # Logique de graphe LangGraph et gestion d'état
├── harness/           # Templates Jinja2 pour la génération de harnais
├── sandbox/           # Environnement d'exécution Dockerisé pour le fuzzing
├── training/          # Scripts d'entraînement GRPO et fonctions de récompense
└── tests/             # Suites de tests pour la validation du pipeline

🧠 Architecture du Pipeline
Le flux de travail suit un cycle de validation rigoureux :

Ingestion du diff et extraction des fonctions affectées.
Génération d'hypothèses structurées par le LLM.
Validation de schéma et de cohérence avec le CPG.
Génération et compilation de harnais de fuzzing.
Exécution timeboxée pour tenter de reproduire un crash.
Classification finale : VALIDATED_FINDING, SUSPICIOUS_PATH ou RESEARCH_QUEUE.
📈 Entraînement (GRPO)
Le projet inclut un script d'entraînement training/train_grpo.py qui utilise une fonction de récompense personnalisée. Le modèle est récompensé non pas sur son "style" de raisonnement, mais sur sa capacité à produire des artefacts techniquement valides et vérifiables en sandbox.

Ce projet est une implémentation des concepts de "Sprint 0" du protocole OmniVuln.