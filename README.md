# OmniVuln-Nexus 🛡️🤖

**OmniVuln-Nexus** est une plateforme evidence-driven de détection, validation et triage de vulnérabilités C/C++.

Son objectif n’est pas de produire des alertes statistiques, mais des **preuves reproductibles** :


diff / source code
→ analyse structurelle
→ hypothèse typée
→ harness de fuzzing
→ exécution sanitizer
→ crash reproductible
→ matching stacktrace/hypothèse
→ SARIF + rapport développeur


Le principe central est simple :

> Le modèle peut proposer une hypothèse.
> Seuls les artefacts vérifiables peuvent valider une vulnérabilité.

---

## Objectif final

OmniVuln-Nexus vise à combiner :

* analyse syntaxique C/C++ ;
* Code Property Graphs ;
* extraction source→sink ;
* génération contrôlée de harnesses libFuzzer ;
* validation ASAN/UBSAN/MSAN ;
* exécution symbolique ciblée ;
* sortie SARIF compatible CI ;
* rapports Markdown lisibles par les développeurs ;
* orchestration agentique contrainte ;
* apprentissage léger uniquement sur traces validées.

La plateforme est conçue pour être intégrée dans des pipelines CI/CD GitHub ou GitLab.

---

## Philosophie

OmniVuln-Nexus refuse les alertes purement probabilistes.

Une alerte bloquante doit être accompagnée d’au moins un artefact vérifiable :

* hypothèse JSON conforme au schéma ;
* sink identifié ;
* chemin source→sink ;
* guard manquant ou insuffisant ;
* harness compilable ;
* crash sanitizer ;
* stacktrace matchée ;
* reproducer ;
* rapport SARIF ;
* rapport Markdown.

Les hypothèses non prouvées restent non bloquantes.

---

## Taxonomie des résultats

| Classe              | Description                                                         | Bloquant |
| ------------------- | ------------------------------------------------------------------- | -------: |
| `validated_finding` | Vulnérabilité reproduite par sanitizer ou preuve formelle           |      Oui |
| `suspicious_path`   | Chemin source→sink plausible mais non reproduit                     |      Non |
| `research_queue`    | Cas haute confiance envoyé à analyse longue, fuzzing étendu ou KLEE |      Non |

---

## Architecture cible

```text
OmniVuln-Nexus
├── deterministic extraction
│   ├── Tree-sitter
│   ├── Clang / LLVM
│   ├── compile_commands.json
│   └── Joern / CPG
│
├── hypothesis layer
│   ├── strict Pydantic schemas
│   ├── CPG node references
│   ├── source→sink paths
│   └── guard expectations
│
├── harness layer
│   ├── Jinja2 templates
│   ├── libFuzzer targets
│   ├── compile retry
│   └── corpus management
│
├── validation layer
│   ├── ASAN
│   ├── UBSAN
│   ├── MSAN
│   ├── libFuzzer
│   ├── crash deduplication
│   └── KLEE / symbolic execution
│
├── reporting layer
│   ├── finding.json
│   ├── summary.json
│   ├── SARIF
│   └── Markdown PR reports
│
└── learning layer
    ├── validated trace dataset
    ├── harness repair
    ├── constrained LLM output
    ├── LoRA / DoRA fine-tuning
    └── GRPO curriculum rewards
```

---

## Pipeline cible

1. Une Pull Request déclenche l’analyse.
2. Le diff est extrait.
3. Les fichiers C/C++ modifiés sont identifiés.
4. Les fonctions affectées sont extraites.
5. Le CPG est construit ou mis à jour.
6. Les chemins source→sink sont recherchés.
7. Une hypothèse JSON stricte est produite.
8. Le schéma est validé.
9. Un harness libFuzzer est généré.
10. Le harness est compilé dans une sandbox.
11. Le fuzzer est exécuté avec timeout.
12. Les logs sanitizer sont parsés.
13. La stacktrace est matchée avec l’hypothèse.
14. Le finding est classifié.
15. Les artefacts SARIF, Markdown et JSON sont générés.
16. La CI bloque uniquement les `validated_finding`.

---

## État actuel

Le Sprint 0 implémente déjà une vertical slice fonctionnelle :

```text
source C
→ diff-aware extraction
→ hypothesis.generated.json
→ validation Pydantic
→ harness Jinja2
→ compilation clang/ASAN/libFuzzer
→ fuzzing time-boxed
→ parsing ASAN
→ matching stacktrace/hypothèse
→ finding.json
→ SARIF local + global
→ Markdown local + global
→ tests pytest
```

Commande principale :

```bash
make clean
make smoke
make test
```

État attendu :

```text
12 passed
```

---

## Artefacts générés

```text
demo/out/summary.json          # résumé machine, à venir
demo/out/omnivuln.sarif        # SARIF global pour CI
demo/out/pr_comment.md         # rapport Markdown global PR
demo/out/finding.json          # copie legacy du dernier finding
demo/out/vuln/finding.json     # finding local par cible
demo/out/vuln/omnivuln.sarif   # SARIF local par cible
demo/out/vuln/pr_comment.md    # Markdown local par cible
```

---

## Structure actuelle du prototype

```text
demo/
  vuln.c
  vuln_patched.c
  vuln.h

harness/
  templates/
    libfuzzer_c.j2

schemas/
  smoke_hypothesis.py

tools/
  build_diff.sh
  list_changed_files.sh
  list_smoke_targets.sh
  extract_memcpy_hypothesis.py
  render_harness.py
  parse_asan.py
  match_crash.py
  finding_to_sarif.py
  findings_to_sarif.py
  finding_to_markdown.py
  findings_to_markdown.py
  run_smoke_pipeline.sh
  run_smoke_negative.sh

tests/
  test_smoke_pipeline.py
```

---

## Roadmap MVP

### Mois 1 — Scaffold industriel

Objectif : transformer le prototype Sprint 0 en pipeline CI robuste.

* `summary.json`
* mode CI strict / allow-findings
* GitHub Actions
* packaging Python propre
* Docker sandbox minimal
* extraction `memcpy` plus robuste
* Tree-sitter C/C++ minimal
* support `compile_commands.json`

### Mois 2 — Analyse structurelle

Objectif : remplacer les heuristiques par une analyse CPG réelle.

* intégration Joern
* CPG slices source→sink
* node IDs CPG dans les hypothèses
* détection simple de guards
* support `memcpy`, `memmove`, `strcpy`
* validation ASAN conservée comme arbitre final

### Mois 3 — PR bot et robustesse harness

Objectif : rendre le système utilisable dans une vraie Pull Request.

* harness multi-signatures
* correction unique si compilation échoue
* crash deduplication
* corpus minimal
* upload SARIF
* commentaire PR Markdown
* stockage des artefacts

### Mois 4 — Évaluation et IA contrôlée

Objectif : introduire le LLM seulement là où il apporte un gain mesurable.

* benchmark gelé
* LLM contraint pour triage ou réparation de harness
* fine-tuning léger sur traces validées
* KLEE sur 1 ou 2 patterns bornés
* rapport de métriques reproductible

---

## Apprentissage

Le fine-tuning n’est pas le socle initial du projet.

Le modèle ne sera entraîné qu’à partir de traces validées :

```text
hypothesis
→ harness
→ compile result
→ fuzz result
→ sanitizer log
→ matched frame
→ classification
```

Les récompenses GRPO futures seront fondées sur des artefacts :

| Signal                    | Récompense |
| ------------------------- | ---------: |
| JSON valide               |  partielle |
| CPG cohérent              |  partielle |
| harness compilé           |       +0.2 |
| target atteint            |       +0.2 |
| UBSAN/MSAN confirmé       |       +0.5 |
| ASAN crash matché         |       +1.0 |
| hallucination CPG         |   pénalité |
| crash non matché          |   pénalité |
| tests fonctionnels cassés |   pénalité |

---

## Sécurité d’exécution

À terme, toute compilation et tout fuzzing devront être exécutés dans une sandbox :

* pas de réseau ;
* timeout strict ;
* limite CPU ;
* limite mémoire ;
* répertoire source en lecture seule ;
* répertoire temporaire isolé ;
* artefacts explicitement exportés.

---

## Commandes utiles

```bash
make clean
make smoke
make smoke-negative
make test
```

Commandes prévues :

```bash
make ci-allow-findings
make ci-strict
```

---

## Non-objectifs immédiats

Le projet ne vise pas immédiatement :

* support multi-langage complet ;
* exploitation offensive ;
* génération automatique de PoC généralisables ;
* self-play Red/Blue ;
* MoE spécialisé ;
* Graph-RAG vectoriel ;
* analyse inter-procédurale complète ;
* preuve formelle généralisée.

Ces éléments ne seront ajoutés qu’après stabilisation du pipeline evidence-driven.

---

## Principe non négociable

Aucune alerte bloquante ne doit être produite sans preuve reproductible.

```text
hypothèse ≠ vulnérabilité
crash matché = finding validé
```

