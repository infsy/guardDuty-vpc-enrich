# GuardDuty VPC Flow Logs Enrichment

Une solution serverless AWS qui enrichit automatiquement les alertes GuardDuty avec les données contextuelles des VPC Flow Logs pour une analyse forensique approfondie des incidents de sécurité.

## Vue d'ensemble

Ce projet implémente une fonction Lambda qui :

1. **Reçoit les alertes GuardDuty** via EventBridge en temps réel
2. **Analyse les VPC Flow Logs** correspondants stockés dans S3
3. **Enrichit les alertes** avec des informations réseau contextuelles
4. **Détecte des patterns suspects** automatiquement
5. **Publie des alertes enrichies** via SNS avec recommandations de sécurité

## Architecture

```
GuardDuty Finding → EventBridge → Lambda → S3 (VPC Flow Logs) 
                                    ↓
                               Enrichment Engine
                                    ↓
                              SNS → Security Team
```

### Composants AWS

- **Lambda Function** : Traitement principal (Python 3.11)
- **EventBridge Rule** : Déclenchement sur les findings GuardDuty
- **S3 Bucket** : Stockage des VPC Flow Logs
- **SNS Topic** : Diffusion des alertes enrichies
- **CloudWatch** : Monitoring et métriques
- **KMS Key** : Chiffrement des données

## Fonctionnalités

### Enrichissement des Alertes

- **Métadonnées GuardDuty** : Extraction complète des informations d'alerte
- **Corrélation temporelle** : Analyse des flow logs dans une fenêtre configurable (±15 min par défaut)
- **Analyse du trafic réseau** : Statistiques de connexions, bytes transférés, IPs distantes
- **Détection de patterns** : Port scanning, exfiltration de données, connexions suspectes

### Patterns Détectés Automatiquement

1. **Port Scanning** : Détection de scans de ports multiples depuis une même IP
2. **Exfiltration de données** : Identification de transferts sortants volumineux (>100MB)
3. **Connexions répétées rejetées** : Tentatives d'accès bloquées répétées
4. **Activité en heures inhabituelles** : Trafic réseau pendant les heures creuses

### Recommandations de Sécurité

Le système génère automatiquement des recommandations contextuelles :

- **Actions immédiates** : Isolation d'instances, blocage de trafic
- **Enquêtes** : Vérification des logs, rotation des credentials
- **Améliorations préventives** : Règles firewall, monitoring renforcé

## Installation et Déploiement

### Prérequis

- AWS CDK v2 installé
- Python 3.11+
- Compte AWS avec permissions appropriées
- VPC Flow Logs activés et stockés dans S3

### Déploiement

1. **Installation des dépendances**
   ```bash
   pip install -r requirements.txt
   pip install -r requirements-dev.txt
   ```

2. **Configuration**
   ```bash
   # Configurer les variables d'environnement
   export CDK_DEFAULT_ACCOUNT=123456789012
   export CDK_DEFAULT_REGION=us-east-1
   ```

3. **Déploiement CDK**
   ```bash
   # Synthèse et déploiement
   cdk bootstrap  # Premier déploiement uniquement
   cdk deploy --parameters FlowLogsBucketName=your-vpc-flow-logs-bucket
   ```

### Configuration Paramètres

Lors du déploiement, vous pouvez configurer :

- **FlowLogsBucketName** : Nom du bucket S3 contenant les VPC Flow Logs
- **SeverityThreshold** : Seuil minimum de sévérité GuardDuty (0-8, défaut: 4)
- **SnsTopicArn** : ARN du topic SNS existant (optionnel)

## Configuration par Environnement

Le projet supporte plusieurs environnements avec des configurations spécifiques :

### Développement (dev)
```bash
cdk deploy -c environment=dev
```
- Mémoire Lambda : 512MB
- Niveau de log : DEBUG  
- Rétention logs : 7 jours
- X-Ray : Désactivé

### Production (prod)
```bash
cdk deploy -c environment=prod
```
- Mémoire Lambda : 1024MB
- Niveau de log : WARN
- Rétention logs : 90 jours
- Seuil sévérité : 6.0

## Tests

### Tests Unitaires

```bash
# Exécution de tous les tests avec couverture
pytest

# Tests unitaires uniquement
pytest tests/unit/ -v

# Tests d'intégration
pytest tests/integration/ -v

# Rapport de couverture détaillé
pytest --cov-report=html
open htmlcov/index.html
```

### Couverture de Code

Le projet maintient une couverture de tests > 80% avec des tests pour :

- ✅ **Parsing GuardDuty** : Extraction et validation des métadonnées
- ✅ **Analyse Flow Logs** : Traitement des logs VPC depuis S3
- ✅ **Moteur d'enrichissement** : Corrélation et détection de patterns
- ✅ **Publication SNS** : Formatage et diffusion des alertes
- ✅ **Intégration complète** : Tests end-to-end du handler Lambda

## Monitoring et Observabilité

### Métriques CloudWatch

- **ProcessingDuration** : Temps de traitement (ms)
- **FlowLogsAnalyzed** : Nombre de logs traités
- **SuspiciousPatternsDetected** : Patterns suspects détectés
- **EnrichmentSuccess/Failure** : Taux de succès/échec

### Logs Structurés

- Format JSON pour CloudWatch Insights
- Correlation ID pour traçabilité
- Niveaux de log configurables

### Alarmes Recommandées

```bash
# Taux d'erreur élevé
aws cloudwatch put-metric-alarm \
  --alarm-name "GuardDuty-Enrichment-ErrorRate" \
  --metric-name "EnrichmentFailure" \
  --namespace "GuardDuty/Enrichment" \
  --statistic "Sum" \
  --threshold 5 \
  --comparison-operator "GreaterThanThreshold"
```

## Structure du Projet

```
guarduty-vpc-enrich/
├── app.py                          # Point d'entrée CDK
├── requirements.txt                # Dépendances production  
├── requirements-dev.txt            # Dépendances développement
├── cdk.json                       # Configuration CDK
├── stacks/
│   └── guardduty_enrichment_stack.py  # Stack CDK principal
├── lambda/
│   ├── handler.py                 # Handler Lambda principal
│   ├── guardduty_parser.py        # Parser des alertes GuardDuty
│   ├── flow_logs_analyzer.py      # Analyseur VPC Flow Logs
│   ├── enrichment_engine.py       # Moteur d'enrichissement
│   └── sns_publisher.py           # Publication SNS
├── tests/
│   ├── unit/                      # Tests unitaires
│   └── integration/               # Tests d'intégration
├── config/
│   └── environment_config.py      # Configuration par environnement
└── README.md                      # Documentation
```

## Sécurité

### Principe du Moindre Privilège

- Permissions IAM minimales par fonction
- Policies spécifiques sans wildcards
- Conditions IAM sur les ressources

### Chiffrement

- KMS pour chiffrement SNS
- S3 SSE pour les logs
- Chiffrement en transit et au repos

### Conformité

- CloudTrail pour tous les appels API
- Logs immutables
- Tags obligatoires pour gouvernance

## Optimisations de Performance

### Traitement Parallèle

- ThreadPoolExecutor pour requêtes S3
- Pagination efficace des gros volumes
- Streaming parsing pour les fichiers volumineux

### Gestion de la Mémoire

- Limitation du nombre de logs traités (10k max)
- Compression des messages SNS
- Cache des métadonnées S3

### Optimisation des Coûts

- Reserved Concurrency Lambda
- S3 Select pour filtrage côté serveur (future amélioration)
- Compression gzip des flow logs

## Dépannage

### Problèmes Courants

1. **Pas de Flow Logs trouvés**
   - Vérifier que les VPC Flow Logs sont activés
   - Contrôler le partitionnement S3 (format attendu)
   - Valider les permissions S3

2. **Erreurs de parsing GuardDuty**
   - Vérifier la structure du finding
   - Contrôler les champs obligatoires
   - Examiner les logs CloudWatch

3. **Échecs de publication SNS**
   - Valider les permissions SNS
   - Vérifier la taille des messages
   - Contrôler la configuration KMS

### Logs de Debug

```bash
# Activer les logs DEBUG temporairement
aws lambda update-function-configuration \
  --function-name guardduty-vpc-enrichment-prod \
  --environment Variables='{LOG_LEVEL=DEBUG}'
```

## Contribution

1. Fork du repository
2. Création d'une branche feature
3. Tests unitaires pour tout nouveau code
4. Couverture de tests > 80% maintenue
5. Pull request avec description détaillée

## Roadmap

- [ ] Support des formats VPC Flow Logs étendus (29 champs)
- [ ] Intégration Threat Intelligence feeds externes
- [ ] Dashboard CloudWatch personnalisé
- [ ] Support multi-régions
- [ ] API REST pour consultation des enrichissements

## Support

Pour les questions ou problèmes :

1. Consulter la documentation des logs CloudWatch
2. Vérifier les métriques de monitoring
3. Examiner les messages dans la Dead Letter Queue
4. Ouvrir une issue GitHub avec les détails d'erreur

---

**Version** : 1.0  
**Dernière mise à jour** : Janvier 2025  
**Compatibilité** : AWS CDK v2, Python 3.11+