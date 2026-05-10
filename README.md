# Cerberion CRM

CRM interne Cerberion — gestion clients, prospects, devis, factures, tâches et signature électronique.

## Démarrage local

```bash
npm install
npm start
```

L'application est disponible sur http://localhost:3000

## Déploiement Railway

1. Push ce dépôt sur GitHub
2. Sur Railway, cliquer sur "New Project" → "Deploy from GitHub repo"
3. Sélectionner ce dépôt
4. Railway détecte automatiquement Node.js et lance `npm install` puis `npm start`
5. Settings → Networking → Generate Domain pour l'URL publique
