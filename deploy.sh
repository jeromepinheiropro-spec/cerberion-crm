#!/usr/bin/env bash
# Cerberion CRM — Script de déploiement GitHub + Railway
# Usage : ./deploy.sh

set -e
cd "$(dirname "$0")"

echo ""
echo "🛡️  Cerberion CRM — Déploiement GitHub + Railway"
echo "================================================"
echo ""

# ----- Vérifs préalables
command -v git >/dev/null 2>&1 || { echo "❌ git n'est pas installé."; exit 1; }
command -v node >/dev/null 2>&1 || { echo "⚠️  node non détecté (pas bloquant)."; }

# ----- Étape 1 : git init
if [ ! -d .git ]; then
  echo "▶ Initialisation du repo git..."
  git init -b main
  git add .
  git commit -m "Initial commit: Cerberion CRM v1"
  echo "✅ Commit initial créé"
else
  echo "✅ Repo git déjà initialisé"
fi

echo ""
# ----- Étape 2 : GitHub
echo "▶ Création du repo sur GitHub"
echo ""
echo "Choisis une option :"
echo "  1) J'ai gh (GitHub CLI) installé — création auto du repo"
echo "  2) Je crée manuellement le repo sur github.com"
echo ""
read -p "Ton choix (1 ou 2) : " CHOICE

if [ "$CHOICE" = "1" ]; then
  command -v gh >/dev/null 2>&1 || { echo "❌ gh n'est pas installé. Installe-le avec : brew install gh"; exit 1; }
  gh auth status >/dev/null 2>&1 || { echo "→ Connexion à GitHub..."; gh auth login; }

  read -p "Nom du repo (par défaut: cerberion-crm) : " REPO_NAME
  REPO_NAME=${REPO_NAME:-cerberion-crm}
  read -p "Public ou privé ? (public/private, défaut: private) : " VISIBILITY
  VISIBILITY=${VISIBILITY:-private}

  echo "▶ Création du repo GitHub $REPO_NAME ($VISIBILITY)..."
  gh repo create "$REPO_NAME" --"$VISIBILITY" --source=. --remote=origin --push
  echo "✅ Repo créé et code pushé"
  REPO_URL=$(gh repo view --json url -q .url)
  echo "🔗 $REPO_URL"
else
  echo ""
  echo "👉 Va sur https://github.com/new et crée un nouveau repo (nom suggéré: cerberion-crm)"
  echo "   ⚠️  Ne coche AUCUNE option (ni README, ni .gitignore, ni licence) — on les a déjà."
  echo ""
  read -p "Une fois le repo créé, colle l'URL HTTPS (ex: https://github.com/ton-user/cerberion-crm.git) : " REPO_URL

  if git remote get-url origin >/dev/null 2>&1; then
    git remote set-url origin "$REPO_URL"
  else
    git remote add origin "$REPO_URL"
  fi

  echo "▶ Push initial vers GitHub..."
  git push -u origin main
  echo "✅ Code pushé"
fi

echo ""
echo "================================================"
echo "✅ GitHub : OK"
echo "================================================"
echo ""

# ----- Étape 3 : Railway
echo "▶ Déploiement sur Railway"
echo ""
echo "Méthode recommandée (Web UI, 30 secondes) :"
echo ""
echo "  1. Va sur https://railway.app/new"
echo "  2. Clique « Deploy from GitHub repo »"
echo "  3. Autorise Railway si demandé, puis sélectionne ton repo"
echo "  4. Railway détecte automatiquement Node.js et lance le build"
echo "  5. Une fois déployé, va dans Settings → Networking → Generate Domain"
echo "     → tu obtiens une URL publique du type https://cerberion-crm.up.railway.app"
echo ""
echo "Méthode CLI (si Railway CLI installé) :"
echo "   npm i -g @railway/cli"
echo "   railway login"
echo "   railway init"
echo "   railway up"
echo "   railway domain"
echo ""

read -p "Ouvrir Railway dans le navigateur maintenant ? (o/N) : " OPEN
if [ "$OPEN" = "o" ] || [ "$OPEN" = "O" ]; then
  open "https://railway.app/new"
fi

echo ""
echo "🎉 Tout est prêt. Le code est sur GitHub, le déploiement Railway est entre tes mains."
