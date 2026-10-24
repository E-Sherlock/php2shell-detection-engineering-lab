#!/usr/bin/env bash
#
# ==============================================================================
# Script : php2shell_triage.sh
# Auteur : Mohamed Lahouar (@E-Sherlock)
# Description : Script de triage judiciaire rapide (DFIR) pour détecter les
#               activités post-exploitation liées à PHP2Shell (CVE-2026-109618/19).
# Utilisation : sudo bash php2shell_triage.sh
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

LOG_DIR="/var/www/"
PHP_LOG_PATHS=("/var/log/php*.log" "/var/log/fpm-php.log" "/var/log/apache2/" "/var/log/nginx/")

echo -e "${BLUE}======================================================================${NC}"
echo -e "${BLUE}      PHP2Shell (CVE-2026-109618/19) - Forensic Triage Script       ${NC}"
echo -e "${BLUE}======================================================================${NC}"
echo -e "Démarrage de l'analyse à : $(date -u)\n"

if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}[!] Erreur : Ce script doit être exécuté avec les privilèges root (sudo).${NC}"
  exit 1
fi

echo -e "${YELLOW}[1/4] Recherche de processus web ayant engendré des shells interactifs...${NC}"
SUSPICIOUS_PROCS=$(ps aux | grep -E '(php-fpm|apache2|nginx|httpd)' | grep -E '(sh|bash|dash|python|perl|nc)' | grep -v 'grep' || true)

if [ -n "$SUSPICIOUS_PROCS" ]; then
  echo -e "${RED}[ALERT CRITIQUE] Processus suspect(s) détecté(s) :${NC}"
  echo "$SUSPICIOUS_PROCS"
else
  echo -e "${GREEN}[OK] Aucun shell interactif directement engendré par les daemons web.${NC}"
fi
echo ""

echo -e "${YELLOW}[2/4] Analyse des fichiers .php créés ou modifiés au cours des dernières 48h dans ${LOG_DIR}...${NC}"
RECENT_FILES=$(find "$LOG_DIR" -type f -name "*.php" -mtime -2 -exec ls -la {} + 2>/dev/null || true)

if [ -n "$RECENT_FILES" ]; then
  echo -e "${YELLOW}[ATTENTION] Fichiers PHP récents trouvés dans le dossier Web :${NC}"
  echo "$RECENT_FILES"
else
  echo -e "${GREEN}[OK] Aucun fichier .php récemment modifié/créé dans $LOG_DIR.${NC}"
fi
echo ""

echo -e "${YELLOW}[3/4] Inspection des journaux système/PHP pour les erreurs OOM / allocation mémoire...${NC}"
FOUND_LOGS=0
for path in "${PHP_LOG_PATHS[@]}"; do
  if ls $path >/dev/null 2>&1; then
    FOUND_LOGS=1
    echo -e "-> Analyse de : $path"
    grep -iE '(out of memory|fatal error|zval|alloc|longjmp)' $path 2>/dev/null | tail -n 10 || true
  fi
done

if [ "$FOUND_LOGS" -eq 0 ]; then
  echo -e "${YELLOW}[INFO] Aucun journal d'erreur PHP standard trouvé dans les emplacements par défaut.${NC}"
fi
echo ""

echo -e "${YELLOW}[4/4] Recherche de connexions réseau actives initiées par des daemons web...${NC}"
WEB_CONNS=$(ss -tpn | grep -E '(php-fpm|apache2|nginx|httpd)' || true)

if [ -n "$WEB_CONNS" ]; then
  echo -e "${YELLOW}[INFO] Connexions réseau associées aux services Web :${NC}"
  echo "$WEB_CONNS"
else
  echo -e "${GREEN}[OK] Aucune connexion réseau suspecte active relevée sur le daemon web.${NC}"
fi

echo -e "\n${BLUE}======================================================================${NC}"
echo -e "${BLUE}    [+] Triage terminé avec succès.                                   ${NC}"
echo -e "${BLUE}======================================================================${NC}"