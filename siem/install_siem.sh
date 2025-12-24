#!/usr/bin/env bash
set -e

echo "============================================"
echo "[1/6] System update"
echo "============================================"
export DEBIAN_FRONTEND=noninteractive
sudo apt-get update -y
sudo apt-get upgrade -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold"

echo "============================================"
echo "[2/6] Base utilities"
echo "============================================"
sudo apt-get install -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" \
  curl wget unzip gnupg lsb-release net-tools htop apt-transport-https software-properties-common lsof openssl

echo "============================================"
echo "[3/6] OpenSSH server"
echo "============================================"
sudo apt-get install -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" openssh-server
sudo systemctl enable ssh || true
sudo systemctl restart ssh || true

echo "============================================"
echo "[4/6] Wazuh SIEM (install only if missing)"
echo "============================================"
if systemctl list-unit-files | awk '{print $1}' | grep -qx "wazuh-manager.service"; then
  echo "Wazuh already installed -> skipping."
else
  curl -fsSLo /tmp/wazuh-install.sh https://packages.wazuh.com/4.7/wazuh-install.sh
  sudo bash /tmp/wazuh-install.sh -a
fi

echo "============================================"
echo "[5/6] Suricata IDS + rules fix"
echo "============================================"
if ! dpkg -s suricata >/dev/null 2>&1; then
  sudo apt-get install -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" suricata
else
  echo "Suricata already installed -> skipping install."
fi

if ! command -v suricata-update >/dev/null 2>&1; then
  sudo apt-get install -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" suricata-update
fi

sudo suricata-update || true

if [ ! -f /var/lib/suricata/rules/suricata.rules ]; then
  echo "WARN: /var/lib/suricata/rules/suricata.rules missing."
  echo "Trying to build suricata.rules from existing *.rules files..."
  sudo mkdir -p /var/lib/suricata/rules
  if ls /var/lib/suricata/rules/*.rules >/dev/null 2>&1; then
    sudo sh -c 'cat /var/lib/suricata/rules/*.rules > /var/lib/suricata/rules/suricata.rules'
  fi
fi

echo "Testing Suricata config..."
sudo suricata -T -c /etc/suricata/suricata.yaml || true

sudo systemctl reset-failed suricata || true
sudo systemctl enable suricata || true
sudo systemctl restart suricata || true

echo "============================================"
echo "[6/6] Wazuh Dashboard SSL + bind fix"
echo "============================================"

sudo mkdir -p /etc/wazuh-dashboard/certs

if [ ! -f /etc/wazuh-dashboard/certs/dashboard-key.pem ] || [ ! -f /etc/wazuh-dashboard/certs/dashboard.pem ]; then
  echo "Dashboard certs missing -> generating self-signed certs."
  sudo openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
    -keyout /etc/wazuh-dashboard/certs/dashboard-key.pem \
    -out /etc/wazuh-dashboard/certs/dashboard.pem \
    -subj "/C=HR/ST=HR/L=Lab/O=ThreatHunting/OU=SIEM/CN=siem" >/dev/null 2>&1
fi

if id wazuh-dashboard >/dev/null 2>&1; then
  sudo chown -R wazuh-dashboard:wazuh-dashboard /etc/wazuh-dashboard/certs
fi
sudo chmod 750 /etc/wazuh-dashboard/certs
sudo chmod 640 /etc/wazuh-dashboard/certs/dashboard-key.pem /etc/wazuh-dashboard/certs/dashboard.pem

DASH_CONF="/etc/wazuh-dashboard/opensearch_dashboards.yml"
if [ -f "$DASH_CONF" ]; then
  if grep -Eq "^[#[:space:]]*server\.host:" "$DASH_CONF"; then
    sudo sed -i -E 's|^[#[:space:]]*server\.host:.*|server.host: "0.0.0.0"|' "$DASH_CONF"
  else
    echo 'server.host: "0.0.0.0"' | sudo tee -a "$DASH_CONF" >/dev/null
  fi

  if grep -Eq "^[#[:space:]]*server\.port:" "$DASH_CONF"; then
    sudo sed -i -E 's|^[#[:space:]]*server\.port:.*|server.port: 443|' "$DASH_CONF"
  else
    echo 'server.port: 443' | sudo tee -a "$DASH_CONF" >/dev/null
  fi

  for key in "server.ssl.enabled" "server.ssl.key" "server.ssl.certificate"; do
    if grep -Eq "^[#[:space:]]*$key:" "$DASH_CONF"; then
      true
    fi
  done

  if grep -Eq "^[#[:space:]]*server\.ssl\.enabled:" "$DASH_CONF"; then
    sudo sed -i -E 's|^[#[:space:]]*server\.ssl\.enabled:.*|server.ssl.enabled: true|' "$DASH_CONF"
  else
    echo 'server.ssl.enabled: true' | sudo tee -a "$DASH_CONF" >/dev/null
  fi

  if grep -Eq "^[#[:space:]]*server\.ssl\.key:" "$DASH_CONF"; then
    sudo sed -i -E 's|^[#[:space:]]*server\.ssl\.key:.*|server.ssl.key: "/etc/wazuh-dashboard/certs/dashboard-key.pem"|' "$DASH_CONF"
  else
    echo 'server.ssl.key: "/etc/wazuh-dashboard/certs/dashboard-key.pem"' | sudo tee -a "$DASH_CONF" >/dev/null
  fi

  if grep -Eq "^[#[:space:]]*server\.ssl\.certificate:" "$DASH_CONF"; then
    sudo sed -i -E 's|^[#[:space:]]*server\.ssl\.certificate:.*|server.ssl.certificate: "/etc/wazuh-dashboard/certs/dashboard.pem"|' "$DASH_CONF"
  else
    echo 'server.ssl.certificate: "/etc/wazuh-dashboard/certs/dashboard.pem"' | sudo tee -a "$DASH_CONF" >/dev/null
  fi

  if ! grep -Eq "^[#[:space:]]*opensearch\.hosts:" "$DASH_CONF"; then
    echo 'opensearch.hosts: ["https://127.0.0.1:9200"]' | sudo tee -a "$DASH_CONF" >/dev/null
  fi
else
  echo "WARN: $DASH_CONF not found (dashboard may not be installed)."
fi

sudo systemctl restart wazuh-indexer || true
sudo systemctl reset-failed wazuh-dashboard || true
sudo systemctl restart wazuh-dashboard || true

echo "============================================"
echo "DONE - Quick status"
echo "============================================"
echo "IPs:"
ip -4 -o addr show scope global | awk '{print " - " $2 " -> " $4}'

echo "Listening ports:"
sudo ss -tulpn | egrep '(:22|:443|:5601|:1514|:1515|:9200)' || true

echo "Access dashboard:"
SIEM_IP=$(ip -4 -o addr show scope global | awk 'NR==1{print $4}' | cut -d/ -f1)
echo " https://${SIEM_IP}"
echo "Note: accept browser certificate warning (self-signed, lab only)."

echo "Username: admin"
echo "Reset Wazuh password (the password is written underneath):"
sudo /usr/share/wazuh-indexer/plugins/opensearch-security/tools/wazuh-passwords-tool.sh -u admin