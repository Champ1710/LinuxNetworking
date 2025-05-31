#!/bin/bash

set -e

# Paths
IPTABLES_DUMP="/root/iptables.dump"
IP6TABLES_DUMP="/root/ip6tables.dump"
NFTABLES_IPV4="/etc/nftables/iptables.nft"
NFTABLES_IPV6="/etc/nftables/ip6tables.nft"
NFTABLES_COMBINED="/etc/nftables/combined.nft"

# Ensure nftables is installed
echo "[+] Installing required packages..."
apt-get update -qq
apt-get install -y nftables iptables iptables-translate

# Backup and convert iptables
echo "[+] Dumping iptables rules..."
iptables-save > "$IPTABLES_DUMP"
ip6tables-save > "$IP6TABLES_DUMP"

echo "[+] Converting iptables to nftables..."
iptables-restore-translate -f "$IPTABLES_DUMP" > "$NFTABLES_IPV4"
ip6tables-restore-translate -f "$IP6TABLES_DUMP" > "$NFTABLES_IPV6"

# Combine IPv4 and IPv6 configs
echo "[+] Combining IPv4 and IPv6 nftables rules..."
cat << 'EOF' > "$NFTABLES_COMBINED"
#!/usr/sbin/nft -f

define INGRESS_INTF = { "swp43", "swp44" }
define INTRA_LINK_NETS = { 10.2.96.0/19 }
define SECURITY_NETS = { 10.1.128.0/24 }

table inet filter {
    sets {
        ingress_intf = { type ifname; elements = $INGRESS_INTF }
        intra_link_nets = { type ipv4_addr; elements = $INTRA_LINK_NETS }
        security_nets = { type ipv4_addr; elements = $SECURITY_NETS }
    }

    chain input {
        type filter hook input priority 0;
        policy drop;

        iifname @ingress_intf ip daddr @intra_link_nets tcp sport { 80, 443, 8080, 8081, 8883 } accept
        ip saddr @intra_link_nets tcp dport 22 accept
        iifname "vlan900" ip saddr @security_nets udp dport { 1756, 1757, 1758 } accept
    }

    chain forward {
        type filter hook forward priority 0;
        policy drop;

        ip saddr @security_nets ip daddr @intra_link_nets tcp sport 442 accept
        ip saddr @intra_link_nets ip daddr @security_nets tcp dport 442 accept

        ip saddr @intra_link_nets ip daddr @security_nets tcp dport 3389 accept
        ip saddr @security_nets ip daddr @intra_link_nets tcp sport 3389 accept
        ip saddr @intra_link_nets ip daddr @security_nets udp dport 3389 accept
        ip saddr @security_nets ip daddr @intra_link_nets udp sport 3389 accept

        ip saddr @intra_link_nets ip daddr @security_nets tcp dport 3001 accept
        ip saddr @security_nets ip daddr @intra_link_nets tcp sport 3001 accept

        ip saddr @intra_link_nets ip daddr @security_nets tcp dport 7700 accept
        ip saddr @security_nets ip daddr @intra_link_nets tcp sport 7700 accept

        iifname "vlan900" ip daddr @security_nets udp sport { 1756, 1757, 1758 } accept
    }

    chain output {
        type filter hook output priority 0;
        policy accept;
    }
}

EOF

# Apply and enable nftables
echo "[+] Applying new nftables ruleset..."
nft -f "$NFTABLES_COMBINED"

echo "[+] Enabling nftables service..."
systemctl enable --now nftables

# Final check
echo "[+] Verifying active nftables ruleset..."
nft list ruleset

echo "[✓] Migration complete."





chmod +x migrate_to_nftables.sh

sudo ./migrate_to_nftables.sh
