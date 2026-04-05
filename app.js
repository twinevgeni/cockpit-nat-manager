/* NAT Manager for Cockpit — Firewalld DNAT/SNAT */

const ZONES = ["public", "external", "internal", "dmz"];

function isProtectedGuestInputRule(line) {
    return line.includes('oif "virbr0" counter packets 9 bytes 5417 reject') || line.includes("handle 324");
}

const NFT_RULE_CLEANUP_TARGETS = [
    {
        family: "ip",
        table: "libvirt_network",
        chain: "guest_input",
        match: line => (line.includes("reject") || line.includes("drop")) && !isProtectedGuestInputRule(line)
    }
];

const NFT_GUEST_INPUT_TARGET = {
    family: "ip",
    table: "libvirt_network",
    chain: "guest_input",
    outInterface: "virbr0"
};

function runCommand(args) {
    return cockpit.spawn(args, { superuser: "require", err: "message" });
}

function reloadFirewallAndCleanup() {
    return runCommand(["firewall-cmd", "--reload"])
        .then(() => cleanupNftRules());
}

function cleanupNftRules() {
    const tasks = NFT_RULE_CLEANUP_TARGETS.map(cleanupNftChainRules);
    return Promise.all(tasks).catch(err => {
        console.warn("NFT cleanup error:", err);
    });
}

function cleanupNftChainRules(target) {
    const { family, table, chain, match } = target;

    return runCommand(["nft", "-a", "list", "chain", family, table, chain])
        .then(data => {
            const handles = extractMatchingHandles(data, match);
            if (handles.length === 0) return null;

            return handles.reduce(
                (promise, handle) => promise.then(() =>
                    runCommand(["nft", "delete", "rule", family, table, chain, "handle", String(handle)])
                ),
                Promise.resolve()
            );
        })
        .catch(err => {
            const message = String(err || "");
            if (message.includes("No such file or directory") || message.includes("No such chain")) {
                return null;
            }
            throw err;
        });
}

function extractMatchingHandles(data, match) {
    if (!data) return [];

    return data
        .split("\n")
        .map(line => line.trim())
        .filter(line => line && line.includes("handle ") && match(line))
        .map(line => {
            const handleMatch = line.match(/\bhandle\s+(\d+)\b/);
            return handleMatch ? handleMatch[1] : null;
        })
        .filter(Boolean);
}

function ensureGuestInputAcceptRule(ip, protocol, port) {
    const { family, table, chain, outInterface } = NFT_GUEST_INPUT_TARGET;

    return runCommand(["nft", "-a", "list", "chain", family, table, chain])
        .then(data => {
            const existingRule = findGuestInputAcceptRule(data, ip, protocol, outInterface);
            const ports = mergePorts(existingRule ? existingRule.ports : [], port);
            const portSet = formatNftPortSet(ports);

            if (!existingRule) {
                return runCommand([
                    "nft", "insert", "rule", family, table, chain,
                    "oif", outInterface,
                    "ip", "daddr", ip,
                    protocol,
                    "dport", portSet,
                    "accept"
                ]);
            }

            return runCommand(["nft", "delete", "rule", family, table, chain, "handle", existingRule.handle])
                .then(() => runCommand([
                    "nft", "insert", "rule", family, table, chain,
                    "oif", outInterface,
                    "ip", "daddr", ip,
                    protocol,
                    "dport", portSet,
                    "accept"
                ]));
        })
        .catch(err => {
            const message = String(err || "");
            if (message.includes("No such file or directory") || message.includes("No such chain")) {
                return null;
            }
            throw err;
        });
}

function findGuestInputAcceptRule(data, ip, protocol, outInterface) {
    if (!data) return null;

    const normalizedProtocol = String(protocol || "").toLowerCase();

    return data
        .split("\n")
        .map(line => line.trim())
        .map(line => parseGuestInputAcceptRule(line, outInterface))
        .filter(Boolean)
        .find(rule => rule.ip === ip && rule.protocol === normalizedProtocol) || null;
}

function parseGuestInputAcceptRule(line, outInterface) {
    if (!line || !line.includes("accept") || !line.includes("handle ")) return null;

    const escapedInterface = escapeRegExp(outInterface);
    const match = line.match(new RegExp(
        `^oif\\s+"${escapedInterface}"\\s+ip\\s+daddr\\s+(\\S+)\\s+(tcp|udp)\\s+dport\\s+(.+?)\\s+accept\\s+#\\s+handle\\s+(\\d+)$`,
        "i"
    ));

    if (!match) return null;

    const [, ip, protocol, portsRaw, handle] = match;
    const ports = parseNftPorts(portsRaw);
    if (ports.length === 0) return null;

    return {
        ip,
        protocol: protocol.toLowerCase(),
        ports,
        handle
    };
}

function parseNftPorts(portsRaw) {
    if (!portsRaw) return [];

    const normalized = portsRaw.trim();
    const value = normalized.startsWith("{") && normalized.endsWith("}")
        ? normalized.slice(1, -1)
        : normalized;

    return value
        .split(",")
        .map(port => port.trim())
        .filter(port => validatePort(port));
}

function mergePorts(existingPorts, newPort) {
    const merged = [...existingPorts.map(String), String(newPort)];
    return Array.from(new Set(merged))
        .filter(port => validatePort(port))
        .sort((left, right) => Number(left) - Number(right));
}

function formatNftPortSet(ports) {
    return `{ ${ports.join(", ")} }`;
}

function escapeRegExp(value) {
    return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// ── Notifications ──────────────────────────────────────────────────────────

function notify(message, type) {
    // type: 'success' | 'error' | 'info'
    const area = document.getElementById("notification-area");
    const icons = { success: "✅", error: "❌", info: "ℹ️" };
    const div = document.createElement("div");
    div.className = `alert alert-${type}`;
    div.innerHTML = `<span>${icons[type] || ""} ${escapeHtml(message)}</span>
        <button class="close" type="button">×</button>`;
    const closeButton = div.querySelector(".close");
    closeButton.addEventListener("click", () => div.remove());
    area.appendChild(div);
    setTimeout(() => { if (div.parentElement) div.remove(); }, 5000);
}

function escapeHtml(str) {
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");
}

// ── Validation ─────────────────────────────────────────────────────────────

const RE_IP   = /^(\d{1,3}\.){3}\d{1,3}$/;
const RE_CIDR = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;
const RE_PORT = /^\d{1,5}$/;

function validateIp(val) { return RE_IP.test(val); }
function validateCidr(val) { return RE_CIDR.test(val) || RE_IP.test(val); }
function validatePort(val) { return RE_PORT.test(val) && +val >= 1 && +val <= 65535; }

function markField(id, valid) {
    const el = document.getElementById(id);
    if (valid) el.classList.remove("invalid");
    else el.classList.add("invalid");
    return valid;
}

function validateDNATForm() {
    const dest   = document.getElementById("dnat_dest_ip").value.trim();
    const port   = document.getElementById("dnat_port").value.trim();
    const toAddr = document.getElementById("dnat_to_addr").value.trim();
    const toPort = document.getElementById("dnat_to_port").value.trim();
    let ok = true;
    ok = markField("dnat_dest_ip", validateIp(dest))   && ok;
    ok = markField("dnat_port",    validatePort(port))  && ok;
    ok = markField("dnat_to_addr", validateIp(toAddr))  && ok;
    ok = markField("dnat_to_port", validatePort(toPort)) && ok;
    return ok;
}

function validateSNATForm() {
    const source   = document.getElementById("snat_source").value.trim();
    const outIface = document.getElementById("snat_out_iface").value.trim();
    const toSource = document.getElementById("snat_to_source").value.trim();
    let ok = true;
    ok = markField("snat_source",    validateCidr(source))  && ok;
    ok = markField("snat_out_iface", outIface.length > 0)   && ok;
    ok = markField("snat_to_source", validateIp(toSource))  && ok;
    return ok;
}

// ── Spinner helpers ────────────────────────────────────────────────────────

function showSpinner(id) { document.getElementById(id).classList.remove("is-hidden"); }
function hideSpinner(id) { document.getElementById(id).classList.add("is-hidden"); }

// ── List rules ─────────────────────────────────────────────────────────────

function refreshRules() {
    listDNAT();
    listSNAT();
}

function listDNAT() {
    const tbody = document.querySelector("#dnat_table tbody");
    showSpinner("dnat_spinner");
    tbody.innerHTML = `<tr class="empty-row"><td colspan="3"><span class="spinner"></span> Загрузка...</td></tr>`;

    // Query each zone for rich rules
    const promises = ZONES.map(zone =>
        runCommand(["firewall-cmd", "--permanent", `--zone=${zone}`, "--list-rich-rules"])
            .then(data => ({ zone, data }))
            .catch(() => ({ zone, data: "" }))
    );

    Promise.all(promises).then(results => {
        hideSpinner("dnat_spinner");
        tbody.innerHTML = "";
        let count = 0;
        results.forEach(({ zone, data }) => {
            if (!data) return;
            data.trim().split("\n").forEach(rule => {
                rule = rule.trim();
                if (!rule || !rule.includes("forward-port")) return;
                count++;
                const row = tbody.insertRow();
                const zoneCell = row.insertCell(0);
                zoneCell.innerHTML = `<span class="badge badge-dnat">${escapeHtml(zone)}</span>`;
                row.insertCell(1).textContent = rule;
                const actionCell = row.insertCell(2);
                const btn = document.createElement("button");
                btn.textContent = "Удалить";
                btn.className = "btn btn-danger";
                btn.onclick = () => removeDNAT(zone, rule, btn);
                actionCell.appendChild(btn);
            });
        });
        if (count === 0) {
            tbody.innerHTML = `<tr class="empty-row"><td colspan="3">Нет DNAT правил</td></tr>`;
        }
    });
}

function listSNAT() {
    const tbody = document.querySelector("#snat_table tbody");
    showSpinner("snat_spinner");
    tbody.innerHTML = `<tr class="empty-row"><td colspan="2"><span class="spinner"></span> Загрузка...</td></tr>`;

    runCommand(["firewall-cmd", "--permanent", "--direct", "--get-all-rules"])
        .then(data => {
            hideSpinner("snat_spinner");
            tbody.innerHTML = "";
            let count = 0;
            if (data) {
                data.trim().split("\n").forEach(rule => {
                    rule = rule.trim();
                    if (!rule || !(rule.includes("nat POSTROUTING") && rule.includes("SNAT"))) return;
                    count++;
                    const row = tbody.insertRow();
                    row.insertCell(0).textContent = rule;
                    const actionCell = row.insertCell(1);
                    const btn = document.createElement("button");
                    btn.textContent = "Удалить";
                    btn.className = "btn btn-danger";
                    btn.onclick = () => removeSNAT(rule, btn);
                    actionCell.appendChild(btn);
                });
            }
            if (count === 0) {
                tbody.innerHTML = `<tr class="empty-row"><td colspan="2">Нет SNAT правил</td></tr>`;
            }
        })
        .catch(err => {
            hideSpinner("snat_spinner");
            tbody.innerHTML = `<tr class="empty-row"><td colspan="2">Ошибка загрузки: ${escapeHtml(String(err))}</td></tr>`;
        });
}

// ── Add rules ──────────────────────────────────────────────────────────────

function addDNAT() {
    if (!validateDNATForm()) {
        notify("Заполните все поля корректно", "error");
        return;
    }

    const dest   = document.getElementById("dnat_dest_ip").value.trim();
    const proto  = document.getElementById("dnat_proto").value;
    const port   = document.getElementById("dnat_port").value.trim();
    const toAddr = document.getElementById("dnat_to_addr").value.trim();
    const toPort = document.getElementById("dnat_to_port").value.trim();
    const zone   = document.getElementById("dnat_zone").value;

    const rule = `rule family="ipv4" destination address="${dest}" forward-port port="${port}" protocol="${proto}" to-addr="${toAddr}" to-port="${toPort}"`;

    const btn = document.getElementById("btn_add_dnat");
    btn.disabled = true;
    btn.textContent = "Добавление...";

    runCommand(["firewall-cmd", "--permanent", `--zone=${zone}`, "--add-rich-rule", rule])
        .then(() => ensureGuestInputAcceptRule(toAddr, proto, toPort))
        .then(() => reloadFirewallAndCleanup())
        .then(() => {
            notify(`DNAT правило добавлено в зону "${zone}"`, "success");
            clearDNATForm();
            refreshRules();
        })
        .catch(err => {
            notify("Ошибка добавления DNAT: " + String(err), "error");
        })
        .finally(() => {
            btn.disabled = false;
            btn.textContent = "Добавить DNAT";
        });
}

function addSNAT() {
    if (!validateSNATForm()) {
        notify("Заполните все поля корректно", "error");
        return;
    }

    const source   = document.getElementById("snat_source").value.trim();
    const outIface = document.getElementById("snat_out_iface").value.trim();
    const toSource = document.getElementById("snat_to_source").value.trim();

    const args = ["ipv4", "nat", "POSTROUTING", "0",
                  "-s", source, "-o", outIface, "-j", "SNAT", "--to-source", toSource];

    const btn = document.getElementById("btn_add_snat");
    btn.disabled = true;
    btn.textContent = "Добавление...";

    runCommand(["firewall-cmd", "--permanent", "--direct", "--add-rule", ...args])
        .then(() => reloadFirewallAndCleanup())
        .then(() => {
            notify("SNAT правило добавлено", "success");
            clearSNATForm();
            refreshRules();
        })
        .catch(err => {
            notify("Ошибка добавления SNAT: " + String(err), "error");
        })
        .finally(() => {
            btn.disabled = false;
            btn.textContent = "Добавить SNAT";
        });
}

// ── Remove rules ───────────────────────────────────────────────────────────

function removeDNAT(zone, rule, btn) {
    if (!confirm(`Удалить DNAT правило из зоны "${zone}"?\n\n${rule}`)) return;
    btn.disabled = true;
    btn.textContent = "...";

    runCommand(["firewall-cmd", "--permanent", `--zone=${zone}`, "--remove-rich-rule", rule])
        .then(() => reloadFirewallAndCleanup())
        .then(() => {
            notify("DNAT правило удалено", "success");
            refreshRules();
        })
        .catch(err => {
            notify("Ошибка удаления DNAT: " + String(err), "error");
            btn.disabled = false;
            btn.textContent = "Удалить";
        });
}

function removeSNAT(rule, btn) {
    if (!confirm(`Удалить SNAT правило?\n\n${rule}`)) return;
    btn.disabled = true;
    btn.textContent = "...";

    // rule format: "ipv4 nat POSTROUTING 0 -s ... -o ... -j SNAT --to-source ..."
    const parts = rule.trim().split(/\s+/);

    runCommand(["firewall-cmd", "--permanent", "--direct", "--remove-rule", ...parts])
        .then(() => reloadFirewallAndCleanup())
        .then(() => {
            notify("SNAT правило удалено", "success");
            refreshRules();
        })
        .catch(err => {
            notify("Ошибка удаления SNAT: " + String(err), "error");
            btn.disabled = false;
            btn.textContent = "Удалить";
        });
}

// ── Clear forms ────────────────────────────────────────────────────────────

function clearDNATForm() {
    ["dnat_dest_ip", "dnat_port", "dnat_to_addr", "dnat_to_port"].forEach(id => {
        const el = document.getElementById(id);
        el.value = "";
        el.classList.remove("invalid");
    });
}

function clearSNATForm() {
    ["snat_source", "snat_out_iface", "snat_to_source"].forEach(id => {
        const el = document.getElementById(id);
        el.value = "";
        el.classList.remove("invalid");
    });
}

// ── Init ───────────────────────────────────────────────────────────────────

document.addEventListener("DOMContentLoaded", () => {
    document.getElementById("btn_add_dnat").addEventListener("click", addDNAT);
    document.getElementById("btn_add_snat").addEventListener("click", addSNAT);
    document.getElementById("btn_refresh").addEventListener("click", refreshRules);
    refreshRules();
});
