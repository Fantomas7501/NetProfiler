/* NetProfiler SPA — Auth, Interactive Network Map, Asset Port Profiling, Query Table, User & Config Management */

(function () {
    "use strict";

    // =========================================================================
    // STATE
    // =========================================================================
    const state = {
        user: null,
        pwBannerDismissed: false,
        networks: [],
        currentNetworkId: null,
        sessions: [],
        currentSessionId: null,
        scanSession: null,
        stats: {
            total_devices: 0,
            total_ports: 0,
            unique_services: 0,
            new_ports_count: 0,
            high_risk_ports: 0,
        },
        devices: [],
        selectedAssetIp: null,
        assetDetailCache: null,

        // View-specific filters
        map: {
            search: "",
            category: "all",
            openOnly: false,
            newOnly: false,
            layout: "radial", // radial | tiers | grid
            zoom: 1,
            panX: 0,
            panY: 0,
            customPositions: {},
        },
        query: {
            search: "",
            openOnly: false,
            viewMode: "cards", // cards | hosts | ports
        },
        assetFilter: {
            search: "",
            protocol: "all",
            risk: "all",
            newOnly: false,
            expandedPorts: {},
        },
        users: [],
        usersFilter: {
            search: "",
            role: "all",
        },
        config: null,
        accountData: null,
    };

    const ROLE_LABELS = {
        admin: "Administrateur",
        analyst: "Analyste",
        viewer: "Lecteur",
    };

    const CATEGORY_META = {
        router: { label: "Routeur / Passerelle", group: "infra" },
        switch: { label: "Commutateur", group: "infra" },
        server: { label: "Serveur", group: "servers" },
        database: { label: "Base de données", group: "servers" },
        storage: { label: "Stockage / NAS", group: "storage" },
        workstation: { label: "Poste de travail", group: "endpoints" },
        printer: { label: "Imprimante", group: "iot" },
        camera: { label: "Caméra IP", group: "iot" },
        unknown: { label: "Équipement réseau", group: "endpoints" },
    };

    // =========================================================================
    // UTILITIES
    // =========================================================================
    function esc(value) {
        if (value === null || value === undefined) return "";
        return String(value)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#39;");
    }

    function formatDate(isoStr) {
        if (!isoStr) return "Jamais";
        const d = new Date(isoStr);
        if (Number.isNaN(d.getTime())) return isoStr;
        return d.toLocaleString("fr-FR", {
            day: "2-digit",
            month: "2-digit",
            year: "numeric",
            hour: "2-digit",
            minute: "2-digit",
        });
    }

    function inferDeviceType(dev) {
        if (dev.device_type && CATEGORY_META[dev.device_type] && dev.device_type !== "unknown") {
            return dev.device_type;
        }
        const hay = `${dev.hostname || ""} ${dev.vendor || ""} ${dev.os || ""}`.toLowerCase();
        const portNums = new Set((dev.ports || []).map((p) => Number(p.port)));
        if (dev.ip && (dev.ip.endsWith(".1") || dev.ip.endsWith(".254")) || /router|gw-|gateway|unifi|pfsense|opnsense|mikrotik|fritz/.test(hay)) {
            return "router";
        }
        if (/switch|catalyst|sw-|aruba|netgear/.test(hay)) return "switch";
        if (/synology|qnap|truenas|nas/.test(hay)) return "storage";
        if (/printer|laserjet|hp inc|brother|epson|canon/.test(hay) || portNums.has(9100) || portNums.has(631)) return "printer";
        if (/cam|axis|hikvision|dahua|rtsp/.test(hay) || portNums.has(554)) return "camera";
        if (/postgres|mysql|mongo|redis|db-/.test(hay) || portNums.has(5432) || portNums.has(3306)) return "database";
        if (/windows 10|windows 11|macos|macbook|iphone|android|wkst/.test(hay)) return "workstation";
        if (/ubuntu|debian|proxmox|linux|centos|redhat|vmware|qemu|srv-|server|pihole|dns/.test(hay)) return "server";
        return "unknown";
    }

    function inferPortRisk(port) {
        if (port.risk_level && ["low", "medium", "high"].includes(port.risk_level)) {
            return port.risk_level;
        }
        const num = Number(port.port);
        if ([21, 23, 69, 6379, 27017, 9200].includes(num)) return "high";
        if ([22, 445, 3389, 3306, 5432, 8080, 9100].includes(num)) return "medium";
        return "low";
    }

    function getAssetStatus(dev) {
        const ports = dev.ports || [];
        if (ports.some((p) => inferPortRisk(p) === "high")) {
            return { level: "danger", color: "#f43f5e", label: "Risque élevé" };
        }
        if (ports.some((p) => p.is_new)) {
            return { level: "warning", color: "#f59e0b", label: "Nouveau port" };
        }
        if (ports.length > 0) {
            return { level: "ok", color: "#10b981", label: "Exposé" };
        }
        return { level: "quiet", color: "#64748b", label: "Aucun port ouvert" };
    }

    function showToast(message, type = "info") {
        const container = document.getElementById("toast-container");
        const el = document.createElement("div");
        el.className = `toast toast--${type}`;
        el.textContent = message;
        container.appendChild(el);
        setTimeout(() => {
            el.style.opacity = "0";
            el.style.transition = "opacity 200ms ease";
            setTimeout(() => el.remove(), 220);
        }, 3600);
    }

    function showError(msg) {
        const box = document.getElementById("error-box");
        box.textContent = msg;
        box.classList.remove("hidden");
    }

    function hideError() {
        document.getElementById("error-box").classList.add("hidden");
    }

    async function copyToClipboard(text, label = "Copié") {
        try {
            await navigator.clipboard.writeText(text);
            showToast(`${label} : ${text}`, "success");
        } catch {
            showToast("Copie impossible dans ce navigateur.", "error");
        }
    }

    // =========================================================================
    // API CLIENT
    // =========================================================================
    async function apiFetch(url, options = {}) {
        const headers = Object.assign({}, options.headers || {});
        if (options.body && !(options.body instanceof FormData) && !headers["Content-Type"]) {
            headers["Content-Type"] = "application/json";
        }
        const res = await fetch(url, {
            credentials: "same-origin",
            ...options,
            headers,
        });

        if (res.status === 401 && !url.startsWith("/api/auth/login")) {
            handleUnauthorized();
            throw new Error("Session expirée. Veuillez vous reconnecter.");
        }

        let data = null;
        const text = await res.text();
        if (text) {
            try {
                data = JSON.parse(text);
            } catch {
                data = { detail: text };
            }
        }

        if (!res.ok) {
            const errMsg = (data && (data.detail || data.error)) || `Erreur HTTP ${res.status}`;
            throw new Error(errMsg);
        }
        return data;
    }

    function handleUnauthorized() {
        state.user = null;
        document.getElementById("app-shell").classList.add("hidden");
        document.getElementById("auth-screen").classList.remove("hidden");
        closeModal();
    }

    // =========================================================================
    // AUTHENTICATION UI
    // =========================================================================
    async function checkAuthAndBoot() {
        try {
            const statusData = await apiFetch("/api/auth/status");
            if (statusData.authenticated && statusData.user) {
                enterAuthenticatedApp(statusData.user);
            } else {
                handleUnauthorized();
            }
        } catch {
            handleUnauthorized();
        }
    }

    async function enterAuthenticatedApp(user) {
        state.user = user;
        document.getElementById("auth-screen").classList.add("hidden");
        document.getElementById("app-shell").classList.remove("hidden");
        updateUserChrome();

        if (!window.location.hash || window.location.hash === "#/" || window.location.hash === "#") {
            window.location.hash = "#/map";
        }

        await loadNetworks();
        renderCurrentRoute();
    }

    function updateUserChrome() {
        const u = state.user;
        if (!u) return;

        const initials = (u.display_name || u.username || "U")
            .split(/\s+/)
            .map((w) => w[0])
            .join("")
            .slice(0, 2)
            .toUpperCase();

        document.getElementById("sidebar-avatar").textContent = initials;
        document.getElementById("sidebar-username").textContent = u.display_name || u.username;
        document.getElementById("sidebar-role").textContent = ROLE_LABELS[u.role] || u.role;

        // Show/hide admin-only Users menu item
        const navUsers = document.getElementById("nav-users");
        navUsers.classList.toggle("hidden", u.role !== "admin");

        // Default password reminder
        const pwBanner = document.getElementById("pw-rotation-banner");
        pwBanner.classList.toggle("hidden", !u.must_change_password || state.pwBannerDismissed);
    }

    // =========================================================================
    // NETWORKS & SCAN DATA LOADING
    // =========================================================================
    function getCurrentNetwork() {
        if (state.currentNetworkId === null) return null;
        return state.networks.find((n) => String(n.id) === String(state.currentNetworkId)) || null;
    }

    async function loadNetworks(preferredNetworkId = null, preserveSessionId = null) {
        try {
            const nets = await apiFetch("/api/networks");
            state.networks = Array.isArray(nets) ? nets : [];

            const desired = preferredNetworkId !== null ? preferredNetworkId : state.currentNetworkId;
            if (desired !== null && state.networks.some((n) => String(n.id) === String(desired))) {
                state.currentNetworkId = Number(desired);
            } else if (state.networks.length > 0) {
                state.currentNetworkId = state.networks[0].id;
            } else {
                state.currentNetworkId = null;
            }

            await loadSessions(preserveSessionId);
        } catch (err) {
            showError(err.message || "Impossible de charger la liste des réseaux.");
        }
    }

    async function selectNetwork(networkId, goToRoute = null) {
        state.currentNetworkId = Number(networkId);
        state.selectedAssetIp = null;
        state.map.zoom = 1;
        state.map.panX = 0;
        state.map.panY = 0;
        state.map.customPositions = {};
        await loadSessions(null);
        if (goToRoute) {
            navigate(goToRoute);
        } else {
            renderCurrentRoute();
        }
    }

    function updateChromeBadges() {
        const net = getCurrentNetwork();
        const subnet = net ? net.cidr : state.scanSession ? state.scanSession.subnet : "Aucun sous-réseau";
        document.getElementById("sidebar-subnet").textContent = net ? `${net.name} • ${net.cidr}` : subnet;

        if (state.scanSession) {
            const label = net ? `${net.name} (${net.cidr})` : `Sous-réseau : ${state.scanSession.subnet}`;
            document.getElementById("subnet-badge").textContent =
                `${label} • Scan #${state.scanSession.id} • ${formatDate(state.scanSession.scan_time)}`;
        } else if (net) {
            document.getElementById("subnet-badge").textContent = `${net.name} (${net.cidr}) • Aucun scan enregistré`;
        } else {
            document.getElementById("subnet-badge").textContent = "Aucune session de scan";
        }
        document.getElementById("nav-badge-devices").textContent = state.stats.total_devices ?? 0;
        document.getElementById("nav-badge-ports").textContent = state.stats.total_ports ?? 0;
    }

    async function loadSessions(preserveSessionId = null) {
        try {
            const qs =
                state.currentNetworkId !== null
                    ? `?network_id=${encodeURIComponent(state.currentNetworkId)}`
                    : "";
            const sessions = await apiFetch(`/api/sessions${qs}`);
            state.sessions = Array.isArray(sessions) ? sessions : [];
            const select = document.getElementById("session-select");
            select.innerHTML = "";

            if (state.sessions.length === 0) {
                const opt = document.createElement("option");
                opt.value = "";
                opt.textContent = "Aucun scan pour ce réseau";
                select.appendChild(opt);
                state.currentSessionId = null;
                state.scanSession = null;
                state.devices = [];
                state.stats = {
                    total_devices: 0,
                    total_ports: 0,
                    unique_services: 0,
                    new_ports_count: 0,
                    high_risk_ports: 0,
                };
                hideError();
                updateChromeBadges();
                return;
            }

            state.sessions.forEach((s, idx) => {
                const opt = document.createElement("option");
                opt.value = s.id;
                opt.textContent =
                    idx === 0
                        ? `Dernier scan (${formatDate(s.scan_time)})`
                        : `${formatDate(s.scan_time)} — ${s.hosts_up} hôtes`;
                select.appendChild(opt);
            });

            const targetId =
                preserveSessionId && state.sessions.some((s) => String(s.id) === String(preserveSessionId))
                    ? preserveSessionId
                    : state.sessions[0].id;

            select.value = String(targetId);
            await loadScanData(targetId);
        } catch (err) {
            showError(err.message || "Impossible de charger l'historique des scans.");
        }
    }

    async function loadScanData(sessionId = null) {
        try {
            const params = new URLSearchParams();
            if (sessionId) params.set("session_id", String(sessionId));
            else if (state.currentNetworkId !== null) params.set("network_id", String(state.currentNetworkId));
            const qs = params.toString() ? `?${params.toString()}` : "";

            const data = await apiFetch(`/api/data${qs}`);
            hideError();

            state.currentSessionId = data.session ? data.session.id : sessionId;
            state.scanSession = data.session || null;
            state.stats = data.stats || {
                total_devices: 0,
                total_ports: 0,
                unique_services: 0,
                new_ports_count: 0,
                high_risk_ports: 0,
            };
            state.devices = data.devices || [];
            state.assetDetailCache = null;

            updateChromeBadges();
        } catch (err) {
            showError(err.message || "Erreur lors du chargement des données du scan.");
        }
    }

    // =========================================================================
    // ROUTER
    // =========================================================================
    function parseHashRoute() {
        const raw = (window.location.hash || "#/map").replace(/^#\/?/, "");
        const parts = raw.split("/").filter(Boolean);
        const route = parts[0] || "map";
        const param = parts[1] ? decodeURIComponent(parts[1]) : null;
        return { route, param };
    }

    function navigate(hashPath) {
        if (window.location.hash === hashPath) {
            renderCurrentRoute();
        } else {
            window.location.hash = hashPath;
        }
    }

    function closeMobileSidebar() {
        document.getElementById("sidebar").classList.remove("open");
        document.getElementById("sidebar-backdrop").classList.remove("open");
    }

    function renderCurrentRoute() {
        if (!state.user) return;
        closeMobileSidebar();

        const { route, param } = parseHashRoute();

        // Update sidebar active highlight
        document.querySelectorAll(".sidebar-nav .nav-item").forEach((el) => {
            el.classList.toggle("active", el.dataset.route === route);
        });

        const titleEl = document.getElementById("topbar-title");
        const titles = {
            map: "Cartographie Réseau",
            asset: "Détails de l'actif & Ports exposés",
            query: "Requête & Inventaire Réseau",
            users: "Gestion des utilisateurs",
            config: "Configuration de la plateforme",
            account: "Mon compte & Sécurité",
        };
        titleEl.textContent = titles[route] || "NetProfiler";
        document.title = `NetProfiler — ${titles[route] || "Réseau"}`;

        switch (route) {
            case "map":
                renderMapView();
                break;
            case "asset":
                renderAssetDetailView(param);
                break;
            case "query":
                renderQueryView();
                break;
            case "users":
                if (state.user.role !== "admin") {
                    showToast("Accès réservé aux administrateurs.", "error");
                    navigate("#/map");
                    return;
                }
                renderUsersView();
                break;
            case "config":
                renderConfigView();
                break;
            case "account":
                renderAccountView();
                break;
            default:
                navigate("#/map");
        }
    }

    // =========================================================================
    // VIEW 1: LANDING PAGE — INTERACTIVE NETWORK TOPOLOGY MAP (#/map)
    // =========================================================================
    function getDeviceIconPath(type) {
        switch (type) {
            case "router":
                return `<path d="M5 12h14M12 5l7 7-7 7M8 9l-3 3 3 3" stroke-linecap="round" stroke-linejoin="round"/>`;
            case "switch":
                return `<rect x="3" y="8" width="18" height="8" rx="2"/><path d="M7 12h.01M11 12h.01M15 12h.01M17 12h.01" stroke-linecap="round"/>`;
            case "server":
                return `<rect x="4" y="4" width="16" height="6" rx="1.5"/><rect x="4" y="14" width="16" height="6" rx="1.5"/><path d="M8 7h.01M8 17h.01" stroke-linecap="round"/>`;
            case "database":
                return `<ellipse cx="12" cy="6" rx="7" ry="3"/><path d="M5 6v12c0 1.66 3.13 3 7 3s7-1.34 7-3V6M5 12c0 1.66 3.13 3 7 3s7-1.34 7-3"/>`;
            case "storage":
                return `<rect x="4" y="4" width="16" height="16" rx="2"/><path d="M8 8h8M8 12h8M8 16h4" stroke-linecap="round"/>`;
            case "printer":
                return `<path d="M6 9V4h12v5M6 18H4a2 2 0 01-2-2v-5a2 2 0 012-2h16a2 2 0 012 2v5a2 2 0 01-2 2h-2"/><rect x="6" y="14" width="12" height="6" rx="1"/>`;
            case "camera":
                return `<path d="M23 7l-7 5 7 5V7z"/><rect x="1" y="5" width="15" height="14" rx="2"/>`;
            case "workstation":
            default:
                return `<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4" stroke-linecap="round"/>`;
        }
    }

    function filterMapDevices() {
        const q = state.map.search.trim().toLowerCase();
        const cat = state.map.category;
        return state.devices.filter((dev) => {
            const devType = inferDeviceType(dev);
            const group = (CATEGORY_META[devType] || CATEGORY_META.unknown).group;
            if (cat !== "all" && group !== cat) return false;
            if (state.map.openOnly && (!dev.ports || dev.ports.length === 0)) return false;
            if (state.map.newOnly && !(dev.ports || []).some((p) => p.is_new)) return false;
            if (!q) return true;
            const hostMatch =
                (dev.ip || "").toLowerCase().includes(q) ||
                (dev.hostname || "").toLowerCase().includes(q) ||
                (dev.vendor || "").toLowerCase().includes(q) ||
                (dev.mac || "").toLowerCase().includes(q) ||
                (dev.os || "").toLowerCase().includes(q);
            const portMatch = (dev.ports || []).some(
                (p) =>
                    String(p.port).includes(q) ||
                    (p.service || "").toLowerCase().includes(q) ||
                    (p.product || "").toLowerCase().includes(q)
            );
            return hostMatch || portMatch;
        });
    }

    function computeMapLayout(devices, width, height) {
        const cx = width / 2;
        const cy = height / 2;
        const nodes = [];
        const links = [];

        if (devices.length === 0) return { nodes, links, hub: null };

        // Identify gateway/router hub if present
        let hubDev = devices.find((d) => inferDeviceType(d) === "router");
        if (!hubDev) {
            hubDev = devices.find((d) => d.ip.endsWith(".1") || d.ip.endsWith(".254"));
        }

        const layout = state.map.layout;

        if (layout === "radial") {
            const others = hubDev ? devices.filter((d) => d.ip !== hubDev.ip) : devices;
            let hubNode;

            if (hubDev) {
                const custom = state.map.customPositions[hubDev.ip];
                hubNode = {
                    id: hubDev.ip,
                    x: custom ? custom.x : cx,
                    y: custom ? custom.y : cy,
                    isVirtualHub: false,
                    device: hubDev,
                };
                nodes.push(hubNode);
            } else {
                hubNode = {
                    id: "__subnet_hub__",
                    x: cx,
                    y: cy,
                    isVirtualHub: true,
                    label: state.scanSession ? state.scanSession.subnet : "Sous-réseau",
                };
                nodes.push(hubNode);
            }

            const innerCount = Math.min(others.length, 10);
            const outerCount = Math.max(0, others.length - innerCount);
            const rInner = Math.min(width, height) * (outerCount > 0 ? 0.25 : 0.31);
            const rOuter = Math.min(width, height) * 0.39;

            others.forEach((dev, idx) => {
                let x, y;
                if (idx < innerCount) {
                    const angle = (2 * Math.PI * idx) / innerCount - Math.PI / 2;
                    x = cx + rInner * Math.cos(angle) * 1.25;
                    y = cy + rInner * Math.sin(angle);
                } else {
                    const oIdx = idx - innerCount;
                    const angle = (2 * Math.PI * oIdx) / outerCount - Math.PI / 2 + Math.PI / outerCount;
                    x = cx + rOuter * Math.cos(angle) * 1.25;
                    y = cy + rOuter * Math.sin(angle);
                }
                const custom = state.map.customPositions[dev.ip];
                const node = {
                    id: dev.ip,
                    x: custom ? custom.x : x,
                    y: custom ? custom.y : y,
                    isVirtualHub: false,
                    device: dev,
                };
                nodes.push(node);
                links.push({
                    source: hubNode,
                    target: node,
                    hasAlert: (dev.ports || []).some((p) => p.is_new || inferPortRisk(p) === "high"),
                });
            });
            return { nodes, links, hub: hubNode };
        }

        if (layout === "tiers") {
            const tiers = {
                infra: [],
                servers: [],
                storage: [],
                endpoints: [],
                iot: [],
            };
            devices.forEach((dev) => {
                const g = (CATEGORY_META[inferDeviceType(dev)] || CATEGORY_META.unknown).group;
                tiers[g].push(dev);
            });
            const nonEmpty = Object.entries(tiers).filter(([, list]) => list.length > 0);
            const rowGap = height / (nonEmpty.length + 1);
            const nodeMap = {};

            nonEmpty.forEach(([, list], rIdx) => {
                const y = rowGap * (rIdx + 1);
                const colGap = width / (list.length + 1);
                list.forEach((dev, cIdx) => {
                    const custom = state.map.customPositions[dev.ip];
                    const node = {
                        id: dev.ip,
                        x: custom ? custom.x : colGap * (cIdx + 1),
                        y: custom ? custom.y : y,
                        isVirtualHub: false,
                        device: dev,
                    };
                    nodes.push(node);
                    nodeMap[dev.ip] = node;
                });
            });

            const rootNode = (hubDev && nodeMap[hubDev.ip]) || nodes[0];
            nodes.forEach((n) => {
                if (n.id !== rootNode.id) {
                    links.push({
                        source: rootNode,
                        target: n,
                        hasAlert: (n.device.ports || []).some((p) => p.is_new || inferPortRisk(p) === "high"),
                    });
                }
            });
            return { nodes, links, hub: rootNode };
        }

        // Grid layout
        const cols = Math.max(3, Math.ceil(Math.sqrt(devices.length * 1.4)));
        const rows = Math.ceil(devices.length / cols);
        const padX = 110;
        const padY = 85;
        const stepX = cols > 1 ? (width - padX * 2) / (cols - 1) : 0;
        const stepY = rows > 1 ? (height - padY * 2) / (rows - 1) : 0;

        devices.forEach((dev, idx) => {
            const col = idx % cols;
            const row = Math.floor(idx / cols);
            const custom = state.map.customPositions[dev.ip];
            nodes.push({
                id: dev.ip,
                x: custom ? custom.x : padX + col * stepX,
                y: custom ? custom.y : padY + row * stepY,
                isVirtualHub: false,
                device: dev,
            });
        });

        return { nodes, links, hub: null };
    }

    function renderMapView() {
        const root = document.getElementById("view-root");
        const filtered = filterMapDevices();
        const activeNet = getCurrentNetwork();
        const isAdmin = state.user && state.user.role === "admin";
        const canScan = state.user && (state.user.role === "admin" || state.user.role === "analyst");

        const categories = [
            { id: "all", label: "Tous" },
            { id: "infra", label: "Infrastructure" },
            { id: "servers", label: "Serveurs & DB" },
            { id: "storage", label: "Stockage" },
            { id: "endpoints", label: "Postes" },
            { id: "iot", label: "IoT & Périph." },
        ];

        const networkSelectorHtml =
            state.networks.length > 0
                ? `
            <section class="network-selector-bar" aria-label="Sélection du réseau à cartographier">
                <div class="network-selector-head">
                    <div style="display:flex; align-items:center; gap:12px; flex-wrap:wrap;">
                        <div>
                            <h2 class="card-title" style="font-size:14px;">Carte du réseau affiché</h2>
                            <p class="card-subtitle" style="font-size:12px;">Sélectionnez un réseau configuré pour afficher sa topologie et ses actifs découverts.</p>
                        </div>
                        <select id="map-network-select" class="select" style="width:270px; padding:6px 10px; font-size:12.5px;" aria-label="Choisir le réseau">
                            ${state.networks
                                .map(
                                    (n) =>
                                        `<option value="${n.id}" ${String(n.id) === String(state.currentNetworkId) ? "selected" : ""}>${esc(n.name)} (${esc(n.cidr)}) — ${n.last_hosts_up} actif(s)</option>`
                                )
                                .join("")}
                        </select>
                    </div>
                    <div style="display:flex; align-items:center; gap:8px; flex-wrap:wrap;">
                        ${
                            canScan && activeNet
                                ? `<button type="button" id="map-scan-network-btn" class="btn btn-secondary btn-sm">Scanner ce réseau</button>`
                                : ""
                        }
                        ${
                            isAdmin
                                ? `<a href="#/config" class="btn btn-secondary btn-sm">+ Gérer les réseaux</a>`
                                : ""
                        }
                    </div>
                </div>

                <div class="network-tab-grid">
                    ${state.networks
                        .map((n) => {
                            const isActive = String(n.id) === String(state.currentNetworkId);
                            return `
                                <button type="button" class="network-tab ${isActive ? "active" : ""}" data-select-network="${n.id}">
                                    <div class="network-tab-top">
                                        <span class="network-tab-name">${esc(n.name)}</span>
                                        <span class="badge ${n.enabled ? "badge-success" : "badge-neutral"}" style="font-size:10px;">${n.enabled ? "Actif" : "En pause"}</span>
                                    </div>
                                    <div class="network-tab-cidr">${esc(n.cidr)}</div>
                                    <div class="network-tab-meta">
                                        <span><strong style="color:var(--text-primary);">${n.last_hosts_up}</strong> actif(s) • <strong style="color:var(--accent-hover);">${n.last_ports_count}</strong> port(s)</span>
                                        <span>${n.scan_count} scan(s)</span>
                                    </div>
                                </button>
                            `;
                        })
                        .join("")}
                </div>
            </section>`
                : `
            <div class="banner banner-info">
                <span>Aucun réseau configuré. ${isAdmin ? "Ajoutez un premier sous-réseau dans la page Configuration." : "Contactez un administrateur."}</span>
                ${isAdmin ? `<a href="#/config" class="btn btn-sm btn-primary">Ajouter un réseau</a>` : ""}
            </div>`;

        root.innerHTML = `
            <!-- Network Selector -->
            ${networkSelectorHtml}

            <!-- KPI Summary Row -->
            <div class="kpi-grid">
                <div class="kpi-card">
                    <div class="kpi-label">Appareils Découverts</div>
                    <div class="kpi-value">${state.stats.total_devices ?? 0}</div>
                </div>
                <div class="kpi-card">
                    <div class="kpi-label">Ports Exposés</div>
                    <div class="kpi-value kpi-value--accent">${state.stats.total_ports ?? 0}</div>
                </div>
                <div class="kpi-card">
                    <div class="kpi-label">Services Distincts</div>
                    <div class="kpi-value kpi-value--success">${state.stats.unique_services ?? 0}</div>
                </div>
                <div class="kpi-card kpi-card--interactive" id="kpi-new-ports" title="Cliquer pour filtrer les actifs avec nouveaux ports">
                    <div class="kpi-label">Nouveaux Ports (vs -1h)</div>
                    <div class="kpi-value kpi-value--warning">${state.stats.new_ports_count ?? 0}</div>
                </div>
            </div>

            <!-- Interactive Network Topology Map -->
            <section class="card map-card" aria-label="Carte topologique du réseau">
                <div class="map-toolbar">
                    <div class="map-toolbar-group" style="flex:1; min-width: 240px;">
                        <div class="search-box" style="max-width: 310px;">
                            <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
                            </svg>
                            <input id="map-search" type="text" class="input" placeholder="Filtrer la carte (IP, hôte, port, service)..." value="${esc(state.map.search)}">
                        </div>
                        <div class="chip-bar" id="map-category-chips">
                            ${categories
                                .map(
                                    (c) => `<button type="button" class="chip ${state.map.category === c.id ? "active" : ""}" data-cat="${c.id}">${c.label}</button>`
                                )
                                .join("")}
                        </div>
                    </div>

                    <div class="map-toolbar-group">
                        <label class="switch">
                            <input id="map-open-only" type="checkbox" ${state.map.openOnly ? "checked" : ""}>
                            <span class="switch-track"></span>
                            <span>Ports ouverts</span>
                        </label>
                        <label class="switch">
                            <input id="map-new-only" type="checkbox" ${state.map.newOnly ? "checked" : ""}>
                            <span class="switch-track"></span>
                            <span>Nouveaux</span>
                        </label>
                        <div class="segmented-control" aria-label="Disposition de la carte">
                            <button type="button" class="segmented-btn ${state.map.layout === "radial" ? "active" : ""}" data-layout="radial">Étoile</button>
                            <button type="button" class="segmented-btn ${state.map.layout === "tiers" ? "active" : ""}" data-layout="tiers">Rôles</button>
                            <button type="button" class="segmented-btn ${state.map.layout === "grid" ? "active" : ""}" data-layout="grid">Grille</button>
                        </div>
                    </div>
                </div>

                <div id="map-viewport" class="map-viewport">
                    <svg id="map-svg" class="map-svg" role="img" aria-label="Topologie des actifs découverts"></svg>
                    <div id="map-tooltip" class="map-tooltip hidden"></div>

                    <div class="map-controls-floating">
                        <button type="button" id="map-zoom-in" class="btn btn-secondary btn-icon" title="Zoomer" aria-label="Zoomer">+</button>
                        <button type="button" id="map-zoom-out" class="btn btn-secondary btn-icon" title="Dézoomer" aria-label="Dézoomer">−</button>
                        <button type="button" id="map-reset" class="btn btn-secondary btn-icon" title="Recadrer la vue" aria-label="Recadrer">
                            <svg width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" d="M4 8V4h4M20 8V4h-4M4 16v4h4M20 16v4h-4"/>
                            </svg>
                        </button>
                    </div>
                </div>

                <div class="map-footer">
                    <div class="legend">
                        <span class="legend-item"><span class="status-dot status-dot--up"></span> Actif (normal)</span>
                        <span class="legend-item"><span class="status-dot status-dot--warn"></span> Nouveau port détecté</span>
                        <span class="legend-item"><span class="status-dot status-dot--danger"></span> Port à risque élevé</span>
                        <span class="legend-item"><span class="status-dot status-dot--muted"></span> 0 port ouvert</span>
                    </div>
                    <div>
                        <strong>${filtered.length}</strong> / ${state.devices.length} actif(s) affiché(s) — Cliquez sur un équipement pour ouvrir ses ports et son profilage.
                    </div>
                </div>
            </section>

            <!-- Quick-Access Asset Strip (Keyboard & Mobile Friendly) -->
            <section>
                <div class="card-header" style="margin-bottom: 12px;">
                    <div>
                        <h2 class="card-title">Accès rapide aux actifs découverts${activeNet ? ` — ${esc(activeNet.name)}` : ""}</h2>
                        <p class="card-subtitle">Cliquez sur une carte ou un nœud ci-dessus pour afficher le profilage complet des ports.</p>
                    </div>
                    <a href="#/query" class="btn btn-secondary btn-sm">Ouvrir la vue Requête &amp; Tableau →</a>
                </div>
                <div class="asset-strip-grid" id="map-asset-strip">
                    ${
                        filtered.length === 0
                            ? `<div class="empty-state" style="grid-column:1/-1;">
                                   ${state.devices.length === 0
                                       ? `Aucun actif enregistré pour ce réseau (${activeNet ? esc(activeNet.cidr) : "—"}). Lancez un scan pour découvrir les hôtes.`
                                       : "Aucun actif ne correspond aux filtres actifs."}
                               </div>`
                            : filtered
                                  .map((dev) => {
                                      const st = getAssetStatus(dev);
                                      const type = inferDeviceType(dev);
                                      const newCnt = (dev.ports || []).filter((p) => p.is_new).length;
                                      return `
                                        <div class="asset-mini-card" data-open-asset="${esc(dev.ip)}" tabindex="0" role="button">
                                            <div style="display:flex; align-items:center; justify-content:space-between; gap:8px;">
                                                <div style="display:flex; align-items:center; gap:8px; min-width:0;">
                                                    <span class="status-dot" style="background:${st.color}"></span>
                                                    <span class="mono" style="font-weight:700; font-size:13.5px;">${esc(dev.ip)}</span>
                                                </div>
                                                <span class="badge ${newCnt > 0 ? "badge-warning" : "badge-accent"}">${(dev.ports || []).length} port(s)</span>
                                            </div>
                                            <div style="font-size:12.5px; color:var(--text-primary); font-weight:500; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">
                                                ${esc(dev.hostname)}
                                            </div>
                                            <div style="font-size:11.5px; color:var(--text-muted); display:flex; justify-content:space-between; gap:6px;">
                                                <span style="white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">${esc((CATEGORY_META[type] || CATEGORY_META.unknown).label)}</span>
                                                <span>${esc(dev.vendor.split(" ")[0])}</span>
                                            </div>
                                        </div>
                                      `;
                                  })
                                  .join("")
                    }
                </div>
            </section>
        `;

        // Wire network selector controls
        const netSelect = document.getElementById("map-network-select");
        if (netSelect) {
            netSelect.addEventListener("change", (e) => {
                selectNetwork(e.target.value);
            });
        }
        document.querySelectorAll("[data-select-network]").forEach((btn) => {
            btn.addEventListener("click", () => {
                selectNetwork(btn.dataset.selectNetwork);
            });
        });
        const mapScanBtn = document.getElementById("map-scan-network-btn");
        if (mapScanBtn && activeNet) {
            mapScanBtn.addEventListener("click", async () => {
                mapScanBtn.disabled = true;
                mapScanBtn.textContent = "Scan en cours...";
                try {
                    const res = await apiFetch(`/api/networks/${activeNet.id}/scan`, { method: "POST" });
                    showToast(`Scan #${res.session.id} enregistré pour ${activeNet.name}.`, "success");
                    await loadNetworks(activeNet.id, res.session.id);
                    renderCurrentRoute();
                } catch (err) {
                    showToast(err.message, "error");
                    mapScanBtn.disabled = false;
                    mapScanBtn.textContent = "Scanner ce réseau";
                }
            });
        }

        // Wire toolbar controls
        document.getElementById("map-search").addEventListener("input", (e) => {
            state.map.search = e.target.value;
            renderMapView();
            const input = document.getElementById("map-search");
            if (input) {
                input.focus();
                input.setSelectionRange(input.value.length, input.value.length);
            }
        });

        document.querySelectorAll("#map-category-chips .chip").forEach((btn) => {
            btn.addEventListener("click", () => {
                state.map.category = btn.dataset.cat;
                state.map.customPositions = {};
                renderMapView();
            });
        });

        document.getElementById("map-open-only").addEventListener("change", (e) => {
            state.map.openOnly = e.target.checked;
            renderMapView();
        });

        document.getElementById("map-new-only").addEventListener("change", (e) => {
            state.map.newOnly = e.target.checked;
            renderMapView();
        });

        document.getElementById("kpi-new-ports").addEventListener("click", () => {
            state.map.newOnly = !state.map.newOnly;
            renderMapView();
        });

        document.querySelectorAll("[data-layout]").forEach((btn) => {
            btn.addEventListener("click", () => {
                state.map.layout = btn.dataset.layout;
                state.map.customPositions = {};
                state.map.zoom = 1;
                state.map.panX = 0;
                state.map.panY = 0;
                renderMapView();
            });
        });

        document.querySelectorAll("[data-open-asset]").forEach((el) => {
            const open = () => navigate(`#/asset/${encodeURIComponent(el.dataset.openAsset)}`);
            el.addEventListener("click", open);
            el.addEventListener("keydown", (e) => {
                if (e.key === "Enter" || e.key === " ") {
                    e.preventDefault();
                    open();
                }
            });
        });

        drawInteractiveTopology(filtered);
    }

    function drawInteractiveTopology(devices) {
        const viewport = document.getElementById("map-viewport");
        const svg = document.getElementById("map-svg");
        const tooltip = document.getElementById("map-tooltip");
        if (!viewport || !svg) return;

        const width = Math.max(760, viewport.clientWidth || 960);
        const height = viewport.clientHeight || 560;
        svg.setAttribute("viewBox", `0 0 ${width} ${height}`);

        const { nodes, links } = computeMapLayout(devices, width, height);

        if (nodes.length === 0) {
            svg.innerHTML = `
                <text x="${width / 2}" y="${height / 2}" text-anchor="middle" fill="#64748b" font-size="14">
                    Aucun équipement à afficher avec les filtres actuels.
                </text>
            `;
            return;
        }

        const ns = "http://www.w3.org/2000/svg";
        svg.innerHTML = "";

        const scene = document.createElementNS(ns, "g");
        scene.setAttribute("id", "map-scene");
        svg.appendChild(scene);

        function applyTransform() {
            const cx = width / 2;
            const cy = height / 2;
            const tx = state.map.panX + cx * (1 - state.map.zoom);
            const ty = state.map.panY + cy * (1 - state.map.zoom);
            scene.setAttribute("transform", `translate(${tx}, ${ty}) scale(${state.map.zoom})`);
        }
        applyTransform();

        // Subtle concentric reference rings in radial mode
        if (state.map.layout === "radial") {
            [0.24, 0.4].forEach((ratio) => {
                const ring = document.createElementNS(ns, "ellipse");
                ring.setAttribute("cx", String(width / 2));
                ring.setAttribute("cy", String(height / 2));
                ring.setAttribute("rx", String(Math.min(width, height) * ratio * 1.25));
                ring.setAttribute("ry", String(Math.min(width, height) * ratio));
                ring.setAttribute("class", "map-ring");
                scene.appendChild(ring);
            });
        }

        // Links layer
        const linksGroup = document.createElementNS(ns, "g");
        scene.appendChild(linksGroup);
        const linkElements = [];

        links.forEach((lk) => {
            const line = document.createElementNS(ns, "line");
            line.setAttribute("x1", String(lk.source.x));
            line.setAttribute("y1", String(lk.source.y));
            line.setAttribute("x2", String(lk.target.x));
            line.setAttribute("y2", String(lk.target.y));
            line.setAttribute("class", `map-link ${lk.hasAlert ? "map-link--alert" : ""}`);
            line.dataset.source = lk.source.id;
            line.dataset.target = lk.target.id;
            linksGroup.appendChild(line);
            linkElements.push({ el: line, link: lk });
        });

        // Nodes layer
        const nodesGroup = document.createElementNS(ns, "g");
        scene.appendChild(nodesGroup);

        function updateLinksForNode(node) {
            linkElements.forEach(({ el, link }) => {
                if (link.source.id === node.id) {
                    el.setAttribute("x1", String(node.x));
                    el.setAttribute("y1", String(node.y));
                }
                if (link.target.id === node.id) {
                    el.setAttribute("x2", String(node.x));
                    el.setAttribute("y2", String(node.y));
                }
            });
        }

        nodes.forEach((node) => {
            const g = document.createElementNS(ns, "g");
            g.setAttribute("class", "map-node");
            g.setAttribute("transform", `translate(${node.x}, ${node.y})`);

            if (node.isVirtualHub) {
                g.innerHTML = `
                    <circle r="30" class="map-node-bg" stroke="#0ea5e9" />
                    <g transform="translate(-11,-11)" stroke="#38bdf8" fill="none" stroke-width="1.8">
                        ${getDeviceIconPath("switch")}
                    </g>
                    <text y="46" class="map-node-label-ip">${esc(node.label)}</text>
                    <text y="60" class="map-node-label-host">Sous-réseau</text>
                `;
                nodesGroup.appendChild(g);
                return;
            }

            const dev = node.device;
            const st = getAssetStatus(dev);
            const devType = inferDeviceType(dev);
            const isRouter = devType === "router";
            const radius = isRouter ? 30 : 25;
            const portsCount = (dev.ports || []).length;
            const hasNew = (dev.ports || []).some((p) => p.is_new);

            g.innerHTML = `
                <circle r="${radius}" class="map-node-bg" stroke="${st.color}" />
                <g transform="translate(-11,-11)" stroke="${st.color === "#64748b" ? "#94a3b8" : "#e2e8f0"}" fill="none" stroke-width="1.8">
                    ${getDeviceIconPath(devType)}
                </g>
                ${
                    portsCount > 0
                        ? `
                    <g transform="translate(${radius - 4}, ${-radius + 4})">
                        <rect x="-11" y="-9" width="22" height="18" rx="9" fill="${hasNew ? "#f59e0b" : "#0ea5e9"}" stroke="#090d14" stroke-width="2" />
                        <text y="3.5" text-anchor="middle" fill="#06131f" font-family="JetBrains Mono, monospace" font-size="10" font-weight="700">${portsCount}</text>
                    </g>`
                        : ""
                }
                <text y="${radius + 17}" class="map-node-label-ip">${esc(dev.ip)}</text>
                <text y="${radius + 31}" class="map-node-label-host">${esc((dev.hostname || "").slice(0, 22))}</text>
            `;

            // Hover tooltip & link highlighting
            g.addEventListener("mouseenter", (evt) => {
                linkElements.forEach(({ el, link }) => {
                    if (link.source.id === node.id || link.target.id === node.id) {
                        el.classList.add("map-link--active");
                    }
                });
                showNodeTooltip(dev, evt);
            });

            g.addEventListener("mousemove", (evt) => {
                positionTooltip(evt);
            });

            g.addEventListener("mouseleave", () => {
                linkElements.forEach(({ el }) => el.classList.remove("map-link--active"));
                tooltip.classList.add("hidden");
            });

            // Drag vs Click detection (click redirects directly to Asset Details!)
            g.addEventListener("pointerdown", (evt) => {
                if (evt.button !== 0) return;
                evt.stopPropagation();
                const startClientX = evt.clientX;
                const startClientY = evt.clientY;
                const origX = node.x;
                const origY = node.y;
                let moved = false;

                function onMove(moveEvt) {
                    const dx = (moveEvt.clientX - startClientX) / state.map.zoom;
                    const dy = (moveEvt.clientY - startClientY) / state.map.zoom;
                    if (Math.hypot(moveEvt.clientX - startClientX, moveEvt.clientY - startClientY) > 5) {
                        moved = true;
                        tooltip.classList.add("hidden");
                    }
                    if (moved) {
                        node.x = origX + dx;
                        node.y = origY + dy;
                        state.map.customPositions[dev.ip] = { x: node.x, y: node.y };
                        g.setAttribute("transform", `translate(${node.x}, ${node.y})`);
                        updateLinksForNode(node);
                    }
                }

                function onUp() {
                    window.removeEventListener("pointermove", onMove);
                    window.removeEventListener("pointerup", onUp);
                    if (!moved) {
                        navigate(`#/asset/${encodeURIComponent(dev.ip)}`);
                    }
                }

                window.addEventListener("pointermove", onMove);
                window.addEventListener("pointerup", onUp);
            });

            nodesGroup.appendChild(g);
        });

        function showNodeTooltip(dev, evt) {
            const st = getAssetStatus(dev);
            const ports = dev.ports || [];
            const topPorts = ports
                .slice(0, 6)
                .map((p) => {
                    const cls = inferPortRisk(p) === "high" ? "badge-danger" : p.is_new ? "badge-warning" : "badge-accent";
                    return `<span class="badge ${cls} mono">${p.port}/${esc(p.protocol)} ${esc(p.service)}</span>`;
                })
                .join("");
            const extraCount = ports.length > 6 ? `<span class="badge badge-neutral">+${ports.length - 6}</span>` : "";

            tooltip.innerHTML = `
                <div style="display:flex; align-items:center; justify-content:space-between; gap:8px;">
                    <span class="map-tooltip-ip">${esc(dev.ip)}</span>
                    <span class="badge" style="background:rgba(148,163,184,0.12); color:${st.color};">${st.label}</span>
                </div>
                <div class="map-tooltip-meta">
                    <div><strong>Hôte :</strong> ${esc(dev.hostname)}</div>
                    <div><strong>Constructeur :</strong> ${esc(dev.vendor)}</div>
                    <div><strong>OS :</strong> ${esc(dev.os)}</div>
                    ${dev.latency_ms ? `<div><strong>Latence :</strong> <span class="mono">${dev.latency_ms} ms</span></div>` : ""}
                </div>
                <div class="map-tooltip-ports">
                    ${topPorts || `<span style="color:var(--text-muted); font-size:11.5px;">Aucun port ouvert détecté</span>`}
                    ${extraCount}
                </div>
                <div class="map-tooltip-cta">Cliquer pour voir les ports &amp; le profilage →</div>
            `;
            tooltip.classList.remove("hidden");
            positionTooltip(evt);
        }

        function positionTooltip(evt) {
            const rect = viewport.getBoundingClientRect();
            let left = evt.clientX - rect.left + 16;
            let top = evt.clientY - rect.top + 16;
            const ttWidth = tooltip.offsetWidth || 260;
            const ttHeight = tooltip.offsetHeight || 160;
            if (left + ttWidth > rect.width - 12) left = evt.clientX - rect.left - ttWidth - 16;
            if (top + ttHeight > rect.height - 12) top = evt.clientY - rect.top - ttHeight - 16;
            tooltip.style.left = `${Math.max(10, left)}px`;
            tooltip.style.top = `${Math.max(10, top)}px`;
        }

        // Canvas pan & wheel zoom
        viewport.onpointerdown = (evt) => {
            if (evt.target.closest(".map-node") || evt.target.closest(".map-controls-floating")) return;
            viewport.classList.add("panning");
            const startX = evt.clientX - state.map.panX;
            const startY = evt.clientY - state.map.panY;

            function onMove(mEvt) {
                state.map.panX = mEvt.clientX - startX;
                state.map.panY = mEvt.clientY - startY;
                applyTransform();
            }
            function onUp() {
                viewport.classList.remove("panning");
                window.removeEventListener("pointermove", onMove);
                window.removeEventListener("pointerup", onUp);
            }
            window.addEventListener("pointermove", onMove);
            window.addEventListener("pointerup", onUp);
        };

        viewport.onwheel = (evt) => {
            evt.preventDefault();
            const factor = evt.deltaY < 0 ? 1.12 : 0.89;
            state.map.zoom = Math.max(0.45, Math.min(2.6, state.map.zoom * factor));
            applyTransform();
        };

        document.getElementById("map-zoom-in").onclick = () => {
            state.map.zoom = Math.min(2.6, state.map.zoom * 1.2);
            applyTransform();
        };
        document.getElementById("map-zoom-out").onclick = () => {
            state.map.zoom = Math.max(0.45, state.map.zoom / 1.2);
            applyTransform();
        };
        document.getElementById("map-reset").onclick = () => {
            state.map.zoom = 1;
            state.map.panX = 0;
            state.map.panY = 0;
            state.map.customPositions = {};
            renderMapView();
        };
    }

    // =========================================================================
    // VIEW 2: ASSET DETAIL & PORT PROFILING (#/asset/:ip)
    // =========================================================================
    async function renderAssetDetailView(requestedIp) {
        const root = document.getElementById("view-root");

        if (state.devices.length === 0) {
            root.innerHTML = `<div class="empty-state">Aucun actif disponible dans la session de scan sélectionnée.</div>`;
            return;
        }

        let ip = requestedIp || state.selectedAssetIp || state.devices[0].ip;
        if (!state.devices.some((d) => d.ip === ip)) {
            ip = state.devices[0].ip;
        }
        state.selectedAssetIp = ip;

        // Fetch enriched asset detail + scan history
        let detail = null;
        try {
            const qs = state.currentSessionId ? `?session_id=${encodeURIComponent(state.currentSessionId)}` : "";
            detail = await apiFetch(`/api/assets/${encodeURIComponent(ip)}${qs}`);
        } catch {
            // Graceful fallback to devices already loaded from /api/data
            const dev = state.devices.find((d) => d.ip === ip);
            detail = dev ? { asset: dev, history: [] } : null;
        }

        if (!detail || !detail.asset) {
            root.innerHTML = `<div class="empty-state">Actif introuvable. <a href="#/map">Retourner à la cartographie</a></div>`;
            return;
        }

        const asset = detail.asset;
        const history = detail.history || [];
        const st = getAssetStatus(asset);
        const devType = inferDeviceType(asset);
        const typeLabel = (CATEGORY_META[devType] || CATEGORY_META.unknown).label;
        const ports = asset.ports || [];

        const f = state.assetFilter;
        const filteredPorts = ports.filter((p) => {
            if (f.protocol !== "all" && (p.protocol || "").toLowerCase() !== f.protocol) return false;
            if (f.risk !== "all" && inferPortRisk(p) !== f.risk) return false;
            if (f.newOnly && !p.is_new) return false;
            if (!f.search.trim()) return true;
            const q = f.search.trim().toLowerCase();
            return (
                String(p.port).includes(q) ||
                (p.service || "").toLowerCase().includes(q) ||
                (p.product || "").toLowerCase().includes(q) ||
                (p.version || "").toLowerCase().includes(q) ||
                (p.extrainfo || "").toLowerCase().includes(q) ||
                (p.cpe || "").toLowerCase().includes(q) ||
                (p.banner || "").toLowerCase().includes(q)
            );
        });

        const riskBadge = (risk) => {
            if (risk === "high") return `<span class="badge badge-danger">Risque élevé</span>`;
            if (risk === "medium") return `<span class="badge badge-warning">Attention</span>`;
            return `<span class="badge badge-success">Standard</span>`;
        };

        root.innerHTML = `
            <div class="detail-topbar">
                <div class="breadcrumb">
                    <a href="#/map">Cartographie</a>
                    <span>/</span>
                    <span class="mono" style="color:var(--text-primary); font-weight:600;">${esc(asset.ip)}</span>
                </div>
                <div style="display:flex; align-items:center; gap:10px; flex-wrap:wrap;">
                    <label for="asset-switcher" style="font-size:12px; color:var(--text-muted);">Changer d'actif :</label>
                    <select id="asset-switcher" class="select" style="width:260px; padding:6px 10px;">
                        ${state.devices
                            .map(
                                (d) =>
                                    `<option value="${esc(d.ip)}" ${d.ip === asset.ip ? "selected" : ""}>${esc(d.ip)} — ${esc(d.hostname)} (${(d.ports || []).length}p)</option>`
                            )
                            .join("")}
                    </select>
                    <a href="#/map" class="btn btn-secondary btn-sm">← Carte</a>
                </div>
            </div>

            <!-- Asset Identity Hero -->
            <section class="card asset-hero">
                <div class="asset-hero-top">
                    <div>
                        <div class="asset-ip-heading">
                            <span class="status-dot" style="width:11px; height:11px; background:${st.color};"></span>
                            <h2>${esc(asset.ip)}</h2>
                            <button type="button" id="copy-ip-btn" class="btn btn-secondary btn-sm" title="Copier l'adresse IP">Copier IP</button>
                            <span class="badge badge-neutral">${esc(asset.hostname)}</span>
                            <span class="badge badge-accent">${esc(typeLabel)}</span>
                        </div>
                        <div style="margin-top:8px; display:flex; align-items:center; gap:10px; flex-wrap:wrap;">
                            <span class="badge ${st.level === "danger" ? "badge-danger" : st.level === "warning" ? "badge-warning" : st.level === "ok" ? "badge-success" : "badge-neutral"}">
                                Statut : ${st.label}
                            </span>
                            ${asset.latency_ms ? `<span class="badge badge-neutral mono">Latence : ${asset.latency_ms} ms</span>` : ""}
                            <span class="badge badge-accent mono">${ports.length} port(s) exposé(s)</span>
                        </div>
                    </div>
                </div>

                <div class="meta-grid">
                    <div>
                        <div class="meta-item-label">Adresse MAC</div>
                        <div class="meta-item-value mono">${esc(asset.mac)}</div>
                    </div>
                    <div>
                        <div class="meta-item-label">Constructeur (OUI)</div>
                        <div class="meta-item-value">${esc(asset.vendor)}</div>
                    </div>
                    <div>
                        <div class="meta-item-label">Système d'exploitation estimé</div>
                        <div class="meta-item-value">${esc(asset.os)}</div>
                    </div>
                    <div>
                        <div class="meta-item-label">Première détection</div>
                        <div class="meta-item-value">${formatDate(asset.first_seen)}</div>
                    </div>
                    <div>
                        <div class="meta-item-label">Dernière observation</div>
                        <div class="meta-item-value">${formatDate(asset.last_seen)}</div>
                    </div>
                </div>
            </section>

            <!-- Exposed Ports & Deep Profiling Section -->
            <section class="card">
                <div class="card-header">
                    <div>
                        <h3 class="card-title">Ports exposés &amp; Informations de profilage</h3>
                        <p class="card-subtitle">Cliquez sur un port pour afficher ou masquer l'empreinte, la bannière, le CPE et les résultats de scripts NSE.</p>
                    </div>
                    <div style="display:flex; gap:8px; flex-wrap:wrap;">
                        <button type="button" id="ports-expand-all" class="btn btn-secondary btn-sm">Tout déplier</button>
                        <button type="button" id="ports-collapse-all" class="btn btn-secondary btn-sm">Tout replier</button>
                    </div>
                </div>

                <div class="toolbar-bar" style="margin-bottom: 16px; background: var(--bg-inset);">
                    <div class="search-box">
                        <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
                        </svg>
                        <input id="asset-port-search" type="text" class="input" placeholder="Rechercher port, service, produit, CPE, bannière..." value="${esc(f.search)}">
                    </div>
                    <select id="asset-proto-filter" class="select" style="width:120px;">
                        <option value="all" ${f.protocol === "all" ? "selected" : ""}>Protocole</option>
                        <option value="tcp" ${f.protocol === "tcp" ? "selected" : ""}>TCP</option>
                        <option value="udp" ${f.protocol === "udp" ? "selected" : ""}>UDP</option>
                    </select>
                    <select id="asset-risk-filter" class="select" style="width:140px;">
                        <option value="all" ${f.risk === "all" ? "selected" : ""}>Tous risques</option>
                        <option value="high" ${f.risk === "high" ? "selected" : ""}>Risque élevé</option>
                        <option value="medium" ${f.risk === "medium" ? "selected" : ""}>Attention</option>
                        <option value="low" ${f.risk === "low" ? "selected" : ""}>Standard</option>
                    </select>
                    <label class="switch">
                        <input id="asset-new-only" type="checkbox" ${f.newOnly ? "checked" : ""}>
                        <span class="switch-track"></span>
                        <span>Nouveaux</span>
                    </label>
                </div>

                <div class="port-list">
                    ${
                        filteredPorts.length === 0
                            ? `<div class="empty-state" style="background:var(--bg-inset);">
                                    ${ports.length === 0 ? "Aucun port ouvert détecté sur cet actif lors de ce scan." : "Aucun port ne correspond aux filtres sélectionnés."}
                               </div>`
                            : filteredPorts
                                  .map((p) => {
                                      const risk = inferPortRisk(p);
                                      const key = `${asset.ip}:${p.port}/${p.protocol}`;
                                      // Expanded by default for visibility of profiling info
                                      const isExpanded =
                                          f.expandedPorts[key] !== undefined ? f.expandedPorts[key] : true;
                                      const prodSummary = [p.product, p.version].filter(Boolean).join(" ") || "Produit non identifié";
                                      const scripts = p.scripts && typeof p.scripts === "object" ? Object.entries(p.scripts) : [];

                                      return `
                                        <article class="port-card" data-port-key="${esc(key)}">
                                            <div class="port-card-summary" data-toggle-port="${esc(key)}">
                                                <div class="port-card-main">
                                                    <span class="port-pill">${p.port}/${esc(p.protocol)}</span>
                                                    <div>
                                                        <div style="display:flex; align-items:center; gap:8px; flex-wrap:wrap;">
                                                            <span class="port-service-name">${esc(p.service || "inconnu")}</span>
                                                            <span class="badge badge-neutral mono">${esc(p.state || "open")}</span>
                                                            ${p.is_new ? `<span class="badge badge-warning">NOUVEAU</span>` : ""}
                                                        </div>
                                                        <div class="port-product-line">
                                                            ${esc(prodSummary)}${p.extrainfo ? ` — <span style="color:var(--text-muted);">${esc(p.extrainfo)}</span>` : ""}
                                                        </div>
                                                    </div>
                                                </div>
                                                <div class="port-card-right">
                                                    ${riskBadge(risk)}
                                                    <span class="btn btn-ghost btn-sm" aria-hidden="true">${isExpanded ? "▾" : "▸"}</span>
                                                </div>
                                            </div>

                                            <div class="port-card-details ${isExpanded ? "" : "hidden"}">
                                                <div class="profile-kv-grid">
                                                    <div>
                                                        <div class="meta-item-label">Produit détecté</div>
                                                        <div class="meta-item-value">${esc(p.product || "Non renseigné")}</div>
                                                    </div>
                                                    <div>
                                                        <div class="meta-item-label">Version</div>
                                                        <div class="meta-item-value mono">${esc(p.version || "Non renseignée")}</div>
                                                    </div>
                                                    <div>
                                                        <div class="meta-item-label">Informations complémentaires</div>
                                                        <div class="meta-item-value">${esc(p.extrainfo || "—")}</div>
                                                    </div>
                                                    <div>
                                                        <div class="meta-item-label">Identifiant CPE</div>
                                                        <div class="meta-item-value mono" style="font-size:12px;">
                                                            ${
                                                                p.cpe
                                                                    ? `<span style="color:var(--accent-hover);">${esc(p.cpe)}</span>`
                                                                    : `<span style="color:var(--text-muted);">Aucun CPE</span>`
                                                            }
                                                        </div>
                                                    </div>
                                                </div>

                                                ${
                                                    p.banner
                                                        ? `<div>
                                                                <div class="meta-item-label">Bannière / Empreinte réseau</div>
                                                                <div class="code-block">${esc(p.banner)}</div>
                                                           </div>`
                                                        : ""
                                                }

                                                ${
                                                    scripts.length > 0
                                                        ? `<div>
                                                                <div class="meta-item-label">Scripts NSE &amp; Résultats de profilage</div>
                                                                <div class="code-block" style="padding:4px 8px;">
                                                                    <table class="script-table">
                                                                        <tbody>
                                                                            ${scripts
                                                                                .map(([sk, sv]) => {
                                                                                    const isAlert = sk.includes("security") || String(sv).includes("CRITIQUE");
                                                                                    return `
                                                                                        <tr>
                                                                                            <td class="script-key">${esc(sk)}</td>
                                                                                            <td class="${isAlert ? "script-val-alert" : ""}">${esc(sv)}</td>
                                                                                        </tr>
                                                                                    `;
                                                                                })
                                                                                .join("")}
                                                                        </tbody>
                                                                    </table>
                                                                </div>
                                                           </div>`
                                                        : ""
                                                }
                                            </div>
                                        </article>
                                      `;
                                  })
                                  .join("")
                    }
                </div>
            </section>

            <!-- Asset Historical Presence -->
            ${
                history.length > 0
                    ? `
            <section class="card">
                <div class="card-header">
                    <div>
                        <h3 class="card-title">Historique des scans pour ${esc(asset.ip)}</h3>
                        <p class="card-subtitle">Évolution du nombre de ports exposés au fil des campagnes de scan.</p>
                    </div>
                </div>
                <div class="table-wrap">
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>Session</th>
                                <th>Date du scan</th>
                                <th>Sous-réseau</th>
                                <th>Ports exposés</th>
                                <th>Nouveaux ports</th>
                                <th></th>
                            </tr>
                        </thead>
                        <tbody>
                            ${history
                                .map((h) => {
                                    const isCurrent = String(h.session_id) === String(state.currentSessionId);
                                    return `
                                        <tr class="${isCurrent ? "row-highlight" : ""}">
                                            <td class="mono">#${h.session_id} ${isCurrent ? `<span class="badge badge-accent">Actuel</span>` : ""}</td>
                                            <td>${formatDate(h.scan_time)}</td>
                                            <td class="mono">${esc(h.subnet)}</td>
                                            <td class="mono" style="font-weight:600;">${h.port_count}</td>
                                            <td>${h.new_ports > 0 ? `<span class="badge badge-warning">+${h.new_ports}</span>` : `<span style="color:var(--text-muted);">0</span>`}</td>
                                            <td style="text-align:right;">
                                                ${
                                                    isCurrent
                                                        ? `<span style="font-size:12px; color:var(--text-muted);">Affiché</span>`
                                                        : `<button type="button" class="btn btn-secondary btn-sm" data-switch-session="${h.session_id}">Inspecter</button>`
                                                }
                                            </td>
                                        </tr>
                                    `;
                                })
                                .join("")}
                        </tbody>
                    </table>
                </div>
            </section>`
                    : ""
            }
        `;

        // Event bindings
        document.getElementById("asset-switcher").addEventListener("change", (e) => {
            navigate(`#/asset/${encodeURIComponent(e.target.value)}`);
        });

        document.getElementById("copy-ip-btn").addEventListener("click", () => {
            copyToClipboard(asset.ip, "Adresse IP copiée");
        });

        document.getElementById("asset-port-search").addEventListener("input", (e) => {
            state.assetFilter.search = e.target.value;
            renderAssetDetailView(asset.ip);
            const el = document.getElementById("asset-port-search");
            if (el) {
                el.focus();
                el.setSelectionRange(el.value.length, el.value.length);
            }
        });

        document.getElementById("asset-proto-filter").addEventListener("change", (e) => {
            state.assetFilter.protocol = e.target.value;
            renderAssetDetailView(asset.ip);
        });

        document.getElementById("asset-risk-filter").addEventListener("change", (e) => {
            state.assetFilter.risk = e.target.value;
            renderAssetDetailView(asset.ip);
        });

        document.getElementById("asset-new-only").addEventListener("change", (e) => {
            state.assetFilter.newOnly = e.target.checked;
            renderAssetDetailView(asset.ip);
        });

        document.querySelectorAll("[data-toggle-port]").forEach((el) => {
            el.addEventListener("click", () => {
                const k = el.dataset.togglePort;
                const current = state.assetFilter.expandedPorts[k] !== undefined ? state.assetFilter.expandedPorts[k] : true;
                state.assetFilter.expandedPorts[k] = !current;
                renderAssetDetailView(asset.ip);
            });
        });

        document.getElementById("ports-expand-all").addEventListener("click", () => {
            ports.forEach((p) => {
                state.assetFilter.expandedPorts[`${asset.ip}:${p.port}/${p.protocol}`] = true;
            });
            renderAssetDetailView(asset.ip);
        });

        document.getElementById("ports-collapse-all").addEventListener("click", () => {
            ports.forEach((p) => {
                state.assetFilter.expandedPorts[`${asset.ip}:${p.port}/${p.protocol}`] = false;
            });
            renderAssetDetailView(asset.ip);
        });

        document.querySelectorAll("[data-switch-session]").forEach((btn) => {
            btn.addEventListener("click", async () => {
                const sid = btn.dataset.switchSession;
                document.getElementById("session-select").value = sid;
                await loadScanData(sid);
                renderAssetDetailView(asset.ip);
            });
        });
    }

    // =========================================================================
    // VIEW 3: QUERY & TABLE PAGE (ORIGINAL PAGE PRESERVED & UPGRADED — #/query)
    // =========================================================================
    function filterQueryDevices() {
        const q = state.query.search.trim().toLowerCase();
        const openOnly = state.query.openOnly;

        return state.devices.filter((dev) => {
            if (openOnly && (!dev.ports || dev.ports.length === 0)) return false;
            if (!q) return true;

            const hostMatch =
                (dev.ip || "").toLowerCase().includes(q) ||
                (dev.mac || "").toLowerCase().includes(q) ||
                (dev.hostname || "").toLowerCase().includes(q) ||
                (dev.vendor || "").toLowerCase().includes(q) ||
                (dev.os || "").toLowerCase().includes(q);

            const portMatch = (dev.ports || []).some(
                (p) =>
                    String(p.port).includes(q) ||
                    (p.protocol || "").toLowerCase().includes(q) ||
                    (p.service || "").toLowerCase().includes(q) ||
                    (p.product || "").toLowerCase().includes(q) ||
                    (p.version || "").toLowerCase().includes(q) ||
                    (p.extrainfo || "").toLowerCase().includes(q)
            );

            return hostMatch || portMatch;
        });
    }

    function exportQueryCSV(devices) {
        const rows = [["IP", "Hostname", "MAC", "Vendor", "OS", "Port", "Protocol", "Service", "Product", "Version", "ExtraInfo", "New"]];
        devices.forEach((dev) => {
            if (!dev.ports || dev.ports.length === 0) {
                rows.push([dev.ip, dev.hostname, dev.mac, dev.vendor, dev.os, "", "", "", "", "", "", ""]);
            } else {
                dev.ports.forEach((p) => {
                    rows.push([
                        dev.ip,
                        dev.hostname,
                        dev.mac,
                        dev.vendor,
                        dev.os,
                        p.port,
                        p.protocol,
                        p.service,
                        p.product,
                        p.version,
                        p.extrainfo,
                        p.is_new ? "YES" : "NO",
                    ]);
                });
            }
        });
        const csv = rows.map((r) => r.map((v) => `"${String(v ?? "").replace(/"/g, '""')}"`).join(",")).join("\n");
        const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
        const a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = `netprofiler_scan_${state.currentSessionId || "export"}.csv`;
        a.click();
        URL.revokeObjectURL(a.href);
        showToast("Export CSV téléchargé.", "success");
    }

    function exportQueryJSON(devices) {
        const blob = new Blob([JSON.stringify({ session: state.scanSession, devices }, null, 2)], {
            type: "application/json",
        });
        const a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = `netprofiler_scan_${state.currentSessionId || "export"}.json`;
        a.click();
        URL.revokeObjectURL(a.href);
        showToast("Export JSON téléchargé.", "success");
    }

    function renderQueryView() {
        const root = document.getElementById("view-root");
        const filtered = filterQueryDevices();
        const q = state.query.search.trim().toLowerCase();

        let bodyHtml = "";
        if (filtered.length === 0) {
            bodyHtml = `<div class="empty-state">Aucun équipement ou service ne correspond à votre recherche.</div>`;
        } else if (state.query.viewMode === "cards") {
            // Original 2-column card layout enhanced with direct navigation to Asset Details
            bodyHtml = `<div class="devices-grid">${filtered
                .map((dev) => {
                    const st = getAssetStatus(dev);
                    const portsHtml =
                        !dev.ports || dev.ports.length === 0
                            ? `<p style="font-size:12px; color:var(--text-muted); font-style:italic; margin:12px 0 4px;">Aucun port ouvert détecté sur les 1000 ports scannés.</p>`
                            : `<div class="table-wrap" style="margin-top:12px;">
                                <table class="data-table compact-table">
                                    <thead>
                                        <tr>
                                            <th>Port</th>
                                            <th>Service</th>
                                            <th>Version / Produit</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        ${dev.ports
                                            .map((p) => {
                                                const match =
                                                    q &&
                                                    (String(p.port).includes(q) ||
                                                        (p.service || "").toLowerCase().includes(q) ||
                                                        (p.product || "").toLowerCase().includes(q));
                                                const newBadge = p.is_new
                                                    ? `<span class="badge badge-warning" style="margin-left:6px; font-size:10px;">NOUVEAU</span>`
                                                    : "";
                                                const details = [p.product, p.version, p.extrainfo].filter(Boolean).join(" ") || "-";
                                                return `
                                                    <tr class="${match ? "row-highlight" : ""}">
                                                        <td class="mono" style="font-weight:600; color:var(--accent-hover); white-space:nowrap;">${p.port}/${esc(p.protocol)}${newBadge}</td>
                                                        <td style="font-weight:500; color:var(--success-text); white-space:nowrap;">${esc(p.service)}</td>
                                                        <td style="color:var(--text-secondary);">${esc(details)}</td>
                                                    </tr>
                                                `;
                                            })
                                            .join("")}
                                    </tbody>
                                </table>
                            </div>`;

                    return `
                        <article class="device-card">
                            <div>
                                <div class="device-card-head">
                                    <div>
                                        <div style="display:flex; align-items:center; gap:9px; flex-wrap:wrap;">
                                            <span class="status-dot" style="background:${st.color};"></span>
                                            <a href="#/asset/${encodeURIComponent(dev.ip)}" class="device-ip-link">${esc(dev.ip)}</a>
                                            <span class="badge badge-neutral">${esc(dev.hostname)}</span>
                                        </div>
                                        <div style="margin-top:6px; display:flex; flex-wrap:wrap; gap:6px 16px; font-size:12px; color:var(--text-secondary);">
                                            <span>MAC : <span class="mono" style="color:var(--text-primary);">${esc(dev.mac)}</span></span>
                                            <span>Constructeur : <span style="color:var(--text-primary);">${esc(dev.vendor)}</span></span>
                                        </div>
                                    </div>
                                    <div style="display:flex; align-items:center; gap:8px;">
                                        <span class="badge badge-accent mono">${(dev.ports || []).length} port(s)</span>
                                        <a href="#/asset/${encodeURIComponent(dev.ip)}" class="btn btn-secondary btn-sm">Détails →</a>
                                    </div>
                                </div>
                                ${
                                    dev.os && dev.os !== "Inconnu"
                                        ? `<div class="device-os-box">OS estimé : <strong style="color:var(--text-primary); font-weight:500;">${esc(dev.os)}</strong></div>`
                                        : ""
                                }
                                ${portsHtml}
                            </div>
                            <div class="device-card-foot">
                                <span>Première détection : ${formatDate(dev.first_seen)}</span>
                                <span>Vu : ${formatDate(dev.last_seen)}</span>
                            </div>
                        </article>
                    `;
                })
                .join("")}</div>`;
        } else if (state.query.viewMode === "hosts") {
            bodyHtml = `
                <div class="card" style="padding:0; overflow:hidden;">
                    <div class="table-wrap">
                        <table class="data-table">
                            <thead>
                                <tr>
                                    <th>Adresse IP</th>
                                    <th>Nom d'hôte</th>
                                    <th>MAC</th>
                                    <th>Constructeur</th>
                                    <th>OS estimé</th>
                                    <th>Ports</th>
                                    <th>Services</th>
                                    <th></th>
                                </tr>
                            </thead>
                            <tbody>
                                ${filtered
                                    .map((dev) => {
                                        const st = getAssetStatus(dev);
                                        const services = (dev.ports || []).map((p) => `${p.port}/${p.service}`).join(", ") || "—";
                                        return `
                                            <tr>
                                                <td class="mono" style="font-weight:600; white-space:nowrap;">
                                                    <span class="status-dot" style="background:${st.color}; margin-right:6px;"></span>
                                                    <a href="#/asset/${encodeURIComponent(dev.ip)}">${esc(dev.ip)}</a>
                                                </td>
                                                <td>${esc(dev.hostname)}</td>
                                                <td class="mono" style="font-size:12px; color:var(--text-secondary);">${esc(dev.mac)}</td>
                                                <td>${esc(dev.vendor)}</td>
                                                <td style="color:var(--text-secondary); font-size:12.5px;">${esc(dev.os)}</td>
                                                <td class="mono" style="font-weight:600;">${(dev.ports || []).length}</td>
                                                <td class="mono" style="font-size:12px; color:var(--text-secondary); max-width:260px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${esc(services)}">${esc(services)}</td>
                                                <td style="text-align:right;">
                                                    <a href="#/asset/${encodeURIComponent(dev.ip)}" class="btn btn-secondary btn-sm">Détails</a>
                                                </td>
                                            </tr>
                                        `;
                                    })
                                    .join("")}
                            </tbody>
                        </table>
                    </div>
                </div>
            `;
        } else {
            // Flat Port-level Audit Table
            const flatPorts = [];
            filtered.forEach((dev) => {
                (dev.ports || []).forEach((p) => {
                    if (
                        !q ||
                        dev.ip.toLowerCase().includes(q) ||
                        dev.hostname.toLowerCase().includes(q) ||
                        String(p.port).includes(q) ||
                        (p.service || "").toLowerCase().includes(q) ||
                        (p.product || "").toLowerCase().includes(q) ||
                        (p.version || "").toLowerCase().includes(q)
                    ) {
                        flatPorts.push({ dev, port: p });
                    }
                });
            });

            bodyHtml = `
                <div class="card" style="padding:0; overflow:hidden;">
                    <div class="table-wrap">
                        <table class="data-table">
                            <thead>
                                <tr>
                                    <th>Actif (IP)</th>
                                    <th>Hôte</th>
                                    <th>Port</th>
                                    <th>Service</th>
                                    <th>Produit &amp; Version</th>
                                    <th>Risque</th>
                                    <th></th>
                                </tr>
                            </thead>
                            <tbody>
                                ${
                                    flatPorts.length === 0
                                        ? `<tr><td colspan="7" style="text-align:center; padding:28px; color:var(--text-muted);">Aucun port exposé dans les résultats filtrés.</td></tr>`
                                        : flatPorts
                                              .map(({ dev, port }) => {
                                                  const risk = inferPortRisk(port);
                                                  const prod = [port.product, port.version, port.extrainfo].filter(Boolean).join(" ") || "—";
                                                  return `
                                                    <tr>
                                                        <td class="mono"><a href="#/asset/${encodeURIComponent(dev.ip)}" style="font-weight:600;">${esc(dev.ip)}</a></td>
                                                        <td>${esc(dev.hostname)}</td>
                                                        <td class="mono" style="color:var(--accent-hover); font-weight:600; white-space:nowrap;">
                                                            ${port.port}/${esc(port.protocol)}
                                                            ${port.is_new ? `<span class="badge badge-warning" style="margin-left:4px;">NEW</span>` : ""}
                                                        </td>
                                                        <td style="color:var(--success-text); font-weight:500;">${esc(port.service)}</td>
                                                        <td style="color:var(--text-secondary);">${esc(prod)}</td>
                                                        <td><span class="badge ${risk === "high" ? "badge-danger" : risk === "medium" ? "badge-warning" : "badge-success"}">${risk === "high" ? "Élevé" : risk === "medium" ? "Attention" : "Standard"}</span></td>
                                                        <td style="text-align:right;"><a href="#/asset/${encodeURIComponent(dev.ip)}" class="btn btn-secondary btn-sm">Profilage</a></td>
                                                    </tr>
                                                  `;
                                              })
                                              .join("")
                                }
                            </tbody>
                        </table>
                    </div>
                </div>
            `;
        }

        root.innerHTML = `
            <!-- Original 4 Stat Cards -->
            <div class="kpi-grid">
                <div class="kpi-card">
                    <div class="kpi-label">Appareils Actifs</div>
                    <div class="kpi-value">${state.stats.total_devices ?? 0}</div>
                </div>
                <div class="kpi-card">
                    <div class="kpi-label">Ports Exposés</div>
                    <div class="kpi-value kpi-value--accent">${state.stats.total_ports ?? 0}</div>
                </div>
                <div class="kpi-card">
                    <div class="kpi-label">Services Distincts</div>
                    <div class="kpi-value kpi-value--success">${state.stats.unique_services ?? 0}</div>
                </div>
                <div class="kpi-card">
                    <div class="kpi-label">Nouveaux Ports (vs -1h)</div>
                    <div class="kpi-value kpi-value--warning">${state.stats.new_ports_count ?? 0}</div>
                </div>
            </div>

            <!-- Search, Filter, View Mode & Export Bar -->
            <div class="toolbar-bar">
                ${
                    state.networks.length > 0
                        ? `<select id="query-network-select" class="select" style="width:230px;" aria-label="Réseau affiché">
                               ${state.networks
                                   .map(
                                       (n) =>
                                           `<option value="${n.id}" ${String(n.id) === String(state.currentNetworkId) ? "selected" : ""}>${esc(n.name)} (${esc(n.cidr)})</option>`
                                   )
                                   .join("")}
                           </select>`
                        : ""
                }
                <div class="search-box">
                    <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
                    </svg>
                    <input id="query-search-input" type="text" class="input" placeholder="Rechercher une IP, MAC, constructeur, port (ex: 22, 443), service (ex: ssh, http, nginx)..." value="${esc(state.query.search)}">
                </div>

                <label class="switch">
                    <input id="query-open-only" type="checkbox" ${state.query.openOnly ? "checked" : ""}>
                    <span class="switch-track"></span>
                    <span>Avec ports ouverts uniquement</span>
                </label>

                <div class="segmented-control">
                    <button type="button" class="segmented-btn ${state.query.viewMode === "cards" ? "active" : ""}" data-qview="cards">Cartes</button>
                    <button type="button" class="segmented-btn ${state.query.viewMode === "hosts" ? "active" : ""}" data-qview="hosts">Table Actifs</button>
                    <button type="button" class="segmented-btn ${state.query.viewMode === "ports" ? "active" : ""}" data-qview="ports">Table Ports</button>
                </div>

                <div style="display:flex; gap:6px;">
                    <button type="button" id="export-csv-btn" class="btn btn-secondary btn-sm">CSV</button>
                    <button type="button" id="export-json-btn" class="btn btn-secondary btn-sm">JSON</button>
                </div>
            </div>

            ${bodyHtml}
        `;

        const qNetSelect = document.getElementById("query-network-select");
        if (qNetSelect) {
            qNetSelect.addEventListener("change", (e) => {
                selectNetwork(e.target.value);
            });
        }

        document.getElementById("query-search-input").addEventListener("input", (e) => {
            state.query.search = e.target.value;
            renderQueryView();
            const inp = document.getElementById("query-search-input");
            if (inp) {
                inp.focus();
                inputFocusEnd(inp);
            }
        });

        function inputFocusEnd(inp) {
            inp.setSelectionRange(inp.value.length, inp.value.length);
        }

        document.getElementById("query-open-only").addEventListener("change", (e) => {
            state.query.openOnly = e.target.checked;
            renderQueryView();
        });

        document.querySelectorAll("[data-qview]").forEach((btn) => {
            btn.addEventListener("click", () => {
                state.query.viewMode = btn.dataset.qview;
                renderQueryView();
            });
        });

        document.getElementById("export-csv-btn").addEventListener("click", () => exportQueryCSV(filtered));
        document.getElementById("export-json-btn").addEventListener("click", () => exportQueryJSON(filtered));
    }

    // =========================================================================
    // VIEW 4: USER MANAGEMENT (ADMIN ONLY — #/users)
    // =========================================================================
    async function renderUsersView() {
        const root = document.getElementById("view-root");
        try {
            state.users = await apiFetch("/api/users");
        } catch (err) {
            showError(err.message);
            return;
        }

        const q = state.usersFilter.search.trim().toLowerCase();
        const roleFilter = state.usersFilter.role;

        const filtered = state.users.filter((u) => {
            if (roleFilter !== "all" && u.role !== roleFilter) return false;
            if (!q) return true;
            return (
                u.username.toLowerCase().includes(q) ||
                (u.display_name || "").toLowerCase().includes(q) ||
                (u.email || "").toLowerCase().includes(q)
            );
        });

        const totalUsers = state.users.length;
        const activeUsers = state.users.filter((u) => u.is_active).length;
        const adminCount = state.users.filter((u) => u.role === "admin" && u.is_active).length;
        const totalSessions = state.users.reduce((acc, u) => acc + (u.active_sessions || 0), 0);

        root.innerHTML = `
            <div class="kpi-grid">
                <div class="kpi-card">
                    <div class="kpi-label">Comptes utilisateurs</div>
                    <div class="kpi-value">${totalUsers}</div>
                </div>
                <div class="kpi-card">
                    <div class="kpi-label">Comptes actifs</div>
                    <div class="kpi-value kpi-value--success">${activeUsers}</div>
                </div>
                <div class="kpi-card">
                    <div class="kpi-label">Administrateurs</div>
                    <div class="kpi-value kpi-value--accent">${adminCount}</div>
                </div>
                <div class="kpi-card">
                    <div class="kpi-label">Sessions ouvertes</div>
                    <div class="kpi-value">${totalSessions}</div>
                </div>
            </div>

            <div class="toolbar-bar">
                <div class="search-box">
                    <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
                    </svg>
                    <input id="users-search" type="text" class="input" placeholder="Rechercher par identifiant, nom ou email..." value="${esc(state.usersFilter.search)}">
                </div>
                <select id="users-role-filter" class="select" style="width:160px;">
                    <option value="all" ${roleFilter === "all" ? "selected" : ""}>Tous les rôles</option>
                    <option value="admin" ${roleFilter === "admin" ? "selected" : ""}>Administrateur</option>
                    <option value="analyst" ${roleFilter === "analyst" ? "selected" : ""}>Analyste</option>
                    <option value="viewer" ${roleFilter === "viewer" ? "selected" : ""}>Lecteur</option>
                </select>
                <button type="button" id="create-user-btn" class="btn btn-primary">+ Nouvel utilisateur</button>
            </div>

            <div class="card" style="padding:0; overflow:hidden;">
                <div class="table-wrap">
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>Utilisateur</th>
                                <th>Email</th>
                                <th>Rôle</th>
                                <th>Statut</th>
                                <th>Sessions</th>
                                <th>Dernière connexion</th>
                                <th style="text-align:right;">Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${filtered
                                .map((u) => {
                                    const isSelf = u.id === state.user.id;
                                    const roleCls = u.role === "admin" ? "badge-accent" : u.role === "analyst" ? "badge-warning" : "badge-neutral";
                                    return `
                                        <tr>
                                            <td>
                                                <div style="font-weight:600;">${esc(u.display_name || u.username)} ${isSelf ? `<span class="badge badge-neutral" style="margin-left:4px;">Vous</span>` : ""}</div>
                                                <div class="mono" style="font-size:12px; color:var(--text-muted);">@${esc(u.username)}</div>
                                            </td>
                                            <td style="color:var(--text-secondary);">${esc(u.email || "—")}</td>
                                            <td><span class="badge ${roleCls}">${ROLE_LABELS[u.role] || u.role}</span></td>
                                            <td>
                                                <span class="badge ${u.is_active ? "badge-success" : "badge-danger"}">
                                                    ${u.is_active ? "Actif" : "Désactivé"}
                                                </span>
                                            </td>
                                            <td class="mono">${u.active_sessions || 0}</td>
                                            <td style="font-size:12.5px; color:var(--text-secondary);">${formatDate(u.last_login_at)}</td>
                                            <td style="text-align:right; white-space:nowrap;">
                                                <button type="button" class="btn btn-secondary btn-sm" data-edit-user="${u.id}">Modifier</button>
                                                ${
                                                    !isSelf
                                                        ? `<button type="button" class="btn btn-danger btn-sm" style="margin-left:6px;" data-delete-user="${u.id}">Supprimer</button>`
                                                        : ""
                                                }
                                            </td>
                                        </tr>
                                    `;
                                })
                                .join("")}
                        </tbody>
                    </table>
                </div>
            </div>
        `;

        document.getElementById("users-search").addEventListener("input", (e) => {
            state.usersFilter.search = e.target.value;
            renderUsersView();
            const inp = document.getElementById("users-search");
            if (inp) {
                inp.focus();
                inp.setSelectionRange(inp.value.length, inp.value.length);
            }
        });

        document.getElementById("users-role-filter").addEventListener("change", (e) => {
            state.usersFilter.role = e.target.value;
            renderUsersView();
        });

        document.getElementById("create-user-btn").addEventListener("click", () => openUserModal(null));

        document.querySelectorAll("[data-edit-user]").forEach((btn) => {
            btn.addEventListener("click", () => {
                const target = state.users.find((u) => String(u.id) === btn.dataset.editUser);
                if (target) openUserModal(target);
            });
        });

        document.querySelectorAll("[data-delete-user]").forEach((btn) => {
            btn.addEventListener("click", () => {
                const target = state.users.find((u) => String(u.id) === btn.dataset.deleteUser);
                if (target) openDeleteUserModal(target);
            });
        });
    }

    function openUserModal(existingUser) {
        const isEdit = Boolean(existingUser);
        const title = isEdit ? `Modifier @${existingUser.username}` : "Créer un utilisateur";

        openModal(`
            <div class="modal-header">
                <h3>${esc(title)}</h3>
                <button type="button" class="btn btn-ghost btn-icon" data-close-modal aria-label="Fermer">✕</button>
            </div>
            <form id="user-modal-form">
                <div class="modal-body">
                    <div id="user-modal-err" class="banner banner-danger hidden" style="margin-bottom:14px;"></div>

                    ${
                        !isEdit
                            ? `
                        <div class="form-group">
                            <label class="form-label" for="u-username">Nom d'utilisateur *</label>
                            <input id="u-username" type="text" class="input mono" required minlength="3" maxlength="32" pattern="[a-zA-Z0-9._-]{3,32}" placeholder="j.dupont">
                            <div class="form-hint">3 à 32 caractères (lettres, chiffres, . _ -)</div>
                        </div>`
                            : ""
                    }

                    <div class="form-grid-2">
                        <div class="form-group">
                            <label class="form-label" for="u-display">Nom affiché</label>
                            <input id="u-display" type="text" class="input" value="${esc(isEdit ? existingUser.display_name : "")}" placeholder="Jean Dupont">
                        </div>
                        <div class="form-group">
                            <label class="form-label" for="u-role">Rôle</label>
                            <select id="u-role" class="select">
                                <option value="viewer" ${isEdit && existingUser.role === "viewer" ? "selected" : ""}>Lecteur (lecture seule)</option>
                                <option value="analyst" ${isEdit && existingUser.role === "analyst" ? "selected" : ""}>Analyste (lecture + scans)</option>
                                <option value="admin" ${isEdit && existingUser.role === "admin" ? "selected" : ""}>Administrateur (accès complet)</option>
                            </select>
                        </div>
                    </div>

                    <div class="form-group">
                        <label class="form-label" for="u-email">Adresse email</label>
                        <input id="u-email" type="email" class="input" value="${esc(isEdit ? existingUser.email : "")}" placeholder="prenom.nom@entreprise.fr">
                    </div>

                    <div class="form-group">
                        <label class="form-label" for="u-password">${isEdit ? "Nouveau mot de passe (laisser vide pour conserver)" : "Mot de passe initial *"}</label>
                        <input id="u-password" type="password" class="input" ${isEdit ? "" : "required"} minlength="8" placeholder="Minimum 8 caractères">
                    </div>

                    <div style="display:flex; flex-direction:column; gap:10px; margin-top:8px;">
                        <label class="switch">
                            <input id="u-active" type="checkbox" ${!isEdit || existingUser.is_active ? "checked" : ""}>
                            <span class="switch-track"></span>
                            <span>Compte actif</span>
                        </label>
                        <label class="switch">
                            <input id="u-must-change" type="checkbox" ${isEdit && existingUser.must_change_password ? "checked" : ""}>
                            <span class="switch-track"></span>
                            <span>Recommander le changement de mot de passe à la prochaine connexion</span>
                        </label>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-close-modal>Annuler</button>
                    <button type="submit" class="btn btn-primary">${isEdit ? "Enregistrer" : "Créer le compte"}</button>
                </div>
            </form>
        `);

        document.getElementById("user-modal-form").addEventListener("submit", async (e) => {
            e.preventDefault();
            const errBox = document.getElementById("user-modal-err");
            errBox.classList.add("hidden");

            const pw = document.getElementById("u-password").value;
            try {
                if (isEdit) {
                    const payload = {
                        display_name: document.getElementById("u-display").value.trim(),
                        email: document.getElementById("u-email").value.trim(),
                        role: document.getElementById("u-role").value,
                        is_active: document.getElementById("u-active").checked,
                        must_change_password: document.getElementById("u-must-change").checked,
                    };
                    if (pw) payload.new_password = pw;
                    await apiFetch(`/api/users/${existingUser.id}`, {
                        method: "PUT",
                        body: JSON.stringify(payload),
                    });
                    showToast(`Utilisateur @${existingUser.username} mis à jour.`, "success");
                } else {
                    const payload = {
                        username: document.getElementById("u-username").value.trim(),
                        display_name: document.getElementById("u-display").value.trim(),
                        email: document.getElementById("u-email").value.trim(),
                        role: document.getElementById("u-role").value,
                        password: pw,
                        is_active: document.getElementById("u-active").checked,
                        must_change_password: document.getElementById("u-must-change").checked,
                    };
                    await apiFetch("/api/users", {
                        method: "POST",
                        body: JSON.stringify(payload),
                    });
                    showToast(`Utilisateur @${payload.username} créé.`, "success");
                }
                closeModal();
                renderUsersView();
            } catch (err) {
                errBox.textContent = err.message;
                errBox.classList.remove("hidden");
            }
        });
    }

    function openDeleteUserModal(target) {
        openModal(`
            <div class="modal-header">
                <h3>Supprimer l'utilisateur</h3>
                <button type="button" class="btn btn-ghost btn-icon" data-close-modal aria-label="Fermer">✕</button>
            </div>
            <div class="modal-body">
                <p style="margin:0; color:var(--text-secondary);">
                    Confirmez-vous la suppression définitive du compte <strong style="color:var(--text-primary);">@${esc(target.username)}</strong> (${esc(target.display_name)}) ? Toutes ses sessions actives seront révoquées.
                </p>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" data-close-modal>Annuler</button>
                <button type="button" id="confirm-del-user" class="btn btn-danger">Supprimer définitivement</button>
            </div>
        `);

        document.getElementById("confirm-del-user").addEventListener("click", async () => {
            try {
                await apiFetch(`/api/users/${target.id}`, { method: "DELETE" });
                closeModal();
                showToast(`Utilisateur @${target.username} supprimé.`, "success");
                renderUsersView();
            } catch (err) {
                showToast(err.message, "error");
            }
        });
    }

    // =========================================================================
    // VIEW 5: CONFIGURATION PAGE (#/config)
    // =========================================================================
    async function renderConfigView() {
        const root = document.getElementById("view-root");
        try {
            const [cfgData, netsData] = await Promise.all([
                apiFetch("/api/config"),
                apiFetch("/api/networks"),
            ]);
            state.config = cfgData;
            state.networks = Array.isArray(netsData) ? netsData : [];
        } catch (err) {
            showError(err.message);
            return;
        }

        const cfg = state.config || {};
        const isAdmin = state.user.role === "admin";
        const canScan = state.user.role === "admin" || state.user.role === "analyst";
        const dis = isAdmin ? "" : "disabled";

        root.innerHTML = `
            ${
                !isAdmin
                    ? `<div class="banner banner-info"><span>Mode lecture seule : seuls les administrateurs peuvent ajouter ou modifier les réseaux et la configuration globale.</span></div>`
                    : ""
            }

            <!-- Multi-Network Management Card -->
            <section class="card" aria-label="Gestion des réseaux à scanner">
                <div class="card-header">
                    <div>
                        <h3 class="card-title">Réseaux à scanner (${state.networks.length})</h3>
                        <p class="card-subtitle">Ajoutez et gérez les sous-réseaux CIDR surveillés. Toutes les données et actifs découverts de chaque réseau sont conservés en base SQLite.</p>
                    </div>
                    ${
                        isAdmin
                            ? `<button type="button" id="add-network-btn" class="btn btn-primary">+ Ajouter un réseau</button>`
                            : ""
                    }
                </div>

                ${
                    state.networks.length === 0
                        ? `<div class="empty-state" style="background:var(--bg-inset);">Aucun réseau configuré pour le moment.</div>`
                        : `
                <div class="table-wrap">
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>Réseau</th>
                                <th>CIDR &amp; Cadence</th>
                                <th>Statut</th>
                                <th>Données en base</th>
                                <th style="text-align:right;">Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${state.networks
                                .map((n) => {
                                    return `
                                        <tr>
                                            <td>
                                                <div style="font-weight:600;">${esc(n.name)}</div>
                                                ${
                                                    n.description
                                                        ? `<div style="font-size:11.5px; color:var(--text-muted); max-width:220px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${esc(n.description)}">${esc(n.description)}</div>`
                                                        : ""
                                                }
                                            </td>
                                            <td style="white-space:nowrap;">
                                                <div class="mono" style="font-weight:600; color:var(--accent-hover);">${esc(n.cidr)}</div>
                                                <div style="font-size:11.5px; color:var(--text-muted);">${n.scan_interval_minutes} min • ${esc(n.port_range)}</div>
                                            </td>
                                            <td>
                                                <span class="badge ${n.enabled ? "badge-success" : "badge-neutral"}">
                                                    ${n.enabled ? "Actif" : "En pause"}
                                                </span>
                                            </td>
                                            <td style="font-size:12.5px; white-space:nowrap;">
                                                <div>
                                                    <span class="mono" style="font-weight:600;">${n.last_hosts_up}</span> actif(s) •
                                                    <span class="mono" style="color:var(--accent-hover);">${n.last_ports_count}</span> port(s)
                                                    <span style="color:var(--text-muted);">(${n.scan_count} scan${n.scan_count > 1 ? "s" : ""})</span>
                                                </div>
                                                <div style="font-size:11.5px; color:var(--text-muted);">Dernier : ${formatDate(n.last_scan_time)}</div>
                                            </td>
                                            <td style="text-align:right; white-space:nowrap;">
                                                <button type="button" class="btn btn-secondary btn-sm" data-view-net-map="${n.id}" title="Afficher la carte de ce réseau">Carte</button>
                                                ${
                                                    canScan
                                                        ? `<button type="button" class="btn btn-secondary btn-sm" style="margin-left:4px;" data-scan-net="${n.id}">Scanner</button>`
                                                        : ""
                                                }
                                                ${
                                                    isAdmin
                                                        ? `<button type="button" class="btn btn-secondary btn-sm" style="margin-left:4px;" data-edit-net="${n.id}">Modifier</button>
                                                           <button type="button" class="btn btn-danger btn-sm" style="margin-left:4px;" data-del-net="${n.id}">Supprimer</button>`
                                                        : ""
                                                }
                                            </td>
                                        </tr>
                                    `;
                                })
                                .join("")}
                        </tbody>
                    </table>
                </div>`
                }
            </section>

            <!-- Global Scanner & Platform Settings -->
            <form id="config-form" style="display:flex; flex-direction:column; gap:18px;">
                <div class="two-col-grid">
                    <!-- Scanner Default Profile -->
                    <section class="card">
                        <div class="card-header">
                            <div>
                                <h3 class="card-title">Paramètres par défaut du scanner</h3>
                                <p class="card-subtitle">Valeurs par défaut proposées lors de l'ajout d'un nouveau réseau.</p>
                            </div>
                        </div>

                        <div class="form-group">
                            <label class="form-label" for="cfg-org">Nom du site / environnement</label>
                            <input id="cfg-org" type="text" class="input" value="${esc(cfg.organization_name || "")}" ${dis}>
                        </div>

                        <div class="form-grid-2">
                            <div class="form-group">
                                <label class="form-label" for="cfg-subnet">Sous-réseau par défaut (CIDR)</label>
                                <input id="cfg-subnet" type="text" class="input mono" value="${esc(cfg.target_subnet || "")}" placeholder="192.168.10.0/24" ${dis}>
                            </div>
                            <div class="form-group">
                                <label class="form-label" for="cfg-interval">Intervalle par défaut (minutes)</label>
                                <input id="cfg-interval" type="number" min="5" max="1440" class="input mono" value="${esc(cfg.scan_interval_minutes || "60")}" ${dis}>
                            </div>
                        </div>

                        <div class="form-grid-2">
                            <div class="form-group">
                                <label class="form-label" for="cfg-ports">Plage de ports par défaut</label>
                                <select id="cfg-ports" class="select" ${dis}>
                                    <option value="top-100" ${cfg.port_range === "top-100" ? "selected" : ""}>Top 100 ports (rapide)</option>
                                    <option value="top-1000" ${cfg.port_range === "top-1000" ? "selected" : ""}>Top 1000 ports (standard)</option>
                                    <option value="1-65535" ${cfg.port_range === "1-65535" ? "selected" : ""}>Tous les ports TCP (1-65535)</option>
                                </select>
                            </div>
                            <div class="form-group">
                                <label class="form-label" for="cfg-flags">Options Nmap par défaut</label>
                                <input id="cfg-flags" type="text" class="input mono" value="${esc(cfg.nmap_flags || "")}" ${dis}>
                            </div>
                        </div>

                        <div style="display:flex; flex-direction:column; gap:12px; margin-top:8px;">
                            <label class="switch">
                                <input id="cfg-os" type="checkbox" ${cfg.enable_os_detection === "true" ? "checked" : ""} ${dis}>
                                <span class="switch-track"></span>
                                <span>Activer la détection de système d'exploitation (-O)</span>
                            </label>
                            <label class="switch">
                                <input id="cfg-scripts" type="checkbox" ${cfg.enable_script_scan === "true" ? "checked" : ""} ${dis}>
                                <span class="switch-track"></span>
                                <span>Activer le profilage par scripts NSE (-sC / bannières)</span>
                            </label>
                        </div>
                    </section>

                    <!-- Alerts, Retention & Sessions -->
                    <section class="card">
                        <div class="card-header">
                            <div>
                                <h3 class="card-title">Alertes, rétention &amp; sécurité</h3>
                                <p class="card-subtitle">Notifications sur nouveaux ports, durée des sessions et archivage.</p>
                            </div>
                        </div>

                        <div style="margin-bottom:16px;">
                            <label class="switch">
                                <input id="cfg-alert-new" type="checkbox" ${cfg.alert_on_new_port === "true" ? "checked" : ""} ${dis}>
                                <span class="switch-track"></span>
                                <span>Déclencher une alerte à chaque nouveau port détecté</span>
                            </label>
                        </div>

                        <div class="form-group">
                            <label class="form-label" for="cfg-webhook">URL Webhook (Slack, Teams, Discord, Gotify)</label>
                            <input id="cfg-webhook" type="url" class="input mono" value="${esc(cfg.alert_webhook_url || "")}" placeholder="https://hooks.example.com/services/..." ${dis}>
                        </div>

                        <div class="form-grid-2">
                            <div class="form-group">
                                <label class="form-label" for="cfg-ttl">Expiration des sessions (heures)</label>
                                <input id="cfg-ttl" type="number" min="1" max="720" class="input mono" value="${esc(cfg.session_ttl_hours || "24")}" ${dis}>
                            </div>
                            <div class="form-group">
                                <label class="form-label" for="cfg-retention">Rétention historique (jours)</label>
                                <input id="cfg-retention" type="number" min="1" max="365" class="input mono" value="${esc(cfg.retention_days || "30")}" ${dis}>
                            </div>
                        </div>

                        <div style="margin-top:20px; padding-top:16px; border-top:1px solid var(--border-subtle); display:flex; align-items:center; justify-content:space-between; gap:10px; flex-wrap:wrap;">
                            <div>
                                <div style="font-size:13px; font-weight:600;">Scan rapide du réseau actif</div>
                                <div style="font-size:12px; color:var(--text-muted);">Enregistre un nouvel instantané pour le réseau actuellement sélectionné.</div>
                            </div>
                            <button type="button" id="trigger-scan-btn" class="btn btn-secondary" ${canScan && state.networks.length > 0 ? "" : "disabled"}>
                                Lancer un scan maintenant
                            </button>
                        </div>
                    </section>
                </div>

                ${
                    isAdmin
                        ? `<div style="display:flex; justify-content:flex-end; gap:10px;">
                               <button type="submit" class="btn btn-primary">Enregistrer les paramètres globaux</button>
                           </div>`
                        : ""
                }
            </form>
        `;

        // Wire Network Management Actions
        const addNetBtn = document.getElementById("add-network-btn");
        if (addNetBtn) {
            addNetBtn.addEventListener("click", () => openNetworkModal(null));
        }

        document.querySelectorAll("[data-view-net-map]").forEach((btn) => {
            btn.addEventListener("click", () => {
                selectNetwork(btn.dataset.viewNetMap, "#/map");
            });
        });

        document.querySelectorAll("[data-scan-net]").forEach((btn) => {
            btn.addEventListener("click", async () => {
                const netId = Number(btn.dataset.scanNet);
                const net = state.networks.find((n) => n.id === netId);
                btn.disabled = true;
                btn.textContent = "Scan...";
                try {
                    const res = await apiFetch(`/api/networks/${netId}/scan`, { method: "POST" });
                    showToast(`Scan #${res.session.id} enregistré pour ${net ? net.name : "le réseau"}.`, "success");
                    await loadNetworks(state.currentNetworkId, state.currentSessionId);
                    renderConfigView();
                } catch (err) {
                    showToast(err.message, "error");
                    btn.disabled = false;
                    btn.textContent = "Scanner";
                }
            });
        });

        document.querySelectorAll("[data-edit-net]").forEach((btn) => {
            btn.addEventListener("click", () => {
                const target = state.networks.find((n) => String(n.id) === btn.dataset.editNet);
                if (target) openNetworkModal(target);
            });
        });

        document.querySelectorAll("[data-del-net]").forEach((btn) => {
            btn.addEventListener("click", () => {
                const target = state.networks.find((n) => String(n.id) === btn.dataset.delNet);
                if (target) openDeleteNetworkModal(target);
            });
        });

        if (isAdmin) {
            document.getElementById("config-form").addEventListener("submit", async (e) => {
                e.preventDefault();
                try {
                    const payload = {
                        organization_name: document.getElementById("cfg-org").value.trim(),
                        target_subnet: document.getElementById("cfg-subnet").value.trim(),
                        scan_interval_minutes: Number(document.getElementById("cfg-interval").value),
                        port_range: document.getElementById("cfg-ports").value,
                        nmap_flags: document.getElementById("cfg-flags").value.trim(),
                        enable_os_detection: document.getElementById("cfg-os").checked,
                        enable_script_scan: document.getElementById("cfg-scripts").checked,
                        alert_on_new_port: document.getElementById("cfg-alert-new").checked,
                        alert_webhook_url: document.getElementById("cfg-webhook").value.trim(),
                        session_ttl_hours: Number(document.getElementById("cfg-ttl").value),
                        retention_days: Number(document.getElementById("cfg-retention").value),
                    };
                    state.config = await apiFetch("/api/config", {
                        method: "PUT",
                        body: JSON.stringify(payload),
                    });
                    showToast("Configuration enregistrée avec succès.", "success");
                } catch (err) {
                    showToast(err.message, "error");
                }
            });
        }

        const triggerBtn = document.getElementById("trigger-scan-btn");
        if (triggerBtn && canScan) {
            triggerBtn.addEventListener("click", async () => {
                triggerBtn.disabled = true;
                triggerBtn.textContent = "Scan en cours...";
                try {
                    const res = await apiFetch("/api/scan/trigger", {
                        method: "POST",
                        body: JSON.stringify({ network_id: state.currentNetworkId }),
                    });
                    showToast(`Nouveau scan #${res.session.id} enregistré.`, "success");
                    await loadNetworks(res.session.network_id || state.currentNetworkId, res.session.id);
                    renderConfigView();
                } catch (err) {
                    showToast(err.message, "error");
                    triggerBtn.disabled = false;
                    triggerBtn.textContent = "Lancer un scan maintenant";
                }
            });
        }
    }

    function openNetworkModal(existingNet) {
        const isEdit = Boolean(existingNet);
        const cfg = state.config || {};
        const title = isEdit ? `Modifier le réseau — ${existingNet.name}` : "Ajouter un réseau à scanner";

        openModal(`
            <div class="modal-header">
                <h3>${esc(title)}</h3>
                <button type="button" class="btn btn-ghost btn-icon" data-close-modal aria-label="Fermer">✕</button>
            </div>
            <form id="network-modal-form">
                <div class="modal-body">
                    <div id="net-modal-err" class="banner banner-danger hidden" style="margin-bottom:14px;"></div>

                    <div class="form-grid-2">
                        <div class="form-group">
                            <label class="form-label" for="net-name">Nom du réseau *</label>
                            <input id="net-name" type="text" class="input" required minlength="2" maxlength="80" value="${esc(isEdit ? existingNet.name : "")}" placeholder="Ex: VLAN Serveurs Debian">
                        </div>
                        <div class="form-group">
                            <label class="form-label" for="net-cidr">Sous-réseau CIDR *</label>
                            <input id="net-cidr" type="text" class="input mono" required value="${esc(isEdit ? existingNet.cidr : "")}" placeholder="192.168.55.0/24">
                        </div>
                    </div>

                    <div class="form-group">
                        <label class="form-label" for="net-desc">Description</label>
                        <input id="net-desc" type="text" class="input" maxlength="300" value="${esc(isEdit ? existingNet.description : "")}" placeholder="Zone, bâtiment, VLAN ou rôle du réseau...">
                    </div>

                    <div class="form-grid-2">
                        <div class="form-group">
                            <label class="form-label" for="net-interval">Intervalle de scan (min)</label>
                            <input id="net-interval" type="number" min="5" max="1440" class="input mono" value="${esc(isEdit ? existingNet.scan_interval_minutes : cfg.scan_interval_minutes || 60)}">
                        </div>
                        <div class="form-group">
                            <label class="form-label" for="net-ports">Plage de ports</label>
                            <select id="net-ports" class="select">
                                ${["top-100", "top-1000", "1-65535"]
                                    .map((opt) => {
                                        const cur = isEdit ? existingNet.port_range : cfg.port_range || "top-1000";
                                        const labels = {
                                            "top-100": "Top 100 ports (rapide)",
                                            "top-1000": "Top 1000 ports (standard)",
                                            "1-65535": "Tous les ports TCP (1-65535)",
                                        };
                                        return `<option value="${opt}" ${cur === opt ? "selected" : ""}>${labels[opt]}</option>`;
                                    })
                                    .join("")}
                            </select>
                        </div>
                    </div>

                    <div class="form-group">
                        <label class="form-label" for="net-flags">Options Nmap</label>
                        <input id="net-flags" type="text" class="input mono" value="${esc(isEdit ? existingNet.nmap_flags : cfg.nmap_flags || "-sV -O --version-intensity 5 -T4")}">
                    </div>

                    <div style="margin-top:8px;">
                        <label class="switch">
                            <input id="net-enabled" type="checkbox" ${!isEdit || existingNet.enabled ? "checked" : ""}>
                            <span class="switch-track"></span>
                            <span>Scan automatique activé pour ce réseau</span>
                        </label>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-close-modal>Annuler</button>
                    <button type="submit" class="btn btn-primary">${isEdit ? "Enregistrer" : "Ajouter le réseau"}</button>
                </div>
            </form>
        `);

        document.getElementById("network-modal-form").addEventListener("submit", async (e) => {
            e.preventDefault();
            const errBox = document.getElementById("net-modal-err");
            errBox.classList.add("hidden");

            const payload = {
                name: document.getElementById("net-name").value.trim(),
                cidr: document.getElementById("net-cidr").value.trim(),
                description: document.getElementById("net-desc").value.trim(),
                scan_interval_minutes: Number(document.getElementById("net-interval").value),
                port_range: document.getElementById("net-ports").value,
                nmap_flags: document.getElementById("net-flags").value.trim(),
                enabled: document.getElementById("net-enabled").checked,
            };

            try {
                if (isEdit) {
                    await apiFetch(`/api/networks/${existingNet.id}`, {
                        method: "PUT",
                        body: JSON.stringify(payload),
                    });
                    showToast(`Réseau '${payload.name}' mis à jour.`, "success");
                    await loadNetworks(state.currentNetworkId, state.currentSessionId);
                } else {
                    const created = await apiFetch("/api/networks", {
                        method: "POST",
                        body: JSON.stringify(payload),
                    });
                    showToast(`Réseau '${created.name}' (${created.cidr}) ajouté.`, "success");
                    await loadNetworks(state.currentNetworkId || created.id, state.currentSessionId);
                }
                closeModal();
                renderConfigView();
            } catch (err) {
                errBox.textContent = err.message;
                errBox.classList.remove("hidden");
            }
        });
    }

    function openDeleteNetworkModal(target) {
        openModal(`
            <div class="modal-header">
                <h3>Retirer le réseau</h3>
                <button type="button" class="btn btn-ghost btn-icon" data-close-modal aria-label="Fermer">✕</button>
            </div>
            <div class="modal-body">
                <p style="margin:0 0 14px; color:var(--text-secondary);">
                    Voulez-vous retirer <strong style="color:var(--text-primary);">${esc(target.name)}</strong> (<span class="mono">${esc(target.cidr)}</span>) de la liste des réseaux à scanner ?
                </p>
                <label class="switch">
                    <input id="net-keep-history" type="checkbox" checked>
                    <span class="switch-track"></span>
                    <span>Conserver les scans et actifs découverts dans la base de données</span>
                </label>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" data-close-modal>Annuler</button>
                <button type="button" id="confirm-del-net" class="btn btn-danger">Supprimer le réseau</button>
            </div>
        `);

        document.getElementById("confirm-del-net").addEventListener("click", async () => {
            const keepHistory = document.getElementById("net-keep-history").checked;
            try {
                await apiFetch(`/api/networks/${target.id}?purge_history=${keepHistory ? "false" : "true"}`, {
                    method: "DELETE",
                });
                closeModal();
                showToast(
                    keepHistory
                        ? `Réseau '${target.name}' retiré (historique conservé en base).`
                        : `Réseau '${target.name}' et son historique supprimés.`,
                    "success"
                );
                const nextNet = state.currentNetworkId === target.id ? null : state.currentNetworkId;
                await loadNetworks(nextNet);
                renderConfigView();
            } catch (err) {
                showToast(err.message, "error");
            }
        });
    }

    // =========================================================================
    // VIEW 6: MY ACCOUNT & SECURITY (#/account)
    // =========================================================================
    async function renderAccountView() {
        const root = document.getElementById("view-root");
        try {
            state.accountData = await apiFetch("/api/auth/me");
        } catch (err) {
            showError(err.message);
            return;
        }

        const u = state.accountData.user;
        const sessions = state.accountData.sessions || [];

        root.innerHTML = `
            <div class="two-col-grid">
                <!-- Profile + Change Password -->
                <section class="card">
                    <div class="card-header">
                        <div>
                            <h3 class="card-title">Changer mon mot de passe</h3>
                            <p class="card-subtitle">Connecté en tant que <strong class="mono">@${esc(u.username)}</strong> (${ROLE_LABELS[u.role] || u.role}).</p>
                        </div>
                    </div>

                    <div id="pw-form-err" class="banner banner-danger hidden" style="margin-bottom:14px;"></div>

                    <form id="change-pw-form">
                        <div class="form-group">
                            <label class="form-label" for="pw-current">Mot de passe actuel</label>
                            <input id="pw-current" type="password" class="input" required autocomplete="current-password">
                        </div>
                        <div class="form-group">
                            <label class="form-label" for="pw-new">Nouveau mot de passe</label>
                            <input id="pw-new" type="password" class="input" required minlength="8" autocomplete="new-password" placeholder="Minimum 8 caractères">
                        </div>
                        <div class="form-group">
                            <label class="form-label" for="pw-confirm">Confirmer le nouveau mot de passe</label>
                            <input id="pw-confirm" type="password" class="input" required minlength="8" autocomplete="new-password">
                        </div>
                        <div class="form-group">
                            <label class="switch">
                                <input id="pw-revoke-others" type="checkbox" checked>
                                <span class="switch-track"></span>
                                <span>Déconnecter toutes mes autres sessions actives</span>
                            </label>
                        </div>
                        <button type="submit" class="btn btn-primary">Mettre à jour le mot de passe</button>
                    </form>
                </section>

                <!-- Active Sessions -->
                <section class="card">
                    <div class="card-header">
                        <div>
                            <h3 class="card-title">Mes sessions actives</h3>
                            <p class="card-subtitle">Appareils actuellement authentifiés avec votre compte.</p>
                        </div>
                    </div>

                    <div class="table-wrap">
                        <table class="data-table">
                            <thead>
                                <tr>
                                    <th>Origine</th>
                                    <th>Créée le</th>
                                    <th>Expire le</th>
                                    <th></th>
                                </tr>
                            </thead>
                            <tbody>
                                ${sessions
                                    .map(
                                        (s) => `
                                        <tr class="${s.is_current ? "row-highlight" : ""}">
                                            <td>
                                                <div class="mono" style="font-size:12.5px;">${esc(s.ip_address)} ${s.is_current ? `<span class="badge badge-success">Actuelle</span>` : ""}</div>
                                                <div style="font-size:11px; color:var(--text-muted); max-width:220px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${esc(s.user_agent)}">${esc(s.user_agent || "Navigateur")}</div>
                                            </td>
                                            <td style="font-size:12px;">${formatDate(s.created_at)}</td>
                                            <td style="font-size:12px;">${formatDate(s.expires_at)}</td>
                                            <td style="text-align:right;">
                                                ${
                                                    s.is_current
                                                        ? `<span style="font-size:11.5px; color:var(--text-muted);">Active</span>`
                                                        : `<button type="button" class="btn btn-danger btn-sm" data-revoke-session="${s.id}">Révoquer</button>`
                                                }
                                            </td>
                                        </tr>
                                    `
                                    )
                                    .join("")}
                            </tbody>
                        </table>
                    </div>
                </section>
            </div>
        `;

        document.getElementById("change-pw-form").addEventListener("submit", async (e) => {
            e.preventDefault();
            const errBox = document.getElementById("pw-form-err");
            errBox.classList.add("hidden");

            const current_password = document.getElementById("pw-current").value;
            const new_password = document.getElementById("pw-new").value;
            const confirm = document.getElementById("pw-confirm").value;
            const revoke_other_sessions = document.getElementById("pw-revoke-others").checked;

            if (new_password !== confirm) {
                errBox.textContent = "La confirmation ne correspond pas au nouveau mot de passe.";
                errBox.classList.remove("hidden");
                return;
            }

            try {
                await apiFetch("/api/auth/change-password", {
                    method: "POST",
                    body: JSON.stringify({ current_password, new_password, revoke_other_sessions }),
                });
                state.user.must_change_password = false;
                updateUserChrome();
                showToast("Mot de passe mis à jour avec succès.", "success");
                renderAccountView();
            } catch (err) {
                errBox.textContent = err.message;
                errBox.classList.remove("hidden");
            }
        });

        document.querySelectorAll("[data-revoke-session]").forEach((btn) => {
            btn.addEventListener("click", async () => {
                try {
                    await apiFetch(`/api/auth/sessions/${btn.dataset.revokeSession}`, { method: "DELETE" });
                    showToast("Session révoquée.", "success");
                    renderAccountView();
                } catch (err) {
                    showToast(err.message, "error");
                }
            });
        });
    }

    // =========================================================================
    // MODAL HELPERS
    // =========================================================================
    function openModal(innerHtml) {
        const root = document.getElementById("modal-root");
        root.innerHTML = `<div class="modal-dialog">${innerHtml}</div>`;
        root.classList.remove("hidden");
        root.querySelectorAll("[data-close-modal]").forEach((el) => {
            el.addEventListener("click", closeModal);
        });
    }

    function closeModal() {
        const root = document.getElementById("modal-root");
        root.classList.add("hidden");
        root.innerHTML = "";
    }

    // =========================================================================
    // GLOBAL EVENT LISTENERS & BOOTSTRAP
    // =========================================================================
    function wireGlobalEvents() {
        // Login form
        document.getElementById("login-form").addEventListener("submit", async (e) => {
            e.preventDefault();
            const errBox = document.getElementById("login-error");
            const btn = document.getElementById("login-submit");
            errBox.classList.add("hidden");
            btn.disabled = true;
            btn.textContent = "Connexion...";

            try {
                const username = document.getElementById("login-username").value.trim();
                const password = document.getElementById("login-password").value;
                const data = await apiFetch("/api/auth/login", {
                    method: "POST",
                    body: JSON.stringify({ username, password }),
                });
                document.getElementById("login-password").value = "";
                await enterAuthenticatedApp(data.user);
                showToast(`Bienvenue, ${data.user.display_name || data.user.username}.`, "success");
            } catch (err) {
                errBox.textContent = err.message;
                errBox.classList.remove("hidden");
            } finally {
                btn.disabled = false;
                btn.textContent = "Se connecter";
            }
        });

        // Toggle password visibility on login
        document.getElementById("toggle-login-pw").addEventListener("click", () => {
            const inp = document.getElementById("login-password");
            inp.type = inp.type === "password" ? "text" : "password";
        });

        // Logout
        document.getElementById("logout-btn").addEventListener("click", async () => {
            try {
                await apiFetch("/api/auth/logout", { method: "POST" });
            } catch {
                // ignore
            }
            handleUnauthorized();
            showToast("Vous êtes déconnecté.", "info");
        });

        // Mobile sidebar drawer
        document.getElementById("mobile-menu-btn").addEventListener("click", () => {
            document.getElementById("sidebar").classList.toggle("open");
            document.getElementById("sidebar-backdrop").classList.toggle("open");
        });
        document.getElementById("sidebar-backdrop").addEventListener("click", closeMobileSidebar);

        // Scan session selector
        document.getElementById("session-select").addEventListener("change", async (e) => {
            if (!e.target.value) return;
            await loadScanData(e.target.value);
            renderCurrentRoute();
        });

        // Refresh button
        document.getElementById("refresh-btn").addEventListener("click", async () => {
            await loadNetworks(state.currentNetworkId, state.currentSessionId);
            renderCurrentRoute();
            showToast("Données actualisées.", "info");
        });

        // Dismiss default password reminder
        document.getElementById("dismiss-pw-banner").addEventListener("click", () => {
            state.pwBannerDismissed = true;
            updateUserChrome();
        });

        // Close modal on backdrop click or Escape key
        document.getElementById("modal-root").addEventListener("click", (e) => {
            if (e.target.id === "modal-root") closeModal();
        });
        document.addEventListener("keydown", (e) => {
            if (e.key === "Escape") closeModal();
        });

        // Hash routing
        window.addEventListener("hashchange", renderCurrentRoute);
    }

    wireGlobalEvents();
    checkAuthAndBoot();
})();
