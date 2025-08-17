import React, { useMemo, useState } from "react";
import {
  Globe, Cable, Smartphone, Monitor, LayoutTemplate, Cloud as CloudIcon,
  Shield, Search, ListChecks, Workflow, Bug, Zap, FileText, Repeat, Lock,
  Network, Settings, Binary, Boxes, Radar,
  BadgeAlert, GitBranch, Activity, Layers, TerminalSquare, Route, Timer,
  ShieldCheck, ClipboardList, PlugZap, CheckCircle2, AlertTriangle, Swords,
} from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";

const ASSETS = [
    { key: "web", label: "Web", hue: 200, Icon: Globe },
    { key: "api", label: "API", hue: 260, Icon: Cable },
    { key: "mobile", label: "Mobile", hue: 160, Icon: Smartphone },
    { key: "thick", label: "Thick Client", hue: 300, Icon: Monitor },
    { key: "thin", label: "Thin Client", hue: 20, Icon: LayoutTemplate },
    { key: "cloud", label: "Cloud", hue: 220, Icon: CloudIcon },
];

const MODES = [
    { key: "black", label: "Black Box", desc: "No prior info; external attacker perspective" },
    { key: "grey", label: "Grey Box", desc: "Limited docs/creds; informed attacker" },
    { key: "white", label: "White Box", desc: "Design + source + creds; collaborative" },
];

const stageIcon = (name) => {
    const map = {
        Planning: ListChecks,
        Scoping: Route,
        Recon: Search,
        "Threat Modeling": Shield,
        Discovery: Radar,
        Exploitation: Zap,
        Risking: BadgeAlert,
        Reporting: FileText,
        Retest: Repeat,
        "Contract Review": ClipboardList,
        "AuthZ Matrix": Lock,
        "Gateway Policy": ShieldCheck,
        "Build Intake": Boxes,
        Static: Layers,
        Dynamic: Activity,
        "API Tests": Network,
        "Store Review": ClipboardList,
        Inventory: Boxes,
        Misconfig: Settings,
    };
    return map[name] || GitBranch;
};

const methodology = {
    web: {
        black: [
            {
                title: "Passive Recon",
                icon: Search,
                items: [
                    "WHOIS/DNS/ASN, subdomain enum (wordlist, permutations, cert transparency)",
                    "Archive & intel: robots/sitemap, Wayback, JS asset scrape & endpoint leak",
                    "Tech fingerprint: headers, response diffing, Wappalyzer-like, CDN/WAF",
                ],
            },
            {
                title: "Active Recon & Enum",
                icon: Radar,
                items: [
                    "Dir brute-force, parameter discovery, hidden features & feature flags",
                    "Auth surfaces: login/SSO/MFA/reset, session cookies, Remember-me flows",
                    "Rate limit baselines, error model, CSP/CORS headers, CSRF tokens",
                ],
            },
            {
                title: "Vulnerability Discovery (OWASP Top 10)",
                icon: Bug,
                items: [
                    "Broken Access Control (IDOR, vertical/horizontal, insecure direct file)",
                    "Cryptographic failures (weak TLS, cookie flags, poor crypto params)",
                    "Injection (SQLi/NoSQLi/Template/LDAP), XSS (reflected/stored/DOM)",
                    "SSRF, insecure deserialization, file uploads, path traversal",
                    "Business logic flaws: negative flows, rate/sequence, race conditions",
                ],
            },
            {
                title: "Exploitation & Impact",
                icon: Zap,
                items: [
                    "WAF evasion, timing & blind techniques (OOB via DNS/HTTP)",
                    "Session fixation/hijack, auth bypass, account takeover",
                    "Data exfil/integrity tamper, privilege escalation",
                ],
            },
            {
                title: "Validation, Risking & Reporting",
                icon: FileText,
                items: [
                    "CVSS + business impact; data classification & compliance mapping",
                    "Clear repro steps, PoC payloads, logs/screens, fix guidance",
                    "Retesting with evidence; regression checks",
                ],
            },
        ],
        grey: [
            { title: "Threat Modeling", icon: Shield, items: ["Trust boundaries, critical assets", "Abuse cases & attacker goals"] },
            { title: "Targeted Testing", icon: Search, items: ["Known modules/APIs", "Role/tenancy matrix", "Session state anomalies"] },
            { title: "Code-aware Payloads", icon: TerminalSquare, items: ["Tailored fuzzing", "Logic negatives", "Race windows"] },
            { title: "Exploit & Verify Fixes", icon: Repeat, items: ["Chain findings", "Mitigation validation", "Hardening advice"] },
        ],
        white: [
            { title: "Secure Design Review", icon: Layers, items: ["Architecture & DFDs", "Headers/TLS/cookies/CSP baselines"] },
            { title: "Secure Code Review", icon: Binary, items: ["Sinks/sources for XSS/SQLi", "Authz gates", "Secrets & deps"] },
            { title: "Instrumented Testing", icon: PlugZap, items: ["Local build + proxy", "Coverage hints", "Debug/test hooks"] },
            { title: "Hardening & Tests", icon: ShieldCheck, items: ["Fix PR review", "Security unit tests", "CICD gate"] },
        ],
    },
    api: {
        black: [
            { title: "Discovery", icon: Search, items: ["Swagger/Redoc leaks", "SDKs/mobile/JS artifacts", "CORS & preflight behavior", "GraphQL introspection"] },
            { title: "Enumeration", icon: Radar, items: ["Verb tampering", "Parameter mining/mass assignment", "Versioning & shadow endpoints", "HATEOAS/links traversal"] },
            { title: "Vuln Discovery", icon: Bug, items: ["Authn/Authz (JWT, OAuth, API keys)", "BOLA/IDOR, BFLA, object property/field filters", "Rate limit/quota & pagination abuse", "SSRF, injections, request smuggling/desync"] },
            { title: "Exploitation", icon: Zap, items: ["Privilege escalation across tenants", "Data exfil/integrity tamper", "DoS via amplification/regex backtracking"] },
            { title: "Reporting & Governance", icon: FileText, items: ["Risk + data class", "Schema validation, least privilege", "Gateway policies & observability"] },
        ],
        grey: [
            { title: "Contract Review", icon: ClipboardList, items: ["OpenAPI/GraphQL schema", "Error models & pagination", "Auth flows & scopes"] },
            { title: "Targeted Tests", icon: Network, items: ["Role matrix & tenancy filters", "ETag/cache semantics", "Idempotency & replay"] },
            { title: "State & Consistency", icon: Timer, items: ["Ordering, race, sagas", "Eventually consistent reads"] },
            { title: "Exploit & Retest", icon: Repeat, items: ["PoC scripts", "SLA-aware fixes", "Mitigation validation"] },
        ],
        white: [
            { title: "Design & Code Review", icon: Layers, items: ["Handlers/middleware", "Schema enforcement", "Secrets & logging hygiene"] },
            { title: "Security Tests w/ Fixtures", icon: Settings, items: ["Seed data & tenancy sims", "Chaos timeouts/faults"] },
            { title: "Gateway Hardening", icon: ShieldCheck, items: ["API gateway/WAF", "mTLS, JWT, scopes", "Telemetry/alerts"] },
        ],
    },
    mobile: {
        black: [
            { title: "App Recon", icon: Smartphone, items: ["Store metadata, trackers", "Static asset scrape", "Endpoints & analytics"] },
            { title: "Static Analysis", icon: Layers, items: ["APK/IPA reverse (smali/class-dump)", "Secrets/deep links/exported comps", "Hardcoded keys & configs"] },
            { title: "Dynamic Analysis", icon: Activity, items: ["TLS pinning bypass", "Frida runtime hooks", "Local storage/clipboard/logs"] },
            { title: "Vulnerability Discovery", icon: Bug, items: ["MASVS: storage/auth/crypto", "API authz, replay, device binding", "WebView injections & intents"] },
            { title: "Exploitation & Report", icon: FileText, items: ["Biometric/session bypass", "Data exfil & tamper", "Fix guidance & evidence"] },
        ],
        grey: [
            { title: "Threat Model", icon: Shield, items: ["App ↔ API ↔ device trust boundaries", "Role abuse & payments/PII", "3rd-party SDKs"] },
            { title: "Focused Testing", icon: Search, items: ["Sensitive modules", "Transport & cert pinning", "Deep links/intents"] },
            { title: "Runtime & Device State", icon: Settings, items: ["Screenshots/backups", "Keyboard cache/logging", "Clipboard protections"] },
            { title: "Report & Retest", icon: Repeat, items: ["MASVS mapping", "Dev fixes", "Revalidation"] },
        ],
        white: [
            { title: "Source Review", icon: Binary, items: ["Secrets in code", "Crypto misuse (ECB/RNG)", "Auth flows & biometrics"] },
            { title: "Instrumented Tests", icon: PlugZap, items: ["QA builds, debug menus", "Feature flags & hooks", "Coverage hints"] },
            { title: "Hardening", icon: ShieldCheck, items: ["Keystore/Keychain", "Anti-tamper/obfuscation", "SDK supply chain"] },
        ],
    },
    thick: {
        black: [
            { title: "Recon", icon: Search, items: ["Installer & binaries/DLLs", "Local endpoints & services"] },
            { title: "Analysis", icon: Layers, items: ["Strings/config/secrets", "Update channels & signatures"] },
            { title: "Vulns & Exploit", icon: Bug, items: ["IPC abuse", "Local privilege escalation", "Insecure storage/registry"] },
        ],
        grey: [{ title: "Focused Tests", icon: Network, items: ["Known modules", "Role checks", "Offline/online modes"] }],
        white: [{ title: "Code Review", icon: Binary, items: ["Authz gates", "Secrets", "Update trust & signing"] }],
    },
    thin: {
        black: [
            { title: "Recon", icon: Search, items: ["Delivery chain", "Browser compat & polyfills", "Caching layers"] },
            { title: "Testing", icon: Bug, items: ["Session mgmt", "Headers (CSP/HSTS/XFO)", "XSS/CSRF/Clickjacking"] },
        ],
        grey: [{ title: "Targeted", icon: Network, items: ["Known modules", "Privilege checks"] }],
        white: [{ title: "Review", icon: Layers, items: ["Config & CSP", "Perf & security overlap"] }],
    },
    cloud: {
        black: [
            { title: "Discovery", icon: Boxes, items: ["Public buckets/blobs", "Exposed services", "IAM footprints & keys"] },
            { title: "Testing", icon: Settings, items: ["CSPM misconfigs", "Metadata service", "Network paths & egress"] },
            { title: "Exploitation", icon: Zap, items: ["Privilege escalation via roles", "Instance profiles abuse", "Data exfil paths"] },
        ],
        grey: [{ title: "Focused", icon: Shield, items: ["Known accounts/projects", "Shared responsibility mapping", "Guardrails checks"] }],
        white: [{ title: "Review", icon: Layers, items: ["IaC policies", "Least privilege IAM", "Logging/monitoring"] }],
    },
};

const preEngagement = {
    common: [
        "Rules of Engagement (RoE), legal & approvals",
        "Scope: domains, IPs, repos, environments, exclusions",
        "Test accounts/roles, MFA/SSO paths, seed data",
        "Time windows & change freezes",
        "Data handling (PII/secrets), backups, rollbacks",
        "Notifications & contacts, severity SLAs",
    ],
    web: ["WAF exceptions/IP allowlist", "Test tenant & mail traps", "Error pages & 2FA flows"],
    api: ["OpenAPI/GraphQL spec versions", "Gateway policies & rate limits", "API keys/scopes"],
    mobile: ["QA builds & symbols", "Device matrix & OS versions", "Store credentials & review mode"],
    thick: ["Installer packages & licenses", "Offline mode datasets", "Local admin rights"],
    thin: ["CDN/cache invalidation", "Feature flags", "Browser support matrix"],
    cloud: ["Accounts/projects IDs", "Read-only auditor roles", "CSPM baseline reports"],
};

const workflows = {
    web: ["Planning", "Scoping", "Recon", "Threat Modeling", "Discovery", "Exploitation", "Risking", "Reporting", "Retest"],
    api: ["Planning", "Contract Review", "Recon", "AuthZ Matrix", "Discovery", "Exploitation", "Gateway Policy", "Reporting", "Retest"],
    mobile: ["Planning", "Build Intake", "Static", "Dynamic", "API Tests", "Exploitation", "Store Review", "Reporting", "Retest"],
    thick: ["Planning", "Install/Runtime", "Discovery", "Exploitation", "Reporting"],
    thin: ["Planning", "Recon", "Testing", "Exploitation", "Reporting"],
    cloud: ["Planning", "Inventory", "Misconfig", "Exploitation", "Reporting"],
};

const stageChecklist = {
    common: {
        Planning: ["Confirm RoE & escalation", "Define SLAs/severity scale", "Identify stakeholders"],
        Scoping: ["Targets & exclusions locked", "Access paths & creds ready", "Tenancy/data classes mapped"],
        Recon: ["Passive OSINT complete", "Tech stack fingerprinted", "Attack surface inventory"],
        "Threat Modeling": ["DFDs & trust boundaries", "Abuse cases listed", "Critical assets prioritized"],
        Discovery: ["OWASP tests run", "Authz matrix exercised", "Fuzzing & wordlists complete"],
        Exploitation: ["Impact validated safely", "Logs/alerts observed", "Chain multi-bug paths"],
        Risking: ["CVSS scored", "Business impact written", "Data class & compliance refs"],
        Reporting: ["PoC & steps included", "Fix guidance specific", "Evidence packaged"],
        Retest: ["Fix verified", "Regression checked", "Ticket closure evidence"],
    },
    web: {
        Recon: ["Subdomain enum", "Param/dir brute-force", "CSP/CORS/Headers noted"],
        Discovery: ["XSS/SQLi/SSRF/path traversal", "CSRF/session mgmt", "Logic/race tests"],
    },
    api: {
        Recon: ["Spec endpoints diffed", "CORS & preflight analyzed", "Shadow/versioned endpoints noted"],
        Discovery: ["BOLA/BFLA/BOPLA", "Rate limit & quota", "Smuggling/desync/SSRF"],
    },
    mobile: {
        Static: ["Secrets & hardcoded keys", "Exported components", "Crypto misuse"],
        Dynamic: ["Pinning bypass", "Runtime hooks", "Local storage/logs"],
    },
};

const offensive = {
    web: [
        "SQLi/NoSQLi/Template/LDAP/XXE",
        "Reflected/Stored/DOM XSS & XS-Leaks",
        "CSRF, Clickjacking, Session fixation",
        "Path traversal & file upload abuse",
        "SSRF, desync/smuggling, cache poisoning",
        "Auth bypass, weak MFA, session hijack",
        "Business logic/sequence/race conditions",
        "Prototype pollution (server/client)",
        "Deserialization (Java/.NET/PHP/Python)",
        "RCE via template injection (SSTI)",
        "HTTP/2 request smuggling, HPACK abuses",
        "CORS misconfig & origin reflection",
        "OAuth/OpenID/SAML misuses (confusion, replay)",
        "Web cache deception/poisoning",
        "CSP bypass chains, sandbox escapes",
        "DNS rebinding & browser pivot",
        "PDF/image render SSRF, XXE in parsers",
    ],
    api: [
        "BOLA/IDOR, BOPLA, BFLA",
        "JWT/OAuth abuses (alg none, kid injection, key confusion)",
        "Mass assignment & over-posting",
        "HTTP request smuggling & desync (H1/H2/H2C)",
        "SSRF via integrations (webhooks, importers)",
        "Abuse of pagination, filtering, search",
        "Resource exhaustion & regex DoS",
        "GraphQL abuses (introspection, alias/fragment bombs, batch attacks)",
        "HMAC/key reuse, nonce/replay issues",
        "WebSocket auth downgrade & CSWSH",
        "Cache key poisoning & ETag revalidation tricks",
    ],
    mobile: [
        "TLS pinning bypass & cert stripping",
        "Intent/WebView injections (JS bridge, scheme abuse)",
        "Biometric/session bypass & re-enroll flows",
        "Device binding/attestation tamper (SafetyNet/DeviceCheck)",
        "Clipboard/log/backup data leaks",
        "Insecure local storage/keystore misuse",
        "Jailbreak/root detection evasion",
        "Side-channel: screenshots, notifications, keyboard cache",
        "IPC/exported components abuse",
        "Deep-link hijack & untrusted inputs",
    ],
    thick: [
        "DLL search-order hijacking & side-loading",
        "Unsigned updates & MITM on update channels",
        "Insecure IPC/RPC, named pipe abuse",
        "Local privilege escalation via services",
        "Insecure registry/keystore permissions",
        "Sensitive data at rest (config/secrets)",
        "NTLM relay/downgrade on auth",
        "Process injection & insecure deserialization",
    ],
    thin: [
        "XSS (templating/DOM), XS-Leaks",
        "Service Worker cache poisoning & offline abuse",
        "Clickjacking/UI redress",
        "CSP/CORS misconfig",
        "Auth/session mis-handling across iframes",
        "Supply chain via CDN & dependency injection",
    ],
    cloud: [
        "Public bucket/blob exposure & ACL misconfig",
        "SSRF to metadata service (IMDSv1) & token theft",
        "Privilege escalation via IAM policies/roles",
        "Cross-account trust abuse & role assumption",
        "Key/secret leakage in logs, images, user-data",
        "Snapshot/AMI/volume exposure",
        "Container escape (cgroups/seccomp) & image poisoning",
        "Kubernetes RBAC/ServiceAccount token abuse",
        "Over-permissive policies on queues/functions",
        "Exposed admin endpoints (Elasticsearch, Redis, etc.)",
        "Serverless warm-start state leakage",
    ],
};

const owasp = {
    web: [
        "A01 Broken Access Control",
        "A02 Cryptographic Failures",
        "A03 Injection",
        "A04 Insecure Design",
        "A05 Security Misconfiguration",
        "A06 Vulnerable & Outdated Components",
        "A07 Identification & Authentication Failures",
        "A08 Software & Data Integrity Failures",
        "A09 Security Logging & Monitoring Failures",
        "A10 Server-Side Request Forgery (SSRF)",
    ],
    api: [
        "API1 Broken Object Level Authorization (BOLA)",
        "API2 Broken Authentication",
        "API3 Broken Object Property Level Authorization (BOPLA)",
        "API4 Unrestricted Resource Consumption",
        "API5 Broken Function Level Authorization (BFLA)",
        "API6 Unrestricted Access to Sensitive Business Flows",
        "API7 Server-Side Request Forgery",
        "API8 Security Misconfiguration",
        "API9 Improper Inventory Management",
        "API10 Unsafe Consumption of APIs",
    ],
    mobile: [
        "M1 Improper Platform Usage",
        "M2 Insecure Data Storage",
        "M3 Insecure Communication",
        "M4 Insecure Authentication",
        "M5 Insufficient Cryptography",
        "M6 Insecure Authorization", 
        "M7 Client Code Quality",
        "M8 Code Tampering",
        "M9 Reverse Engineering",
        "M10 Extraneous Functionality",
        "MASVS-ARCH Architecture & Threat Model",
        "MASVS-PLATFORM Platform Interaction",
        "MASVS-STORAGE Data Storage & Privacy",
        "MASVS-CRYPTO Cryptography",
        "MASVS-AUTH Authentication & Session",
        "MASVS-NETWORK Network & Transport",
        "MASVS-CODE Resilience & Tamper",
        "MASVS-RESILIENCE Anti-Reversing",
    ],
};

function SectionCard({ title, subtitle, children, hue = 210, icon: IconComp = null }) {
    return (
        <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.25 }}
            className="relative rounded-2xl p-5 bg-slate-900/60 ring-1 ring-slate-700/50 shadow-xl overflow-hidden"
            style={{ boxShadow: `0 10px 40px -12px hsl(${hue} 90% 60% / 0.25)` }}
        >
            <div
                className="pointer-events-none absolute inset-0 opacity-30"
                style={{
                    background:
                        "radial-gradient(1200px 300px at 10% -10%, hsl(var(--h) 90% 60% / .08), transparent), radial-gradient(800px 300px at 110% 10%, hsl(var(--h) 90% 60% / .06), transparent)",
                    "--h": hue,
                }}
            />
            <div className="relative">
                <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center gap-2">
                        {IconComp && <IconComp className="w-4 h-4 text-slate-300" />}
                        <h3 className="text-slate-100 text-lg font-semibold tracking-tight">{title}</h3>
                    </div>
                    {subtitle && (
                        <span className="text-xs text-slate-400 bg-slate-800/60 px-2 py-1 rounded-full">{subtitle}</span>
                    )}
                </div>
                {children}
            </div>
        </motion.div>
    );
}

function Chip({ active, children, onClick, hue }) {
    return (
        <button
            onClick={onClick}
            className={`px-3 py-1.5 rounded-full text-sm transition shadow-sm border ${active
                    ? "bg-gradient-to-r from-slate-100 to-slate-200 text-slate-900 border-slate-300"
                    : "bg-slate-800/60 text-slate-200 border-slate-700 hover:bg-slate-700/60"
                }`}
            style={active ? { boxShadow: `0 6px 18px -6px hsl(${hue} 90% 60% / .6)` } : {}}
        >
            {children}
        </button>
    );
}

function Badge({ children }) {
    return (
        <span className="text-[10px] uppercase tracking-wider text-slate-300 bg-slate-800/70 px-2 py-1 rounded-full border border-slate-700">
            {children}
        </span>
    );
}

function Node({ title, items = [], hue = 210, IconComp = null }) {
    const [open, setOpen] = useState(false);
    return (
        <div className="group">
            <button
                onClick={() => setOpen((v) => !v)}
                className="w-full text-left bg-slate-800/70 hover:bg-slate-700/70 transition rounded-xl p-4 border border-slate-700/60"
                style={{ boxShadow: `0 10px 24px -12px hsl(${hue} 90% 60% / 0.35)` }}
            >
                <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                        <span
                            className="inline-flex items-center justify-center w-6 h-6 rounded-lg"
                            style={{ backgroundColor: `hsl(${hue} 90% 18% / .35)`, boxShadow: `inset 0 0 0 1px hsl(${hue} 90% 60% / .35)` }}
                        >
                            {IconComp ? <IconComp className="w-3.5 h-3.5 text-slate-200" /> : <Bug className="w-3.5 h-3.5 text-slate-200" />}
                        </span>
                        <span className="text-slate-100 font-medium">{title}</span>
                    </div>
                    <span className="text-slate-400 text-sm">{open ? "Hide" : "Show"}</span>
                </div>
                <AnimatePresence initial={false}>
                    {open && (
                        <motion.ul
                            initial={{ opacity: 0, height: 0 }}
                            animate={{ opacity: 1, height: "auto" }}
                            exit={{ opacity: 0, height: 0 }}
                            className="mt-3 space-y-1.5 text-slate-300 text-sm list-disc ml-5"
                        >
                            {items.map((it, i) => (
                                <li key={i}>{it}</li>
                            ))}
                        </motion.ul>
                    )}
                </AnimatePresence>
            </button>
        </div>
    );
}

function FlowConnector({ hue = 210 }) {
    return (
        <div className="relative h-6" aria-hidden>
            <div
                className="absolute left-5 right-5 top-3 h-[2px]"
                style={{
                    background:
                        `linear-gradient(90deg, transparent, hsl(${hue} 90% 60% / .7), transparent)`,
                    filter: "drop-shadow(0 0 6px hsl(var(--h) 90% 60% / .9))",
                    "--h": hue,
                }}
            />
        </div>
    );
}

function Checklist({ items = [] }) {
    return (
        <ul className="space-y-1.5 text-sm">
            {items.map((i, idx) => (
                <li key={idx} className="flex items-start gap-2 text-slate-300">
                    <CheckCircle2 className="w-4 h-4 mt-0.5" />
                    <span>{i}</span>
                </li>
            ))}
        </ul>
    );
}

function MethodologyMap({ asset, mode, hue }) {
    const blocks = (methodology[asset]?.[mode] || []).map((b) => ({ ...b, IconComp: b.icon }));
    return (
        <div className="grid md:grid-cols-2 xl:grid-cols-3 gap-5">
            {blocks.map((b, i) => (
                <div key={i} className="relative">
                    <Node title={b.title} items={b.items} hue={hue} IconComp={b.IconComp} />
                    {i < blocks.length - 1 && <FlowConnector hue={hue} />}
                </div>
            ))}
            {blocks.length === 0 && (
                <div className="text-slate-400 text-sm">No methodology defined for this combination.</div>
            )}
        </div>
    );
}

function PipelineStep({ name, idx, total, status = "pending", hue, checklist = [] }) {
    const pct = Math.round(((idx + 1) / total) * 100);
    const Icon = stageIcon(name);
    const statusStyle = {
        active: `ring-2 ring-slate-300 bg-gradient-to-r from-slate-100 to-slate-200 text-slate-900`,
        done: `bg-slate-800/70 text-slate-200 border-slate-600`,
        pending: `bg-slate-900/60 text-slate-300 border-slate-700`,
    }[status];
    return (
        <motion.div layout className="flex flex-col items-start">
            <div
                className={`px-3 py-2 rounded-xl border ${statusStyle} flex items-center gap-2`}
                style={
                    status === "active"
                        ? { boxShadow: `0 10px 24px -10px hsl(${hue} 90% 60% / .5)` }
                        : {}
                }
            >
                <Icon className="w-4 h-4" />
                <div>
                    <div className="text-[11px] text-slate-500">Step {idx + 1}</div>
                    <div className="text-sm font-semibold">{name}</div>
                </div>
            </div>
            <div className="w-full mt-2">
                <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden">
                    <motion.div
                        className="h-full rounded-full"
                        initial={{ width: 0 }}
                        animate={{ width: `${pct}%` }}
                        transition={{ duration: 0.6 }}
                        style={{ backgroundColor: `hsl(${hue} 90% 60%)` }}
                    />
                </div>
            </div>
            {checklist.length > 0 && (
                <div className="mt-3 w-full bg-slate-900/50 rounded-lg p-3 border border-slate-700">
                    <Checklist items={checklist} />
                </div>
            )}
        </motion.div>
    );
}

function WorkflowRail({ asset, hue }) {
    const steps = workflows[asset] || [];
    const [active, setActive] = useState(2);
    const assetChecks = stageChecklist[asset] || {};
    return (
        <div className="space-y-6">
            <div className="flex flex-wrap items-stretch gap-5">
                {steps.map((s, i) => (
                    <div key={i} className="min-w-[240px] flex-1">
                        <PipelineStep
                            name={s}
                            idx={i}
                            total={steps.length}
                            status={i < active ? "done" : i === active ? "active" : "pending"}
                            hue={hue}
                            checklist={[...(stageChecklist.common[s] || []), ...(assetChecks[s] || [])]}
                        />
                    </div>
                ))}
            </div>
            <div className="flex gap-2">
                <button
                    onClick={() => setActive((a) => Math.max(0, a - 1))}
                    className="px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-100"
                >
                    ◀ Prev
                </button>
                <button
                    onClick={() => setActive((a) => Math.min(steps.length - 1, a + 1))}
                    className="px-3 py-2 rounded-lg bg-slate-100 text-slate-900 hover:bg-slate-200 border border-slate-300"
                    style={{ boxShadow: `0 10px 20px -10px hsl(${hue} 90% 60% / .4)` }}
                >
                    Next ▶
                </button>
            </div>
        </div>
    );
}

function Legend({ asset, mode, hue }) {
    const modeDesc = MODES.find((m) => m.key === mode)?.desc;
    const assetLabel = ASSETS.find((a) => a.key === asset)?.label;
    return (
        <div className="flex flex-wrap items-center gap-3 text-xs">
            <Badge>Asset: {assetLabel}</Badge>
            <Badge>Mode: {mode.toUpperCase()}</Badge>
            <span className="text-slate-400">•</span>
            <span className="text-slate-300">{modeDesc}</span>
            <span className="ml-2 inline-flex items-center gap-2 text-slate-400">
                <span className="w-2 h-2 rounded-full" style={{ backgroundColor: `hsl(${hue} 90% 60%)` }} />
                <span>Visual connectors</span>
            </span>
        </div>
    );
}


function OffensiveSidebar({ asset }) {
    const list = offensive[asset] || [];
    return (
        <SectionCard title="Offensive Techniques" subtitle="Attack Catalog" hue={240} icon={Swords}>
            <div className="max-h-64 overflow-auto pr-1">
                <div className="flex flex-wrap gap-2">
                    {list.map((t, i) => (
                        <span key={i} className="px-2 py-1 rounded-lg text-xs bg-slate-900/60 border border-slate-700">
                            {t}
                        </span>
                    ))}
                </div>
            </div>
        </SectionCard>
    );
}

function AssetSidebar({ asset, setAsset }) {
    return (
        <aside className="w-full md:w-60 shrink-0">
            <SectionCard title="Assets" subtitle="Click to select" hue={220} icon={Boxes}>
                <div className="grid grid-cols-2 md:grid-cols-1 gap-2">
                    {ASSETS.map((a) => (
                        <button
                            key={a.key}
                            onClick={() => setAsset(a.key)}
                            className={`flex items-center gap-2 px-3 py-2 rounded-xl border transition text-left ${asset === a.key
                                    ? "bg-gradient-to-r from-slate-100 to-slate-200 text-slate-900 border-slate-300"
                                    : "bg-slate-800/70 text-slate-100 border-slate-700 hover:bg-slate-700"
                                }`}
                            style={
                                asset === a.key
                                    ? { boxShadow: `0 10px 20px -10px hsl(${a.hue} 90% 60% / .45)` }
                                    : {}
                            }
                        >
                            <a.Icon className={`w-4 h-4 ${asset === a.key ? "text-slate-900" : "text-slate-300"}`} />
                            <span className="font-medium">{a.label}</span>
                        </button>
                    ))}
                </div>
            </SectionCard>
            <SectionCard title="Quick Tips" hue={260} icon={BadgeAlert}>
                <ul className="text-slate-300 text-sm space-y-2 list-disc ml-5">
                    <li>Click nodes to expand detailed steps.</li>
                    <li>Switch modes (Black/Grey/White) to change assumptions.</li>
                    <li>Use Workflow page for stage tracking and labels.</li>
                </ul>
            </SectionCard>
        </aside>
    );
}

function ModeHeader({ mode, setMode, hue }) {
    return (
        <div className="flex flex-wrap items-center gap-2">
            {MODES.map((m) => (
                <Chip key={m.key} active={mode === m.key} onClick={() => setMode(m.key)} hue={hue}>
                    {m.label}
                </Chip>
            ))}
        </div>
    );
}

function PreEngagement({ asset }) {
    const base = preEngagement.common;
    const extra = preEngagement[asset] || [];
    return (
        <div className="grid md:grid-cols-2 gap-3 text-sm">
            <div className="bg-slate-800/60 rounded-xl p-4 border border-slate-700">
                <div className="flex items-center gap-2 text-slate-200 font-semibold mb-1"><ListChecks className="w-4 h-4" /> Core</div>
                <ul className="list-disc ml-5 text-slate-300 space-y-1">{base.map((i, idx) => (<li key={idx}>{i}</li>))}</ul>
            </div>
            <div className="bg-slate-800/60 rounded-xl p-4 border border-slate-700">
                <div className="flex items-center gap-2 text-slate-200 font-semibold mb-1"><Settings className="w-4 h-4" /> Asset-specific</div>
                <ul className="list-disc ml-5 text-slate-300 space-y-1">{extra.map((i, idx) => (<li key={idx}>{i}</li>))}</ul>
            </div>
        </div>
    );
}

function OWASPPanel({ asset, hue }) {
    const list = owasp[asset] || [];
    const off = offensive[asset] || [];
    return (
        <div className="grid md:grid-cols-2 gap-4">
            <div className="bg-slate-800/60 rounded-xl p-4 border border-slate-700">
                <div className="flex items-center gap-2 text-slate-200 font-semibold mb-2"><AlertTriangle className="w-4 h-4" /> OWASP / MASVS</div>
                <div className="flex flex-wrap gap-2">
                    {list.map((t, i) => (
                        <span key={i} className="px-2 py-1 rounded-lg text-xs bg-slate-900/60 border border-slate-700">{t}</span>
                    ))}
                </div>
            </div>
            <div className="bg-slate-800/60 rounded-xl p-4 border border-slate-700">
                <div className="flex items-center gap-2 text-slate-200 font-semibold mb-2"><Swords className="w-4 h-4" /> Offensive Techniques</div>
                <div className="flex flex-wrap gap-2">
                    {off.map((t, i) => (
                        <span key={i} className="px-2 py-1 rounded-lg text-xs bg-slate-900/60 border border-slate-700">{t}</span>
                    ))}
                </div>
            </div>
        </div>
    );
}

function Page1({ asset, setAsset, mode, setMode }) {
    const hue = ASSETS.find((a) => a.key === asset)?.hue ?? 210;
    return (
        <div className="max-w-7xl mx-auto p-5 grid md:grid-cols-[260px,1fr] gap-5">
            <AssetSidebar asset={asset} setAsset={setAsset} />
            <main className="space-y-5">
                <SectionCard title="Pre-Engagement" subtitle="Before any testing" hue={hue} icon={ListChecks}>
                    <PreEngagement asset={asset} />
                </SectionCard>
                <SectionCard title="Pentesting Modes" subtitle="Black • Grey • White" hue={hue} icon={Shield}>
                    <div className="flex flex-wrap items-center justify-between gap-3">
                        <ModeHeader mode={mode} setMode={setMode} hue={hue} />
                        <Legend asset={asset} mode={mode} hue={hue} />
                    </div>
                </SectionCard>
                <SectionCard title="Methodology Map" subtitle="Visual & Expandable" hue={hue} icon={Workflow}>
                    <MethodologyMap asset={asset} mode={mode} hue={hue} />
                </SectionCard>
                <SectionCard title="Standards & Techniques" subtitle="OWASP • MASVS • OffSec" hue={hue} icon={ClipboardList}>
                    <OWASPPanel asset={asset} hue={hue} />
                </SectionCard>
            </main>
        </div>
    );
}

function Page2({ asset, setAsset }) {
    const hue = ASSETS.find((a) => a.key === asset)?.hue ?? 210;
    const [tab, setTab] = useState(asset);
    const tabs = ASSETS.map((a) => ({ key: a.key, label: `${a.label} PT`, hue: a.hue, Icon: a.Icon }));
    const onTab = (k) => { setTab(k); setAsset(k); };
    const stageDesc = (stage) => ({
        Planning: "Define scope, RoE, SLAs, data handling, stakeholders.",
        Scoping: "Targets, envs, exclusions, access routes, creds, tenants.",
        Recon: "OSINT, fingerprinting, inventory, attack surface mapping.",
        "Threat Modeling": "STRIDE/abuse cases, trust boundaries, hotspots.",
        Discovery: "Systematic tests (OWASP/ASVS/MASVS), fuzzing, authz checks.",
        Exploitation: "Exploit chains to validate impact; safe proofing.",
        Risking: "CVSS + business impact; data class & compliance mapping.",
        Reporting: "PoCs, repro steps, fixes, evidence, governance links.",
        Retest: "Verify fixes, regressions, evidence of closure.",
        "Contract Review": "OpenAPI/GraphQL, auth flows, error models.",
        "AuthZ Matrix": "Role/tenant object access matrix; IDOR/BOLA/BFLA.",
        "Gateway Policy": "Rate limiting, schema validation, JWT/OAuth, WAF.",
        "Build Intake": "QA builds, symbols, device matrix, test creds.",
        Static: "Code/resources (secrets, crypto, exported comps).",
        Dynamic: "Runtime hooks, TLS pinning bypass, storage/logs.",
        "API Tests": "On-device API authz, replay, device binding, WebViews.",
        "Store Review": "Store policies, privacy, trackers, assets.",
        Inventory: "Enumerate cloud assets, identities, networks, data.",
        Misconfig: "CSPM, IAM least privilege, storage exposure, keys.",
    })[stage] || "";
    return (
        <div className="max-w-7xl mx-auto p-5 grid md:grid-cols-[260px,1fr] gap-5">
            <aside className="w-full md:w-60 shrink-0">
                <SectionCard title="Assets" subtitle="Workflow Tabs" hue={220} icon={Boxes}>
                    <div className="grid grid-cols-2 md:grid-cols-1 gap-2">
                        {tabs.map((t) => (
                            <button
                                key={t.key}
                                onClick={() => onTab(t.key)}
                                className={`px-3 py-2 rounded-xl border text-left flex items-center gap-2 ${tab === t.key
                                        ? "bg-gradient-to-r from-slate-100 to-slate-200 text-slate-900 border-slate-300"
                                        : "bg-slate-800/70 text-slate-100 border-slate-700 hover:bg-slate-700"
                                    }`}
                                style={
                                    tab === t.key ? { boxShadow: `0 10px 20px -10px hsl(${t.hue} 90% 60% / .45)` } : {}
                                }
                            >
                                <t.Icon className={`w-4 h-4 ${tab === t.key ? "text-slate-900" : "text-slate-300"}`} />
                                {t.label}
                            </button>
                        ))}
                    </div>
                </SectionCard>
            </aside>
            <main className="space-y-5">
                <SectionCard title="VAPT Workflow" subtitle="End-to-End Pipeline" hue={hue} icon={Workflow}>
                    <div className="mb-4 text-slate-300 text-sm">
                        Visualize and label the full lifecycle for <span className="text-slate-100 font-medium">{ASSETS.find(a => a.key === tab)?.label}</span>.
                    </div>
                    <WorkflowRail asset={tab} hue={hue} />
                </SectionCard>
                <SectionCard title="Stage Details" subtitle="Descriptions + Checklists" hue={hue} icon={FileText}>
                    <div className="grid md:grid-cols-2 gap-4 text-sm text-slate-300">
                        {(workflows[tab] || []).map((stage, i) => (
                            <div key={i} className="bg-slate-800/60 rounded-xl p-4 border border-slate-700">
                                <div className="flex items-center gap-2 text-slate-200 font-semibold mb-1">
                                    {React.createElement(stageIcon(stage), { className: "w-4 h-4" })}
                                    {stage}
                                </div>
                                <p className="leading-relaxed mb-2">{stageDesc(stage)}</p>
                                <Checklist items={[...(stageChecklist.common[stage] || []), ...((stageChecklist[tab] || {})[stage] || [])]} />
                            </div>
                        ))}
                    </div>
                </SectionCard>
                <SectionCard title="Standards & Techniques" subtitle="OWASP • MASVS • OffSec" hue={hue} icon={ClipboardList}>
                    <OWASPPanel asset={tab} hue={hue} />
                </SectionCard>
                <SectionCard title="Pre-Engagement (Quick View)" subtitle="Checklist for this asset" hue={hue} icon={ListChecks}>
                    <PreEngagement asset={tab} />
                </SectionCard>
            </main>
        </div>
    );
}

// --- Tools Landscape Data ---
const TOOLS = {
    web: {
        SAST: [
            "SonarQube (Open Source/Paid)", "Checkmarx (Paid)", "Fortify SCA (Paid)", "Bandit (Open Source)", "Semgrep (Open Source/Paid)", "ESLint Security Plugin (Open Source)", "CodeQL (Free/Paid)", "Veracode (Paid)"
        ],
        DAST: [
            "OWASP ZAP (Open Source)", "Burp Suite Pro (Paid)", "Nikto (Open Source)", "W3AF (Open Source)", "Arachni (Open Source)", "Netsparker/Invicti (Paid)", "Acunetix (Paid)", "AppScan (Paid)"
        ]
    },
    api: {
        SAST: [
            "SpectralOps (Paid)", "APISec (Paid)", "42Crunch (Paid)", "GitLeaks (Open Source)", "Semgrep API Rules (Open Source/Paid)", "TruffleHog (Open Source)"
        ],
        DAST: [
            "Postman (Free/Paid)", "OWASP ZAP API Scan (Open Source)", "Burp Suite REST/GraphQL (Paid)", "Hoppscotch (Open Source)", "ReadyAPI (Paid)", "APIsec.ai (Paid)", "Insomnia (Free/Paid)", "SoapUI (Open Source/Paid)"
        ]
    },
    mobile: {
        SAST: [
            "MobSF (Open Source)", "QARK (Open Source)", "AndroBugs (Open Source)", "Fortify SCA Mobile Plugin (Paid)", "Codified Security (Paid)", "Veracode Mobile (Paid)"
        ],
        DAST: [
            "MobSF Dynamic (Open Source)", "Drozer (Open Source)", "Objection (Open Source)", "Frida (Open Source)", "Xposed Framework (Open Source)", "Needle (Open Source)", "Appium (Open Source)", "Cycript (Open Source)"
        ]
    },
    cloud: {
        SAST: [
            "Checkov (Open Source)", "Terrascan (Open Source)", "CloudSploit (Open Source)", "Prowler (Open Source)", "ScoutSuite (Open Source)", "TruffleHog (Open Source)", "GitLeaks (Open Source)", "Bridgecrew (Paid)"
        ],
        DAST: [
            "Pacu (Open Source)", "CloudGoat (Open Source)", "Rhino Security Labs AWS Tools (Open Source)", "CS Suite (Open Source)", "SkyArk (Open Source)", "CloudBrute (Open Source)", "Nimbostratus (Open Source)", "Dome9 (Paid)"
        ]
    },
    thick: {
        SAST: [
            "Fortify SCA (Paid)", "Veracode SAST (Paid)", "SonarQube (Open Source/Paid)", "PVS-Studio (Paid)", "Checkmarx (Paid)", "Coverity (Paid)"
        ],
        DAST: [
            "Burp Suite with Proxies (Paid)", "Wireshark (Open Source)", "Echo Mirage (Free)", "Process Monitor (Free)", "Fiddler (Free)", "Scapy (Open Source)", "API Monitor (Free)", "CFF Explorer (Free)", "x64dbg (Open Source)"
        ]
    },
    thin: {
        SAST: [
            "SonarQube (Open Source/Paid)", "ESLint Security Plugin (Open Source)", "Semgrep (Open Source/Paid)", "Checkmarx (Paid)", "Fortify SCA (Paid)", "Retire.js (Open Source)", "Snyk (Free/Paid)"
        ],
        DAST: [
            "OWASP ZAP (Open Source)", "Burp Suite (Paid)", "Nikto (Open Source)", "Arachni (Open Source)", "Browser Developer Tools (Free)", "Tamper Data (Free)", "WebScarab (Open Source)", "Grabber (Open Source)"
        ]
    }
};

function ToolsCard({ title, tools, color }) {
    return (
        <div className="bg-slate-800/60 rounded-xl p-4 border border-slate-700 shadow-md h-full flex flex-col">
            <div className="font-semibold text-slate-200 mb-2" style={{ color }}>{title}</div>
            <ul className="space-y-1 flex-1">
                {tools.map((tool, i) => (
                    <li key={i} className="bg-slate-900/60 px-2 py-1 rounded text-slate-300 text-sm border border-slate-700">
                        {tool}
                    </li>
                ))}
            </ul>
        </div>
    );
}

function Page3() {
    return (
        <div className="max-w-7xl mx-auto p-5 space-y-8">
            <h2 className="text-2xl font-bold text-slate-100 mb-2">Tools Landscape</h2>
            <div className="grid gap-8 grid-cols-1 md:grid-cols-2 lg:grid-cols-3">
                {Object.entries(TOOLS).map(([key, val]) => {
                    const asset = ASSETS.find(a => a.key === key);
                    return (
                        <div key={key} className="flex flex-col h-full justify-between space-y-4">
                            <div className="flex items-center gap-2 mb-2">
                                {asset?.Icon && <asset.Icon className="w-5 h-5 text-slate-300" />}
                                <span className="text-lg font-semibold text-slate-100">{asset?.label} Pentesting</span>
                            </div>
                            <div className="flex flex-col gap-4 flex-1">
                                <ToolsCard title="SAST Tools" tools={val.SAST} color="#38bdf8" />
                                <ToolsCard title="DAST Tools" tools={val.DAST} color="#22d3ee" />
                            </div>
                        </div>
                    );
                })}
            </div>
        </div>
    );
}

function TopNav({ page, setPage }) {
    return (
        <header className="sticky top-0 z-40 backdrop-blur supports-[backdrop-filter]:bg-slate-950/60 bg-slate-950/80 border-b border-slate-800">
            <div className="max-w-7xl mx-auto px-5 py-3 flex items-center justify-between">
                <div className="flex items-center gap-3">
                    <div className="w-2.5 h-2.5 rounded-full bg-cyan-400 shadow-[0_0_20px] shadow-cyan-500/60" />
                    <h1 className="text-slate-100 font-semibold tracking-tight">
                        VAPT Studio – Asset Methodologies & Workflow
                    </h1>
                </div>
                <nav className="flex items-center gap-2">
                    <button
                        onClick={() => setPage(-1)}
                        className={`px-3 py-1.5 rounded-lg text-sm border transition ${
                            page === -1
                                ? "bg-gradient-to-r from-slate-100 to-slate-200 text-slate-900 border-slate-300"
                                : "bg-slate-800/70 text-slate-100 border-slate-700 hover:bg-slate-700"
                        }`}
                    >
                        Overview
                    </button>
                    <button
                        onClick={() => setPage(0)}
                        className={`px-3 py-1.5 rounded-lg text-sm border transition ${
                            page === 0
                                ? "bg-gradient-to-r from-slate-100 to-slate-200 text-slate-900 border-slate-300"
                                : "bg-slate-800/70 text-slate-100 border-slate-700 hover:bg-slate-700"
                        }`}
                    >
                        Page 1: Asset Methodology
                    </button>
                    <button
                        onClick={() => setPage(1)}
                        className={`px-3 py-1.5 rounded-lg text-sm border transition ${
                            page === 1
                                ? "bg-gradient-to-r from-slate-100 to-slate-200 text-slate-900 border-slate-300"
                                : "bg-slate-800/70 text-slate-100 border-slate-700 hover:bg-slate-700"
                        }`}
                    >
                        Page 2: VAPT Workflow
                    </button>
                    <button
                        onClick={() => setPage(2)}
                        className={`px-3 py-1.5 rounded-lg text-sm border transition ${
                            page === 2
                                ? "bg-gradient-to-r from-slate-100 to-slate-200 text-slate-900 border-slate-300"
                                : "bg-slate-800/70 text-slate-100 border-slate-700 hover:bg-slate-700"
                        }`}
                    >
                        Page 3: Tools Landscape
                    </button>
                </nav>
            </div>
        </header>
    );
}

export default function App() {
    const [page, setPage] = useState(-1);
    const [asset, setAsset] = useState("web");
    const [mode, setMode] = useState("black");
    const hue = useMemo(() => ASSETS.find((a) => a.key === asset)?.hue ?? 210, [asset]);

    function Overview() {
        // Steps and icons for the workflow
        const steps = [
            {
                label: "Pre-Engagement",
                desc: "Define scope, agreements, and rules of engagement.",
                icon: <FileText className="w-8 h-8 text-cyan-300" />,
            },
            {
                label: "Information Gathering",
                desc: "Reconnaissance and intelligence collection.",
                icon: <Search className="w-8 h-8 text-green-300" />,
            },
            {
                label: "Web Application Testing",
                desc: "Security testing of web applications.",
                icon: <Globe className="w-8 h-8 text-blue-400" />,
            },
            {
                label: "API Testing",
                desc: "Security validation of APIs.",
                icon: <Cable className="w-8 h-8 text-purple-400" />,
            },
            {
                label: "Mobile Testing",
                desc: "Mobile app penetration testing.",
                icon: <Smartphone className="w-8 h-8 text-cyan-400" />,
            },
            {
                label: "Vulnerability Assessment",
                desc: "Vulnerability scanning and detection.",
                icon: <AlertTriangle className="w-8 h-8 text-green-400" />,
            },
            {
                label: "Exploitation",
                desc: "Exploiting discovered vulnerabilities.",
                icon: <Zap className="w-8 h-8 text-purple-400" />,
            },
            {
                label: "Post-Exploitation",
                desc: "Persistence, lateral movement, maintaining access.",
                icon: <Network className="w-8 h-8 text-blue-400" />,
            },
            {
                label: "Reporting",
                desc: "Document findings, risks, and provide remediation recommendations.",
                icon: <ShieldCheck className="w-8 h-8 text-cyan-300" />,
            },
        ];
        const [step, setStep] = React.useState(0);
        const [playing, setPlaying] = React.useState(true);
        React.useEffect(() => {
            if (!playing) return;
            const t = setTimeout(() => setStep((s) => (s + 1) % steps.length), 2200);
            return () => clearTimeout(t);
        }, [step, playing]);
        // Progress bar color
        const progress = ((step + 1) / steps.length) * 100;
        return (
            <div className="min-h-screen flex flex-col items-center justify-center bg-[#10121a] px-2 py-8 font-['Orbitron','Rajdhani','Eurostile',sans-serif]">
                <h1 className="text-4xl md:text-5xl font-extrabold text-purple-300 mb-2 tracking-wider text-center drop-shadow-[0_0_16px_#b300ff]">VAPT Workflow</h1>
                <div className="text-cyan-200 text-lg mb-6 tracking-wide text-center">Vulnerability Assessment & Penetration Testing Process</div>
                <button
                    className="mb-6 px-5 py-2 rounded-lg border border-cyan-400 text-cyan-200 bg-[#0a0a0f] shadow-[0_0_12px_#00f0ff] hover:bg-cyan-900/10 transition"
                    onClick={() => setPlaying((p) => !p)}
                >
                    {playing ? "Pause Animation" : "Resume Animation"}
                </button>
                <div className="flex flex-col md:flex-row gap-8 w-full max-w-5xl items-center justify-center">
                    {/* Animated step card */}
                    <div className="flex-1 flex items-center justify-center">
                        <div className="relative w-full max-w-md">
                            <div className="rounded-2xl bg-[#181c24] border border-cyan-900/60 shadow-[0_0_32px_#00f0ff55] px-8 py-8 min-h-[220px] flex flex-col justify-center animate-fadein"
                                style={{ boxShadow: step === steps.length - 1 ? '0 0 32px #00f0ff99, 0 0 64px #b300ff44' : '0 0 32px #00f0ff55' }}>
                                <div className="flex items-center gap-4 mb-2">
                                    <span className="inline-flex items-center justify-center w-12 h-12 rounded-xl bg-[#10121a] border border-cyan-800 shadow-[0_0_16px_#00f0ff]">
                                        {steps[step].icon}
                                    </span>
                                    <span className="text-cyan-100 text-xs tracking-widest font-bold">STEP {step + 1}</span>
                                </div>
                                <div className="text-2xl font-bold text-cyan-100 mb-1 drop-shadow-[0_0_8px_#00f0ff]">{steps[step].label}</div>
                                <div className="text-slate-300 text-base mb-2">{steps[step].desc}</div>
                            </div>
                            <div className="mt-3">
                                <div className="text-xs text-cyan-200 mb-1 flex justify-between">
                                    <span>Progress</span>
                                    <span>{step + 1} / {steps.length}</span>
                                </div>
                                <div className="w-full h-2 rounded-full bg-[#23263a] overflow-hidden">
                                    <div className="h-full rounded-full bg-gradient-to-r from-cyan-400 via-blue-400 to-purple-400 transition-all duration-500" style={{ width: `${progress}%` }} />
                                </div>
                            </div>
                        </div>
                    </div>
                    {/* Steps grid */}
                    <div className="flex-1 grid grid-cols-2 md:grid-cols-3 gap-4">
                        {steps.map((s, i) => (
                            <div
                                key={i}
                                className={`rounded-xl border border-cyan-900/60 bg-[#181c24] flex flex-col items-center py-6 px-2 shadow-[0_0_12px_#00f0ff33] transition-all duration-300 ${i === step ? 'ring-2 ring-cyan-400 shadow-[0_0_32px_#00f0ff99]' : ''}`}
                                style={i === step ? { boxShadow: '0 0 32px #00f0ff99, 0 0 64px #b300ff44' } : {}}
                            >
                                <span className="inline-flex items-center justify-center w-10 h-10 rounded-lg bg-[#10121a] border border-cyan-800 mb-2">
                                    {s.icon}
                                </span>
                                <span className="text-cyan-100 font-semibold text-sm mb-1 text-center">{s.label}</span>
                                <span className="text-cyan-400 text-xs font-mono">{(i + 1).toString().padStart(2, '0')}</span>
                            </div>
                        ))}
                    </div>
                </div>
                {/* Navigation dots */}
                <div className="flex gap-2 mt-8">
                    {steps.map((_, i) => (
                        <button
                            key={i}
                            className={`w-3 h-3 rounded-full ${i === step ? 'bg-cyan-400 shadow-[0_0_8px_#00f0ff]' : 'bg-[#23263a]'}`}
                            onClick={() => setStep(i)}
                            aria-label={`Go to step ${i + 1}`}
                        />
                    ))}
                </div>
            </div>
        );
    }

    // Neon icons for overview
    function HandshakeIcon() {
        return (
            <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="#00f0ff" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" className="w-8 h-8 drop-shadow-[0_0_8px_#00f0ff]">
                <path d="M4 19l-2-2a2 2 0 0 1 0-2.83l7.17-7.17a2 2 0 0 1 2.83 0l7.17 7.17a2 2 0 0 1 0 2.83l-2 2" />
                <path d="M16 7l-1.5-1.5a2 2 0 0 0-2.83 0L10 7" />
            </svg>
        );
    }
    function MagnifierIcon() {
        return (
            <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="#00ff99" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" className="w-8 h-8 drop-shadow-[0_0_8px_#00ff99]">
                <circle cx="11" cy="11" r="8" />
                <line x1="21" y1="21" x2="16.65" y2="16.65" />
            </svg>
        );
    }
    function BrowserIcon() {
        return (
            <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="#00f0ff" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" className="w-8 h-8 drop-shadow-[0_0_8px_#00f0ff]">
                <rect x="3" y="4" width="18" height="16" rx="2" />
                <line x1="3" y1="8" x2="21" y2="8" />
            </svg>
        );
    }
    function ApiIcon() {
        return (
            <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="#b300ff" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" className="w-8 h-8 drop-shadow-[0_0_8px_#b300ff]">
                <rect x="4" y="4" width="16" height="16" rx="4" />
                <path d="M8 12h8" />
                <path d="M12 8v8" />
            </svg>
        );
    }

    return (
        <div className="min-h-screen bg-slate-950 text-slate-100">
            <TopNav page={page} setPage={setPage} />
            <div className="relative overflow-hidden border-b border-slate-800">
                <div
                    className="h-16 w-full"
                    style={{
                        background:
                            `radial-gradient(600px 60px at 10% 10%, hsl(${hue} 90% 60% / .22), transparent), radial-gradient(600px 60px at 90% 0%, hsl(${hue} 90% 60% / .20), transparent)`,
                    }}
                />
            </div>
            {page === -1 ? (
                <Overview />
            ) : page === 0 ? (
                <Page1 asset={asset} setAsset={setAsset} mode={mode} setMode={setMode} />
            ) : page === 1 ? (
                <Page2 asset={asset} setAsset={setAsset} />
            ) : (
                <Page3 />
            )}
            <footer className="max-w-7xl mx-auto px-5 py-10 text-slate-400 text-xs">
                <div className="flex flex-wrap items-center justify-between gap-3">
                    <div>© {new Date().getFullYear()}</div>
                </div>
            </footer>
        </div>
    );
}
