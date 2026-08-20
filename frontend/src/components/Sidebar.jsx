import {
    LayoutDashboard,
    ShieldAlert,
    AlertTriangle,
    Database,
    Search,
    MailWarning,
    Server,
    Crosshair,
    Bot
} from "lucide-react";

function Sidebar({ setPage }) {
    const menu = [
        { name: "Dashboard", icon: LayoutDashboard },
        { name: "Alerts", icon: ShieldAlert },
        { name: "Incidents", icon: AlertTriangle },
        { name: "IOC Intelligence", icon: Database },
        { name: "Threat Hunting", icon: Search },
        { name: "Phishing", icon: MailWarning },
        { name: "Honeypot", icon: Server },
        { name: "MITRE ATT&CK", icon: Crosshair },
        { name: "AI SOC Agent", icon: Bot }
    ];

    return (
        <aside className="sidebar">

            <div className="logo">
                <div className="logo-title">SENTINELX</div>
                <div className="logo-subtitle">AI SOC PLATFORM</div>
            </div>

            <nav>
                {menu.map((item) => {
                    const Icon = item.icon;

                    return (
                        <button
                            key={item.name}
                            className="nav-item"
                            onClick={() => setPage(item.name)}
                        >
                            <Icon size={19} />
                            <span>{item.name}</span>
                        </button>
                    );
                })}
            </nav>

            <div className="sidebar-footer">
                <div className="status-dot"></div>
                <span>System Online</span>
            </div>

        </aside>
    );
}

export default Sidebar;

