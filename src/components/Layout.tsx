import { type ReactNode, type ComponentType } from "react";
import { NavLink, Outlet } from "react-router-dom";
import { FormattedMessage } from "react-intl";
import {
  Activity,
  Cog,
  Layers,
  type LucideProps,
  Rss,
  Server,
  Zap,
} from "lucide-react";

interface NavItemSpec {
  to: string;
  end: boolean;
  icon: ComponentType<LucideProps>;
  messageId: string;
  defaultLabel: string;
}

const items: NavItemSpec[] = [
  { to: "/",              end: true,  icon: Activity, messageId: "nav.home",          defaultLabel: "Connection" },
  { to: "/servers",       end: false, icon: Server,   messageId: "nav.servers",       defaultLabel: "Servers" },
  { to: "/subscriptions", end: false, icon: Rss,      messageId: "nav.subscriptions", defaultLabel: "Subscriptions" },
  { to: "/routing",       end: false, icon: Layers,   messageId: "nav.routing",       defaultLabel: "Routing" },
];

export function Layout({ children }: { children?: ReactNode }) {
  return (
    <div className="layout">
      <nav className="nav">
        <div className="brand">
          <span className="brand-mark" aria-hidden="true">
            <Zap size={16} strokeWidth={2.5} />
          </span>
          <FormattedMessage id="app.title" defaultMessage="Nexray" />
        </div>

        {items.map((it) => (
          <NavLink
            key={it.to}
            to={it.to}
            end={it.end}
            className={({ isActive }) => (isActive ? "active" : undefined)}
          >
            <it.icon size={18} className="icon" />
            <FormattedMessage id={it.messageId} defaultMessage={it.defaultLabel} />
          </NavLink>
        ))}

        <span style={{ flex: 1 }} />

        <NavLink
          to="/settings"
          className={({ isActive }) => (isActive ? "active" : undefined)}
        >
          <Cog size={18} className="icon" />
          <FormattedMessage id="nav.settings" defaultMessage="Settings" />
        </NavLink>
      </nav>
      <main className="page">{children ?? <Outlet />}</main>
    </div>
  );
}
