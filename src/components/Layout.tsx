import { type ReactNode } from "react";
import { NavLink, Outlet } from "react-router-dom";
import { FormattedMessage } from "react-intl";

export function Layout({ children }: { children?: ReactNode }) {
  return (
    <div className="layout">
      <nav className="nav">
        <NavLink
          to="/"
          end
          className={({ isActive }) => (isActive ? "active" : undefined)}
        >
          <FormattedMessage id="nav.home" />
        </NavLink>
        <NavLink
          to="/profile"
          className={({ isActive }) => (isActive ? "active" : undefined)}
        >
          <FormattedMessage id="nav.profile" />
        </NavLink>
        <NavLink
          to="/add-server"
          className={({ isActive }) => (isActive ? "active" : undefined)}
        >
          <FormattedMessage id="nav.add_server" defaultMessage="Add Server" />
        </NavLink>
        <NavLink
          to="/subscriptions"
          className={({ isActive }) => (isActive ? "active" : undefined)}
        >
          <FormattedMessage id="nav.subscriptions" defaultMessage="Subscriptions" />
        </NavLink>
        <NavLink
          to="/pool"
          className={({ isActive }) => (isActive ? "active" : undefined)}
        >
          <FormattedMessage id="nav.pool" defaultMessage="Pool" />
        </NavLink>
        <NavLink
          to="/routing"
          className={({ isActive }) => (isActive ? "active" : undefined)}
        >
          <FormattedMessage id="nav.routing" defaultMessage="Routing" />
        </NavLink>
        <span style={{ flex: 1 }} />
        <NavLink
          to="/settings"
          className={({ isActive }) => (isActive ? "active" : undefined)}
        >
          <FormattedMessage id="nav.settings" defaultMessage="Settings" />
        </NavLink>
      </nav>
      <main className="page">{children ?? <Outlet />}</main>
    </div>
  );
}
