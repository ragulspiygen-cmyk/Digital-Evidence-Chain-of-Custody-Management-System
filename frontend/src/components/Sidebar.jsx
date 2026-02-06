import React from 'react';
import { NavLink } from 'react-router-dom';
import { LayoutDashboard, FileText, Upload, Users, ShieldAlert } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

const Sidebar = () => {
    const { user } = useAuth();

    const linkClass = ({ isActive }) =>
        `flex items-center gap-3 p-3 rounded-lg transition-colors ${isActive ? 'bg-primary/20 text-primary border border-primary/20' : 'text-secondary hover:bg-white/5'}`;

    return (
        <aside className="w-64 bg-card border-r border-border min-h-screen p-4 flex flex-col gap-2">
            <NavLink to="/" className={linkClass}>
                <LayoutDashboard size={20} /> Dashboard
            </NavLink>
            <NavLink to="/evidence" className={linkClass}>
                <FileText size={20} /> Evidence List
            </NavLink>

            {(user.role === "Evidence Collector" || user.role === "Admin") && (
                <NavLink to="/upload" className={linkClass}>
                    <Upload size={20} /> Upload Evidence
                </NavLink>
            )}

            {user.role === "Admin" && (
                <NavLink to="/admin" className={linkClass}>
                    <Users size={20} /> Admin Panel
                </NavLink>
            )}

            {/* Demo helper */}
            <div className="mt-8 border-t border-border pt-4">
                <div className="text-xs text-secondary uppercase font-bold mb-2 px-2">Demo Tools</div>
                <div className="px-3 py-2 bg-white/5 rounded text-xs text-secondary">
                    <p className="mb-1"><strong>OTP Secret:</strong> {user.otp_secret}</p>
                    <p className="text-[10px] opacity-70">Use this to login</p>
                </div>
            </div>
        </aside>
    );
};

export default Sidebar;
