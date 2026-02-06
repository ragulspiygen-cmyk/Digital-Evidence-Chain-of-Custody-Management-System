import React from 'react';
import { useAuth } from '../context/AuthContext';
import { Shield, LogOut, User } from 'lucide-react';

const Navbar = () => {
    const { user, logout } = useAuth();

    return (
        <nav className="navbar justify-between">
            <div className="flex items-center gap-2">
                <Shield className="text-primary" size={24} />
                <span className="font-bold text-lg">ChainOfCustody<span className="text-primary">.Secure</span></span>
            </div>

            {user && (
                <div className="flex items-center gap-4">
                    <div className="flex items-center gap-2 text-sm text-secondary">
                        <User size={16} />
                        <span>{user.username} ({user.role})</span>
                    </div>
                    <button onClick={logout} className="btn btn-secondary text-sm px-3 py-1">
                        <LogOut size={16} /> Logout
                    </button>
                </div>
            )}
        </nav>
    );
};

export default Navbar;
