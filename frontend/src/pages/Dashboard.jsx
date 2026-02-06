import React, { useEffect, useState } from 'react';
import api from '../api';
import { Users, FileText, ShieldCheck } from 'lucide-react';

const StatCard = ({ title, value, icon: Icon, color }) => (
    <div className="card glass-card flex items-center gap-4">
        <div className={`p-3 rounded-full bg-${color}/20 text-${color}`}>
            <Icon size={24} color={`var(--${color})`} />
        </div>
        <div>
            <p className="text-secondary text-sm">{title}</p>
            <p className="text-2xl font-bold">{value}</p>
        </div>
    </div>
);

const Dashboard = () => {
    const [stats, setStats] = useState({ users: 0, evidence: 0, secure: 0 });

    useEffect(() => {
        api.get('/stats').then(res => setStats(res.data)).catch(err => console.error(err));
    }, []);

    return (
        <div>
            <h1 className="text-2xl font-bold mb-6">System Overview</h1>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
                <StatCard title="Total Evidence" value={stats.evidence} icon={FileText} color="primary" />
                <StatCard title="Secure Files" value={stats.secure} icon={ShieldCheck} color="success" />
                <StatCard title="Active Users" value={stats.users} icon={Users} color="accent" />
            </div>

            <div className="card glass-card">
                <h2 className="text-xl font-bold mb-4">Recent Activity</h2>
                <p className="text-secondary">System logs and chain of custody updates would appear here.</p>
                {/* Could fetch recent logs here */}
            </div>
        </div>
    );
};

export default Dashboard;
