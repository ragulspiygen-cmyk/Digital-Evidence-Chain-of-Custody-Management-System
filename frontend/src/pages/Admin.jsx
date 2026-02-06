import React, { useEffect, useState } from 'react';
import api from '../api';
import { Users, Trash2 } from 'lucide-react';

const Admin = () => {
    const [users, setUsers] = useState([]);

    useEffect(() => {
        api.get('/users').then(res => setUsers(res.data));
    }, []);

    return (
        <div>
            <h1 className="text-2xl font-bold mb-6">Admin Panel</h1>

            <div className="card w-full">
                <div className="flex items-center gap-2 mb-4">
                    <Users className="text-primary" />
                    <h2 className="text-xl font-bold">User Management</h2>
                </div>

                <table className="table">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Username</th>
                            <th>Role</th>
                            <th>Status</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {users.map(u => (
                            <tr key={u.id}>
                                <td>{u.id}</td>
                                <td className="font-bold">{u.username}</td>
                                <td><span className="badge badge-info">{u.role}</span></td>
                                <td><span className="text-success text-sm">Active</span></td>
                                <td>
                                    <button
                                        onClick={async () => {
                                            if (!window.confirm(`Delete user ${u.username}?`)) return;
                                            try {
                                                await api.delete(`/users/${u.id}`);
                                                setUsers(users.filter(user => user.id !== u.id));
                                            } catch (err) {
                                                alert("Failed to delete user: " + (err.response?.data?.detail || err.message));
                                            }
                                        }}
                                        className="btn btn-danger py-1 px-2 text-xs"
                                    >
                                        <Trash2 size={14} />
                                    </button>
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>

            <div className="card w-full mt-6">
                <h2 className="text-xl font-bold mb-4">System Logs</h2>
                <p className="text-secondary">View system-wide access logs here (Not implemented in demo UI).</p>
            </div>
        </div>
    );
};

export default Admin;
