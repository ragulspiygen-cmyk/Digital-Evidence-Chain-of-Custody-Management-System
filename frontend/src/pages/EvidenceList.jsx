import React, { useEffect, useState } from 'react';
import api from '../api';
import { FileText, ShieldCheck, ShieldAlert, Activity, AlertTriangle, Check, Trash2, Search, CheckCircle } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

const CustodyModal = ({ evidenceId, onClose }) => {
    const [chain, setChain] = useState([]);

    useEffect(() => {
        api.get(`/custody/${evidenceId}`).then(res => setChain(res.data));
    }, [evidenceId]);

    return (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center z-50 p-4" onClick={onClose}>
            <div className="bg-card w-full max-w-2xl rounded-lg border border-border overflow-hidden" onClick={e => e.stopPropagation()}>
                <div className="p-4 border-b border-border flex justify-between items-center">
                    <h3 className="font-bold text-lg">Chain of Custody History</h3>
                    <button onClick={onClose} className="text-secondary hover:text-white">&times;</button>
                </div>
                <div className="p-4 max-h-[60vh] overflow-y-auto">
                    <div className="relative border-l-2 border-primary/30 ml-3 space-y-8 pl-6 py-2">
                        {chain.map((c, i) => (
                            <div key={i} className="relative">
                                <div className="absolute -left-[31px] top-1 w-4 h-4 rounded-full bg-primary border-4 border-card"></div>
                                <div className="glass-card p-3 text-sm">
                                    <div className="flex justify-between mb-1">
                                        <span className="font-bold text-primary">{c.action}</span>
                                        <span className="text-xs text-secondary">{new Date(c.timestamp).toLocaleString()}</span>
                                    </div>
                                    <p className="mb-2">User: <span className="text-white">{c.user}</span> <span className="text-xs bg-white/10 px-1 rounded">{c.role}</span></p>
                                    <p className="text-secondary italic">"{c.details}"</p>
                                    <div className="mt-2 pt-2 border-t border-white/5 w-full">
                                        <p className="text-[10px] text-secondary mb-1">Digital Signature:</p>
                                        <div className="block w-full text-[9px] font-mono text-secondary bg-black/20 p-2 rounded max-h-24 overflow-y-auto" style={{ wordBreak: 'break-all', overflowWrap: 'anywhere', whiteSpace: 'normal' }}>
                                            {c.signature}
                                        </div>
                                    </div>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            </div>
        </div>
    );
};

const EvidenceList = () => {
    const [evidence, setEvidence] = useState([]);
    const [verificationResults, setVerificationResults] = useState({});
    const [selectedEvidence, setSelectedEvidence] = useState(null);
    const { user } = useAuth();

    const loadEvidence = () => {
        api.get('/evidence').then(res => setEvidence(res.data));
    };

    useEffect(() => {
        loadEvidence();
    }, []);

    const handleVerify = async (id) => {
        setVerificationResults(prev => ({ ...prev, [id]: { loading: true } }));
        try {
            const res = await api.get(`/evidence/${id}/verify`);
            setVerificationResults(prev => ({ ...prev, [id]: res.data }));
        } catch (err) {
            setVerificationResults(prev => ({ ...prev, [id]: { status: "ERROR", loading: false } }));
        }
    };

    const handleApprove = async (id) => {
        try {
            await api.post(`/evidence/${id}/approve`);
            loadEvidence();
        } catch (err) {
            alert("Approval Failed: " + (err.response?.data?.detail || "Unknown Error"));
        }
    };

    const handleAnalyze = async (id) => {
        try {
            // In a real app this would stick a record and trigger download
            await api.get(`/evidence/${id}/analyze`);
            alert("Evidence Accessed for Analysis. Chain of custody updated.");
            loadEvidence();
        } catch (err) {
            alert("Access Denied: " + (err.response?.data?.detail || "Unknown Error"));
        }
    };

    const handleDelete = async (id) => {
        if (!window.confirm("Are you sure? This action is permanent and only allowed for Admins.")) return;
        try {
            await api.delete(`/evidence/${id}`);
            loadEvidence();
        } catch (err) {
            alert("Delete Failed: " + (err.response?.data?.detail || "Unknown Error"));
        }
    };

    const handleTamper = async (id) => {
        if (!window.confirm("WARNING: This will corrupt the file on the server to demonstrate detection. Proceed?")) return;
        await api.post(`/evidence/${id}/tamper`);
        loadEvidence();
    };

    return (
        <div>
            <div className="flex justify-between items-center mb-6">
                <h1 className="text-2xl font-bold">Evidence Chain</h1>
                <button onClick={loadEvidence} className="btn btn-secondary text-xs">Refresh</button>
            </div>

            <div className="card w-full overflow-hidden">
                <table className="table">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Filename</th>
                            <th>Uploader</th>
                            <th>Date</th>
                            <th>Status</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {evidence.map(e => {
                            const verifyState = verificationResults[e.id];
                            return (
                                <tr key={e.id} className="hover:bg-white/5 transition-colors">
                                    <td className="font-mono text-xs text-secondary">#{e.id}</td>
                                    <td className="font-medium">
                                        <div className="flex flex-col">
                                            <div className="flex items-center gap-2">
                                                <FileText size={16} className="text-primary" />
                                                {e.filename}
                                            </div>

                                            {e.approval_status === 'APPROVED' ? (
                                                <span className="text-[10px] text-success mt-1 flex items-center gap-1"><CheckCircle size={10} /> Approved</span>
                                            ) : (
                                                <span className="text-[10px] text-secondary mt-1">Pending Approval</span>
                                            )}
                                        </div>
                                    </td>
                                    <td>{e.uploader_name}</td>
                                    <td className="text-sm text-secondary">{new Date(e.upload_time).toLocaleDateString()}</td>
                                    <td>
                                        {verifyState ? (
                                            verifyState.loading ? (
                                                <span className="text-xs animate-pulse">Verifying...</span>
                                            ) : (
                                                <span className={`badge ${verifyState.status === "VERIFIED" ? 'badge-success' : 'badge-danger'} flex items-center gap-1 w-fit`}>
                                                    {verifyState.status === "VERIFIED" ? <ShieldCheck size={12} /> : <ShieldAlert size={12} />}
                                                    {verifyState.status}
                                                </span>
                                            )
                                        ) : (
                                            <button onClick={() => handleVerify(e.id)} className="text-xs text-primary hover:underline">
                                                Verify Integrity
                                            </button>
                                        )}
                                        {e.status === "COMPROMISED" && !verifyState && (
                                            <span className="badge badge-danger ml-2">FLAGGED</span>
                                        )}
                                    </td>
                                    <td>
                                        <div className="flex gap-2">
                                            <button onClick={() => setSelectedEvidence(e.id)} className="btn btn-secondary py-1 px-2 text-xs" title="View Chain">
                                                <Activity size={14} />
                                            </button>

                                            {/* RBAC: Analyze (Analyst, Supervisor, Admin) */}
                                            {["Forensic Analyst", "Supervisor", "Admin"].includes(user.role) && (
                                                <button onClick={() => handleAnalyze(e.id)} className="btn btn-secondary py-1 px-2 text-xs" title="Analyze">
                                                    <Search size={14} />
                                                </button>
                                            )}

                                            {/* RBAC: Approve (Supervisor, Admin) */}
                                            {["Supervisor", "Admin"].includes(user.role) && e.approval_status !== "APPROVED" && (
                                                <button onClick={() => handleApprove(e.id)} className="btn btn-secondary py-1 px-2 text-xs text-success" title="Approve">
                                                    <Check size={14} />
                                                </button>
                                            )}

                                            {/* RBAC: Delete (Admin Only) */}
                                            {user.role === "Admin" && (
                                                <button onClick={() => handleDelete(e.id)} className="btn btn-danger py-1 px-2 text-xs" title="Delete">
                                                    <Trash2 size={14} />
                                                </button>
                                            )}

                                            {/* RBAC: Tamper (Admin Only - Demo) */}
                                            {user.role === "Admin" && (
                                                <button onClick={() => handleTamper(e.id)} className="btn btn-secondary py-1 px-2 text-xs text-danger border border-danger/30" title="Simulate Tamper">
                                                    <AlertTriangle size={14} />
                                                </button>
                                            )}
                                        </div>
                                    </td>
                                </tr>
                            );
                        })}
                    </tbody>
                </table>
            </div>

            {selectedEvidence && <CustodyModal evidenceId={selectedEvidence} onClose={() => setSelectedEvidence(null)} />}
        </div>
    );
};

export default EvidenceList;
