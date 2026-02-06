import React, { useState } from 'react';
import api from '../api';
import { Upload, File, CheckCircle } from 'lucide-react';
import { useNavigate } from 'react-router-dom';

const EvidenceUpload = () => {
    const [file, setFile] = useState(null);
    const [description, setDescription] = useState('');
    const [uploading, setUploading] = useState(false);
    const navigate = useNavigate();

    const handleUpload = async (e) => {
        e.preventDefault();
        if (!file) return;

        setUploading(true);
        const formData = new FormData();
        formData.append('file', file);
        formData.append('description', description);

        try {
            await api.post('/upload_evidence', formData, {
                headers: { 'Content-Type': 'multipart/form-data' }
            });
            navigate('/evidence');
        } catch (err) {
            console.error(err);
            const msg = err.response?.data?.detail || "Upload failed. Check console for details.";
            alert("Error: " + msg);
        } finally {
            setUploading(false);
        }
    };

    return (
        <div className="max-w-2xl mx-auto">
            <h1 className="text-2xl font-bold mb-6">Upload Digital Evidence</h1>
            <div className="card glass-card">
                <form onSubmit={handleUpload}>
                    <div className="mb-6">
                        <label className="block text-center p-8 border-2 border-dashed border-border rounded-lg cursor-pointer hover:border-primary transition-colors">
                            <input type="file" className="hidden" onChange={e => setFile(e.target.files[0])} />
                            <Upload className="mx-auto mb-2 text-secondary" size={32} />
                            <p className="text-lg font-medium">{file ? file.name : "Click to Select File"}</p>
                            <p className="text-sm text-secondary mt-1">Files are automatically encrypted and signed.</p>
                        </label>
                    </div>

                    <div className="input-group">
                        <label className="label">Description / Case Number</label>
                        <textarea
                            className="input h-32 resize-none"
                            value={description}
                            onChange={e => setDescription(e.target.value)}
                            required
                            placeholder="Enter case details..."
                        ></textarea>
                    </div>

                    <button disabled={uploading} className="btn w-full justify-center">
                        {uploading ? "Encrypting & Uploading..." : "Secure Upload"}
                    </button>

                    <div className="mt-4 p-4 bg-black/20 rounded text-xs text-secondary font-mono">
                        <p className="flex items-center gap-2"><CheckCircle size={12} className="text-success" /> AES-256 Encryption</p>
                        <p className="flex items-center gap-2 mt-1"><CheckCircle size={12} className="text-success" /> SHA-256 Hashing</p>
                        <p className="flex items-center gap-2 mt-1"><CheckCircle size={12} className="text-success" /> RSA Digital Signature</p>
                    </div>
                </form>
            </div>
        </div>
    );
};

export default EvidenceUpload;
