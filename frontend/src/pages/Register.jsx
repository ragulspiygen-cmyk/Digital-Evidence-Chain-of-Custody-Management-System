import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { useNavigate, Link } from 'react-router-dom';
import { Shield, UserPlus } from 'lucide-react';
import { QRCodeSVG } from 'qrcode.react';

const Register = () => {
    const [formData, setFormData] = useState({
        username: '',
        password: '',
        role: 'Evidence Collector'
    });
    const [registrationData, setRegistrationData] = useState(null);
    const [error, setError] = useState('');
    const { register } = useAuth();

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');
        try {
            const res = await register(formData.username, formData.password, formData.role);
            setRegistrationData(res);
        } catch (err) {
            console.error(err);
            setError(err.response?.data?.detail || err.message || 'Registration failed');
        }
    };

    if (registrationData) {
        return (
            <div className="flex items-center justify-center min-h-screen">
                <div className="card glass-card w-full max-w-md text-center">
                    <Shield className="text-success mx-auto mb-4" size={48} />
                    <h2 className="text-2xl font-bold mb-2">Registration Successful</h2>
                    <p className="text-secondary mb-6">Scan this QR Code with your Authenticator App</p>

                    <div className="bg-white p-4 rounded mb-4 inline-block">
                        {registrationData.otp_uri ? (
                            <QRCodeSVG value={registrationData.otp_uri} size={200} />
                        ) : (
                            <code className="text-black text-xl font-mono">{registrationData.otp_secret}</code>
                        )}
                    </div>

                    <p className="text-sm text-secondary mb-6 font-mono bg-black/20 p-2 rounded break-all">
                        Secret: {registrationData.otp_secret}
                    </p>

                    <Link to="/login" className="btn w-full justify-center">Proceed to Login</Link>
                </div>
            </div>
        );
    }

    return (
        <div className="flex items-center justify-center min-h-screen">
            <div className="card glass-card w-full max-w-md">
                <div className="flex justify-center mb-6">
                    <UserPlus className="text-primary" size={48} />
                </div>
                <h2 className="text-2xl font-bold text-center mb-6">Create Account</h2>

                {error && <div className="alert text-sm text-center">{error}</div>}

                <form onSubmit={handleSubmit}>
                    <div className="input-group">
                        <label className="label">Username</label>
                        <input type="text" className="input" value={formData.username} onChange={e => setFormData({ ...formData, username: e.target.value })} required />
                    </div>
                    <div className="input-group">
                        <label className="label">Password</label>
                        <input type="password" className="input" value={formData.password} onChange={e => setFormData({ ...formData, password: e.target.value })} required />
                    </div>
                    <div className="input-group">
                        <label className="label">Role</label>
                        <select className="input" value={formData.role} onChange={e => setFormData({ ...formData, role: e.target.value })}>
                            <option value="Evidence Collector">Evidence Collector</option>
                            <option value="Forensic Analyst">Forensic Analyst</option>
                            <option value="Supervisor">Supervisor</option>
                            <option value="Admin">Admin</option>
                        </select>
                    </div>
                    <button type="submit" className="btn w-full justify-center">Register User</button>
                </form>
                <div className="mt-4 text-center text-sm text-secondary">
                    Already have an account? <Link to="/login" className="text-primary hover:underline">Login here</Link>
                </div>
            </div>
        </div>
    );
};

export default Register;
