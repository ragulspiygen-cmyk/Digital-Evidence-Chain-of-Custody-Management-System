import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { useNavigate, Link } from 'react-router-dom';
import { Shield, Key, Lock, User as UserIcon } from 'lucide-react';

const Login = () => {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [otp, setOtp] = useState(''); // Initial login might not ask, but easier to ask all at once for demo simplicity or error handling
    const [error, setError] = useState('');
    const { login } = useAuth();
    const navigate = useNavigate();
    const [step, setStep] = useState(1); // 1: Creds, 2: OTP

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');

        try {
            await login(username, password, otp);
            navigate('/');
        } catch (err) {
            if (err.response?.status === 403 && err.response?.data?.detail === "OTP Required") {
                // Wait, my backend logic throws 403 if OTP missing.
                // So if I send empty otp, I catch it here and show OTP input.
                setStep(2);
                setError("Please enter your MFA Code");
            } else {
                setError(err.response?.data?.detail || 'Login failed');
            }
        }
    };

    return (
        <div className="flex items-center justify-center min-h-screen bg-dark">
            <div className="card glass-card w-full max-w-md">
                <div className="flex justify-center mb-6">
                    <Shield className="text-primary" size={48} />
                </div>
                <h2 className="text-2xl font-bold text-center mb-6">Secure Lab Access</h2>

                {error && <div className="alert text-sm text-center">{error}</div>}

                <form onSubmit={handleSubmit}>
                    {step === 1 && (
                        <>
                            <div className="input-group">
                                <label className="label">Username</label>
                                <div className="relative">
                                    <UserIcon className="absolute left-3 top-3 text-secondary" size={18} />
                                    <input
                                        type="text"
                                        className="input pl-10"
                                        value={username}
                                        onChange={(e) => setUsername(e.target.value)}
                                        required
                                    />
                                </div>
                            </div>
                            <div className="input-group">
                                <label className="label">Password</label>
                                <div className="relative">
                                    <Lock className="absolute left-3 top-3 text-secondary" size={18} />
                                    <input
                                        type="password"
                                        className="input pl-10"
                                        value={password}
                                        onChange={(e) => setPassword(e.target.value)}
                                        required
                                    />
                                </div>
                            </div>
                        </>
                    )}

                    {step === 2 && (
                        <div className="input-group">
                            <label className="label">MFA Code (OTP)</label>
                            <div className="relative">
                                <Key className="absolute left-3 top-3 text-secondary" size={18} />
                                <input
                                    type="text"
                                    className="input pl-10"
                                    value={otp}
                                    onChange={(e) => setOtp(e.target.value)}
                                    placeholder="Enter 6-digit code"
                                    required
                                    autoFocus
                                />
                            </div>
                            <p className="text-xs text-secondary mt-2">Check your authenticator app.</p>
                        </div>
                    )}

                    <button type="submit" className="btn w-full justify-center">
                        {step === 1 ? 'Verify Credentials' : 'Authenticate'}
                    </button>
                </form>

                <div className="mt-4 text-center text-sm text-secondary">
                    Don't have an account? <Link to="/register" className="text-primary hover:underline">Register here</Link>
                </div>
            </div>
        </div>
    );
};

export default Login;
