import React, { createContext, useContext, useState, useEffect } from 'react';
import api from '../api';

const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
    const [user, setUser] = useState(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const token = localStorage.getItem('token');
        if (token) {
            api.get('/users/me')
                .then(res => {
                    setUser(res.data);
                })
                .catch(() => {
                    localStorage.removeItem('token');
                })
                .finally(() => setLoading(false));
        } else {
            setLoading(false);
        }
    }, []);

    const login = async (username, password, otp) => {
        const formData = new FormData();
        formData.append('username', username);
        formData.append('password', password);
        // OTP usually sent separate or as param, backend expects form-data for login
        // but code uses Depends() form oauth2, and otp_code as Query/Form. 
        // Let's modify backend to accept query param or form. 
        // In main.py: otp_code: str = Form(None)

        // We append it to form data as it's cleaner
        if (otp) formData.append('otp_code', otp);

        const res = await api.post('/token', formData);
        localStorage.setItem('token', res.data.access_token);
        const userRes = await api.get('/users/me');
        setUser(userRes.data);
        return userRes.data;
    };

    const register = async (username, password, role) => {
        const res = await api.post('/register', { username, password, role });
        return res.data;
    };

    const logout = () => {
        localStorage.removeItem('token');
        setUser(null);
    };

    return (
        <AuthContext.Provider value={{ user, login, logout, register, loading }}>
            {children}
        </AuthContext.Provider>
    );
};

export const useAuth = () => useContext(AuthContext);
