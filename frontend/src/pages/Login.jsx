import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ShieldCheck, Lock } from 'lucide-react';
import { useAuth } from '../lib/auth';

export default function Login() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState(null);
  const { login } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
      });
      if (res.ok) {
        const data = await res.json();
        login(data.token);
        
        // Decode token to find role
        const payload = JSON.parse(atob(data.token.split('.')[1]));
        const role = payload.role;
        
        if (role === 'ROLE_SOC_ANALYST') navigate('/analyst-dashboard');
        else if (role === 'ROLE_AUDITOR') navigate('/auditor-dashboard');
        else if (role === 'ROLE_ADMIN') navigate('/admin-dashboard');
        else navigate('/');
      } else {
        setError('Invalid credentials');
      }
    } catch (err) {
      setError('Connection failed');
    }
  };

  return (
    <div className="flex flex-col items-center justify-center h-[70vh] animate-fade-in">
      <div className="w-full max-w-md bg-surface p-8 rounded-xl border border-line shadow-lg">
        <div className="flex flex-col items-center mb-8">
          <div className="w-12 h-12 bg-accent text-surface rounded-lg flex items-center justify-center shadow-[0_0_20px_rgba(0,255,65,0.4)] mb-4">
            <ShieldCheck size={28} className="stroke-[2.5px]" />
          </div>
          <h2 className="text-2xl font-bold font-display text-ink uppercase tracking-tight">SecureMailScope</h2>
          <p className="text-ink-3 mt-1 text-sm">Sign in to access your dashboard</p>
        </div>

        {error && (
          <div className="bg-crit/10 border border-crit/30 text-crit px-4 py-2 rounded-md mb-6 text-sm font-medium">
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-ink-2 mb-1">Username</label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full bg-surface-2 border border-line rounded-md px-4 py-2 text-ink focus:outline-none focus:border-accent focus:ring-1 focus:ring-accent transition-colors"
              required
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-ink-2 mb-1">Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full bg-surface-2 border border-line rounded-md px-4 py-2 text-ink focus:outline-none focus:border-accent focus:ring-1 focus:ring-accent transition-colors"
              required
            />
          </div>
          <button
            type="submit"
            className="w-full bg-accent text-surface font-bold py-2.5 rounded-md hover:bg-accent/90 transition-colors shadow-sm flex items-center justify-center gap-2 mt-6"
          >
            <Lock size={16} /> Sign In
          </button>
        </form>
        
        <div className="mt-6 text-center text-xs text-ink-3">
          Demo Accounts:<br/>
          <span className="font-mono">analyst / password</span><br/>
          <span className="font-mono">auditor / password</span><br/>
          <span className="font-mono">admin / password</span>
        </div>
      </div>
    </div>
  );
}
