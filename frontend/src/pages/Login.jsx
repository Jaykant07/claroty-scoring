import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import "./Login.css";

export default function Login() {
  const [password, setPassword] = useState("");
  const navigate = useNavigate();

  const handleLogin = (e) => {
    e.preventDefault();
    if (password === "admin") {
      localStorage.setItem("claroty_role", "admin");
    } else {
      localStorage.setItem("claroty_role", "operator");
    }
    navigate("/");
  };

  return (
    <div className="login-container">
      <div className="login-card">
        <h2 className="login-title">Claroty OT Platform</h2>
        <p className="login-subtitle">Gatekeeper Authentication</p>
        <form onSubmit={handleLogin}>
          <input
            type="password"
            placeholder="Passcode ('admin' or 'operator')"
            className="login-input"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
          <button type="submit" className="login-btn">Secure Gateway Login</button>
        </form>
      </div>
    </div>
  );
}
