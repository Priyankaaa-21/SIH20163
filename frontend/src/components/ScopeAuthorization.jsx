import React from 'react';
import { Link } from 'react-router-dom';
import { 
  ShieldCheck, 
  ArrowLeft, 
  AlertOctagon, 
  CheckCircle2, 
  XCircle, 
  Lock, 
  FileCheck,
  Server,
  Terminal
} from 'lucide-react';

const ScopeAuthorization = () => {
  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 'var(--space-4)' }}>
        <Link to="/" className="btn btn-secondary">
          <ArrowLeft size={16} /> Back to Dashboard
        </Link>
        <span className="badge-authorized" style={{ fontSize: '13px', padding: '6px 14px' }}>
          <ShieldCheck size={16} /> Authorized, local environment
        </span>
      </div>

      {/* Main Header Panel */}
      <div className="panel" style={{ marginBottom: 'var(--space-4)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
          <Lock size={28} color="#34d399" />
          <div>
            <h1 style={{ margin: 0, fontSize: 'var(--text-lg)', fontWeight: 700 }}>
              Scope of Assessment & Ethical Authorization
            </h1>
            <p style={{ margin: 0, color: 'var(--text-secondary)', fontSize: 'var(--text-sm)' }}>
              Evaluation framework, testing boundaries, authorization credentials, and non-claims for the SIH 26163 Security Audit.
            </p>
          </div>
        </div>
      </div>

      {/* Authorized Boundary Details */}
      <div className="details-grid" style={{ marginBottom: 'var(--space-4)' }}>
        <div className="panel detail-block">
          <h2 style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <FileCheck size={18} color="var(--accent-light)" /> Authorized Target Boundaries
          </h2>
          <table className="report-table" style={{ marginTop: '12px' }}>
            <tbody>
              <tr>
                <td style={{ fontWeight: 600, width: '160px', color: 'var(--text-secondary)' }}>Target Environment</td>
                <td>Local Sandbox / Air-Gapped Verification Testbed (`localhost:8000`)</td>
              </tr>
              <tr>
                <td style={{ fontWeight: 600, color: 'var(--text-secondary)' }}>Assessment Type</td>
                <td>White-Box Static AST Analysis & Automated TestClient PoC Verification</td>
              </tr>
              <tr>
                <td style={{ fontWeight: 600, color: 'var(--text-secondary)' }}>Auditing Authority</td>
                <td>SIH 26163 Security Evaluation & Vulnerability Management Team</td>
              </tr>
              <tr>
                <td style={{ fontWeight: 600, color: 'var(--text-secondary)' }}>Network Stance</td>
                <td>Strictly offline / air-gapped; 0 external outbound network requests</td>
              </tr>
              <tr>
                <td style={{ fontWeight: 600, color: 'var(--text-secondary)' }}>Data Privacy Stance</td>
                <td>Critical infrastructure coordinates coarsened with deterministic HMAC noise</td>
              </tr>
            </tbody>
          </table>
        </div>

        <div className="panel detail-block">
          <h2 style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Server size={18} color="#38bdf8" /> Verification Mechanics
          </h2>
          <p style={{ fontSize: 'var(--text-sm)', color: 'var(--text-primary)', lineHeight: 1.6 }}>
            Security audits in this platform are conducted via deterministic execution engines:
          </p>
          <ul style={{ paddingLeft: '20px', fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
            <li><strong>AST Code Auditing:</strong> Analyzes Python Abstract Syntax Trees for auth checks, rate limiters, and CORS configurations.</li>
            <li><strong>Before/After PoC Suite:</strong> Executes standalone TestClient harnesses comparing pre-patch baseline implementations (`backend/baseline/`) with hardened app handlers.</li>
            <li><strong>Cryptographic Evidence:</strong> All collected evidence is dynamically signed with SHA-256 digests at execution time.</li>
          </ul>
        </div>
      </div>

      {/* Prominent Section: Claims This Project Does NOT Make */}
      <div className="panel" style={{ borderLeft: '4px solid #ef4444', marginBottom: 'var(--space-4)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', marginBottom: 'var(--space-3)' }}>
          <AlertOctagon size={22} color="#ef4444" />
          <h2 style={{ margin: 0, fontSize: 'var(--text-base)', fontWeight: 700, color: '#fca5a5' }}>
            Explicit Claims This Project DOES NOT Make (Limitations & Non-Claims)
          </h2>
        </div>
        <p style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', marginBottom: 'var(--space-4)' }}>
          To preserve complete transparency with judges and security evaluators, the following boundaries are explicitly declared:
        </p>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: '12px', background: 'rgba(239, 68, 68, 0.06)', padding: '12px', borderRadius: 'var(--radius)', border: '1px solid rgba(239, 68, 68, 0.15)' }}>
            <XCircle size={20} color="#ef4444" style={{ flexShrink: 0, marginTop: '2px' }} />
            <div>
              <strong style={{ color: '#fca5a5' }}>1. No Live External System Exploitation</strong>
              <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', marginTop: '2px' }}>
                This project does NOT perform active attacks, port scans, or denial-of-service simulations against production UN, IAEA, or external third-party news service providers.
              </div>
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'flex-start', gap: '12px', background: 'rgba(239, 68, 68, 0.06)', padding: '12px', borderRadius: 'var(--radius)', border: '1px solid rgba(239, 68, 68, 0.15)' }}>
            <XCircle size={20} color="#ef4444" style={{ flexShrink: 0, marginTop: '2px' }} />
            <div>
              <strong style={{ color: '#fca5a5' }}>2. No Real-World Secret Exfiltration</strong>
              <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', marginTop: '2px' }}>
                This project does NOT store, transmit, or expose real production secrets, API keys, or operational certificates. All scanned tokens are sanitized or synthetic placeholders.
              </div>
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'flex-start', gap: '12px', background: 'rgba(239, 68, 68, 0.06)', padding: '12px', borderRadius: 'var(--radius)', border: '1px solid rgba(239, 68, 68, 0.15)' }}>
            <XCircle size={20} color="#ef4444" style={{ flexShrink: 0, marginTop: '2px' }} />
            <div>
              <strong style={{ color: '#fca5a5' }}>3. No Physical Site Access or SCADA Intrusion</strong>
              <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', marginTop: '2px' }}>
                This assessment does NOT claim physical penetration, operational technology (OT) bypass, or hardware access to real-world radiological or nuclear facilities.
              </div>
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'flex-start', gap: '12px', background: 'rgba(239, 68, 68, 0.06)', padding: '12px', borderRadius: 'var(--radius)', border: '1px solid rgba(239, 68, 68, 0.15)' }}>
            <XCircle size={20} color="#ef4444" style={{ flexShrink: 0, marginTop: '2px' }} />
            <div>
              <strong style={{ color: '#fca5a5' }}>4. No Complete Production Immunity Claim</strong>
              <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', marginTop: '2px' }}>
                While tested application vulnerabilities have been fully remediated and verified, comprehensive defense requires runtime Web Application Firewalls (WAFs), continuous threat modeling, and zero-trust identity federation.
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Rules of Engagement / Ethics */}
      <div className="panel">
        <h2 style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <CheckCircle2 size={18} color="#10b981" /> Ethical Rules of Engagement
        </h2>
        <p style={{ fontSize: 'var(--text-sm)', color: 'var(--text-primary)', lineHeight: 1.6 }}>
          All vulnerability assessment workflows adhere strictly to standard ISO/IEC 29147 (Vulnerability Disclosure) and OWASP code of ethics. Research is performed solely for defensive verification, regression-testing remediations, and protecting critical infrastructure datasets.
        </p>
      </div>
    </div>
  );
};

export default ScopeAuthorization;
