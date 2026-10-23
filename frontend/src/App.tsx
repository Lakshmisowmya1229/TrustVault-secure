import { useState } from 'react'
import './App.css'

const API_URL = 'http://127.0.0.1:8001'

type DocumentItem = {
  id: string
  name: string
  owner: string
  category: string
  size: number
  created_at: string
}

function App() {
  const [username, setUsername] = useState('owner')
  const [password, setPassword] = useState('')
  const [token, setToken] = useState(localStorage.getItem('trustvault_token') || '')
  const [user, setUser] = useState<{ username: string; role: string } | null>(null)
  const [documents, setDocuments] = useState<DocumentItem[]>([])
  const [page, setPage] = useState('Dashboard')
  const [message, setMessage] = useState('')
  const [busy, setBusy] = useState(false)
  const [category, setCategory] = useState('General')
  const [search, setSearch] = useState('')
  const [file, setFile] = useState<File | null>(null)
  const [audit, setAudit] = useState<Record<string, unknown>[]>([])
  const [auditValid, setAuditValid] = useState<boolean | null>(null)
  const [selectedDocument, setSelectedDocument] = useState<DocumentItem | null>(null)
  const [grantUsername, setGrantUsername] = useState('')
  const [grantPermission, setGrantPermission] = useState<'read' | 'edit'>('read')
  const [revokeUsername, setRevokeUsername] = useState('')

  async function api(path: string, options: RequestInit = {}) {
    const headers = new Headers(options.headers)
    if (token) headers.set('Authorization', `Bearer ${token}`)
    if (options.body && !(options.body instanceof FormData)) {
      headers.set('Content-Type', 'application/json')
    }

    const response = await fetch(`${API_URL}${path}`, { ...options, headers })
    if (!response.ok) {
      const data = await response.json().catch(() => ({}))
      throw new Error(data.detail || `Request failed (${response.status})`)
    }
    return response
  }

  async function loadDocuments() {
    const response = await api(`/documents?q=${encodeURIComponent(search)}`)
    setDocuments(await response.json())
  }

  async function login(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setBusy(true)
    setMessage('')
    try {
      const body = new URLSearchParams({ username, password })
      const response = await fetch(`${API_URL}/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body,
      })
      const data = await response.json()
      if (!response.ok) throw new Error(data.detail || 'Login failed')
      localStorage.setItem('trustvault_token', data.access_token)
      setToken(data.access_token)

      const meResponse = await fetch(`${API_URL}/me`, {
        headers: { Authorization: `Bearer ${data.access_token}` },
      })
      if (!meResponse.ok) throw new Error('Could not load your account')
      setUser(await meResponse.json())
      setMessage('Welcome to TrustVault!')
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Unable to log in')
    } finally {
      setBusy(false)
    }
  }
  async function uploadDocument(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!file) {
      setMessage('Please choose a file first.')
      return
    }

    const form = new FormData()
    form.append('file', file)
    form.append('category', category)

    setBusy(true)
    try {
      const response = await api('/documents', { method: 'POST', body: form })
      const result = await response.json()
      setMessage(`Uploaded ${result.name} successfully.`)
      setFile(null)
      await loadDocuments()
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Upload failed')
    } finally {
      setBusy(false)
    }
  }

  async function downloadDocument(doc: DocumentItem) {
    try {
      const response = await api(`/documents/${encodeURIComponent(doc.id)}/download`)
      const blob = await response.blob()
      const url = URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = doc.name
      link.click()
      URL.revokeObjectURL(url)
      setMessage(`Downloaded ${doc.name}`)
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Download failed')
    }
  }

  async function grantAccess(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!selectedDocument) return
    const target = grantUsername.trim()
    if (!target) {
      setMessage('Enter the username you want to share this document with.')
      return
    }
    setBusy(true)
    setMessage('')
    try {
      const response = await api(`/documents/${encodeURIComponent(selectedDocument.id)}/grants`, {
        method: 'POST',
        body: JSON.stringify({ username: target, permission: grantPermission }),
      })
      const result = await response.json()
      setMessage(`Access granted to ${result.username} (${result.permission}).`)
      setGrantUsername('')
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Could not grant access')
    } finally {
      setBusy(false)
    }
  }

  async function revokeAccess(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!selectedDocument) return

    const target = revokeUsername.trim()
    if (!target) {
      setMessage('Enter the username whose access you want to revoke.')
      return
    }

    setBusy(true)
    setMessage('')
    try {
      const response = await api(`/documents/${encodeURIComponent(selectedDocument.id)}/grants/${encodeURIComponent(target)}`, {
        method: 'DELETE',
      })
      const result = await response.json()
      setMessage(`Access revoked for ${result.username}.`)
      setRevokeUsername('')
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Could not revoke access')
    } finally {
      setBusy(false)
    }
  }

  async function loadAudit() {
    try {
      const response = await api('/admin/audit?limit=50')
      setAudit(await response.json())
      const verifyResponse = await api('/admin/audit/verify')
      const result = await verifyResponse.json()
      setAuditValid(result.valid)
      setMessage('Audit records loaded.')
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Unable to load audit records')
    }
  }

  function logout() {
    localStorage.removeItem('trustvault_token')
    setToken('')
    setUser(null)
    setDocuments([])
    setAudit([])
    setAuditValid(null)
    setMessage('You have signed out.')
  }

  async function navigate(nextPage: string) {
    setPage(nextPage)
    setMessage('')
    if (nextPage === 'Documents' || nextPage === 'Dashboard') {
      try {
        await loadDocuments()
      } catch (error) {
        setMessage(error instanceof Error ? error.message : 'Could not load documents')
      }
    }
    if (nextPage === 'Security Audit') await loadAudit()
  }

  if (!user) {
    return (
      <main className="login-screen">
        <section className="login-card">
          <div className="brand-mark">T</div>
          <p className="eyebrow">SECURE DOCUMENT WORKSPACE</p>
          <h1>Welcome to <span>TrustVault</span></h1>
          <p className="muted">Your documents. Your permissions. Your proof.</p>

          <form onSubmit={login} className="login-form">
            <label>Username
              <input value={username} onChange={e => setUsername(e.target.value)} required />
            </label>
            <label>Password
              <input type="password" value={password} onChange={e => setPassword(e.target.value)} required />
            </label>
            <button disabled={busy}>{busy ? 'Signing in…' : 'Sign in securely →'}</button>
          </form>
          <p className="hint">Use an account configured in your TrustVault backend.</p>
          {message && <p className="message">{message}</p>}
          <div className="login-footer"><span>🔒 Protected workspace</span><span>Audit-enabled</span></div>
        </section>
      </main>
    )
  }
  return (
    <main className="app-shell">
      <aside className="sidebar">
        <div className="brand"><div className="brand-mark">T</div><div><strong>TrustVault</strong><small>SECURE WORKSPACE</small></div></div>
        <p className="nav-label">WORKSPACE</p>
        {['Dashboard', 'Documents', 'Upload Document', 'Security Audit'].map(item => (
          <button key={item} className={`nav-item ${page === item ? 'active' : ''}`} onClick={() => navigate(item)}>
            <span>{({ Dashboard: '◫', Documents: '▤', 'Upload Document': '↑', 'Security Audit': '◉' } as Record<string, string>)[item]}</span>{item}
          </button>
        ))}
        <div className="sidebar-bottom">
          <div className="avatar">{user.username.slice(0, 1).toUpperCase()}</div>
          <div className="profile"><strong>{user.username}</strong><small>{user.role}</small></div>
          <button className="logout" onClick={logout} title="Sign out">↪</button>
        </div>
      </aside>

      <section className="main-area">
        <header className="topbar"><div><span className="status-dot" /> Workspace protected</div><span>TRUSTVAULT / {page.toUpperCase()}</span></header>
        <div className="content">
          <div className="welcome-row">
            <div><p className="eyebrow">YOUR SECURE WORKSPACE</p><h1>{page === 'Dashboard' ? `Welcome back, ${user.username}` : page}</h1><p className="muted">Manage confidential files with confidence.</p></div>
            <div className="date-chip">🔐 Access controlled</div>
          </div>

          {message && <div className="notice">{message}<button onClick={() => setMessage('')}>×</button></div>}

          {page === 'Dashboard' && <>
            <div className="stats-grid">
              <article className="stat-card"><span className="stat-icon purple">▤</span><p>Total accessible documents</p><h2>{documents.length}</h2><small>Files available to your account</small></article>
              <article className="stat-card"><span className="stat-icon green">✓</span><p>Workspace security</p><h2>Active</h2><small>Authentication enabled</small></article>
              <article className="stat-card"><span className="stat-icon orange">◉</span><p>Your role</p><h2 className="role-value">{user.role}</h2><small>Backend-enforced permissions</small></article>
            </div>
            <section className="panel"><div className="panel-heading"><div><h2>Recent documents</h2><p>Your latest accessible files</p></div><button className="text-button" onClick={() => navigate('Documents')}>View all →</button></div><DocumentTable documents={documents.slice(0, 5)} onDownload={downloadDocument} currentUsername={user.username} onManageAccess={doc => { setSelectedDocument(doc); setPage('Documents'); setMessage('') }} /></section>
          </>}

          {page === 'Documents' && <section className="panel"><div className="panel-heading"><div><h2>Document library</h2><p>Search, download, and manage sharing for your documents</p></div><button className="primary small" onClick={() => navigate('Upload Document')}>+ Upload</button></div><div className="search-row"><input placeholder="Search document names…" value={search} onChange={e => setSearch(e.target.value)} onKeyDown={e => e.key === 'Enter' && loadDocuments()} /><button className="secondary" onClick={loadDocuments}>Search</button></div>{selectedDocument && selectedDocument.owner === user.username && <section className="panel access-panel"><div className="panel-heading"><div><h2>Manage access</h2><p>Document: {selectedDocument.name}</p></div><button className="secondary" onClick={() => setSelectedDocument(null)}>Close</button></div><p className="muted">Grant a registered user read or edit permission, or revoke their access. Usernames must already exist in TrustVault.</p><form className="upload-form" onSubmit={grantAccess}><label>Username to share with<input value={grantUsername} onChange={e => setGrantUsername(e.target.value)} placeholder="e.g. viewer" required /></label><label>Permission<select value={grantPermission} onChange={e => setGrantPermission(e.target.value as 'read' | 'edit')}><option value="read">Read — view and download</option><option value="edit">Edit — edit document metadata</option></select></label><button className="primary" disabled={busy}>{busy ? 'Please wait…' : 'Grant access'}</button></form><form className="upload-form revoke-form" onSubmit={revokeAccess}><label>Username to remove<input value={revokeUsername} onChange={e => setRevokeUsername(e.target.value)} placeholder="e.g. viewer" required /></label><button className="secondary" disabled={busy}>{busy ? 'Please wait…' : 'Revoke access'}</button></form></section>}<DocumentTable documents={documents} onDownload={downloadDocument} currentUsername={user.username} onManageAccess={doc => { setSelectedDocument(doc); setGrantUsername(''); setRevokeUsername(''); setMessage('') }} /></section>}

          {page === 'Upload Document' && <section className="panel upload-panel"><div className="panel-heading"><div><h2>Upload a document</h2><p>Allowed: PDF, TXT, PNG, JPG, JPEG, DOCX · Max 10 MB</p></div></div><form onSubmit={uploadDocument} className="upload-form"><label className="dropzone"><span className="upload-symbol">↑</span><strong>{file ? file.name : 'Choose a file to upload'}</strong><span>Click here to browse your computer</span><input type="file" accept=".pdf,.txt,.png,.jpg,.jpeg,.docx" onChange={e => setFile(e.target.files?.[0] || null)} /></label><label>Document category<input value={category} onChange={e => setCategory(e.target.value)} maxLength={80} required /></label><button className="primary" disabled={busy}>{busy ? 'Uploading…' : 'Upload securely'}</button></form></section>}

          {page === 'Security Audit' && <section className="panel"><div className="panel-heading"><div><h2>Security audit trail</h2><p>Hash-chain verification from your backend</p></div><button className="secondary" onClick={loadAudit}>Refresh</button></div><div className={`verification ${auditValid === null ? '' : auditValid ? 'valid' : 'invalid'}`}>{auditValid === null ? 'Verification not yet completed' : auditValid ? '✓ Audit chain verified' : '⚠ Audit chain verification failed'}</div>{audit.length === 0 ? <p className="muted">No audit records loaded, or your account does not have administrator access.</p> : <div className="audit-list">{audit.map((event, index) => <article className="audit-event" key={String(event.id ?? index)}><span className="audit-dot" /><div><strong>{String(event.action ?? 'Event')}</strong><p>{String(event.outcome ?? '')} · {String(event.timestamp ?? '')}</p><small>{String(event.details ?? '')}</small></div></article>)}</div>}</section>}

          <footer className="footer">TrustVault · Secure document sharing <span>Built with React + FastAPI</span></footer>
        </div>
      </section>
    </main>
  )
}

function DocumentTable({ documents, onDownload, currentUsername, onManageAccess }: { documents: DocumentItem[]; onDownload: (doc: DocumentItem) => void; currentUsername?: string; onManageAccess?: (doc: DocumentItem) => void }) {
  if (documents.length === 0) return <div className="empty-state"><span>▤</span><strong>No documents found</strong><p>Upload a file or try a different search.</p></div>
  return <div className="table-wrap"><table><thead><tr><th>DOCUMENT</th><th>CATEGORY</th><th>OWNER</th><th>SIZE</th><th>ACTION</th></tr></thead><tbody>{documents.map(doc => <tr key={doc.id}><td><span className="file-icon">▤</span><span className="file-name">{doc.name}</span></td><td><span className="category-chip">{doc.category}</span></td><td>{doc.owner}</td><td>{(doc.size / 1024).toFixed(1)} KB</td><td><button className="download-button" onClick={() => onDownload(doc)}>↓ Download</button>{doc.owner === currentUsername && onManageAccess && <button className="secondary small" style={{ marginLeft: 8 }} onClick={() => onManageAccess(doc)}>Manage access</button>}</td></tr>)}</tbody></table></div>
}
export default App