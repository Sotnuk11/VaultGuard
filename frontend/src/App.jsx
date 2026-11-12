import React, { useState, useEffect } from 'react';
import axios from 'axios';

// Визначаємо адресу бекенду: або з налаштувань Vercel, або локально
const API_URL = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';

// An expired or invalid token sends the user back to the login screen.
axios.interceptors.response.use(
  (r) => r,
  (error) => {
    if (error.response?.status === 401 && error.config?.url && !error.config.url.endsWith('/api/login')) {
      delete axios.defaults.headers.common.Authorization;
      window.location.reload();
    }
    return Promise.reject(error);
  }
);

function App() {
  // --- АВТОРИЗАЦІЯ ---
  const [user, setUser] = useState(null);
  const [loginForm, setLoginForm] = useState({ user: '', pass: '' });

  // --- ДИНАМІЧНИЙ UI ---
  const [toast, setToast] = useState({ show: false, msg: '', type: 'success' });
  const [confirmModal, setConfirmModal] = useState({ show: false, msg: '', action: null });
  const [accessModal, setAccessModal] = useState({ show: false, folder: null, selectedUsers: [] });

  const showToast = (msg, type = 'success') => {
    setToast({ show: true, msg, type });
    setTimeout(() => setToast({ show: false, msg: '', type: 'success' }), 3000);
  };

  const askConfirm = (msg, action) => {
    setConfirmModal({ show: true, msg, action });
  };

  // --- СТАН ДАНИХ ---
  const [view, setView] = useState('vault'); 
  const [folders, setFolders] = useState([]);
  const [selectedFolder, setSelectedFolder] = useState(null);
  const [items, setItems] = useState([]);
  const [systemUsers, setSystemUsers] = useState([]);
  
  const [newFolder, setNewFolder] = useState('');
  const [newUser, setNewUser] = useState({ username: '', password: '' });
  const [itemForm, setItemForm] = useState({ name: '', pass: '', master: '' });
  const [inlineMaster, setInlineMaster] = useState({});

  // --- API ЗАПИТИ ---
  const loadFolders = async () => {
    if (!user) return;
    try {
      const res = await axios.get(`${API_URL}/api/folders`);
      setFolders(res.data);
    } catch (e) {
      console.error("Помилка завантаження папок", e);
      showToast('Не вдалося завантажити папки', 'error');
    }
  };

  const loadItems = async (fId) => {
    setSelectedFolder(fId);
    try {
      const res = await axios.get(`${API_URL}/api/folders/${fId}/items`);
      setItems(res.data.map(i => ({ ...i, decrypted: null })));
    } catch (e) { 
      console.error("Помилка завантаження паролів", e); 
      showToast('Не вдалося завантажити паролі', 'error');
    }
  };

  useEffect(() => {
    if (user) {
      (async () => {
        try {
          const res = await axios.get(`${API_URL}/api/folders`);
          setFolders(res.data);
        } catch (e) { 
          console.error("Помилка завантаження папок", e); 
          showToast('Не вдалося завантажити рівні', 'error');
        }
        
        if (user.role === 'admin') {
          try {
            const res = await axios.get(`${API_URL}/api/users`);
            setSystemUsers(res.data);
          } catch (e) {
            console.error('loadUsers error', e);
            showToast('Не вдалося завантажити користувачів', 'error');
          }
        }
      })();
    }
  }, [user]);

  const handleLogin = async (e) => {
    e.preventDefault();
    try {
      const res = await axios.post(`${API_URL}/api/login`, { username: loginForm.user, password: loginForm.pass });
      // The JWT is kept in memory only (not localStorage), so it disappears on refresh/close.
      axios.defaults.headers.common.Authorization = `Bearer ${res.data.token}`;
      setUser({ id: res.data.id, username: res.data.username, role: res.data.role });
      showToast(`Вітаємо, ${res.data.username}!`);
    } catch { 
      showToast('Невірний логін або пароль!', 'error'); 
    }
  };

  const handleIAmHere = async () => {
    try {
      await axios.post(`${API_URL}/api/iamhere`);
      showToast("СИСТЕМУ DEAD MAN'S SWITCH СКИНУТО. ВИ В БЕЗПЕЦІ.", 'success');
    } catch { 
      showToast("Помилка зв'язку з сервером!", 'error'); 
    }
  };

  const handleCreateUser = async (e) => {
    e.preventDefault();
    try {
      await axios.post(`${API_URL}/api/users`, newUser);
      setNewUser({ username: '', password: '' }); 
      showToast('Користувача створено!');
      if (user.role === 'admin') {
        const res = await axios.get(`${API_URL}/api/users`);
        setSystemUsers(res.data);
      }
    } catch {
      showToast('Не вдалося створити користувача', 'error');
    }
  };

  const handleCreateFolder = async () => {
    if (!newFolder) return;
    try {
      await axios.post(`${API_URL}/api/folders`, { name: newFolder, allowed_user_ids: [user.id] });
      setNewFolder(''); 
      showToast('Рівень створено!'); 
      loadFolders();
    } catch {
      showToast('Не вдалося створити рівень', 'error');
    }
  };

  const handleSaveAccess = async () => {
    try {
      await axios.put(`${API_URL}/api/folders/${accessModal.folder.id}/access`, { allowed_user_ids: accessModal.selectedUsers });
      setAccessModal({ show: false, folder: null, selectedUsers: [] });
      showToast('Права оновлено!'); 
      loadFolders();
    } catch {
      showToast('Не вдалося оновити права', 'error');
    }
  };

  const toggleUserAccess = (uId) => {
    const current = accessModal.selectedUsers;
    if (current.includes(uId)) setAccessModal({ ...accessModal, selectedUsers: current.filter(id => id !== uId) });
    else setAccessModal({ ...accessModal, selectedUsers: [...current, uId] });
  };

  const handleDeleteFolder = (fId) => {
    askConfirm("Видалити рівень та всі паролі всередині?", async () => {
      try {
        await axios.delete(`${API_URL}/api/folders/${fId}`);
        if (selectedFolder === fId) { setSelectedFolder(null); setItems([]); }
        showToast('Рівень видалено!'); loadFolders(); setConfirmModal({ show: false });
      } catch {
        showToast('Не вдалося видалити рівень', 'error'); setConfirmModal({ show: false });
      }
    });
  };

  const handleCreateItem = async (e) => {
    e.preventDefault();
    try {
      await axios.post(`${API_URL}/api/encrypt`, { server_name: itemForm.name, password: itemForm.pass, master_password: itemForm.master, folder_id: selectedFolder });
      setItemForm({ name: '', pass: '', master: '' }); 
      showToast('Пароль зашифровано!'); 
      loadItems(selectedFolder);
    } catch {
      showToast('Помилка шифрування!', 'error');
    }
  };

  const handleDeleteItem = (iId) => {
    askConfirm("Безповоротно видалити пароль?", async () => {
      try {
        await axios.delete(`${API_URL}/api/items/${iId}`);
        showToast('Пароль видалено!'); loadItems(selectedFolder); setConfirmModal({ show: false });
      } catch {
        showToast('У вас немає прав для видалення!', 'error'); setConfirmModal({ show: false });
      }
    });
  };

  const handleDecrypt = async (iId) => {
    const mPass = inlineMaster[iId];
    if (!mPass) return showToast('Введи майстер-пароль!', 'error');
    try {
      const res = await axios.post(`${API_URL}/api/decrypt`, { item_id: iId, master_password: mPass });
      setItems(items.map(i => i.id === iId ? { ...i, decrypted: res.data.password } : i));
      setInlineMaster({ ...inlineMaster, [iId]: '' });
    } catch {
      showToast('Невірний пароль!', 'error');
    }
  };

  // --- СТИЛІ ТЕМНОЇ ТЕМИ ---
  const theme = {
    bg: '#0b0f19', sidebar: '#111827', card: '#1f2937', text: '#f3f4f6', 
    textMuted: '#9ca3af', primary: '#3b82f6', success: '#10b981', danger: '#ef4444', border: '#374151'
  };

  const inputStyle = { padding: '10px 14px', background: '#111827', border: `1px solid ${theme.border}`, borderRadius: '6px', color: theme.text, width: '100%', boxSizing: 'border-box', outline: 'none' };
  const btnStyle = (bg, color = 'white') => ({ background: bg, color: color, border: 'none', padding: '10px 16px', borderRadius: '6px', cursor: 'pointer', fontWeight: 'bold', transition: '0.2s' });
  const overlayStyle = { position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, background: 'rgba(0,0,0,0.7)', display: 'flex', justifyContent: 'center', alignItems: 'center', zIndex: 1000 };
  const modalStyle = { background: theme.card, padding: '30px', borderRadius: '12px', width: '400px', boxShadow: '0 10px 25px rgba(0,0,0,0.5)', color: theme.text, border: `1px solid ${theme.border}` };
  const toastStyle = (type) => ({ position: 'fixed', top: '20px', right: '20px', background: type === 'error' ? theme.danger : theme.success, color: 'white', padding: '15px 25px', borderRadius: '8px', boxShadow: '0 4px 15px rgba(0,0,0,0.3)', fontWeight: 'bold', zIndex: 9999, transition: '0.3s' });
  const tdStyle = { padding: '16px', borderBottom: `1px solid ${theme.border}` };

  if (!user) {
    return (
      <div style={{ display: 'flex', height: '100vh', justifyContent: 'center', alignItems: 'center', background: theme.bg, color: theme.text, fontFamily: 'sans-serif' }}>
        <form onSubmit={handleLogin} style={{ background: theme.card, padding: '40px', borderRadius: '12px', textAlign: 'center', width: '320px', border: `1px solid ${theme.border}` }}>
          <h2 style={{ marginBottom: '5px', color: theme.primary }}>🛡️ VaultGuard</h2>
          <p style={{ color: theme.textMuted, marginBottom: '25px', fontSize: '14px' }}>Система безпечного доступу</p>
          <input value={loginForm.user} onChange={e => setLoginForm({...loginForm, user: e.target.value})} placeholder="Логін" style={{...inputStyle, marginBottom: '15px'}} required />
          <input type="password" value={loginForm.pass} onChange={e => setLoginForm({...loginForm, pass: e.target.value})} placeholder="Пароль" style={{ ...inputStyle, marginBottom: '25px' }} required />
          <button type="submit" style={{...btnStyle(theme.primary), width: '100%', fontSize: '16px'}}>АВТОРИЗАЦІЯ</button>
        </form>
        {toast.show && <div style={toastStyle(toast.type)}>{toast.msg}</div>}
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', height: '100vh', background: theme.bg, color: theme.text, fontFamily: 'sans-serif' }}>
      
      {/* САЙДБАР */}
      <div style={{ width: '300px', background: theme.sidebar, padding: '25px', display: 'flex', flexDirection: 'column', borderRight: `1px solid ${theme.border}` }}>
        <h2 style={{ color: theme.primary, margin: '0 0 5px 0' }}>🛡️ VaultGuard</h2>
        <div style={{ color: theme.textMuted, fontSize: '13px', marginBottom: '25px' }}>
          Доступ: <strong style={{ color: user.role === 'admin' ? theme.danger : theme.success }}>{user.role.toUpperCase()}</strong> ({user.username})
          <button onClick={() => setUser(null)} style={{ marginLeft: '10px', background: 'transparent', color: theme.textMuted, border: `1px solid ${theme.border}`, borderRadius: '4px', cursor: 'pointer', padding: '2px 8px' }}>Вихід</button>
        </div>

        {user.role === 'admin' && (
          <div style={{ background: 'rgba(239, 68, 68, 0.1)', border: `1px solid ${theme.danger}`, padding: '15px', borderRadius: '8px', marginBottom: '25px', textAlign: 'center' }}>
            <h4 style={{ margin: '0 0 10px 0', color: theme.danger, fontSize: '12px', letterSpacing: '1px' }}>🚨 DEAD MAN'S SWITCH</h4>
            <button onClick={handleIAmHere} style={{ background: theme.danger, color: 'white', padding: '10px', border: 'none', borderRadius: '6px', cursor: 'pointer', fontWeight: 'bold', width: '100%' }}>
              RESET KILL SWITCH
            </button>
          </div>
        )}

        {user.role === 'admin' && (
          <div style={{ display: 'flex', gap: '5px', marginBottom: '25px', background: theme.bg, padding: '5px', borderRadius: '8px' }}>
            <button onClick={() => setView('vault')} style={{...btnStyle(view === 'vault' ? theme.card : 'transparent', view === 'vault' ? theme.text : theme.textMuted), flex: 1}}>Сховище</button>
            <button onClick={() => setView('users')} style={{...btnStyle(view === 'users' ? theme.card : 'transparent', view === 'users' ? theme.text : theme.textMuted), flex: 1}}>Користувачі</button>
          </div>
        )}

        {view === 'vault' && (
          <>
            <h4 style={{ color: theme.textMuted, textTransform: 'uppercase', fontSize: '12px', letterSpacing: '1px', marginBottom: '15px' }}>Рівні доступу</h4>
            <div style={{ flex: 1, overflowY: 'auto', marginBottom: '20px' }}>
              {folders.map(f => (
                <div key={f.id} style={{ display: 'flex', alignItems: 'center', marginBottom: '8px' }}>
                  <div onClick={() => loadItems(f.id)} style={{ flex: 1, cursor: 'pointer', padding: '12px', background: selectedFolder === f.id ? theme.primary : theme.card, borderRadius: '6px' }}>
                    📁 {f.name}
                  </div>
                  {user.role === 'admin' && (
                    <div style={{ display: 'flex', marginLeft: '5px' }}>
                      <button onClick={() => setAccessModal({ show: true, folder: f, selectedUsers: f.allowed_user_ids })} style={{ background: theme.card, border: 'none', padding: '12px 10px', borderRadius: '6px', marginRight: '5px' }}>🔑</button>
                      <button onClick={() => handleDeleteFolder(f.id)} style={{ background: 'rgba(239, 68, 68, 0.1)', color: theme.danger, border: 'none', padding: '12px 10px', borderRadius: '6px' }}>🗑️</button>
                    </div>
                  )}
                </div>
              ))}
            </div>
            {user.role === 'admin' && (
              <div style={{ display: 'flex', gap: '5px', background: theme.card, padding: '10px', borderRadius: '8px' }}>
                <input value={newFolder} onChange={e => setNewFolder(e.target.value)} placeholder="Нова..." style={inputStyle} />
                <button onClick={handleCreateFolder} style={btnStyle(theme.success)}>+</button>
              </div>
            )}
          </>
        )}
      </div>

      {/* ОСНОВНА ПАНЕЛЬ */}
      <div style={{ flex: 1, padding: '40px', overflowY: 'auto' }}>
        {view === 'users' && user.role === 'admin' && (
          <div style={{ maxWidth: '800px', margin: '0 auto' }}>
            <h2 style={{ marginBottom: '25px' }}>👥 Керування Користувачами</h2>
            <form onSubmit={handleCreateUser} style={{ background: theme.card, padding: '25px', borderRadius: '12px', display: 'flex', gap: '15px', marginBottom: '30px', border: `1px solid ${theme.border}` }}>
              <input value={newUser.username} onChange={e => setNewUser({...newUser, username: e.target.value})} placeholder="Логін" style={inputStyle} required />
              <input value={newUser.password} onChange={e => setNewUser({...newUser, password: e.target.value})} placeholder="Пароль" style={inputStyle} required />
              <button type="submit" style={btnStyle(theme.success)}>Створити</button>
            </form>
            <div style={{ background: theme.card, borderRadius: '12px', border: `1px solid ${theme.border}`, overflow: 'hidden' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                <thead><tr><th style={tdStyle}>Користувач</th><th style={tdStyle}>Роль</th></tr></thead>
                <tbody>{systemUsers.map(u => (<tr key={u.id}><td style={tdStyle}>{u.username}</td><td style={tdStyle}>{u.role}</td></tr>))}</tbody>
              </table>
            </div>
          </div>
        )}

        {view === 'vault' && selectedFolder ? (
          <div style={{ maxWidth: '1000px', margin: '0 auto' }}>
            <h2>📁 {folders.find(f => f.id === selectedFolder)?.name}</h2>
            <form onSubmit={handleCreateItem} style={{ background: theme.card, padding: '25px', borderRadius: '12px', display: 'flex', gap: '15px', margin: '25px 0', border: `1px solid ${theme.border}` }}>
              <input value={itemForm.name} onChange={e => setItemForm({...itemForm, name: e.target.value})} placeholder="Назва" style={inputStyle} required />
              <input type="password" value={itemForm.pass} onChange={e => setItemForm({...itemForm, pass: e.target.value})} placeholder="Пароль" style={inputStyle} required />
              <input type="password" value={itemForm.master} onChange={e => setItemForm({...itemForm, master: e.target.value})} placeholder="Майстер-ключ" style={inputStyle} required />
              <button type="submit" style={btnStyle(theme.primary)}>Зберегти</button>
            </form>
            <div style={{ background: theme.card, borderRadius: '12px', border: `1px solid ${theme.border}` }}>
              <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                <tbody>
                  {items.map(i => (
                    <tr key={i.id}><td style={tdStyle}>{i.server_name}</td>
                      <td style={tdStyle}>
                        {i.decrypted ? <span style={{color: theme.success}}>{i.decrypted}</span> : 
                        <div style={{display:'flex', gap:'5px'}}>
                          <input type="password" placeholder="Майстер-ключ" value={inlineMaster[i.id] || ''} onChange={e => setInlineMaster({...inlineMaster, [i.id]: e.target.value})} style={inputStyle} />
                          <button onClick={() => handleDecrypt(i.id)} style={btnStyle(theme.primary)}>🔓</button>
                        </div>}
                      </td>
                      {user.role === 'admin' && <td style={tdStyle}><button onClick={() => handleDeleteItem(i.id)} style={btnStyle(theme.danger)}>🗑️</button></td>}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        ) : view === 'vault' && <div style={{textAlign:'center', marginTop:'100px'}}>Оберіть рівень доступу</div>}
      </div>

      {/* МОДАЛКИ ТА ТОСТИ */}
      {accessModal.show && (
        <div style={overlayStyle}>
          <div style={modalStyle}>
            <h3>Налаштування доступу</h3>
            <div style={{maxHeight:'200px', overflowY:'auto', margin:'15px 0'}}>
              {systemUsers.map(u => (
                <label key={u.id} style={{display:'block', padding:'10px'}}>
                  <input type="checkbox" checked={accessModal.selectedUsers.includes(u.id)} disabled={u.role==='admin'} onChange={() => toggleUserAccess(u.id)} /> {u.username}
                </label>
              ))}
            </div>
            <button onClick={handleSaveAccess} style={btnStyle(theme.success)}>Зберегти</button>
            <button onClick={() => setAccessModal({show:false})} style={{...btnStyle('transparent'), color: theme.textMuted}}>Скасувати</button>
          </div>
        </div>
      )}

      {confirmModal.show && (
        <div style={overlayStyle}>
          <div style={modalStyle}>
            <h3>⚠️ {confirmModal.msg}</h3>
            <button onClick={confirmModal.action} style={btnStyle(theme.danger)}>Видалити</button>
            <button onClick={() => setConfirmModal({show:false})} style={btnStyle('transparent')}>Скасувати</button>
          </div>
        </div>
      )}
      {toast.show && <div style={toastStyle(toast.type)}>{toast.msg}</div>}
    </div>
  );
}

export default App;