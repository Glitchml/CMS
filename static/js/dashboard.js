// Utility functions
function sanitizeInput(input) {
   return input.trim();
}

async function fetchWithProtection(url, options = {}) {
   const csrfToken = document.getElementById('csrfToken').value;
   return fetch(url, {
      ...options,
      credentials: 'include',
      headers: {
         ...options.headers,
         'Content-Type': 'application/json',
         'X-CSRF-Token': csrfToken
      }
   });
}

// Load dashboard data on page load
window.addEventListener('DOMContentLoaded', () => {
   fetchUserData();
   fetchRecentSessions();
   setupWebSocket();
});

// Fetch and display user profile info
async function fetchUserData() {
   const errorState = document.getElementById('errorState');
   const loadingState = document.getElementById('loadingState');
   
   try {
      loadingState.style.display = 'block';
      errorState.style.display = 'none';
      
      const res = await fetchWithProtection('/api/user');
      if (!res.ok) throw new Error(`Failed to fetch user: ${res.status}`);
      const data = await res.json();

      document.querySelector('.user-name').textContent = data.name || 'Unknown User';
      document.querySelector('.user-email').textContent = data.email || 'No email';
      document.querySelector('.welcome-title').textContent = `Welcome back, ${data.name ? data.name.split(' ')[0] : 'User'}!`;

   } catch (err) {
      console.error('Error loading user data:', err);
      errorState.textContent = 'Failed to load user data. Please try again.';
      errorState.style.display = 'block';
      handleUnauthorized(err);
   } finally {
      loadingState.style.display = 'none';
   }
}

// Fetch recent sessions
async function fetchRecentSessions() {
   const errorState = document.getElementById('errorState');
   try {
      const res = await fetchWithProtection('/api/sessions?recent=true');
      if (!res.ok) throw new Error('Failed to fetch sessions');
      const sessions = await res.json();
      renderSessions(sessions);
   } catch (err) {
      console.error('Failed to load sessions:', err);
      errorState.textContent = 'Failed to load sessions. Please try again.';
      errorState.style.display = 'block';
   }
}

// Render session cards into UI
function renderSessions(sessions) {
   const container = document.getElementById('sessionsList');
   container.innerHTML = '';

   if (sessions.length === 0) {
      container.innerHTML = `
         <div class="no-sessions">
            <i class="fas fa-calendar-alt empty-icon"></i>
            <p>No recent sessions found.</p>
         </div>`;
      return;
   }

   sessions.forEach(session => {
      const card = document.createElement('div');
      card.className = 'session-card';
      card.innerHTML = `
         <div class="session-header">
            <h3 class="session-title">${session.title}</h3>
            <span class="session-date">${formatDate(session.date)}</span>
         </div>
         <p class="session-description">${session.description || ''}</p>
         <div class="session-meta">
            <span class="session-type">${session.type}</span>
            <span class="session-duration">${session.duration} min</span>
         </div>
         <button class="btn btn-primary join-button" onclick="joinSession('${session.id}')">
            <i class="fas fa-sign-in-alt"></i> Join Session
         </button>
      `;
      container.appendChild(card);
   });
}

// Format date utility
function formatDate(dateStr) {
   const date = new Date(dateStr);
   return date.toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

// Join session handler
async function joinSession(sessionId) {
   try {
      const res = await fetchWithProtection(`/api/sessions/${sessionId}/join`, {
         method: 'POST'
      });
      if (!res.ok) throw new Error('Failed to join session');
      window.open(`session.html?id=${sessionId}`, '_blank');
   } catch (err) {
      console.error('Join session failed:', err);
      document.getElementById('errorState').textContent = 'Unable to join session.';
      document.getElementById('errorState').style.display = 'block';
   }
}

// WebSocket for real-time updates
function setupWebSocket() {
   const ws = new WebSocket('wss://localhost:5000/ws/sessions');

   ws.onopen = () => {
      console.log('WebSocket connected');
      // Note: Using session-based user ID is better; this is a placeholder
      ws.send(JSON.stringify({ type: 'subscribe', userId: 'anonymous' }));
      document.getElementById('wsStatus').classList.remove('disconnected');
      document.getElementById('wsStatus').classList.add('connected');
      document.getElementById('wsStatus').querySelector('span').textContent = 'Connected';
   };

   ws.onmessage = (event) => {
      try {
         const message = JSON.parse(event.data);
         if (message.type === 'session_update') {
            fetchRecentSessions();
         }
      } catch (e) {
         console.error('Message parsing error:', e);
      }
   };

   ws.onclose = () => {
      console.log('WebSocket disconnected');
      document.getElementById('wsStatus').classList.remove('connected');
      document.getElementById('wsStatus').classList.add('disconnected');
      document.getElementById('wsStatus').querySelector('span').textContent = 'Disconnected';
      setTimeout(setupWebSocket, 5000);
   };
}

// Handle unauthorized access
function handleUnauthorized(error) {
   console.error('Authentication error:', error);
   if (error.message.includes('401')) {
      const retry = confirm('Session expired. Redirect to login?');
      if (retry) {
         window.location.href = '/login';
      }
   }
}

// Navigation handler
document.querySelectorAll('.nav-item').forEach(item => {
   item.addEventListener('click', () => {
      const pageName = item.querySelector('span').textContent.toLowerCase();
      const routes = {
         dashboard: '/dashboard',
         networking: '/networking',
         profile: '/profile',
         sessions: '/sessions',
         settings: '/settings'
      };
      const url = routes[pageName] || '#';
      if (url !== '#') {
         window.location.href = url;
      } else {
         console.error('No route defined for:', pageName);
      }
   });
});

// Logout confirmation
document.querySelector('.user-profile').addEventListener('click', () => {
   const confirmLogout = confirm('Are you sure you want to log out?');
   if (confirmLogout) {
      signOut();
   }
});

// Sign out function
async function signOut() {
   try {
      const res = await fetchWithProtection('/api/auth/logout', {
         method: 'POST'
      });
      if (!res.ok) throw new Error('Logout failed');
      localStorage.clear();
      sessionStorage.clear();
      window.location.href = '/login';
   } catch (error) {
      console.error('Logout failed:', error);
      document.getElementById('errorState').textContent = 'Logout failed. Please try again.';
      document.getElementById('errorState').style.display = 'block';
   }
}