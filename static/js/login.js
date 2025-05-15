document.getElementById('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const formData = {
        username: document.getElementById('username').value.trim(),
        password: document.getElementById('password').value,
        remember: document.getElementById('remember').checked
    };

    if (!formData.username || !formData.password) {
        alert('Please fill in all required fields');
        return;
    }

    try {
        const response = await fetch('/api/auth/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
            body: JSON.stringify(formData)
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || 'Login failed');
        }

        window.location.href = '/dashboard';
    } catch (error) {
        console.error('Login error:', error);
        alert(`Failed to login: ${error.message}`);
    }
});

document.querySelector('.toggle-password').addEventListener('click', (e) => {
    const passwordInput = document.getElementById('password');
    const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
    passwordInput.setAttribute('type', type);
    e.target.classList.toggle('fa-eye');
    e.target.classList.toggle('fa-eye-slash');
});document.getElementById('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const formData = {
        username: document.getElementById('username').value.trim(),
        password: document.getElementById('password').value,
        remember: document.getElementById('remember').checked
    };

    if (!formData.username || !formData.password) {
        alert('Please fill in all required fields');
        return;
    }

    try {
        const response = await fetch('/api/auth/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
            body: JSON.stringify(formData)
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || 'Login failed');
        }

        window.location.href = '/dashboard';
    } catch (error) {
        console.error('Login error:', error);
        alert(`Failed to login: ${error.message}`);
    }
});

document.querySelector('.toggle-password').addEventListener('click', (e) => {
    const passwordInput = document.getElementById('password');
    const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
    passwordInput.setAttribute('type', type);
    e.target.classList.toggle('fa-eye');
    e.target.classList.toggle('fa-eye-slash');
});