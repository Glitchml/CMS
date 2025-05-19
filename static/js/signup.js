document.getElementById('signupForm').addEventListener('submit', async (e) => {
    e.preventDefault();

    const fullName = document.getElementById('fullName').value.trim();
    const email = document.getElementById('email').value.trim();
    const password = document.getElementById('password').value;
    const confirmPassword = document.getElementById('confirmPassword').value;
    const terms = document.getElementById('terms').checked;

    if (!fullName || !email || !password || !confirmPassword) {
        alert('All fields are required');
        return;
    }

    if (password !== confirmPassword) {
        alert('Passwords do not match');
        return;
    }

    if (!terms) {
        alert('You must agree to the Terms & Conditions');
        return;
    }

    try {
        const response = await fetch('/api/auth/register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                fullName,
                email,
                password
            })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || 'Registration failed');
        }

        alert('Registration successful! Please login.');
        window.location.href = '/login';
    } catch (error) {
        console.error('Registration failed:', error);
        alert(`Failed to register: ${error.message}`);
    }
});

document.querySelectorAll('.toggle-password').forEach(icon => {
    icon.addEventListener('click', (e) => {
        const passwordInput = e.target.previousElementSibling;
        const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
        passwordInput.setAttribute('type', type);
        e.target.classList.toggle('fa-eye');
        e.target.classList.toggle('fa-eye-slash');
    });
});
