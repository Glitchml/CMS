document.addEventListener('DOMContentLoaded', () => {
    const urlParams = new URLSearchParams(window.location.search);
    const token = urlParams.get('token');
    
    if (!token) {
        alert('Invalid or missing reset token');
        window.location.href = '/forgot-password';
        return;
    }
    
    document.getElementById('resetToken').value = token;
    
    const resetPasswordForm = document.getElementById('resetPasswordForm');
    resetPasswordForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const token = document.getElementById('resetToken').value;
        const password = document.getElementById('password').value;
        const confirmPassword = document.getElementById('confirmPassword').value;
        
        if (!password || !confirmPassword) {
            alert('All fields are required');
            return;
        }
        
        if (password !== confirmPassword) {
            alert('Passwords do not match');
            return;
        }
        
        try {
            const response = await fetch('/api/auth/reset-password', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    token,
                    password,
                    confirmPassword
                })
            });
            
            const data = await response.json();
            
            if (response.ok) {
                alert('Password reset successful! Redirecting to login...');
                setTimeout(() => {
                    window.location.href = '/login';
                }, 2000);
            } else {
                throw new Error(data.error || 'Failed to reset password');
            }
        } catch (error) {
            console.error('Error:', error);
            alert(`Failed to reset password: ${error.message}`);
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
});