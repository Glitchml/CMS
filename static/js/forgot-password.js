document.getElementById('forgotPasswordForm').addEventListener('submit', async (e) => {
   e.preventDefault();

   const email = document.getElementById('email').value.trim();

   if (!email) {
       alert('Please enter your email');
       return;
   }

   try {
       const response = await fetch('/api/auth/forgot-password', {
           method: 'POST',
           headers: {
               'Content-Type': 'application/json',
           },
           body: JSON.stringify({ email })
       });

       const data = await response.json();

       if (!response.ok) {
           throw new Error(data.error || 'Failed to send reset link');
       }

       alert('Password reset link sent! Check your email.');
       setTimeout(() => {
           window.location.href = '/login';
       }, 2000);
   } catch (error) {
       console.error('Error:', error);
       alert(`Failed to send reset link: ${error.message}`);
   }
});