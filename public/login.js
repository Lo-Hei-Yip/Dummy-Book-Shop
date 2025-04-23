document.addEventListener('DOMContentLoaded', () => {
    fetch('/api/user')
        .then(response => response.json())
        .then(data => {
            const userDisplay = document.getElementById('user-display');
            const logoutBtn = document.getElementById('logout-btn');
            const loginLink = document.getElementById('login-link');
            const accountLink = document.getElementById('account-link');
            const adminLink = document.getElementById('admin-link'); 

            if (data && data.email) {
                // User is logged in
                userDisplay.textContent = `Welcome, ${data.email}`;
                logoutBtn.classList.remove('hidden');
                loginLink.classList.add('hidden');
                accountLink.classList.remove('hidden'); 
                if (data.isAdmin && adminLink) {
                    adminLink.classList.remove('hidden'); 
                } else if (adminLink) {
                    adminLink.classList.add('hidden'); 
                }
            } else {
                // User is not logged in
                userDisplay.textContent = 'Welcome, guest';
                logoutBtn.classList.add('hidden');
                loginLink.classList.remove('hidden');
                accountLink.classList.add('hidden'); 
                if (adminLink) {
                    adminLink.classList.add('hidden'); 
                }
            }
        })
        .catch(error => console.error('Error fetching user:', error));
    
    // Fetch CSRF tokens
    fetch('/api/csrf-token')
        .then(response => response.json())
        .then(data => {
            document.getElementById('csrf-token').value = data.csrfToken;
            document.getElementById('signup-csrf-token').value = data.csrfToken;
        })
        .catch(error => console.error('Error fetching CSRF token:', error));

    // Password validation 
    function validateSignupPassword(password, confirmPassword) {
        const requirements = {
            length: password.length >= 8,
            upper: /[A-Z]/.test(password),
            lower: /[a-z]/.test(password),
            special: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password),
            match: password === confirmPassword
        };
    
        document.getElementById('req-length').className = requirements.length ? 'valid' : 'invalid';
        document.getElementById('req-upper').className = requirements.upper ? 'valid' : 'invalid';
        document.getElementById('req-lower').className = requirements.lower ? 'valid' : 'invalid';
        document.getElementById('req-special').className = requirements.special ? 'valid' : 'invalid';
        document.getElementById('req-match').className = requirements.match ? 'valid' : 'invalid';
    
        const submitBtn = document.getElementById('signup-submit-btn');
        submitBtn.disabled = !Object.values(requirements).every(Boolean);
        
        return Object.values(requirements).every(Boolean);
    }
    
    //signup
    document.getElementById('signup-password').addEventListener('input', function() {
        const password = this.value;
        const confirmPassword = document.getElementById('confirm-password').value;
        validateSignupPassword(password, confirmPassword);
    });
    
    document.getElementById('confirm-password').addEventListener('input', function() {
        const password = document.getElementById('signup-password').value;
        const confirmPassword = this.value;
        validateSignupPassword(password, confirmPassword);
    });

    //logout
    document.getElementById('logout-btn').addEventListener('click', (e) => {
        e.preventDefault();
        fetch('/api/csrf-token')
            .then(response => response.json())
            .then(data => {
                fetch('/logout', {
                    method: 'POST',
                    headers: { 'X-CSRF-Token': data.csrfToken }
                })
                .then(() => window.location.href = '/index.html')
                .catch(error => console.error('Error logging out:', error));
            });
    });
});