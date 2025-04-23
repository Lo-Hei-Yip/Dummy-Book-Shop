document.addEventListener('DOMContentLoaded', () => {
    // Fetch CSRF token for password form
    fetch('/api/csrf-token')
        .then(response => response.json())
        .then(data => {
            document.getElementById('csrf-token').value = data.csrfToken;
        })
        .catch(error => console.error('Error fetching CSRF token:', error));

    // Fetch user info for navigation
    fetch('/api/user')
        .then(response => response.json())
        .then(data => {
            const userDisplay = document.getElementById('user-display');
            const logoutBtn = document.getElementById('logout-btn');
            const loginLink = document.getElementById('login-link');
            const accountLink = document.getElementById('account-link');
            const adminLink = document.getElementById('admin-link');

            if (data && data.email) {
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
        
        


    // Password validation function
    function validatePassword(currentPassword, newPassword, confirmPassword) {
        const requirements = {
            length: newPassword.length >= 8,
            upper: /[A-Z]/.test(newPassword),
            lower: /[a-z]/.test(newPassword),
            special: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(newPassword),
            different: newPassword !== currentPassword,
            match: newPassword === confirmPassword
        };
    
        document.getElementById('req-length').className = requirements.length ? 'valid' : 'invalid';
        document.getElementById('req-upper').className = requirements.upper ? 'valid' : 'invalid';
        document.getElementById('req-lower').className = requirements.lower ? 'valid' : 'invalid';
        document.getElementById('req-special').className = requirements.special ? 'valid' : 'invalid';
        document.getElementById('req-different').className = requirements.different ? 'valid' : 'invalid';
        document.getElementById('req-match').className = requirements.match ? 'valid' : 'invalid';
    
        const submitBtn = document.getElementById('submit-btn');
        submitBtn.disabled = !Object.values(requirements).every(Boolean);
        
        return Object.values(requirements).every(Boolean);
    }
    
    document.getElementById('new-password').addEventListener('input', function() {
        const currentPassword = document.getElementById('current-password').value;
        const newPassword = this.value;
        const confirmPassword = document.getElementById('confirm-password').value;
        validatePassword(currentPassword, newPassword, confirmPassword);
    });
    
    document.getElementById('confirm-password').addEventListener('input', function() {
        const currentPassword = document.getElementById('current-password').value;
        const newPassword = document.getElementById('new-password').value;
        const confirmPassword = this.value;
        validatePassword(currentPassword, newPassword, confirmPassword);
    });
    
    document.getElementById('current-password').addEventListener('input', function() {
        const currentPassword = this.value;
        const newPassword = document.getElementById('new-password').value;
        const confirmPassword = document.getElementById('confirm-password').value;
        validatePassword(currentPassword, newPassword, confirmPassword);
    });




    // Fetch and display recent orders
    async function populateOrdersTable() {
        try {
            const response = await fetch('/api/user/orders');
            if (!response.ok) {
                throw new Error(`HTTP error ${response.status}`);
            }
            const orders = await response.json();
            const tbody = document.getElementById('orders-table-body');
            tbody.innerHTML = ''; 

            if (orders.length === 0) {
                const row = document.createElement('tr');
                row.innerHTML = `<td colspan="6">No recent orders found.</td>`;
                tbody.appendChild(row);
                return;
            }

            orders.forEach(order => {
                const row = document.createElement('tr');
                const createdAt = order.createdAt ? new Date(order.createdAt) : null;
                row.innerHTML = `
                    <td>${order.orderID}</td>
                    <td>${order.total}</td>
                    <td>${order.currency}</td>
                    <td>${order.status}</td>
                    <td>${createdAt && !isNaN(createdAt) ? createdAt.toLocaleString('en-US', { 
                        year: 'numeric',
                        month: '2-digit',
                        day: '2-digit',
                        hour: '2-digit',
                        minute: '2-digit',
                        second: '2-digit',
                        hour12: false 
                    }) : 'N/A'}</td>
                    <td>
                        ${order.items && order.items.length > 0
                            ? `<ul>${order.items.map(item => `
                                <li>${item.productName} (ID: ${item.pid}) - Qty: ${item.quantity}, Price: $${item.price}</li>
                            `).join('')}</ul>`
                            : 'No items'}
                    </td>
                `;
                tbody.appendChild(row);
            });
        } catch (error) {
            console.error('Error fetching orders:', error);
            const tbody = document.getElementById('orders-table-body');
            tbody.innerHTML = `<tr><td colspan="6">Failed to load orders. Please try again.</td></tr>`;
        }
    }

    populateOrdersTable();

    // Logout functionality
    document.getElementById('logout-btn').addEventListener('click', (e) => {
        e.preventDefault();
        fetch('/api/csrf-token')
            .then(response => response.json())
            .then(data => {
                fetch('/logout', {
                    method: 'POST',
                    headers: { 'X-CSRF-Token': data.csrfToken }
                })
                .then(() => {
                    window.location.href = '/index.html';
                })
                .catch(error => console.error('Error logging out:', error));
            })
            .catch(error => console.error('Error fetching CSRF token for logout:', error));
    });
});