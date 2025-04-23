document.addEventListener('DOMContentLoaded', () => {
    async function getCsrfToken() {
        const response = await fetch('/api/csrf-token');
        const data = await response.json();
        return data.csrfToken;
    }

    async function populateSelects() {
        const categories = await fetch('/api/categories').then(res => res.json());
        const products = await fetch('/api/products').then(res => res.json());

        const categorySelects = [
            document.getElementById('category'),
            document.getElementById('update-category'),
            document.getElementById('update-category-id'),
            document.getElementById('delete-category-id')
        ];
        categorySelects.forEach(select => {
            if (select) {
                select.innerHTML = ''; 
                const defaultOption = document.createElement('option');
                defaultOption.value = '';
                defaultOption.textContent = 'Select Category';
                select.appendChild(defaultOption);
                categories.forEach(cat => {
                    const option = document.createElement('option');
                    option.value = cat.catid;
                    option.textContent = cat.name; 
                    select.appendChild(option);
                });
            }
        });

        const productSelects = [
            document.getElementById('update-product-id'),
            document.getElementById('delete-product-id')
        ];
        productSelects.forEach(select => {
            if (select) {
                select.innerHTML = ''; 
                const defaultOption = document.createElement('option');
                defaultOption.value = '';
                defaultOption.textContent = 'Select Product';
                select.appendChild(defaultOption);
                products.forEach(prod => {
                    const option = document.createElement('option');
                    option.value = prod.pid;
                    option.textContent = prod.name; 
                    select.appendChild(option);
                });
            }
        });
    }

    async function populateOrdersTable() {
        try {
            const response = await fetch('/api/orders');
            if (!response.ok) {
                throw new Error(`HTTP error ${response.status}`);
            }
            const orders = await response.json();
            const tbody = document.getElementById('orders-table-body');
            tbody.innerHTML = ''; 
    
            orders.forEach(order => {
                const row = document.createElement('tr');
                const createdAt = order.createdAt ? new Date(order.createdAt) : null;
                row.innerHTML = `
                    <td>${order.orderID}</td>
                    <td>${order.userID || 'Guest'}</td>
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
            alert('Failed to load orders. Please try again.');
        }
    }

    
    populateSelects();
    populateOrdersTable();

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

    document.getElementById('add-category-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const nameInput = document.getElementById('category-name');
        const name = nameInput.value.trim();
        if (!/^[a-zA-Z0-9\s]{1,50}$/.test(name)) {
            alert('Category name must be 1-50 characters and contain only letters, numbers, and spaces.');
            return;
        }
        const csrfToken = await getCsrfToken();
        fetch('/api/categories', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken
            },
            body: JSON.stringify({ name })
        })
        .then(response => response.json())
        .then(data => {
            if (data.error) alert('Error: ' + data.error);
            else {
                alert('Category added successfully!');
                nameInput.value = ''; 
                window.location.reload();
            }
        })
        .catch(error => console.error('Error adding category:', error));
    });

    document.getElementById('update-category-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const catid = document.getElementById('update-category-id').value;
        const nameInput = document.getElementById('update-category-name');
        const name = nameInput.value.trim();
        if (!catid) {
            alert('Please select a category.');
            return;
        }
        if (!/^[a-zA-Z0-9\s]{1,50}$/.test(name)) {
            alert('Category name must be 1-50 characters and contain only letters, numbers, and spaces.');
            return;
        }
        const csrfToken = await getCsrfToken();
        fetch('/api/categories', {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken
            },
            body: JSON.stringify({ catid, name })
        })
        .then(response => response.json())
        .then(data => {
            if (data.error) alert('Error: ' + data.error);
            else {
                alert('Category updated successfully!');
                nameInput.value = ''; 
                window.location.reload();
            }
        })
        .catch(error => console.error('Error updating category:', error));
    });

    document.getElementById('delete-category-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const catid = document.getElementById('delete-category-id').value;
        if (!catid) {
            alert('Please select a category.');
            return;
        }
        const csrfToken = await getCsrfToken();
        fetch('/api/categories', {
            method: 'DELETE',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken
            },
            body: JSON.stringify({ catid })
        })
        .then(response => response.json())
        .then(data => {
            if (data.error) alert('Error: ' + data.error);
            else {
                alert('Category deleted successfully!');
                window.location.reload();
            }
        })
        .catch(error => console.error('Error deleting category:', error));
    });

    document.getElementById('add-product-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const form = e.target;
        const formData = new FormData(form);
    
        const name = formData.get('name').trim();
        const price = formData.get('price');
        const description = formData.get('description').trim();
        const catid = document.getElementById('category').value;
        const imageFile = form.image.files[0];
    
        // Check if a file is selected
        if (!imageFile) {
            alert('Please select an image file.');
            return;
        }
    
        if (!catid || catid === '') {
            alert('Please select a category.');
            return;
        }
        if (!/^[a-zA-Z0-9\s]{1,100}$/.test(name)) {
            alert('Product name must be 1-100 characters and contain only letters, numbers, and spaces.');
            return;
        }
        if (!/^\d+(\.\d{1,2})?$/.test(price) || parseFloat(price) <= 0) {
            alert('Price must be a positive number with up to 2 decimal places.');
            return;
        }
        if (description.length < 1 || description.length > 500) {
            alert('Description must be 1-500 characters.');
            return;
        }
    
        try {
            const csrfToken = await getCsrfToken();
            const response = await fetch('/api/products', {
                method: 'POST',
                headers: { 'X-CSRF-Token': csrfToken },
                body: formData
            });
    
            const data = await response.json();
            if (data.error) {
                alert('Error: ' + data.error);
            } else {
                alert('Product added successfully!');
                form.reset();
                window.location.reload();
            }
        } catch (error) {
            console.error('Error adding product:', error);
            alert('An error occurred while adding the product');
        }
    });

    document.getElementById('update-product-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const formData = new FormData(e.target);
        const pid = formData.get('pid');
        const name = formData.get('name').trim();
        const price = formData.get('price');
        const description = formData.get('description').trim();
        const catid = formData.get('catid');
    
        console.log('FormData values:', { pid, catid, name, price, description });
    
        if (!pid) {
            alert('Please select a product.');
            return;
        }
        if (name && !/^[a-zA-Z0-9\s]{1,100}$/.test(name)) {
            alert('Product name must be 1-100 characters and contain only letters, numbers, and spaces.');
            return;
        }
        if (price && (!/^\d+(\.\d{1,2})?$/.test(price) || parseFloat(price) <= 0)) {
            alert('Price must be a positive number with up to 2 decimal places.');
            return;
        }
        if (description && (description.length < 1 || description.length > 500)) {
            alert('Description must be 1-500 characters.');
            return;
        }
    
        try {
            const csrfToken = await getCsrfToken();
            const response = await fetch('/api/products', {
                method: 'PUT',
                headers: { 'X-CSRF-Token': csrfToken },
                body: formData
            });
            const data = await response.json();
            if (data.error) {
                alert('Error: ' + data.error);
            } else {
                alert('Product updated successfully!');
                e.target.reset(); 
                window.location.reload();
            }
        } catch (error) {
            console.error('Error updating product:', error);
            alert('An error occurred while updating the product');
        }
    });

    document.getElementById('delete-product-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const pid = document.getElementById('delete-product-id').value;
        if (!pid) {
            alert('Please select a product.');
            return;
        }
        const csrfToken = await getCsrfToken();
        fetch('/api/products', {
            method: 'DELETE',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken
            },
            body: JSON.stringify({ pid })
        })
        .then(response => response.json())
        .then(data => {
            if (data.error) alert('Error: ' + data.error);
            else {
                alert('Product deleted successfully!');
                window.location.reload();
            }
        })
        .catch(error => console.error('Error deleting product:', error));
    });

    document.getElementById('logout-btn').addEventListener('click', (e) => {
        e.preventDefault();
        getCsrfToken().then(csrfToken => {
            fetch('/logout', {
                method: 'POST',
                headers: { 'X-CSRF-Token': csrfToken }
            })
            .then(() => {
                window.location.href = '/index.html';
            })
            .catch(error => console.error('Error logging out:', error));
        });
    });
});