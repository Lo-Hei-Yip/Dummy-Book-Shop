document.addEventListener('DOMContentLoaded', () => {
    let currentCategory = null;
    let stripe; // Initialize stripe variable to be set after fetching public key

    // Fetch Stripe public key
    fetch('/api/stripe-public-key')
        .then(response => response.json())
        .then(data => {
            stripe = Stripe(data.publicKey); // Initialize Stripe with fetched key
        })
        .catch(error => console.error('Error fetching Stripe public key:', error));

    // Fetch CSRF token
    fetch('/api/csrf-token')
        .then(response => response.json())
        .then(data => {
            document.getElementById('csrf-token').value = data.csrfToken;
        })
        .catch(error => console.error('Error fetching CSRF token:', error));

    // User authentication handling
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
                if (data.isAdmin && adminLink) adminLink.classList.remove('hidden');
                else if (adminLink) adminLink.classList.add('hidden');
            } else {
                userDisplay.textContent = 'Welcome, guest';
                logoutBtn.classList.add('hidden');
                loginLink.classList.remove('hidden');
                accountLink.classList.add('hidden');
                if (adminLink) adminLink.classList.add('hidden');
            }
        })
        .catch(error => console.error('Error fetching user:', error));

    // Logout functionality
    document.getElementById('logout-btn').addEventListener('click', () => {
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

    // Shopping Cart Class
    class ShoppingCart {
        constructor() {
            this.items = JSON.parse(localStorage.getItem('cart')) || [];
            this.updateCartUI();
        }

        addItem(pid, quantity) {
            fetch(`/api/products/${pid}`)
                .then(response => response.json())
                .then(product => {
                    const existingItem = this.items.find(item => item.pid === pid);
                    if (existingItem) {
                        existingItem.quantity = Math.min(existingItem.quantity + quantity, 10);
                    } else {
                        this.items.push({ pid, name: product.name, price: product.price, quantity });
                    }
                    this.saveAndUpdate();
                });
        }

        updateItemQuantity(pid, quantity) {
            const item = this.items.find(item => item.pid === pid);
            if (item) {
                if (quantity <= 0) this.removeItem(pid);
                else item.quantity = Math.min(quantity, 10);
                this.saveAndUpdate();
            }
        }

        removeItem(pid) {
            this.items = this.items.filter(item => item.pid !== pid);
            this.saveAndUpdate();
        }

        saveAndUpdate() {
            localStorage.setItem('cart', JSON.stringify(this.items));
            this.updateCartUI();
        }

        getItems() {
            return this.items;
        }

        clearCart() {
            this.items = [];
            this.saveAndUpdate();
        }

        updateCartUI() {
            const cartItemsElement = document.getElementById('cart-items');
            const cartTotalElement = document.getElementById('cart-total');
            cartItemsElement.innerHTML = '';
            let total = 0;

            this.items.forEach(item => {
                const listItem = document.createElement('li');
                
                const nameSpan = document.createElement('span');
                nameSpan.className = 'product-name';
                nameSpan.textContent = item.name;
                
                const quantityInput = document.createElement('input');
                quantityInput.type = 'number';
                quantityInput.min = '1';
                quantityInput.max = '10';
                quantityInput.value = item.quantity;
                
                const removeBtn = document.createElement('button');
                removeBtn.className = 'remove-btn';
                removeBtn.textContent = 'Remove';
                
                const priceSpan = document.createElement('span');
                priceSpan.className = 'product-price';
                priceSpan.textContent = `$${(item.price * item.quantity).toFixed(2)}`;
                
                listItem.append(nameSpan, quantityInput, removeBtn, priceSpan);

                quantityInput.addEventListener('change', () => {
                    const newQuantity = parseInt(quantityInput.value);
                    if (newQuantity > 10 || newQuantity < 1 || isNaN(newQuantity)) {
                        alert('Quantity must be between 1 and 10.');
                        quantityInput.value = item.quantity;
                        return;
                    }
                    this.updateItemQuantity(item.pid, newQuantity);
                });

                removeBtn.addEventListener('click', () => this.removeItem(item.pid));
                cartItemsElement.appendChild(listItem);
                total += item.price * item.quantity;
            });

            cartTotalElement.textContent = total.toFixed(2);
        }
    }

    const cart = new ShoppingCart();

    // Checkout functionality
    function checkout(event) {
        event.preventDefault();
        const cartItems = cart.getItems();
        
        if (cartItems.length === 0) {
            alert('Your cart is empty!');
            return;
        }
    
        const items = cartItems.map(item => ({
            pid: item.pid,
            quantity: item.quantity
        }));
    
        fetch('/api/csrf-token')
            .then(response => response.json())
            .then(data => {
                return fetch('/create-checkout-session', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-Token': data.csrfToken
                    },
                    body: JSON.stringify({ items })
                });
            })
            .then(response => response.json())
            .then(async data => {
                if (data.error) {
                    alert(`Checkout failed: ${data.error}`);
                    return;
                }
    
                // Set hidden fields for orderId and digest in the index.html
                document.getElementById('invoice').value = data.orderId;
                document.getElementById('custom').value = data.digest;
    
                cart.clearCart();
    
                if (!stripe) {
                    alert('Checkout failed: Unable to initialize payment system.');
                    console.error('Stripe not initialized');
                    return;
                }
    
                const { error } = await stripe.redirectToCheckout({
                    sessionId: data.id
                });
    
                if (error) {
                    alert(`Checkout failed: ${error.message}`);
                }
            })
            .catch(error => {
                console.error('Error during checkout:', error);
                alert('Checkout failed: Unable to process your order.');
            });
    }

    // Category loading
    function loadCategories() {
        fetch('/api/categories')
            .then(response => response.json())
            .then(categories => {
                const categoryList = document.getElementById('category-list');
                categoryList.innerHTML = '';
                
                categories.forEach(category => {
                    const li = document.createElement('li');
                    const a = document.createElement('a');
                    a.href = '#';
                    a.textContent = category.name;
                    a.addEventListener('click', (e) => {
                        e.preventDefault();
                        loadProducts(category.catid, category.name);
                    });
                    li.appendChild(a);
                    categoryList.appendChild(li);
                });
            })
            .catch(error => console.error('Error loading categories:', error));
    }

    // Product loading functions
    function loadProducts(catid, categoryName) {
        fetch(`/api/products?catid=${catid}`)
            .then(response => response.json())
            .then(products => {
                currentCategory = { catid, name: categoryName };
                renderProductList(products, `Books in ${categoryName}`);
            })
            .catch(error => console.error('Error loading products:', error));
    }

    function loadAllProducts() {
        fetch('/api/products')
            .then(response => response.json())
            .then(products => {
                currentCategory = { catid: null, name: 'All Books' };
                renderProductList(products, 'All Books');
            })
            .catch(error => console.error('Error loading all products:', error));
    }

    function renderProductList(products, title) {
        const productList = document.getElementById('product-list');
        const categoryTitle = document.getElementById('category-title');
        
        categoryTitle.textContent = title;
        productList.innerHTML = '';

        products.forEach(product => {
            const productItem = document.createElement('div');
            productItem.classList.add('product-item');
            
            const img = document.createElement('img');
            img.src = `images/${product.pid}_thumb.jpg`;
            img.alt = product.name;
            img.className = 'product-image-small';
            
            const h2 = document.createElement('h2');
            h2.textContent = product.name;
            
            const p = document.createElement('p');
            p.textContent = `$${product.price}`;
            
            const button = document.createElement('button');
            button.className = 'view-details-btn';
            button.textContent = 'View Details';
            button.addEventListener('click', () => {
                const breadcrumbCategory = currentCategory.name === 'All Books' ? null : currentCategory.name;
                loadProductDetails(product.pid, breadcrumbCategory);
            });
            
            productItem.append(img, h2, p, button);
            productList.appendChild(productItem);
        });

        showProductList();
    }

    function loadProductDetails(pid, categoryName) {
        fetch(`/api/products/${pid}`)
            .then(response => response.json())
            .then(product => {
                const productDetailsContent = document.getElementById('product-details-content');
                productDetailsContent.innerHTML = '';
                
                const img = document.createElement('img');
                img.src = `images/${product.pid}_large.jpg`;
                img.alt = product.name;
                img.className = 'product-image-large';
                
                const h2 = document.createElement('h2');
                h2.textContent = product.name;
                
                const priceP = document.createElement('p');
                priceP.textContent = `$${product.price}`;
                
                const descP = document.createElement('p');
                const strong = document.createElement('strong');
                strong.textContent = 'Description: ';
                descP.append(strong, product.description);
                
                const label = document.createElement('label');
                label.htmlFor = `quantity-${pid}`;
                label.textContent = 'Quantity:';
                
                const input = document.createElement('input');
                input.type = 'number';
                input.id = `quantity-${pid}`;
                input.min = '1';
                input.max = '10';
                input.value = '1';
                
                const button = document.createElement('button');
                button.className = 'add-to-cart-btn';
                button.textContent = 'Add to Cart';
                button.addEventListener('click', () => {
                    const quantityInput = document.getElementById(`quantity-${pid}`);
                    const quantity = parseInt(quantityInput.value);
                    if (quantity < 1 || quantity > 10 || isNaN(quantity)) {
                        alert('Quantity must be between 1 and 10.');
                        quantityInput.value = 1;
                        return;
                    }
                    cart.addItem(product.pid, quantity);
                });
                
                productDetailsContent.append(img, h2, priceP, descP, label, input, button);
                updateBreadcrumb(categoryName, product.name);
                showProductDetails();
            })
            .catch(error => console.error('Error loading product details:', error));
    }

    // UI state management
    function showProductList() {
        document.getElementById('product-details').classList.add('hidden');
        document.getElementById('product-list').classList.remove('hidden');
        document.getElementById('category-title').classList.remove('hidden');
        document.getElementById('page-title').classList.remove('hidden');
        
        if (currentCategory && currentCategory.name !== 'All Books') {
            updateBreadcrumb(currentCategory.name);
        } else {
            document.getElementById('breadcrumb').innerHTML = `<a href="index.html" id="home-link">Home</a>`;
        }
    }

    function showProductDetails() {
        document.getElementById('product-details').classList.remove('hidden');
        document.getElementById('product-list').classList.add('hidden');
        document.getElementById('category-title').classList.add('hidden');
        document.getElementById('page-title').classList.add('hidden');
    }

    function updateBreadcrumb(categoryName, productName) {
        const breadcrumb = document.getElementById('breadcrumb');
        breadcrumb.innerHTML = `<a href="index.html" id="home-link">Home</a>`;
        
        if (categoryName) {
            const link = currentCategory?.catid 
                ? `index.html?category=${currentCategory.catid}` 
                : 'index.html';
            breadcrumb.innerHTML += ` > <a href="${link}" class="category-link">${categoryName}</a>`;
        }
        
        if (productName) {
            breadcrumb.innerHTML += ` > <span>${productName}</span>`;
        }
    }

    // Event listeners
    document.getElementById('cart-form').addEventListener('submit', checkout);
    document.getElementById('home-link').addEventListener('click', (e) => {
        e.preventDefault();
        showProductList();
    });

    // Initial page load
    const urlParams = new URLSearchParams(window.location.search);
    const categoryId = urlParams.get('category');

    if (categoryId) {
        fetch(`/api/categories/${categoryId}`)
            .then(response => response.json())
            .then(category => {
                currentCategory = category;
                loadProducts(category.catid, category.name);
            })
            .catch(error => console.error('Error loading category:', error));
    } else {
        currentCategory = { catid: null, name: 'All Books' };
        loadAllProducts();
    }

    loadCategories();
});